package agent

// Reattach after the engine lost this server's record (e.g. its database was wiped).
// The agent presents its existing server token + untrusted inventory. The engine records an orphan
// pending admin approval; it does NOT auto-admit the machine or bind it to an org/server.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/databases"
	"github.com/vinodkumar937/f2c-agent/internal/docker"
	"github.com/vinodkumar937/f2c-agent/internal/sysinfo"
	"github.com/vinodkumar937/f2c-agent/internal/update"
	"github.com/vinodkumar937/f2c-agent/internal/version"
)

type reattachIdentity struct {
	ClaimedServerID  string   `json:"claimedServerId"`
	TokenFingerprint string   `json:"tokenFingerprint"`
	Hostname         string   `json:"hostname"`
	IPs              []string `json:"ips"`
	PublicIP         string   `json:"publicIp,omitempty"`
	Arch             string   `json:"arch"`
	AgentVersion     string   `json:"agentVersion"`
	AgentHash        string   `json:"agentHash,omitempty"`
}

type reattachInventory struct {
	Containers []map[string]any `json:"containers"`
	Databases  []map[string]any `json:"databases"`
	Volumes    []string         `json:"volumes"`
	CaddyHosts []string         `json:"caddyHosts"`
}

func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func collectLocalIPs() []string {
	out := []string{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				out = append(out, v4.String())
			} else if ip.To16() != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func collectDatabaseInventory(stateDir string) []map[string]any {
	base := filepath.Join(stateDir, "databases")
	rows := []map[string]any{}
	_ = filepath.WalkDir(base, func(path string, d os.DirEntry, e error) error {
		if e != nil || d == nil || d.IsDir() || d.Name() != "database.json" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var s databases.Spec
		if json.Unmarshal(b, &s) != nil {
			return nil
		}
		// Never include credentials — inventory is untrusted and may be shown to an operator.
		rows = append(rows, map[string]any{
			"orgId": s.Org, "databaseName": s.Name, "type": s.Type,
			"container": s.Container, "volume": s.Volume, "generation": s.Generation,
			"user": s.User, "database": s.Database, "deleted": s.Deleted,
		})
		return nil
	})
	return rows
}

func collectCaddyHosts(caddyAdmin string) []string {
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Get(strings.TrimRight(caddyAdmin, "/") + "/config/apps/http/servers")
	if err != nil {
		return []string{}
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return []string{}
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var raw any
	if json.Unmarshal(b, &raw) != nil {
		return []string{}
	}
	hosts := map[string]struct{}{}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if m, ok := t["match"].([]any); ok {
				for _, x := range m {
					mm, _ := x.(map[string]any)
					if hs, ok := mm["host"].([]any); ok {
						for _, h := range hs {
							if s, ok := h.(string); ok && s != "" && !strings.Contains(s, "*") {
								hosts[strings.ToLower(s)] = struct{}{}
							}
						}
					}
				}
			}
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(raw)
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	return out
}

func collectReattachInventory(stateDir, caddyAdmin string) reattachInventory {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	containers := []map[string]any{}
	if list, err := docker.ManagedContainers(ctx); err == nil {
		for _, c := range list {
			containers = append(containers, map[string]any{
				"name": c.Name, "state": c.State, "image": c.Image, "status": c.Status, "hostPort": c.HostPort,
			})
		}
	}
	return reattachInventory{
		Containers: containers,
		Databases:  collectDatabaseInventory(stateDir),
		Volumes:    docker.CollectVolumeInventory(ctx),
		CaddyHosts: collectCaddyHosts(caddyAdmin),
	}
}

func Reattach(engine, stateDir, caddyAdmin, publicIP string, insecure bool) error {
	cfg, err := config.Load(stateDir)
	if err != nil {
		return err
	}
	if engine == "" {
		engine = cfg.Engine
	}
	u, err := config.CheckEngineURL(engine, insecure)
	if err != nil {
		return err
	}
	publicIP, err = config.ResolvePublicIP(publicIP, config.DetectPublicIP)
	if err != nil {
		return err
	}
	hn, _ := os.Hostname()
	inv := collectReattachInventory(stateDir, caddyAdmin)
	id := reattachIdentity{
		ClaimedServerID:  cfg.ServerID,
		TokenFingerprint: tokenFingerprint(cfg.Token),
		Hostname:         hn,
		IPs:              collectLocalIPs(),
		PublicIP:         publicIP,
		Arch:             sysinfo.HostArch(),
		AgentVersion:     version.Version,
		AgentHash:        update.SelfHash(),
	}
	body, _ := json.Marshal(map[string]any{
		"token":     cfg.Token, // presented once for hashing; never logged by a correct engine
		"identity":  id,
		"inventory": inv,
	})
	client := &http.Client{Timeout: 60 * time.Second}
	res, err := client.Post(u.String()+"/agent/reattach", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	var out struct {
		Status   string `json:"status"`
		OrphanID string `json:"orphanId"`
		Error    string `json:"error"`
		Code     string `json:"code"`
		Message  string `json:"message"`
	}
	_ = json.Unmarshal(rb, &out)
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		fmt.Printf("reattach: recorded as orphan %s (status=%s); waiting for admin approval\n", out.OrphanID, out.Status)
		if out.Message != "" {
			fmt.Println(out.Message)
		}
		return nil
	}
	if res.StatusCode == http.StatusConflict && (out.Code == "already_known" || out.Status == "already_known") {
		fmt.Println("reattach: engine already knows this server token; start the agent normally (`f2c-agent run`)")
		return nil
	}
	if out.Code != "" {
		return fmt.Errorf("engine returned %d (%s): %s", res.StatusCode, out.Code, firstNonEmpty(out.Error, out.Message))
	}
	return fmt.Errorf("engine returned %d: %s", res.StatusCode, firstNonEmpty(out.Error, string(rb)))
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	if b != "" {
		return b
	}
	return "(no message)"
}
