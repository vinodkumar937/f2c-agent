package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/metrics"
	"github.com/vinodkumar937/f2c-agent/internal/sysinfo"
	"github.com/vinodkumar937/f2c-agent/internal/version"
)

// Config is the long-lived server identity, stored 0600 in <state-dir>/agent.json.
type Config struct {
	Engine   string `json:"engine"`
	ServerID string `json:"serverId"`
	Token    string `json:"token"`
}

func configPath(stateDir string) string { return filepath.Join(stateDir, "agent.json") }

func Load(stateDir string) (*Config, error) {
	b, err := os.ReadFile(configPath(stateDir))
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("agent.json: %w", err)
	}
	if c.Engine == "" || c.Token == "" {
		return nil, errors.New("agent.json is incomplete")
	}
	return &c, nil
}

// WriteFile0600 writes atomically with owner-only permissions.
func WriteFile0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func CheckEngineURL(raw string, insecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(raw, "\r\n\t ") {
		return nil, fmt.Errorf("engine URL must be http(s)://host[:port]")
	}
	// TLS (https/wss) is required beyond loopback; --insecure no longer overrides this.
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		if insecure {
			return nil, errors.New("--insecure is no longer supported for non-loopback engines; use https:// (wss)")
		}
		return nil, errors.New("refusing plain http to a non-loopback engine (use https://)")
	}
	return u, nil
}

// SaveToken atomically replaces the server token in agent.json (live rotation).
func SaveToken(stateDir string, c Config, token string) error {
	c.Token = token
	b, _ := json.MarshalIndent(c, "", "  ")
	return WriteFile0600(configPath(stateDir), b)
}

func Join(engine, token, stateDir, provider, publicIP string, insecure bool) error {
	u, err := CheckEngineURL(engine, insecure)
	if err != nil {
		return err
	}
	publicIP, err = ResolvePublicIP(publicIP, DetectPublicIP)
	if err != nil {
		return err
	}
	m := metrics.Collect(stateDir)
	body, _ := json.Marshal(map[string]any{
		"token": token,
		"info": map[string]any{
			"cpuCount": runtime.NumCPU(), "memoryMb": m.MemTotalMb, "diskGb": m.DiskTotalGb,
			"agentVersion": version.Version, "provider": provider, "publicIp": publicIP, "arch": sysinfo.HostArch(),
		},
	})
	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Post(u.String()+"/agent/join", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusCreated {
		var e struct{ Error, Code string }
		_ = json.Unmarshal(rb, &e)
		if e.Code != "" {
			return fmt.Errorf("engine returned %d (%s): %s", res.StatusCode, e.Code, e.Error)
		}
		return fmt.Errorf("engine returned %d: %s", res.StatusCode, e.Error)
	}
	var out struct {
		ServerID    string `json:"serverId"`
		ServerToken string `json:"serverToken"`
	}
	if err := json.Unmarshal(rb, &out); err != nil || out.ServerToken == "" {
		return errors.New("bad join response")
	}
	c, _ := json.MarshalIndent(Config{Engine: u.String(), ServerID: out.ServerID, Token: out.ServerToken}, "", "  ")
	if err := WriteFile0600(configPath(stateDir), c); err != nil {
		return err
	}
	fmt.Printf("joined as %s; token saved to %s\n", out.ServerID, configPath(stateDir))
	return nil
}

// nonPublicNets: loopback, private, link-local, CGNAT, unspecified, documentation and multicast ranges (the engine
// applies the same rule to the address it records).
var nonPublicNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
		"192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// isPublicIP reports whether s is a globally routable unicast IPv4 or IPv6 address.
func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range nonPublicNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// ResolvePublicIP: an explicit --public-ip must be public; without one, try detect (cloud metadata) and fall back
// to "" (the engine then uses the address it sees, if that is public).
func ResolvePublicIP(explicit string, detect func() string) (string, error) {
	if explicit != "" {
		if !isPublicIP(explicit) {
			return "", fmt.Errorf("--public-ip %q is not a public IP address (loopback, private, link-local, CGNAT or unspecified)", explicit)
		}
		return explicit, nil
	}
	if ip := detect(); isPublicIP(ip) {
		fmt.Printf("public IP %s detected from the cloud metadata service (override with --public-ip)\n", ip)
		return ip, nil
	}
	return "", nil
}

// DetectPublicIP asks the DigitalOcean droplet metadata service (link-local, 2 s timeout); "" elsewhere.
func DetectPublicIP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Get("http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address")
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64))
	return strings.TrimSpace(string(b))
}
