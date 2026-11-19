package caddy

// Step 9e: per-server routing support. The engine pushes this server's Caddy config with caddy_apply plus the list
// of public hosts on this server; the local Caddy's on-demand TLS asks GET /tls/ask?domain=<host> here (127.0.0.1
// only), so this server only ever obtains certificates for its own hosts. http_probe lets the engine health-check
// apps through this server's Caddy.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

const maxAskHosts = 10000

var (
	hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// Probe paths: absolute, printable, no spaces or control characters.
	probePathRe = regexp.MustCompile(`^/[\x21-\x7e]{0,511}$`)
)

// parseAskHosts validates the caddy_apply "hosts" list (lowercase DNS names, no wildcards).
func parseAskHosts(v any) (map[string]bool, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, protocol.BadRequest(errors.New("hosts must be an array of host names"))
	}
	if len(list) > maxAskHosts {
		return nil, protocol.BadRequest(fmt.Errorf("at most %d hosts", maxAskHosts))
	}
	out := make(map[string]bool, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok || len(s) > 253 || !hostRe.MatchString(s) {
			return nil, protocol.BadRequest(fmt.Errorf("invalid host %q", fmt.Sprint(item)))
		}
		out[s] = true
	}
	return out, nil
}

func (a *Manager) askPath() string { return filepath.Join(a.stateDir, "ask-hosts.json") }

// setAskHosts replaces the allowed hosts and persists them so a restarted agent answers the same way.
func (a *Manager) setAskHosts(h map[string]bool) error {
	list := make([]string, 0, len(h))
	for k := range h {
		list = append(list, k)
	}
	b, _ := json.Marshal(list)
	if err := config.WriteFile0600(a.askPath(), b); err != nil {
		return err
	}
	a.askMu.Lock()
	a.askHosts = h
	a.askMu.Unlock()
	return nil
}

func (a *Manager) loadAskHosts() {
	b, err := os.ReadFile(a.askPath())
	if err != nil {
		return
	}
	var list []string
	if json.Unmarshal(b, &list) != nil {
		return
	}
	h := make(map[string]bool, len(list))
	for _, s := range list {
		h[s] = true
	}
	a.askMu.Lock()
	a.askHosts = h
	a.askMu.Unlock()
}

func (a *Manager) askAllowed(domain string) bool {
	a.askMu.RLock()
	defer a.askMu.RUnlock()
	h := strings.ToLower(strings.TrimSuffix(domain, "."))
	return a.askHosts[h] && issuanceAllowed(h) // step 4: capped registered domain -> only hosts with a cert
}

// askHandler answers Caddy's on-demand TLS permission check: 200 = issue, 404 = refuse.
func (a *Manager) askHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/tls/ask" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if a.askAllowed(r.URL.Query().Get("domain")) {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "unknown host", http.StatusNotFound)
}

// ServeAsk listens on a loopback address only; it stops with ctx.
func (a *Manager) ServeAsk(ctx context.Context, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || (host != "127.0.0.1" && host != "::1" && host != "localhost") {
		log.Printf("tls ask: refusing non-loopback listen address %q", addr)
		return
	}
	a.loadAskHosts()
	a.loadAccessHostMap()
	srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(a.askHandler), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("tls ask: %v", err)
	}
}

// adminListen turns the --caddy-admin URL into Caddy's admin.listen (so a pushed config keeps the admin API where
// the agent expects it).
func adminListen(caddyAdmin string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(caddyAdmin, "http://"), "https://")
	return strings.TrimRight(s, "/")
}

type probeArgs struct {
	Host string
	Path string
	Port int
}

func parseProbeArgs(args map[string]any) (probeArgs, error) {
	p := probeArgs{Host: strings.ToLower(util.Str(args, "host")), Path: util.Str(args, "path"), Port: int(util.Num(args, "port"))}
	if p.Path == "" {
		p.Path = "/"
	}
	if !hostRe.MatchString(p.Host) || len(p.Host) > 253 {
		return p, protocol.BadRequest(errors.New("invalid host"))
	}
	if !probePathRe.MatchString(p.Path) {
		return p, protocol.BadRequest(errors.New("path must start with / and contain no spaces (max 512 chars)"))
	}
	if p.Port == 0 {
		p.Port = 80
	}
	if p.Port < 1 || p.Port > 65535 {
		return p, protocol.BadRequest(errors.New("invalid port"))
	}
	return p, nil
}

// HTTPProbe GETs http://127.0.0.1:<port><path> with the given Host (the server's Caddy), no redirects followed.
func HTTPProbe(ctx context.Context, args map[string]any) (any, error) {
	p, err := parseProbeArgs(args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(p.Port)+p.Path, nil)
	req.Host = p.Host
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return map[string]any{"status": 0, "error": util.Tail(err.Error(), 300)}, nil
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64*1024))
	return map[string]any{"status": res.StatusCode, "ms": time.Since(start).Milliseconds()}, nil
}
