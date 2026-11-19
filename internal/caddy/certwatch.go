package caddy

// Step 4 (on-demand "other" servers): Let's Encrypt rate-limit support.
// - watchCerts discovers ACME certs and reports each newly seen one
//   ({t:"cert_issued", host, issuedAt, expiresAt}) to the engine.
// - Discovery prefers a TLS dial to 127.0.0.1:443 with SNI (no filesystem permissions).
//   Hosts probed: askHosts from caddy_apply, plus a synthetic label under the DNS-01 wildcard domain.
//   Filesystem scan of Caddy's cert storage remains as a best-effort supplement when readable.
// - Race fix: wait until the websocket is connected, and only mark a cert "seen" after send succeeds
//   (otherwise a pre-connect scan would permanently suppress cert_issued).
// - The engine sends the registered domains at the cap (caddy_apply "issuanceBlocked"); /tls/ask then refuses
//   hosts under them that have no cert yet, so Caddy doesn't burn failed attempts.
// - tls_warm: one HTTPS request to https://<host>/ through 127.0.0.1:443 (SNI = host) after a deploy.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

var certState struct {
	sync.RWMutex
	seen    map[string]time.Time // host -> NotBefore of the newest cert successfully reported
	blocked map[string]bool      // registered domains at the issuance cap
}

type certMeta struct{ notBefore, notAfter time.Time }

// Manager is everything that talks to the local Caddy or watches its certificates: caddy_apply, cert_install, the
// on-demand TLS "ask" endpoint, the DNS-01 token and the certificate watcher. It needs only the state dir, Caddy's
// admin address, the certificate dir, a way to send frames and a way to tell whether the engine link is up.
type Manager struct {
	stateDir   string
	caddyAdmin string
	certDir    string
	send       func(any) bool
	hasConn    func() bool

	// Hosts this server may get certificates for (step 9e), from the last caddy_apply.
	askMu    sync.RWMutex
	askHosts map[string]bool
}

// caddyCertHost normalizes a leaf name to Caddy's on-disk style (*.example.com -> wildcard_.example.com).
func caddyCertHost(name string) string {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if strings.HasPrefix(n, "*.") {
		return "wildcard_." + strings.TrimPrefix(n, "*.")
	}
	return n
}

func metaFromCert(c *x509.Certificate) (host string, meta certMeta, ok bool) {
	if c == nil {
		return "", certMeta{}, false
	}
	name := c.Subject.CommonName
	if len(c.DNSNames) > 0 {
		name = c.DNSNames[0]
	}
	if name == "" {
		return "", certMeta{}, false
	}
	return caddyCertHost(name), certMeta{notBefore: c.NotBefore, notAfter: c.NotAfter}, true
}

// probeTLSCert dials 127.0.0.1:443 with SNI=sni and returns the leaf cert meta (host key from SAN/CN).
func probeTLSCert(sni string) (string, certMeta, bool) {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	if sni == "" || strings.Contains(sni, "*") {
		return "", certMeta{}, false
	}
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", warmAddr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // local Caddy; we only need the leaf fields
	})
	if err != nil {
		return "", certMeta{}, false
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", certMeta{}, false
	}
	return metaFromCert(state.PeerCertificates[0])
}

// scanCerts returns host -> leaf NotBefore/NotAfter for ACME certs under dir (Caddy: <issuer>/<host>/<host>.crt; "local" = internal CA).
func scanCerts(dir string) map[string]certMeta {
	out := map[string]certMeta{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".crt") {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if strings.HasPrefix(rel, "local"+string(filepath.Separator)) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil
		}
		host := strings.ToLower(strings.TrimSuffix(filepath.Base(p), ".crt"))
		if prev, ok := out[host]; !ok || c.NotBefore.After(prev.notBefore) {
			out[host] = certMeta{notBefore: c.NotBefore, notAfter: c.NotAfter}
		}
		return nil
	})
	return out
}

// discoverCerts prefers TLS SNI probes (no file perms); merges a filesystem scan when readable.
func (a *Manager) discoverCerts(dir string) map[string]certMeta {
	out := map[string]certMeta{}
	merge := func(host string, meta certMeta) {
		if host == "" {
			return
		}
		if prev, ok := out[host]; !ok || meta.notBefore.After(prev.notBefore) {
			out[host] = meta
		}
	}

	// Wildcard DNS-01: probe a synthetic label under the stored domain (SNI cannot be "*.domain").
	if f, err := a.loadDNSToken(); err == nil && f.Domain != "" && f.Provider != "other" {
		sni := "f2c-certwatch." + f.Domain
		if host, meta, ok := probeTLSCert(sni); ok {
			// Prefer reporting the wildcard subject when the leaf is the wildcard cert.
			if strings.HasPrefix(host, "wildcard_.") || host == caddyCertHost("*."+f.Domain) {
				merge(caddyCertHost("*."+f.Domain), meta)
			} else {
				merge(host, meta)
			}
		}
	}

	a.askMu.RLock()
	hosts := make([]string, 0, len(a.askHosts))
	for h := range a.askHosts {
		hosts = append(hosts, h)
	}
	a.askMu.RUnlock()
	for _, h := range hosts {
		if host, meta, ok := probeTLSCert(h); ok {
			merge(host, meta)
		}
	}

	for host, meta := range scanCerts(dir) {
		merge(host, meta)
	}
	return out
}

// certEventsToSend returns cert_issued payloads for certs not yet successfully reported (or newer NotBefore).
func certEventsToSend(now time.Time, found map[string]certMeta) []map[string]any {
	certState.RLock()
	defer certState.RUnlock()
	var ev []map[string]any
	for h, meta := range found {
		nb := meta.notBefore.UTC().Truncate(time.Second)
		if prev, ok := certState.seen[h]; ok && !nb.After(prev) {
			continue
		}
		if now.Sub(nb) > 7*24*time.Hour {
			continue
		}
		ev = append(ev, map[string]any{
			"t":         "cert_issued",
			"host":      h,
			"issuedAt":  nb.Format(time.RFC3339),
			"expiresAt": meta.notAfter.UTC().Truncate(time.Second).Format(time.RFC3339),
		})
	}
	return ev
}

func markCertSeen(host string, issuedAt string) {
	nb, err := time.Parse(time.RFC3339, issuedAt)
	if err != nil {
		return
	}
	certState.Lock()
	defer certState.Unlock()
	if certState.seen == nil {
		certState.seen = map[string]time.Time{}
	}
	if prev, ok := certState.seen[host]; ok && !nb.After(prev) {
		return
	}
	certState.seen[host] = nb
}

func (a *Manager) Watch(ctx context.Context, dir string) {
	// Wait for a live engine connection so the first scan's send() can succeed.
	for !a.hasConn() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		for _, e := range certEventsToSend(time.Now(), a.discoverCerts(dir)) {
			if a.send(e) {
				host, _ := e["host"].(string)
				issued, _ := e["issuedAt"].(string)
				markCertSeen(host, issued)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func setIssuanceBlocked(v any) {
	m := map[string]bool{}
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok && hostRe.MatchString(strings.ToLower(s)) {
				m[strings.ToLower(s)] = true
			}
		}
	}
	certState.Lock()
	certState.blocked = m
	certState.Unlock()
}

// issuanceAllowed: false only when host is under a capped registered domain and has no cert on disk/reported yet.
func issuanceAllowed(host string) bool {
	certState.RLock()
	defer certState.RUnlock()
	h := caddyCertHost(host)
	if _, has := certState.seen[h]; has {
		return true
	}
	if _, has := certState.seen[host]; has {
		return true
	}
	for d := range certState.blocked {
		if host == d || strings.HasSuffix(host, "."+d) {
			return false
		}
	}
	return true
}

// tls_warm
var (
	warmAddr    = "127.0.0.1:443"
	warmTimeout = 30 * time.Second
	warmRoots   *x509.CertPool // nil = system roots (tests override)
)

func TLSWarm(ctx context.Context, args map[string]any) (any, error) {
	host := strings.ToLower(strings.TrimSuffix(util.Str(args, "host"), "."))
	if !hostRe.MatchString(host) {
		return nil, protocol.BadRequest(errors.New("invalid host"))
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", warmAddr)
		},
		TLSClientConfig: &tls.Config{ServerName: host, RootCAs: warmRoots},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var lastErr string
	for attempt := 1; attempt <= 2; attempt++ {
		c, cancel := context.WithTimeout(ctx, warmTimeout)
		req, _ := http.NewRequestWithContext(c, http.MethodGet, "https://"+host+"/", nil)
		res, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64*1024))
			res.Body.Close()
			issuer := ""
			if res.TLS != nil && len(res.TLS.PeerCertificates) > 0 {
				issuer = res.TLS.PeerCertificates[0].Issuer.String()
			}
			cancel()
			return map[string]any{"ok": true, "status": res.StatusCode, "issuer": issuer, "attempts": attempt}, nil
		}
		cancel()
		lastErr = util.Tail(err.Error(), 300)
	}
	return map[string]any{"ok": false, "error": lastErr, "attempts": 2}, nil
}

// New builds the Caddy manager: the agent's state dir, Caddy's admin address, the certificate dir, a way to send
// frames and a way to tell whether the engine link is up.
func New(stateDir, caddyAdmin, certDir string, send func(any) bool, hasConn func() bool) *Manager {
	return &Manager{stateDir: stateDir, caddyAdmin: caddyAdmin, certDir: certDir, send: send, hasConn: hasConn}
}
