package caddy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/docker"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

// Apply loads a full JSON config into the local Caddy (POST /load on the admin API: atomic, a rejected
// Config keeps the running one). Optional hosts replace the /tls/ask allow-list after a successful load.
func (a *Manager) Apply(ctx context.Context, args map[string]any) (any, error) {
	cfg, ok := args["config"].(map[string]any)
	if !ok {
		return nil, protocol.BadRequest(errors.New("config must be a JSON object"))
	}
	setIssuanceBlocked(args["issuanceBlocked"]) // Let's Encrypt cap per registered domain (engine-computed)
	hosts, err := parseAskHosts(args["hosts"])
	if err != nil {
		return nil, err
	}
	// the server's wildcard via DNS-01 (token from the 0600 file the engine sent with dns_token).
	wildcard, err := a.applyDNSPolicy(cfg, args["wildcard"])
	if err != nil {
		return nil, err
	}
	// Keep Caddy's admin API where this agent talks to it (a config without "admin" would reset it).
	if _, has := cfg["admin"]; !has {
		cfg["admin"] = map[string]any{"listen": adminListen(a.caddyAdmin)}
	}
	b, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.caddyAdmin, "/")+"/load", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		// The admin API could not be reached (or answered too late): retryable. A deadline becomes "timeout" via DefaultCode.
		return nil, protocol.DefaultCode(protocol.CodeCaddyUnavailable, fmt.Errorf("caddy admin: %w", err))
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(rb))
		if wildcard != "" { // Caddy can echo provider config in errors; never pass the DNS token on
			if f, e := a.loadDNSToken(); e == nil && f.Token != "" {
				msg = strings.ReplaceAll(msg, f.Token, "[redacted]")
			}
		}
		return nil, protocol.WithCode(protocol.CodeCaddyRejected, fmt.Errorf("caddy /load returned %d: %s", res.StatusCode, msg))
	}
	a.applyAccessHostMap(cfg) // multi-public Compose: extra service hosts are reported under the parent app
	if hosts != nil {
		if err := a.setAskHosts(hosts); err != nil {
			return nil, fmt.Errorf("config applied, but saving the TLS host list failed: %w", err)
		}
	}
	out := map[string]any{"applied": true, "bytes": len(b), "hosts": len(hosts), "wildcard": wildcard}
	return out, nil
}

// CertInstall writes a validated cert/key pair (e.g. a wildcard certificate) to <cert-dir>; key 0600.
func (a *Manager) CertInstall(args map[string]any) (any, error) {
	domain := strings.ToLower(util.Str(args, "domain"))
	if !docker.DomainRe.MatchString(domain) {
		return nil, protocol.BadRequest(errors.New("invalid domain"))
	}
	certPem, keyPem := util.Str(args, "certPem"), util.Str(args, "keyPem")
	pair, err := tls.X509KeyPair([]byte(certPem), []byte(keyPem))
	if err != nil {
		return nil, protocol.BadRequest(fmt.Errorf("cert/key do not form a valid pair: %w", err))
	}
	blk, _ := pem.Decode([]byte(certPem))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(strings.Replace(domain, "*.", "x.", 1)); err != nil {
		return nil, protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("certificate does not cover %s", domain))
	}
	_ = pair
	file := strings.Replace(domain, "*.", "_wildcard.", 1)
	if err := os.MkdirAll(a.certDir, 0o700); err != nil {
		return nil, err
	}
	crt, key := filepath.Join(a.certDir, file+".crt"), filepath.Join(a.certDir, file+".key")
	if err := config.WriteFile0600(key, []byte(keyPem)); err != nil {
		return nil, err
	}
	if err := os.WriteFile(crt+".tmp", []byte(certPem), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(crt+".tmp", crt); err != nil {
		return nil, err
	}
	return map[string]any{"certPath": crt, "keyPath": key, "notAfter": leaf.NotAfter.UTC().Format(time.RFC3339)}, nil
}
