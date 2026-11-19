package caddy

// M2.9: the server's wildcard certificate via DNS-01. The engine sends this server's DNS provider token over the
// live connection ("dns_token": never queued, never logged); it is saved 0600 in the state dir and synced into
// /etc/f2c-agent/caddy-dns.env (DO_AUTH_TOKEN / CF_API_TOKEN) so Caddy can reference {env.*} placeholders.
// caddy_apply inserts a DNS-01 policy for *.<domain> that uses those placeholders (never embeds the token literal).
// After the env file changes, install.sh's f2c-caddy-dns-env.path unit restarts Caddy so EnvironmentFile is re-read
// (agent stays NoNewPrivileges=yes; no sudo from the agent).

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

type dnsTokenFile struct {
	Provider string `json:"provider"`
	Domain   string `json:"domain"`
	Token    string `json:"token"`
}

var dnsProviders = map[string]bool{"digitalocean": true, "cloudflare": true, "other": true} // other = on-demand HTTP-01 (no DNS-01 policy here)

func (a *Manager) dnsTokenPath() string { return filepath.Join(a.stateDir, "dns-token.json") }

func validWildcard(provider, domain string) bool {
	return dnsProviders[provider] && len(domain) <= 253 && hostRe.MatchString(domain)
}

// saveDNSToken writes the token atomically with mode 0600 (temp file, chmod, rename).
func (a *Manager) saveDNSToken(f dnsTokenFile) error {
	b, _ := json.Marshal(f)
	tmp, err := os.CreateTemp(a.stateDir, ".dns-token-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.dnsTokenPath())
}

func (a *Manager) loadDNSToken() (dnsTokenFile, error) {
	var f dnsTokenFile
	b, err := os.ReadFile(a.dnsTokenPath())
	if err != nil {
		return f, err
	}
	err = json.Unmarshal(b, &f)
	return f, err
}

const caddyDNSEnvPath = "/etc/f2c-agent/caddy-dns.env"

func dnsEnvTokenKey(provider string) string {
	switch provider {
	case "cloudflare":
		return "CF_API_TOKEN"
	default:
		return "DO_AUTH_TOKEN"
	}
}

func dnsProviderPlaceholder(provider string) map[string]any {
	if provider == "cloudflare" {
		return map[string]any{"name": "cloudflare", "api_token": "{env.CF_API_TOKEN}"}
	}
	return map[string]any{"name": "digitalocean", "auth_token": "{env.DO_AUTH_TOKEN}"}
}

// syncCaddyDNSEnv writes domain/provider/token into caddy-dns.env (0640) without echoing the token.
// Returns whether the token value changed (systemd Path unit restarts Caddy to re-read EnvironmentFile).
func syncCaddyDNSEnv(f dnsTokenFile) (changed bool, err error) {
	key := dnsEnvTokenKey(f.Provider)
	want := map[string]string{
		"F2C_WILDCARD_DOMAIN": f.Domain,
		"F2C_DNS_PROVIDER":    f.Provider,
		key:                   f.Token,
	}
	cur := map[string]string{}
	if b, e := os.ReadFile(caddyDNSEnvPath); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			k, v, _ := strings.Cut(line, "=")
			cur[k] = v
		}
	} else if !os.IsNotExist(e) {
		return false, e
	}
	changed = cur[key] != f.Token || cur["F2C_WILDCARD_DOMAIN"] != f.Domain || cur["F2C_DNS_PROVIDER"] != f.Provider
	if !changed {
		return false, nil
	}
	// Preserve unrelated keys.
	for k, v := range cur {
		if _, keep := want[k]; !keep {
			want[k] = v
		}
	}
	var b strings.Builder
	order := []string{"F2C_WILDCARD_DOMAIN", "F2C_DNS_PROVIDER", key}
	seen := map[string]bool{}
	for _, k := range order {
		fmt.Fprintf(&b, "%s=%s\n", k, want[k])
		seen[k] = true
	}
	for k, v := range want {
		if seen[k] {
			continue
		}
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	tmp := caddyDNSEnvPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o640); err != nil {
		return false, err
	}
	_ = os.Chmod(tmp, 0o640)
	if err := os.Rename(tmp, caddyDNSEnvPath); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return changed, nil
}

// DNSToken handles the engine's "dns_token" message and confirms with dns_token_ok (the token is never echoed).
func (a *Manager) DNSToken(m protocol.Message) {
	reply := map[string]any{"t": "dns_token_ok", "id": m.ID, "ok": false}
	if m.ID == "" || !validWildcard(m.Provider, m.Domain) || m.Token == "" || len(m.Token) > 512 || strings.ContainsAny(m.Token, "\r\n") {
		reply["error"] = "invalid dns_token message"
		reply["code"] = protocol.CodeBadRequest // sent only at protocol >= 1 (Agent.send drops it below)
		a.send(reply)
		return
	}
	f := dnsTokenFile{Provider: m.Provider, Domain: m.Domain, Token: m.Token}
	if err := a.saveDNSToken(f); err != nil {
		reply["error"] = "could not save the DNS token: " + err.Error()
		reply["code"] = protocol.V1Code(err)
		a.send(reply)
		return
	}
	if _, err := syncCaddyDNSEnv(f); err != nil {
		reply["error"] = "DNS token saved locally, but caddy-dns.env update failed: " + err.Error()
		reply["code"] = protocol.V1Code(err)
		a.send(reply)
		return
	}
	// Caddy picks up EnvironmentFile via f2c-caddy-dns-env.path (install.sh); agent does not sudo-restart.
	log.Printf("DNS token for *.%s (%s) saved", m.Domain, m.Provider)
	reply["ok"] = true
	a.send(reply)
}

// applyDNSPolicy edits cfg's apps.tls.automation.policies in place when caddy_apply names a wildcard. Returns the
// wildcard subject applied ("" when none).
func (a *Manager) applyDNSPolicy(cfg map[string]any, v any) (string, error) {
	if v == nil {
		return "", nil
	}
	w, ok := v.(map[string]any)
	if !ok {
		return "", protocol.BadRequest(errors.New("wildcard must be an object or null"))
	}
	domain, _ := w["domain"].(string)
	provider, _ := w["provider"].(string)
	if !validWildcard(provider, domain) {
		return "", protocol.BadRequest(errors.New("invalid wildcard"))
	}
	if provider == "other" {
		// "other": the engine config already has the on-demand *.<domain> policy (HTTP-01); nothing to add.
		return "", nil
	}
	var provBlock map[string]any
	{
		f, err := a.loadDNSToken()
		if err != nil || f.Domain != domain || f.Provider != provider || f.Token == "" {
			return "", protocol.WithCode(protocol.CodeCaddyRejected, fmt.Errorf("no stored DNS token for *.%s (%s)", domain, provider))
		}
		// Prefer env placeholders so the live Caddy config never embeds the token literal.
		provBlock = dnsProviderPlaceholder(provider)
		// Ensure the env file is present for this token (idempotent; no Caddy restart here —
		// dns_token already restarted when the value changed).
		if _, err := syncCaddyDNSEnv(f); err != nil {
			return "", fmt.Errorf("caddy-dns.env sync failed: %w", err)
		}
	}
	apps, _ := cfg["apps"].(map[string]any)
	tls, _ := apps["tls"].(map[string]any)
	auto, _ := tls["automation"].(map[string]any)
	if auto == nil {
		return "", protocol.WithCode(protocol.CodeCaddyRejected, errors.New("config has no apps.tls.automation"))
	}
	pols, _ := auto["policies"].([]any)
	subject := "*." + domain
	covered := func(h string) bool {
		return strings.HasSuffix(h, "."+domain) && !strings.Contains(strings.TrimSuffix(h, "."+domain), ".")
	}
	var acmeIssuers []any
	out := make([]any, 0, len(pols)+1)
	insertAt := -1
	for _, p := range pols {
		pm, ok := p.(map[string]any)
		if !ok || pm["on_demand"] != true {
			out = append(out, p)
			continue
		}
		if insertAt < 0 {
			insertAt = len(out)
		}
		if acmeIssuers == nil {
			acmeIssuers, _ = pm["issuers"].([]any)
		}
		subs, _ := pm["subjects"].([]any)
		kept := make([]any, 0, len(subs))
		for _, s := range subs {
			if hs, _ := s.(string); !covered(hs) {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 && len(subs) > 0 {
			continue // every host is under the wildcard
		}
		pm["subjects"] = kept
		out = append(out, pm)
	}
	if insertAt < 0 {
		insertAt = len(out)
	}
	if acmeIssuers == nil {
		acmeIssuers = []any{map[string]any{"module": "acme"}}
	}
	issuers := make([]any, 0, len(acmeIssuers))
	for _, is := range acmeIssuers {
		im, ok := is.(map[string]any)
		if !ok {
			continue
		}
		c := map[string]any{}
		for k, v := range im {
			c[k] = v
		}
		c["challenges"] = map[string]any{"dns": map[string]any{"provider": provBlock, "resolvers": []any{"1.1.1.1", "8.8.8.8"}}}
		issuers = append(issuers, c)
	}
	policy := map[string]any{"subjects": []any{subject}, "issuers": issuers}
	out = append(out[:insertAt], append([]any{policy}, out[insertAt:]...)...)
	auto["policies"] = out
	return subject, nil
}
