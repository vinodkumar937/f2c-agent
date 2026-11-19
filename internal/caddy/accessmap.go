package caddy

// Multi-public Compose: one app can answer on several hosts (its primary host, custom domains, and the custom domains of
// its non-primary public services). The engine maps an access-log host to an app through the app's own host list, which
// does not include the extra service domains, so those minutes would be dropped. caddy_apply already tells us which
// route belongs to which app (the route "@id"), so on every successful apply we derive "service host -> the app's
// primary host" and report extra-service traffic under the primary host. The heartbeat "access" rows keep their shape.
//
// Route ids the engine builds, each optionally prefixed "tls-" for the :443 server:
//   app-<app>                      the app's primary host (match.host[0])
//   dom-<app>-<slug(host)>         another custom/default host of the primary service (the engine maps these itself)
//   svcd-dom-<app>-<slug(host)>    a custom domain of a non-primary service  -> mapped to the parent app
// slug(host) = host with every run of characters outside [a-z0-9] replaced by "-". A colliding route id may also
// append "-<8 lowercase hex>" after the slug (dom-, svcd-dom-, and redir-dom- alike). Because the host is known, the
// app name is the id with the fixed prefix and the "-<slug(host)>" suffix removed — or, if that does not match,
// "-<slug(host)>-<8hex>" — so a '-' in an app name or a host that looks like another app's name cannot confuse it.

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/vinodkumar937/f2c-agent/internal/config"
)

const (
	routeIDPrimary = "app-"
	routeIDService = "svcd-dom-"
	routeIDTLS     = "tls-"
)

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

var accessHosts struct {
	sync.RWMutex
	m map[string]string // extra service host -> the parent app's primary host
}

// accessHostFor returns the host an access-log entry is reported under.
func accessHostFor(host string) string {
	accessHosts.RLock()
	defer accessHosts.RUnlock()
	if p, ok := accessHosts.m[host]; ok {
		return p
	}
	return host
}

func setAccessHosts(m map[string]string) {
	accessHosts.Lock()
	accessHosts.m = m
	accessHosts.Unlock()
}

// routeHosts returns a route's @id and its first host matcher list (nil when it has none).
func routeHosts(r any) (string, []string) {
	rm, ok := r.(map[string]any)
	if !ok {
		return "", nil
	}
	id, _ := rm["@id"].(string)
	matches, _ := rm["match"].([]any)
	for _, m := range matches {
		mm, _ := m.(map[string]any)
		hl, _ := mm["host"].([]any)
		var out []string
		for _, h := range hl {
			if s, ok := h.(string); ok && s != "" {
				out = append(out, strings.ToLower(s))
			}
		}
		if len(out) > 0 {
			return id, out
		}
	}
	return id, nil
}

// deriveAccessHostMap builds "extra service host -> parent app primary host" from a caddy_apply config.
func deriveAccessHostMap(cfg map[string]any) map[string]string {
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	primary := map[string]string{} // app -> primary host
	type svc struct{ app, host string }
	var extras []svc
	for _, s := range servers {
		sm, _ := s.(map[string]any)
		routes, _ := sm["routes"].([]any)
		for _, r := range routes {
			id, hosts := routeHosts(r)
			if id == "" || len(hosts) == 0 {
				continue
			}
			id = strings.TrimPrefix(id, routeIDTLS)
			switch {
			case strings.HasPrefix(id, routeIDPrimary):
				if app := strings.TrimPrefix(id, routeIDPrimary); app != "" {
					primary[app] = hosts[0]
				}
			case strings.HasPrefix(id, routeIDService):
				rest := strings.TrimPrefix(id, routeIDService)
				for _, h := range hosts {
					if app, ok := appFromHostSuffix(rest, h); ok {
						extras = append(extras, svc{app, h})
					}
				}
			}
		}
	}
	out := map[string]string{}
	for _, e := range extras {
		if p, ok := primary[e.app]; ok && p != e.host {
			out[e.host] = p
		}
	}
	return out
}

// appFromHostSuffix extracts the app name from the part of a route id after its fixed prefix
// (for example the rest of "svcd-dom-<app>-<slug(host)>" or "svcd-dom-<app>-<slug(host)>-<8hex>").
// The exact "-<slug>" suffix is tried first so a host whose slug itself ends in 8 hex characters
// is not mistaken for a collision suffix.
func appFromHostSuffix(rest, host string) (string, bool) {
	slug := slugRe.ReplaceAllString(host, "-")
	if app, ok := strings.CutSuffix(rest, "-"+slug); ok && app != "" {
		return app, true
	}
	if n := len(rest); n >= 9 && rest[n-9] == '-' && isLowerHex8(rest[n-8:]) {
		if app, ok := strings.CutSuffix(rest[:n-9], "-"+slug); ok && app != "" {
			return app, true
		}
	}
	return "", false
}

func isLowerHex8(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (a *Manager) accessMapPath() string { return filepath.Join(a.stateDir, "access-hosts.json") }

// applyAccessHostMap installs the map derived from a just-applied config and keeps a copy on disk, so a restarted agent
// (before the engine re-sends an unchanged caddy_apply) still attributes the extra hosts. A save failure is logged only:
// it must not fail an apply that Caddy already accepted.
func (a *Manager) applyAccessHostMap(cfg map[string]any) {
	m := deriveAccessHostMap(cfg)
	setAccessHosts(m)
	b, _ := json.Marshal(m)
	if err := config.WriteFile0600(a.accessMapPath(), b); err != nil {
		log.Printf("access log: saving host map: %v", err)
	}
}

func (a *Manager) loadAccessHostMap() {
	b, err := os.ReadFile(a.accessMapPath())
	if err != nil {
		return
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return
	}
	setAccessHosts(m)
}
