package caddy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

// route mirrors the engine's route shape: "@id" + match.host.
func route(id string, hosts ...string) any {
	hl := make([]any, len(hosts))
	for i, h := range hosts {
		hl[i] = h
	}
	return map[string]any{"@id": id, "match": []any{map[string]any{"host": hl}}, "terminal": true}
}

func cfgWith(routes80, routes443 []any) map[string]any {
	srv := func(r []any) any { return map[string]any{"routes": r} }
	return map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": srv(routes80), "srv1": srv(routes443)}}}}
}

func resetAccess() {
	accessMu.Lock()
	accessBuckets = map[string]map[string]*accessBucket{}
	accessMu.Unlock()
	setAccessHosts(nil)
}

func TestDeriveAccessHostMap(t *testing.T) {
	r80 := []any{
		route("app-shop", "shop.localhost"),
		route("dom-shop-www-shop-com", "www.shop.com"),
		route("svcd-dom-shop-admin-shop-com", "admin.shop.com"),
		route("svcd-dom-shop-api-shop-com", "api.shop.com"),
		route("svcd-dom-shop-billing-shop-com-a1b2c3d4", "billing.shop.com"), // collision suffix
		route("redir-dom-shop-old-example-com", "old.example.com"),
		// app 'foo-api' vs app 'foo' with service domain: ids look alike, but each parses to its own app.
		route("app-foo", "foo.localhost"),
		route("app-foo-api", "foo-api.localhost"),
		route("svcd-dom-foo-api-example-com", "api.example.com"), // app foo, domain api.example.com
		route("svcd-dom-foo-api-api-foo-org", "api.foo.org"),     // app foo-api, domain api.foo.org
		route("svcd-dom-ghost-x-y-com", "x.y.com"),               // app without a primary route: ignored
		map[string]any{"@id": "catch-all", "handle": []any{}},    // no host matcher
		"not-a-route",
	}
	r443 := make([]any, 0, len(r80))
	for _, r := range r80 {
		if m, ok := r.(map[string]any); ok {
			c := map[string]any{}
			for k, v := range m {
				c[k] = v
			}
			c["@id"] = "tls-" + m["@id"].(string)
			r443 = append(r443, c)
		}
	}
	got := deriveAccessHostMap(cfgWith(r80, r443))
	want := map[string]string{
		"admin.shop.com":   "shop.localhost",
		"api.shop.com":     "shop.localhost",
		"billing.shop.com": "shop.localhost",
		"api.example.com":  "foo.localhost",
		"api.foo.org":      "foo-api.localhost",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("map = %v, want %v", got, want)
	}
}

func TestAppFromHostSuffix(t *testing.T) {
	tests := []struct {
		name string
		rest string
		host string
		want string
		ok   bool
	}{
		{name: "no suffix", rest: "shop-admin-shop-com", host: "admin.shop.com", want: "shop", ok: true},
		{name: "with suffix", rest: "shop-admin-shop-com-a1b2c3d4", host: "admin.shop.com", want: "shop", ok: true},
		{name: "app name containing hyphen", rest: "foo-api-api-foo-org", host: "api.foo.org", want: "foo-api", ok: true},
		{name: "app name containing hyphen with suffix", rest: "foo-api-api-foo-org-deadbeef", host: "api.foo.org", want: "foo-api", ok: true},
		{name: "slug ends with 8 hex, no suffix", rest: "shop-a-deadbeef-example-com", host: "a.deadbeef.example.com", want: "shop", ok: true},
		{name: "slug ends with 8 hex, with suffix", rest: "shop-a-deadbeef-example-com-abcd1234", host: "a.deadbeef.example.com", want: "shop", ok: true},
		{name: "7-char hex tail not stripped", rest: "shop-admin-shop-com-abc1234", host: "admin.shop.com", want: "", ok: false},
		{name: "non-hex tail not stripped", rest: "shop-admin-shop-com-abcdxyz1", host: "admin.shop.com", want: "", ok: false},
		{name: "uppercase hex tail not stripped", rest: "shop-admin-shop-com-ABCD1234", host: "admin.shop.com", want: "", ok: false},
		{name: "empty app rejected", rest: "admin-shop-com", host: "admin.shop.com", want: "", ok: false},
		{name: "empty app with suffix rejected", rest: "admin-shop-com-a1b2c3d4", host: "admin.shop.com", want: "", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := appFromHostSuffix(tt.rest, tt.host)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("appFromHostSuffix(%q, %q) = %q, %v; want %q, %v", tt.rest, tt.host, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestDeriveAccessHostMapEmptyOrBroken(t *testing.T) {
	for _, cfg := range []map[string]any{{}, {"apps": 1}, {"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"s": map[string]any{"routes": "x"}}}}}} {
		if m := deriveAccessHostMap(cfg); len(m) != 0 {
			t.Fatalf("expected empty map, got %v", m)
		}
	}
}

func TestRecordAccessReportsExtraHostsUnderParent(t *testing.T) {
	resetAccess()
	defer resetAccess()
	setAccessHosts(map[string]string{"admin.shop.com": "shop.localhost"})
	now := time.Date(2026, 11, 18, 12, 0, 30, 0, time.UTC)
	line := func(host string, status int) []byte {
		b, _ := json.Marshal(map[string]any{"status": status, "size": 10, "duration": 0.01, "request": map[string]any{"host": host}})
		return b
	}
	recordAccess(line("Admin.Shop.com:443", 200), now) // extra service host, any case, with a port
	recordAccess(line("shop.localhost", 500), now)
	recordAccess(line("www.shop.com", 200), now) // primary service custom domain: unchanged
	rows := TakeAccessMinutes(now.Add(time.Minute))
	byHost := map[string]map[string]any{}
	for _, r := range rows {
		byHost[r["host"].(string)] = r
	}
	if len(byHost) != 2 {
		t.Fatalf("hosts = %v", byHost)
	}
	if r := byHost["shop.localhost"]; r["requests"] != 2 || r["s2xx"] != 1 || r["s5xx"] != 1 {
		t.Fatalf("shop.localhost row = %v", r)
	}
	if byHost["www.shop.com"]["requests"] != 1 {
		t.Fatalf("www.shop.com row = %v", byHost["www.shop.com"])
	}
	if _, ok := byHost["admin.shop.com"]; ok {
		t.Fatal("extra host reported on its own")
	}
}

func fakeCaddy(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestApplyMultiRouteAskHostsAndStaleCleanup(t *testing.T) {
	resetAccess()
	defer resetAccess()
	dir := t.TempDir()
	srv := fakeCaddy(t)
	m := New(dir, srv.URL, dir, func(any) bool { return true }, func() bool { return true })

	full := cfgWith(
		[]any{route("app-shop", "shop.localhost"), route("svcd-dom-shop-admin-shop-com", "admin.shop.com"), route("svcd-dom-shop-api-shop-com", "api.shop.com")},
		[]any{route("tls-app-shop", "shop.localhost"), route("tls-svcd-dom-shop-admin-shop-com", "admin.shop.com"), route("tls-svcd-dom-shop-api-shop-com", "api.shop.com")},
	)
	if _, err := m.Apply(t.Context(), map[string]any{"config": full, "hosts": []any{"admin.shop.com", "api.shop.com", "shop.com"}}); err != nil {
		t.Fatal(err)
	}
	for h, want := range map[string]bool{"admin.shop.com": true, "api.shop.com": true, "shop.com": true, "gone.shop.com": false} {
		if got := m.askAllowed(h); got != want {
			t.Fatalf("askAllowed(%s) = %v, want %v", h, got, want)
		}
	}
	if accessHostFor("api.shop.com") != "shop.localhost" || accessHostFor("admin.shop.com") != "shop.localhost" {
		t.Fatal("extra hosts not mapped to the parent app")
	}

	// The persisted map survives a restart (new Manager, memory cleared) until the next caddy_apply.
	setAccessHosts(nil)
	m2 := New(dir, srv.URL, dir, func(any) bool { return true }, func() bool { return true })
	m2.loadAccessHostMap()
	if accessHostFor("api.shop.com") != "shop.localhost" {
		t.Fatal("map not restored after restart")
	}
	if fi, err := os.Stat(m.accessMapPath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("access map file: %v %v", fi, err)
	}

	// The api service stops being public: the engine's next config has no route for it. Mapping and ask list follow.
	less := cfgWith(
		[]any{route("app-shop", "shop.localhost"), route("svcd-dom-shop-admin-shop-com", "admin.shop.com")},
		[]any{route("tls-app-shop", "shop.localhost"), route("tls-svcd-dom-shop-admin-shop-com", "admin.shop.com")},
	)
	if _, err := m.Apply(t.Context(), map[string]any{"config": less, "hosts": []any{"admin.shop.com", "shop.com"}}); err != nil {
		t.Fatal(err)
	}
	if accessHostFor("api.shop.com") != "api.shop.com" || m.askAllowed("api.shop.com") {
		t.Fatal("stale extra host still mapped or allowed")
	}
	if accessHostFor("admin.shop.com") != "shop.localhost" {
		t.Fatal("remaining extra host lost")
	}
}

func TestApplyRejectedKeepsAccessMap(t *testing.T) {
	resetAccess()
	defer resetAccess()
	dir := t.TempDir()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusBadRequest) }))
	defer bad.Close()
	setAccessHosts(map[string]string{"admin.shop.com": "shop.localhost"})
	m := New(dir, bad.URL, dir, func(any) bool { return true }, func() bool { return true })
	cfg := cfgWith([]any{route("app-x", "x.localhost")}, nil)
	if _, err := m.Apply(t.Context(), map[string]any{"config": cfg}); err == nil {
		t.Fatal("expected error")
	}
	if accessHostFor("admin.shop.com") != "shop.localhost" {
		t.Fatal("a rejected config must keep the running map")
	}
}
