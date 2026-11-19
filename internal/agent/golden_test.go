package agent

// Golden tests for the result frames of the main failure paths (docs/protocol.md section 5.1). The cases run the real
// handlers against a fake `docker` on PATH (and a fake Caddy admin API). The protocol 0 frames in golden_data_test.go were
// produced by the agent as it was BEFORE result codes at protocol >= 1 existed (TestGoldenDump on that tree), so the
// protocol 0 test proves those frames did not change by a single byte.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

const fakeDockerScript = `#!/bin/sh
d="$F2C_FAKE_DOCKER_DIR"
v="$1"
if [ -f "$d/$v.sleep" ]; then exec sleep "$(cat "$d/$v.sleep")"; fi
if [ -f "$d/$v.out" ]; then cat "$d/$v.out"; fi
if [ -f "$d/$v.err" ]; then cat "$d/$v.err" >&2; exit 1; fi
exit 0
`

type goldenCase struct {
	name  string
	typ   string
	args  map[string]any
	fake  map[string]string // "<verb>.out" / ".err" / ".sleep" -> file content
	admin func(w http.ResponseWriter, r *http.Request)
	// adminURL overrides the Caddy admin address (default: the httptest server when admin is set, else a closed port).
}

func goldenCases() []goldenCase {
	managed := map[string]string{"inspect.out": "1\n"}
	merge := func(ms ...map[string]string) map[string]string {
		o := map[string]string{}
		for _, m := range ms {
			for k, v := range m {
				o[k] = v
			}
		}
		return o
	}
	return []goldenCase{
		{name: "unknown_type", typ: "frobnicate"},
		{name: "pull_ok", typ: "pull", args: map[string]any{"image": "nginx:1"}, fake: map[string]string{"image.out": "sha256:abc\n"}},
		{name: "pull_bad_ref", typ: "pull", args: map[string]any{"image": "bad image"}},
		{name: "pull_denied", typ: "pull", args: map[string]any{"image": "nginx:1"}, fake: map[string]string{"pull.err": "Error response from daemon: pull access denied for nginx, repository does not exist or may require 'docker login': denied: requested access to the resource is denied\n"}},
		{name: "pull_manifest_unknown", typ: "pull", args: map[string]any{"image": "nginx:nope"}, fake: map[string]string{"pull.err": "Error response from daemon: manifest for nginx:nope not found: manifest unknown: manifest unknown\n"}},
		{name: "pull_network", typ: "pull", args: map[string]any{"image": "nginx:1"}, fake: map[string]string{"pull.err": "Error response from daemon: Get \"https://registry-1.docker.io/v2/\": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)\n"}},
		{name: "pull_no_space", typ: "pull", args: map[string]any{"image": "nginx:1"}, fake: map[string]string{"pull.err": "write /var/lib/docker/tmp/GetImageBlob1: no space left on device\n"}},
		{name: "run_port_in_use", typ: "run", args: map[string]any{"name": "web", "image": "nginx:1"}, fake: map[string]string{"inspect.err": "Error: No such object: web\n", "run.err": "docker: Error response from daemon: driver failed programming external connectivity on endpoint web: Bind for 127.0.0.1:20001 failed: port is already allocated.\n"}},
		{name: "run_pull_denied", typ: "run", args: map[string]any{"name": "web", "image": "nginx:1"}, fake: map[string]string{"inspect.err": "Error: No such object: web\n", "run.err": "Unable to find image 'nginx:1' locally\ndocker: Error response from daemon: pull access denied for nginx, repository does not exist or may require 'docker login'.\n"}},
		{name: "run_docker_down", typ: "run", args: map[string]any{"name": "web", "image": "nginx:1"}, fake: map[string]string{"inspect.err": "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n", "run.err": "docker: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?.\n"}},
		{name: "run_privileged", typ: "run", args: map[string]any{"name": "web", "image": "nginx:1", "privileged": true}},
		{name: "run_unknown_option", typ: "run", args: map[string]any{"name": "web", "image": "nginx:1", "bogus": true}},
		{name: "run_bad_name", typ: "run", args: map[string]any{"name": "Bad Name", "image": "nginx:1"}},
		{name: "run_bad_hostport", typ: "run", args: map[string]any{"name": "web", "image": "nginx:1", "hostPort": float64(80)}},
		{name: "stop_missing", typ: "stop", args: map[string]any{"name": "web"}, fake: map[string]string{"inspect.err": "Error: No such object: web\n"}},
		{name: "stop_unmanaged", typ: "stop", args: map[string]any{"name": "web"}, fake: map[string]string{"inspect.out": "\n"}},
		{name: "stop_ok", typ: "stop", args: map[string]any{"name": "web"}, fake: managed},
		{name: "rm_unmanaged", typ: "rm", args: map[string]any{"name": "web"}, fake: map[string]string{"inspect.out": "\n"}},
		{name: "rm_missing", typ: "rm", args: map[string]any{"name": "web"}, fake: map[string]string{"inspect.err": "Error: No such object: web\n"}},
		{name: "rename_exists", typ: "rename", args: map[string]any{"name": "web", "to": "web2"}, fake: managed},
		{name: "rename_same", typ: "rename", args: map[string]any{"name": "web", "to": "web"}, fake: managed},
		{name: "exec_empty_cmd", typ: "exec", args: map[string]any{"name": "web", "cmd": []any{}}, fake: managed},
		{name: "exec_timeout_stays_ok", typ: "exec", args: map[string]any{"name": "web", "cmd": []any{"sleep", "9"}, "timeoutSeconds": float64(1)}, fake: merge(managed, map[string]string{"exec.sleep": "9"})},
		{name: "logs_ok", typ: "logs", args: map[string]any{"name": "web"}, fake: merge(managed, map[string]string{"logs.out": "line1\nline2\n"})},
		{name: "logs_nonzero_exit", typ: "logs", args: map[string]any{"name": "web"}, fake: merge(managed, map[string]string{"logs.out": "line1\nline2\n", "logs.err": "Error response from daemon: oops\n"})},
		{name: "logs_missing", typ: "logs", args: map[string]any{"name": "web"}, fake: map[string]string{"inspect.err": "Error: No such object: web\n"}},
		{name: "stats_docker_down", typ: "stats", args: map[string]any{}, fake: map[string]string{"ps.err": "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n"}},
		{name: "network_rm_unmanaged", typ: "network_rm", args: map[string]any{"name": "f2c-stk-x"}, fake: map[string]string{"network.out": "\n"}},
		{name: "network_rm_bad_name", typ: "network_rm", args: map[string]any{"name": "bridge"}},
		{name: "volume_rm_in_use", typ: "volume_rm", args: map[string]any{"name": "f2c-f2c-x"}, fake: map[string]string{"volume.out": "f2c-f2c-x\n", "ps.out": "abc123\n"}},
		{name: "caddy_apply_bad_config", typ: "caddy_apply", args: map[string]any{"config": "nope"}},
		{name: "caddy_apply_unreachable", typ: "caddy_apply", args: map[string]any{"config": map[string]any{"apps": map[string]any{}}}},
		{name: "caddy_apply_rejected", typ: "caddy_apply", args: map[string]any{"config": map[string]any{"apps": map[string]any{}}}, admin: func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad config: unknown module", 400) }},
		{name: "cert_install_bad_domain", typ: "cert_install", args: map[string]any{"domain": "not a domain"}},
		{name: "tls_warm_bad_host", typ: "tls_warm", args: map[string]any{"host": "not a host"}},
		{name: "http_probe_bad_port", typ: "http_probe", args: map[string]any{"host": "app.example.com", "port": float64(70000)}},
		{name: "build_bad_args", typ: "build", args: map[string]any{}},
		{name: "load_bad_args", typ: "load", args: map[string]any{}},
		{name: "image_present_bad", typ: "image_present", args: map[string]any{"image": "x"}},
		{name: "self_update_bad_sha", typ: "self_update", args: map[string]any{"sha256": "abc"}},
		{name: "harden_bad_args", typ: "harden", args: map[string]any{}},
	}
}

// goldenAgent builds an agent whose docker is the fake one in a temp dir and whose Caddy admin API is the case's fake.
func goldenAgent(t *testing.T, c goldenCase) *Agent {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	fake := filepath.Join(dir, "fake")
	for _, d := range []string{bin, fake} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDockerScript), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range c.fake {
		if err := os.WriteFile(filepath.Join(fake, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("F2C_FAKE_DOCKER_DIR", fake)
	admin := "http://127.0.0.1:1" // nothing listens: connection refused
	if c.admin != nil {
		srv := httptest.NewServer(http.HandlerFunc(c.admin))
		t.Cleanup(srv.Close)
		admin = srv.URL
	}
	cfg := &config.Config{Engine: "https://engine.example.com", ServerID: "srv_EXAMPLE", Token: "f2cs_EXAMPLE_NOT_A_REAL_TOKEN"}
	return New(cfg, filepath.Join(dir, "state"), admin, filepath.Join(dir, "certs"), false)
}

// runGolden runs one case at the given session protocol and returns what the handler returned.
func runGolden(t *testing.T, c goldenCase, proto int) (any, error) {
	t.Helper()
	a := goldenAgent(t, c)
	a.sendHook = func(any) {} // stream frames are not part of the result
	if proto > 0 {
		a.neg.Store(&negotiated{protocol: proto})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return a.execute(ctx, protocol.Message{ID: "g1", Type: c.typ, Args: c.args})
}

// TestGoldenDump prints the protocol 0 frames as Go source for golden_data_test.go. Run it on a tree from before result codes at protocol >= 1 existed:
//
//	F2C_GOLDEN_DUMP=1 go test ./internal/agent -run TestGoldenDump -v
func TestGoldenDump(t *testing.T) {
	if os.Getenv("F2C_GOLDEN_DUMP") == "" {
		t.Skip("set F2C_GOLDEN_DUMP=1 to print the golden frames")
	}
	out := map[string]string{}
	for _, c := range goldenCases() {
		data, err := runGolden(t, c, 0)
		b, _ := json.Marshal(protocol.ResultMessage("g1", data, err))
		out[c.name] = string(b)
	}
	names := make([]string, 0, len(out))
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Println("GOLDEN-BEGIN")
	for _, n := range names {
		fmt.Printf("\t%q: %q,\n", n, out[n])
	}
	fmt.Println("GOLDEN-END")
}
