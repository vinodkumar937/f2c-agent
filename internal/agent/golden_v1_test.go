package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

// goldenV1 is the code each failing case gets at protocol >= 1. "" = the case succeeds (ok:true) at every protocol.
var goldenV1 = map[string]string{
	"unknown_type": "unknown_cmd", "pull_ok": "", "pull_bad_ref": "bad_request", "pull_denied": "image_not_found",
	"pull_manifest_unknown": "image_not_found", "pull_network": "image_pull_failed", "pull_no_space": "no_space",
	"run_port_in_use": "port_in_use", "run_pull_denied": "image_not_found", "run_docker_down": "docker_unavailable",
	"run_privileged": "not_allowed", "run_unknown_option": "bad_request", "run_bad_name": "bad_request", "run_bad_hostport": "bad_request",
	"stop_missing": "not_found", "stop_unmanaged": "not_allowed", "stop_ok": "", "rm_unmanaged": "not_allowed", "rm_missing": "",
	"rename_exists": "conflict", "rename_same": "bad_request", "exec_empty_cmd": "bad_request", "exec_timeout_stays_ok": "",
	"logs_ok": "", "logs_nonzero_exit": "internal", "logs_missing": "not_found", "stats_docker_down": "docker_unavailable",
	"network_rm_unmanaged": "not_allowed", "network_rm_bad_name": "bad_request", "volume_rm_in_use": "conflict",
	"caddy_apply_bad_config": "bad_request", "caddy_apply_unreachable": "caddy_unavailable", "caddy_apply_rejected": "caddy_rejected",
	"cert_install_bad_domain": "bad_request", "tls_warm_bad_host": "bad_request", "http_probe_bad_port": "bad_request",
	"build_bad_args": "bad_request", "load_bad_args": "bad_request", "image_present_bad": "bad_request",
	"self_update_bad_sha": "bad_request", "harden_bad_args": "harden_bad_request",
}

func frameJSON(t *testing.T, a *Agent, data any, err error) string {
	t.Helper()
	b, merr := json.Marshal(protocol.ResultMessageFor("g1", data, err, a.SessionProtocol()))
	if merr != nil {
		t.Fatal(merr)
	}
	return string(b)
}

// Protocol 0: byte for byte what the agent sent before result codes at protocol >= 1.
func TestGoldenProtocol0(t *testing.T) {
	cases := goldenCases()
	if len(cases) != len(goldenV0) || len(cases) != len(goldenV1) {
		t.Fatalf("cases %d, golden v0 %d, expected v1 %d", len(cases), len(goldenV0), len(goldenV1))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, err := runGolden(t, c, 0)
			a := &Agent{}
			if got := frameJSON(t, a, data, err); got != goldenV0[c.name] {
				t.Fatalf("protocol 0 frame changed\n got: %s\nwant: %s", got, goldenV0[c.name])
			}
			b, _ := json.Marshal(protocol.ResultMessage("g1", data, err)) // the protocol 0 builder gives the same bytes
			if string(b) != goldenV0[c.name] {
				t.Fatalf("ResultMessage differs: %s", b)
			}
		})
	}
}

// Protocol 1: the same handlers; every failure carries a code from the list and the error text is unchanged.
func TestGoldenProtocol1(t *testing.T) {
	known := map[string]bool{}
	for _, c := range append(append([]string{}, protocol.V1Codes...), protocol.KeptV1Codes...) {
		known[c] = true
	}
	for _, c := range goldenCases() {
		t.Run(c.name, func(t *testing.T) {
			data, err := runGolden(t, c, 1)
			a := &Agent{}
			a.neg.Store(&negotiated{protocol: 1})
			var got, v0 map[string]any
			if e := json.Unmarshal([]byte(frameJSON(t, a, data, err)), &got); e != nil {
				t.Fatal(e)
			}
			if e := json.Unmarshal([]byte(goldenV0[c.name]), &v0); e != nil {
				t.Fatal(e)
			}
			want := goldenV1[c.name]
			if want == "" { // success: identical frame at both protocols
				if got["ok"] != true || !jsonEqual(got, v0) {
					t.Fatalf("a success must be identical at protocol 1: %v vs %v", got, v0)
				}
				return
			}
			if got["ok"] != false {
				t.Fatalf("expected a failure at protocol 1, got %v", got)
			}
			code, _ := got["code"].(string)
			if code != want || !known[code] {
				t.Fatalf("code = %q, want %q (frame %v)", code, want, got)
			}
			if _, has := got["data"]; has {
				t.Fatalf("a failure carries no data: %v", got)
			}
			if v0["ok"] == false { // text unchanged; only the code is added
				if got["error"] != v0["error"] {
					t.Fatalf("error text changed:\n got: %v\nwant: %v", got["error"], v0["error"])
				}
			}
		})
	}
}

func jsonEqual(a, b map[string]any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// The one deliberate behaviour change at protocol 1 (decision 6): a non-zero exit of docker logs is a failure whose text is the
// output tail; at protocol 0 it stays ok:true.
func TestGoldenLogsNonZeroExit(t *testing.T) {
	var c goldenCase
	for _, x := range goldenCases() {
		if x.name == "logs_nonzero_exit" {
			c = x
		}
	}
	if _, err := runGolden(t, c, 0); err != nil {
		t.Fatalf("protocol 0 must stay ok:true: %v", err)
	}
	_, err := runGolden(t, c, 1)
	if err == nil || !strings.HasPrefix(err.Error(), "docker logs: line1\nline2\n") || !strings.Contains(err.Error(), "oops") {
		t.Fatalf("protocol 1: %v", err)
	}
}

// Replies of the three live-connection exchanges get their code only at protocol >= 1.
func TestReplyCodeGate(t *testing.T) {
	reply := func() map[string]any {
		return map[string]any{"t": "token_rotated", "id": "r1", "ok": false, "error": "invalid rotation message", "code": "bad_request"}
	}
	a := &Agent{}
	got := a.gateReplyCode(reply()).(map[string]any)
	if _, has := got["code"]; has || got["error"] != "invalid rotation message" || len(got) != 4 {
		t.Fatalf("protocol 0 must drop the code: %v", got)
	}
	if orig := reply(); orig["code"] != "bad_request" { // the handler's own map is never mutated
		t.Fatal("unexpected")
	}
	a.neg.Store(&negotiated{protocol: 1})
	if got := a.gateReplyCode(reply()).(map[string]any); got["code"] != "bad_request" {
		t.Fatalf("protocol 1 keeps the code: %v", got)
	}
	// other frames are never touched
	a2 := &Agent{}
	other := map[string]any{"t": "result", "id": "x", "ok": false, "code": "unknown_command"}
	if got := a2.gateReplyCode(other).(map[string]any); got["code"] != "unknown_command" {
		t.Fatalf("result frames must pass through: %v", got)
	}
	for _, typ := range []string{"registry_login", "dns_token_ok"} {
		m := map[string]any{"t": typ, "id": "r", "ok": false, "error": "e", "code": "internal"}
		if _, has := (&Agent{}).gateReplyCode(m).(map[string]any)["code"]; has {
			t.Fatalf("%s at protocol 0 must drop the code", typ)
		}
	}
}
