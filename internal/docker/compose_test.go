package docker

import (
	"reflect"
	"strings"
	"testing"
)

func a(m map[string]any) map[string]any { return m }

func parseOK(t *testing.T, m map[string]any) runOptions {
	t.Helper()
	o, err := parseRunOptions(m)
	if err != nil {
		t.Fatalf("parseRunOptions(%v): %v", m, err)
	}
	return o
}

func parseErr(t *testing.T, m map[string]any, want string) {
	t.Helper()
	_, err := parseRunOptions(m)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("parseRunOptions(%v): want error containing %q, got %v", m, want, err)
	}
}

func TestComposeCapIsAdvertised(t *testing.T) {
	if ComposeCap < 1 {
		t.Fatal("composeCap must be at least 1")
	}
}

func TestPlainRunUnchanged(t *testing.T) {
	// No stack options: no cap flags, no stack flags (existing apps keep today's behaviour).
	o := parseOK(t, a(map[string]any{"network": "f2c-net", "volumes": []any{map[string]any{"name": "f2c-x", "target": "/d"}}, "cmd": []any{"a", "b"}}))
	args := strings.Join(dockerRunOptionArgs(o), " ")
	for _, bad := range []string{"--cap-drop", "--cap-add", "no-new-privileges", "--entrypoint", "--network-alias", "--health", "--read-only", "--user"} {
		if strings.Contains(args, bad) {
			t.Errorf("plain run must not carry %s: %s", bad, args)
		}
	}
	if !reflect.DeepEqual(runTailArgs(o), []string{"a", "b"}) {
		t.Errorf("tail = %v", runTailArgs(o))
	}
	if r := capsReport(o); r["noNewPrivileges"] != false || r["drop"] != "" {
		t.Errorf("caps report for a plain container: %v", r)
	}
}

func TestStackRunFlags(t *testing.T) {
	o := parseOK(t, a(map[string]any{
		"network": "f2c-stk-f2c-shop-ab12cd", "noPublish": true,
		"aliases":    []any{"db", "pg"},
		"entrypoint": []any{"docker-entrypoint.sh", "--first"},
		"cmd":        []any{"postgres", "-c", "x=y"},
		"user":       "1000:1000", "workdir": "/srv", "readOnly": true, "init": true, "stopTimeoutS": float64(30),
		"capProfile": "stack-v1", "capAdd": []any{"CHOWN", "SETUID"},
		"health": map[string]any{"cmd": []any{"pg_isready", "-U", "my app"}, "intervalS": float64(5), "timeoutS": float64(3), "retries": float64(10), "startPeriodS": float64(10)},
	}))
	want := []string{
		"--network", "f2c-stk-f2c-shop-ab12cd",
		"--user", "1000:1000", "--workdir", "/srv", "--read-only", "--init", "--stop-timeout", "30",
		"--entrypoint", "docker-entrypoint.sh",
		"--network-alias", "db", "--network-alias", "pg",
		"--health-cmd", "pg_isready -U 'my app'", "--health-interval", "5s", "--health-timeout", "3s", "--health-retries", "10", "--health-start-period", "10s",
		"--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--security-opt", "no-new-privileges",
	}
	if got := dockerRunOptionArgs(o); !reflect.DeepEqual(got, want) {
		t.Errorf("docker args\n got %v\nwant %v", got, want)
	}
	if got := runTailArgs(o); !reflect.DeepEqual(got, []string{"--first", "postgres", "-c", "x=y"}) {
		t.Errorf("tail = %v", got)
	}
	if !o.Stack.NoPublish {
		t.Error("noPublish lost")
	}
	r := capsReport(o)
	if r["profile"] != "stack-v1" || r["drop"] != "ALL" || r["noNewPrivileges"] != true || !reflect.DeepEqual(r["add"], []string{"CHOWN", "SETUID"}) {
		t.Errorf("caps report: %v", r)
	}
}

func TestOneShotOption(t *testing.T) {
	if !parseOK(t, a(map[string]any{"oneShot": true})).Stack.OneShot {
		t.Error("oneShot lost")
	}
	parseErr(t, a(map[string]any{"oneShot": "yes"}), "oneShot must be")
	if parseOK(t, a(map[string]any{})).Stack.OneShot {
		t.Error("oneShot must default to false")
	}
}

func TestStackProfileAlwaysDropsAll(t *testing.T) {
	o := parseOK(t, a(map[string]any{"capProfile": "stack-v1"}))
	args := dockerRunOptionArgs(o)
	got := strings.Join(args, " ")
	if got != "--cap-drop ALL --security-opt no-new-privileges" {
		t.Errorf("profile without add-back: %q", got)
	}
}

func TestCapAddIsDefaultDeny(t *testing.T) {
	for _, c := range []string{"SYS_ADMIN", "NET_ADMIN", "NET_RAW", "ALL", "all", "chown", "SYS_PTRACE", "DAC_READ_SEARCH", "MKNOD", "SETFCAP", "FOWNER", "NET_BIND_SERVICE", "KILL", ""} {
		parseErr(t, a(map[string]any{"capProfile": "stack-v1", "capAdd": []any{c}}), "not allowed")
	}
	parseErr(t, a(map[string]any{"capAdd": []any{"CHOWN"}}), "capAdd needs capProfile")
	parseErr(t, a(map[string]any{"capProfile": "other"}), "capProfile must be")
	parseErr(t, a(map[string]any{"capProfile": "stack-v1", "capAdd": []any{"CHOWN", "CHOWN"}}), "duplicate capability")
	parseErr(t, a(map[string]any{"capProfile": "stack-v1", "capAdd": "CHOWN"}), "capAdd must be an array")
	parseErr(t, a(map[string]any{"capProfile": "stack-v1", "capAdd": []any{1}}), "not allowed")
	for _, ok := range []string{"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"} {
		parseOK(t, a(map[string]any{"capProfile": "stack-v1", "capAdd": []any{ok}}))
	}
	// A pass-through attempt through the generic keys is still refused.
	parseErr(t, a(map[string]any{"cap_add": []any{"SYS_ADMIN"}}), "unknown run option")
	parseErr(t, a(map[string]any{"securityOpt": []any{"seccomp=unconfined"}}), "unknown run option")
	parseErr(t, a(map[string]any{"privileged": true}), "privileged containers are not allowed")
}

func TestStackOptionValidation(t *testing.T) {
	net := "f2c-stk-f2c-x"
	parseErr(t, a(map[string]any{"aliases": []any{"db"}}), "aliases need a network")
	parseErr(t, a(map[string]any{"network": net, "aliases": []any{"Bad Alias"}}), "invalid network alias")
	parseErr(t, a(map[string]any{"network": net, "aliases": []any{"a", "a"}}), "duplicate network alias")
	parseErr(t, a(map[string]any{"network": net, "aliases": []any{"a", "b", "c", "d", "e", "f", "g", "h", "i"}}), "aliases must be")
	parseErr(t, a(map[string]any{"noPublish": "yes"}), "noPublish must be")
	parseErr(t, a(map[string]any{"noPublish": true, "hostPort": float64(20001)}), "cannot be combined")
	parseErr(t, a(map[string]any{"entrypoint": []any{}}), "entrypoint must be")
	parseErr(t, a(map[string]any{"entrypoint": []any{""}}), "start with the program")
	parseErr(t, a(map[string]any{"user": "root; rm -rf /"}), "user must be")
	parseErr(t, a(map[string]any{"user": "a:b:c"}), "user must be")
	parseErr(t, a(map[string]any{"workdir": "relative"}), "workdir must be")
	parseErr(t, a(map[string]any{"workdir": "/a/../b"}), "workdir must be")
	parseErr(t, a(map[string]any{"readOnly": "true"}), "readOnly must be")
	parseErr(t, a(map[string]any{"stopTimeoutS": float64(0)}), "stopTimeoutS must be")
	parseErr(t, a(map[string]any{"stopTimeoutS": float64(500)}), "stopTimeoutS must be")
	parseErr(t, a(map[string]any{"health": "curl"}), "health must be an object")
	parseErr(t, a(map[string]any{"health": map[string]any{}}), "exactly one of cmd or shell")
	parseErr(t, a(map[string]any{"health": map[string]any{"cmd": []any{"a"}, "shell": "b"}}), "exactly one of cmd or shell")
	parseErr(t, a(map[string]any{"health": map[string]any{"shell": "true", "bogus": 1}}), "unknown health option")
	parseErr(t, a(map[string]any{"health": map[string]any{"shell": "true", "retries": float64(0)}}), "retries must be")
	parseErr(t, a(map[string]any{"health": map[string]any{"shell": "true", "intervalS": float64(99999)}}), "intervalS must be")
	parseErr(t, a(map[string]any{"health": map[string]any{"shell": ""}}), "health.shell")
	// Reserved labels stay reserved.
	parseErr(t, a(map[string]any{"labels": map[string]any{"f2c.app": "x"}}), "reserved")
	parseErr(t, a(map[string]any{"labels": map[string]any{"f2c.agent": "1"}}), "reserved")
	// Stack labels are allowed.
	parseOK(t, a(map[string]any{"labels": map[string]any{"f2c.stack": "s", "f2c.service": "web", "f2c.deploy": "42"}}))
	// Everything not listed is still refused (default deny).
	for _, k := range []string{"pidMode", "devices", "securityOpt", "capDrop", "tmpfs", "dns", "extraHosts", "sysctls", "shmSize", "hostname"} {
		parseErr(t, a(map[string]any{k: "x"}), "unknown run option")
	}
	// Shell health form.
	o := parseOK(t, a(map[string]any{"health": map[string]any{"shell": "curl -f http://localhost/ || exit 1"}}))
	if got := strings.Join(dockerRunOptionArgs(o), "|"); got != "--health-cmd|curl -f http://localhost/ || exit 1" {
		t.Errorf("shell health args: %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{"plain": "plain", "a b": "'a b'", "it's": `'it'\''s'`, "": "''", "$HOME": "'$HOME'", "a;b": "'a;b'", "-U": "-U", "x=y": "x=y"}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetworkAndVolumeRmValidation(t *testing.T) {
	for _, n := range []string{"f2c-stk-f2c-shop-ab12cd", "f2c-stk-x"} {
		if _, err := validateNetworkRm(a(map[string]any{"name": n})); err != nil {
			t.Errorf("network %q should be removable: %v", n, err)
		}
	}
	for _, n := range []string{"f2c-net", "bridge", "host", "none", "f2c-stk-", "f2c-stk-X", "stk-f2c-x", "f2c-stk-../x", ""} {
		if _, err := validateNetworkRm(a(map[string]any{"name": n})); err == nil {
			t.Errorf("network %q must be refused", n)
		}
	}
	for _, n := range []string{"f2c-f2c-shop-ab12cd-pgdata", "f2c-f2c-x"} {
		if _, err := validateVolumeRm(a(map[string]any{"name": n})); err != nil {
			t.Errorf("volume %q should be removable: %v", n, err)
		}
	}
	for _, n := range []string{"f2c-pgdata", "f2c-redis-data", "f2c-net", "f2c-db-main", "pgdata", "/var/lib/docker", "f2c-f2c-x/../y", "f2c-f2c-X", "", "f2c-f2c-" + strings.Repeat("a", 60)} {
		if _, err := validateVolumeRm(a(map[string]any{"name": n})); err == nil {
			t.Errorf("volume %q must be refused", n)
		}
	}
}

func TestParseInspectDetail(t *testing.T) {
	out := "/f2c-shop-ab12cd-web\thealthy\t2\t0\t2026-11-14T05:01:50.123Z\n/f2c-shop-ab12cd-db\t\t0\t137\t2026-11-14T05:01:30Z\nnoise line\n"
	got := parseInspectDetail(out)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	w := got["f2c-shop-ab12cd-web"]
	if w.Health != "healthy" || w.Restarts != 2 || w.ExitCode != 0 || w.StartedAt != "2026-11-14T05:01:50.123Z" {
		t.Errorf("web: %+v", w)
	}
	d := got["f2c-shop-ab12cd-db"]
	if d.Health != "" || d.ExitCode != 137 {
		t.Errorf("db: %+v", d)
	}
}

func TestRunArgKeysIncludeStackOptions(t *testing.T) {
	for _, k := range stackArgKeys {
		if !runArgKeys[k] {
			t.Errorf("%s missing from runArgKeys", k)
		}
	}
	for _, k := range []string{"privileged", "binds", "capAdd2", "securityOpt"} {
		if runArgKeys[k] {
			t.Errorf("%s must not be an accepted run arg", k)
		}
	}
}
