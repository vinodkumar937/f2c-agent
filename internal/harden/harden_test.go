package harden

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseHardenArgs(t *testing.T) {
	r, err := parseHardenArgs(map[string]any{"runId": "harden-abc123", "mode": "apply", "allowIps": []any{"203.0.113.7", "2001:db8::/48"}, "swapGb": float64(4), "sshKeysOnly": false}, "https://engine.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if r.SwapGB != 4 || r.SSHKeysOnly || len(r.AllowIPs) != 2 || r.Engine != "https://engine.example.com" {
		t.Fatalf("unexpected %+v", r)
	}
	enc := string(r.encode())
	for _, want := range []string{"id=harden-abc123\n", "mode=apply\n", "allow_ip=203.0.113.7\n", "allow_ip=2001:db8::/48\n", "swap_gb=4\n", "ssh_keys_only=0\n", "engine=https://engine.example.com\n"} {
		if !strings.Contains(enc, want) {
			t.Fatalf("encoded request missing %q:\n%s", want, enc)
		}
	}
	d, err := parseHardenArgs(map[string]any{"runId": "harden-x", "mode": "dry_run"}, "")
	if err != nil || d.SwapGB != 2 || !d.SSHKeysOnly || d.Engine != "" {
		t.Fatalf("defaults: %+v %v", d, err)
	}
	bad := []map[string]any{
		{"runId": "x", "mode": "apply"},
		{"runId": "harden-a", "mode": "reboot"},
		{"runId": "harden-a", "mode": "apply", "allowIps": []any{"192.0.2.4\nmode=apply"}},
		{"runId": "harden-a", "mode": "apply", "allowIps": []any{"not-an-ip"}},
		{"runId": "harden-a", "mode": "apply", "swapGb": float64(17)},
		{"runId": "harden-a", "mode": "apply", "swapGb": float64(1.5)},
		{"runId": "harden-a", "mode": "rollback", "backupId": "../../etc"},
		{"runId": "harden-a\nmode=apply", "mode": "dry_run"},
	}
	for i, b := range bad {
		if _, err := parseHardenArgs(b, ""); err == nil {
			t.Fatalf("bad[%d] accepted: %v", i, b)
		}
	}
	if r, _ := parseHardenArgs(map[string]any{"runId": "harden-a", "mode": "dry_run"}, "https://e.example.com/x?y=$(id)"); r.Engine != "" {
		t.Fatalf("unsafe engine URL passed through: %q", r.Engine)
	}
}

// fakeUnit stands in for f2c-harden.service (systemctl show).
type fakeUnit struct {
	mu sync.Mutex
	u  hardenUnit
}

func (f *fakeUnit) set(u hardenUnit) { f.mu.Lock(); f.u = u; f.mu.Unlock() }
func (f *fakeUnit) state(context.Context) (hardenUnit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.u, nil
}

// setupHarden points every harden path at a temp dir, makes waits short and returns an agent plus the fake unit.
func setupHarden(t *testing.T) (*Service, *fakeUnit) {
	t.Helper()
	dir := t.TempDir()
	oldScript, oldUnit, oldRes, oldPoll, oldActive, oldState := hardenScript, hardenPathUnit, hardenResultsDir, hardenPoll, hardenUnitActive, hardenUnitState
	oldTimeout, oldFollow, oldTrig, oldIdle := hardenTimeout, hardenFollowMax, hardenTriggerGrace, hardenNoResultGrace
	t.Cleanup(func() {
		hardenScript, hardenPathUnit, hardenResultsDir, hardenPoll, hardenUnitActive, hardenUnitState = oldScript, oldUnit, oldRes, oldPoll, oldActive, oldState
		hardenTimeout, hardenFollowMax, hardenTriggerGrace, hardenNoResultGrace = oldTimeout, oldFollow, oldTrig, oldIdle
	})
	hardenScript, hardenPathUnit, hardenResultsDir, hardenPoll = filepath.Join(dir, "harden.sh"), filepath.Join(dir, "f2c-harden.path"), filepath.Join(dir, "results"), 5*time.Millisecond
	hardenTimeout, hardenFollowMax, hardenTriggerGrace, hardenNoResultGrace = 3*time.Second, 4*time.Second, 300*time.Millisecond, 50*time.Millisecond
	hardenUnitActive = func(context.Context) bool { return true }
	fu := &fakeUnit{u: hardenUnit{InvocationID: "inv-0", ActiveState: "inactive", Result: "success"}}
	hardenUnitState = fu.state
	for _, f := range []string{hardenScript, hardenPathUnit} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(hardenResultsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return &Service{engine: func() string { return "https://engine.example.com" }, stateDir: filepath.Join(dir, "state")}, fu
}

// fakeService simulates f2c-harden.path + f2c-harden.service: takes the request for runID, runs, and (when result
// is not "") writes it. It counts how often it ran.
func fakeService(t *testing.T, a *Service, fu *fakeUnit, runID, result string, runs *int, exitStatus int) {
	t.Helper()
	go func() {
		req := filepath.Join(a.stateDir, "harden", "request")
		for i := 0; i < 400; i++ {
			if b, err := os.ReadFile(req); err == nil && strings.Contains(string(b), "id="+runID+"\n") {
				*runs++
				fu.set(hardenUnit{InvocationID: fmt.Sprintf("inv-%d", *runs), ActiveState: "activating"})
				_ = os.Remove(req)
				time.Sleep(20 * time.Millisecond)
				if result != "" {
					_ = os.WriteFile(filepath.Join(hardenResultsDir, runID+".json"), []byte(result), 0o640)
				}
				res := "success"
				if exitStatus != 0 {
					res = "exit-code"
				}
				fu.set(hardenUnit{InvocationID: fmt.Sprintf("inv-%d", *runs), ActiveState: "inactive", Result: res, ExecMainStatus: exitStatus})
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
}

// resultFor(t)(a.cmdHarden(...)): the result map, failing the test on an error.
func resultFor(t *testing.T) func(any, error) map[string]any {
	return func(out any, err error) map[string]any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		m, ok := out.(map[string]any)
		if !ok {
			t.Fatalf("want a result map, got %T %v", out, out)
		}
		return m
	}
}

func TestCmdHardenFlow(t *testing.T) {
	a, fu := setupHarden(t)
	args := map[string]any{"runId": "harden-t1", "mode": "dry_run"}
	_ = os.Remove(hardenScript)
	if _, err := a.Run(context.Background(), args); err == nil || !strings.HasPrefix(err.Error(), "harden_not_installed") {
		t.Fatalf("want harden_not_installed, got %v", err)
	}
	if err := os.WriteFile(hardenScript, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.hardenRunsPath()); err == nil {
		t.Fatal("a refused run must not be recorded")
	}
	runs := 0
	fakeService(t, a, fu, "harden-t1", `{"id":"harden-t1","mode":"dry_run","status":"succeeded","message":"dry run: nothing changed","steps":[],"audit":[{"event":"start"}]}`, &runs, 0)
	m := resultFor(t)(a.Run(context.Background(), args))
	if m["status"] != "succeeded" || m["mode"] != "dry_run" || runs != 1 {
		t.Fatalf("unexpected result %v (runs %d)", m, runs)
	}
	if audit, _ := m["audit"].([]any); len(audit) < 3 { // root "start" + agent queued/triggered/outcome
		t.Fatalf("audit not merged: %v", m["audit"])
	}
	st, err := os.Stat(a.hardenRunsPath())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("runs.json: %v %v", st, err)
	}
	time.Sleep(20 * time.Millisecond) // the follower records the outcome right after replying
	rs, _ := loadHardenRuns(a.hardenRunsPath())
	if r, ok := findHardenRun(rs, "harden-t1"); !ok || r.Status != "succeeded" || r.Message != "dry run: nothing changed" {
		t.Fatalf("record: %+v %v", r, ok)
	}

	// A stale result for another id is ignored; cancellation ends the wait.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := waitHardenResult(ctx, &hardenWait{path: filepath.Join(hardenResultsDir, "harden-t1.json"), runID: "harden-other", resultOnly: true}); err == nil {
		t.Fatal("want an error for a mismatched run id")
	}
}

// H2: the same run id is never run twice, also after an agent restart and with the result file gone.
func TestHardenDedupe(t *testing.T) {
	a, fu := setupHarden(t)
	args := map[string]any{"runId": "harden-d1", "mode": "apply"}
	runs := 0
	fakeService(t, a, fu, "harden-d1", `{"id":"harden-d1","mode":"apply","status":"succeeded","message":"hardened; backup 20261117-120000","backupId":"20261117-120000","steps":[]}`, &runs, 0)
	m := resultFor(t)(a.Run(context.Background(), args))
	if m["status"] != "succeeded" || runs != 1 {
		t.Fatalf("first run: %v", m)
	}
	time.Sleep(20 * time.Millisecond)
	check := func(label string, m map[string]any) {
		t.Helper()
		// 9.2: the earlier result unchanged (status, message, backup) plus replayed:true; no harden_ prefix added
		if m["status"] != "succeeded" || m["message"] != "hardened; backup 20261117-120000" || m["backupId"] != "20261117-120000" || m["replayed"] != true || m["id"] != "harden-d1" {
			t.Fatalf("%s: %v", label, m)
		}
		for _, k := range []string{"steps", "mode"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("%s: replay lacks %s: %v", label, k, m)
			}
		}
		if _, err := os.Stat(filepath.Join(a.stateDir, "harden", "request")); err == nil {
			t.Fatalf("%s: a request was queued again", label)
		}
	}
	check("repeat", resultFor(t)(a.Run(context.Background(), args)))
	// Agent restart (new process state) + the root result pruned: answered from runs.json alone
	a2 := &Service{engine: a.engine, stateDir: a.stateDir}
	if err := os.Remove(filepath.Join(hardenResultsDir, "harden-d1.json")); err != nil {
		t.Fatal(err)
	}
	check("after restart", resultFor(t)(a2.Run(context.Background(), args)))
	if runs != 1 {
		t.Fatalf("ran %d times", runs)
	}
}

func TestHardenDedupeUnknownOutcome(t *testing.T) {
	a, _ := setupHarden(t)
	// recorded as requested (agent died mid-run), no result, unit idle: refused, outcome unknown
	if err := saveHardenRuns(a.hardenRunsPath(), []hardenRun{{ID: "harden-u1", Mode: "apply", RequestedAt: "2026-11-17T10:00:00Z", Status: "requested"}}); err != nil {
		t.Fatal(err)
	}
	m := resultFor(t)(a.Run(context.Background(), map[string]any{"runId": "harden-u1", "mode": "apply"}))
	msg, _ := m["message"].(string)
	if m["status"] != "failed" || m["replayed"] != true || strings.HasPrefix(msg, "harden_") || !strings.Contains(msg, "outcome is unknown") || m["startedAt"] != "2026-11-17T10:00:00Z" {
		t.Fatalf("unknown outcome: %v", m)
	}
	// ... but a result that shows up while waiting (unit still running after an agent restart) is returned
	if err := saveHardenRuns(a.hardenRunsPath(), []hardenRun{{ID: "harden-u2", Mode: "apply", Status: "requested"}}); err != nil {
		t.Fatal(err)
	}
	hardenUnitState = func(context.Context) (hardenUnit, error) { return hardenUnit{ActiveState: "activating"}, nil }
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(hardenResultsDir, "harden-u2.json"), []byte(`{"id":"harden-u2","mode":"apply","status":"rolled_back","message":"post-check failed; all changes rolled back"}`), 0o640)
	}()
	m = resultFor(t)(a.Run(context.Background(), map[string]any{"runId": "harden-u2", "mode": "apply"}))
	if m["status"] != "rolled_back" || m["message"] != "post-check failed; all changes rolled back" || m["replayed"] != true {
		t.Fatalf("late result: %v", m)
	}
	rs, _ := loadHardenRuns(a.hardenRunsPath())
	if r, _ := findHardenRun(rs, "harden-u2"); r.Status != "rolled_back" {
		t.Fatalf("late result not recorded: %+v", r)
	}
}

// Medium (a): the script exits without writing a result -> failed within seconds, not after the full wait.
func TestHardenScriptExitWithoutResult(t *testing.T) {
	a, fu := setupHarden(t)
	runs := 0
	fakeService(t, a, fu, "harden-e1", "", &runs, 2)
	start := time.Now()
	m := resultFor(t)(a.Run(context.Background(), map[string]any{"runId": "harden-e1", "mode": "apply"}))
	msg, _ := m["message"].(string)
	if m["status"] != "failed" || !strings.HasPrefix(msg, "harden_script_failed:") || !strings.Contains(msg, "exit status 2") || m["id"] != "harden-e1" {
		t.Fatalf("got %v", m)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
	for _, k := range []string{"steps", "prechecks", "postchecks", "warnings", "sshPorts"} {
		if _, ok := m[k].([]any); !ok {
			t.Fatalf("synthesized result lacks %s: %v", k, m)
		}
	}
}

func TestHardenNotTriggered(t *testing.T) {
	a, _ := setupHarden(t)
	m := resultFor(t)(a.Run(context.Background(), map[string]any{"runId": "harden-n1", "mode": "dry_run"}))
	if msg, _ := m["message"].(string); m["status"] != "failed" || !strings.HasPrefix(msg, "harden_not_triggered:") {
		t.Fatalf("got %v", m)
	}
	if _, err := os.Stat(filepath.Join(a.stateDir, "harden", "request")); err == nil {
		t.Fatal("request not withdrawn")
	}
	// another run held the unit the whole time
	hardenUnitState = func(context.Context) (hardenUnit, error) {
		return hardenUnit{InvocationID: "inv-9", ActiveState: "activating"}, nil
	}
	m = resultFor(t)(a.Run(context.Background(), map[string]any{"runId": "harden-n2", "mode": "dry_run"}))
	if msg, _ := m["message"].(string); !strings.HasPrefix(msg, "harden_running:") {
		t.Fatalf("got %v", m)
	}
}

func TestHardenRunsStore(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "harden", "runs.json")
	var runs []hardenRun
	for i := 0; i < 250; i++ {
		runs = append(runs, hardenRun{ID: fmt.Sprintf("harden-r%d", i), Status: "succeeded"})
	}
	if err := saveHardenRuns(p, runs); err != nil {
		t.Fatal(err)
	}
	got, err := loadHardenRuns(p)
	if err != nil || len(got) != hardenMaxRuns || got[0].ID != "harden-r50" || got[len(got)-1].ID != "harden-r249" {
		t.Fatalf("bounded store: %d %v", len(got), err)
	}
	if prev, err := claimHardenRun(p, hardenRequest{RunID: "harden-r249", Mode: "apply"}); err != nil || prev == nil {
		t.Fatalf("claim of a known id: %v %v", prev, err)
	}
	if prev, err := claimHardenRun(p, hardenRequest{RunID: "harden-new", Mode: "apply"}); err != nil || prev != nil {
		t.Fatalf("claim of a new id: %v %v", prev, err)
	}
	if got, _ := loadHardenRuns(p); got[len(got)-1].ID != "harden-new" || got[len(got)-1].Status != "requested" || len(got) != hardenMaxRuns {
		t.Fatalf("after claim: %+v", got[len(got)-1])
	}
	// a corrupt history refuses new runs instead of forgetting which ids ran
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, _ := setupHarden(t)
	a.stateDir = dir
	if _, err := a.Run(context.Background(), map[string]any{"runId": "harden-c1", "mode": "dry_run"}); err == nil || !strings.HasPrefix(err.Error(), "harden_state_unreadable:") {
		t.Fatalf("corrupt runs.json: %v", err)
	}
	if b, _ := json.Marshal(hardenRunsFile{Version: 2}); os.WriteFile(p, b, 0o600) == nil {
		if _, err := loadHardenRuns(p); err == nil {
			t.Fatal("unknown version accepted")
		}
	}
}

func TestParseHardenUnit(t *testing.T) {
	u := parseHardenUnit("InvocationID=abc123\nActiveState=deactivating\nResult=timeout\nExecMainStatus=143\n")
	if u.InvocationID != "abc123" || !u.busy() || u.Result != "timeout" || u.ExecMainStatus != 143 {
		t.Fatalf("%+v", u)
	}
	if (hardenUnit{ActiveState: "inactive"}).busy() || (hardenUnit{ActiveState: "failed"}).busy() {
		t.Fatal("inactive/failed must not be busy")
	}
}
