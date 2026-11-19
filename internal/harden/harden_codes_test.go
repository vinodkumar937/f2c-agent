package harden

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

// Protocol >= 1 (docs/protocol.md section 5): a failure the agent detects itself is ok:false with a code and no data (the
// error text is the old message, prefix included); a failure harden.sh reports stays ok:true with the full result.

func failCode(t *testing.T, out any, err error, wantCode, wantPrefix string) {
	t.Helper()
	if err == nil || out != nil {
		t.Fatalf("want an error and no data, got out=%v err=%v", out, err)
	}
	if got := protocol.ResultCode(err); got != wantCode {
		t.Fatalf("code = %q, want %q (%v)", got, wantCode, err)
	}
	if !strings.HasPrefix(err.Error(), wantPrefix) {
		t.Fatalf("text %q must keep the prefix %q", err.Error(), wantPrefix)
	}
	if m := protocol.ResultMessageFor("h", out, err, 1); m["ok"] != false || m["code"] != wantCode || m["data"] != nil {
		t.Fatalf("frame %v", m)
	}
	// at protocol 0 the same failure is a legacy frame without any of the new codes
	if m := protocol.ResultMessage("h", nil, err); !protocol.LegacyCodes[wantCode] && m["code"] != nil {
		t.Fatalf("protocol 0 frame has a new code: %v", m)
	}
}

func TestHardenCodesScriptEndedWithoutResult(t *testing.T) {
	a, fu := setupHarden(t)
	a.SetCodes(func() bool { return true })
	runs := 0
	fakeService(t, a, fu, "harden-c1", "", &runs, 2)
	out, err := a.Run(context.Background(), map[string]any{"runId": "harden-c1", "mode": "apply"})
	failCode(t, out, err, protocol.CodeHardenScriptFailed, "harden_script_failed:")
	if !strings.Contains(err.Error(), "exit status 2") {
		t.Fatal(err)
	}
}

func TestHardenCodesNotTriggeredAndRunning(t *testing.T) {
	a, _ := setupHarden(t)
	a.SetCodes(func() bool { return true })
	out, err := a.Run(context.Background(), map[string]any{"runId": "harden-c2", "mode": "dry_run"})
	failCode(t, out, err, protocol.CodeHardenFailed, "harden_not_triggered:")
	// another run held the unit the whole time
	hardenUnitState = func(context.Context) (hardenUnit, error) {
		return hardenUnit{InvocationID: "inv-9", ActiveState: "activating"}, nil
	}
	out, err = a.Run(context.Background(), map[string]any{"runId": "harden-c3", "mode": "dry_run"})
	failCode(t, out, err, protocol.CodeConflict, "harden_running:")
}

func TestHardenCodesAgentBusy(t *testing.T) {
	a, _ := setupHarden(t)
	if !hardenBusy.TryLock() {
		t.Skip("another test holds the harden lock")
	}
	defer hardenBusy.Unlock()
	args := map[string]any{"runId": "harden-c4", "mode": "dry_run"}
	// protocol 0: ok:true with a failed result, as before
	out, err := a.Run(context.Background(), args)
	m, _ := out.(map[string]any)
	if err != nil || m["status"] != "failed" || !strings.HasPrefix(m["message"].(string), "harden_running:") {
		t.Fatalf("protocol 0: %v %v", out, err)
	}
	a.SetCodes(func() bool { return true })
	out, err = a.Run(context.Background(), args)
	failCode(t, out, err, protocol.CodeConflict, "harden_running:")
}

func TestHardenCodesUnknownOutcomeReplay(t *testing.T) {
	a, _ := setupHarden(t)
	if err := saveHardenRuns(a.hardenRunsPath(), []hardenRun{{ID: "harden-c5", Mode: "apply", RequestedAt: "2026-11-17T10:00:00Z", Status: "requested"}}); err != nil {
		t.Fatal(err)
	}
	a.SetCodes(func() bool { return true })
	out, err := a.Run(context.Background(), map[string]any{"runId": "harden-c5", "mode": "apply"})
	failCode(t, out, err, protocol.CodeHardenFailed, "run harden-c5 was already requested")
}

// A result written by harden.sh, even a failed or rolled back one, is a completed run: ok:true with the whole audit.
func TestHardenCodesScriptReportedStaysOK(t *testing.T) {
	for _, status := range []string{"failed", "rolled_back"} {
		a, fu := setupHarden(t)
		a.SetCodes(func() bool { return true })
		id := "harden-c6" + status[:1]
		runs := 0
		fakeService(t, a, fu, id, `{"id":"`+id+`","mode":"apply","status":"`+status+`","message":"post-check failed","steps":[],"audit":[{"event":"start"}]}`, &runs, 0)
		out, err := a.Run(context.Background(), map[string]any{"runId": id, "mode": "apply"})
		m, _ := out.(map[string]any)
		if err != nil || m["status"] != status || m["message"] != "post-check failed" {
			t.Fatalf("%s: %v %v", status, out, err)
		}
		if f := protocol.ResultMessageFor("h", out, err, 1); f["ok"] != true || f["data"] == nil {
			t.Fatalf("%s: frame %v", status, f)
		}
		time.Sleep(30 * time.Millisecond) // let the follower record the outcome before the temp dir goes away
	}
}

// The six existing harden codes stay as they are at every protocol.
func TestHardenExistingCodesUnchanged(t *testing.T) {
	a, _ := setupHarden(t)
	a.SetCodes(func() bool { return true })
	if _, err := a.Run(context.Background(), map[string]any{"mode": "dry_run"}); protocol.ResultCode(err) != protocol.CodeHardenBadRequest {
		t.Fatalf("bad request: %v", err)
	}
	if err := errHardenState("/x/runs.json", context.DeadlineExceeded); protocol.ResultCode(err) != protocol.CodeHardenStateUnreadable {
		t.Fatalf("state: %v", err)
	}
	if protocol.ResultCode(errHardenNotInstalled) != protocol.CodeHardenNotInstalled {
		t.Fatal("not installed")
	}
	for _, c := range []string{protocol.CodeHardenNotInstalled, protocol.CodeHardenBadRequest, protocol.CodeHardenStateUnreadable, protocol.CodeHardenScriptFailed, protocol.CodeHardenInterrupted, protocol.CodeHardenTimeout} {
		if !protocol.LegacyCodes[c] {
			t.Errorf("%s must be sent at every protocol", c)
		}
	}
}
