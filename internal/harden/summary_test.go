package harden

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

func TestHardenErrorCodes(t *testing.T) {
	a, _ := setupHarden(t)
	_, err := a.Run(context.Background(), map[string]any{"runId": "harden-c1", "mode": "nope"})
	if protocol.ResultCode(err) != "harden_bad_request" {
		t.Fatalf("bad request: %v (%q)", err, protocol.ResultCode(err))
	}
	_ = os.Remove(hardenScript)
	_, err = a.Run(context.Background(), map[string]any{"runId": "harden-c2", "mode": "dry_run"})
	if protocol.ResultCode(err) != "harden_not_installed" || !strings.HasPrefix(err.Error(), "harden_not_installed:") {
		t.Fatalf("not installed: %v (%q)", err, protocol.ResultCode(err))
	}
	if m := protocol.ResultMessage("x", nil, err); m["code"] != "harden_not_installed" {
		t.Fatalf("%v", m)
	}
}

var summaryTestMu sync.Mutex // the summary cache is process-wide

func TestHardenSummary(t *testing.T) {
	summaryTestMu.Lock()
	defer summaryTestMu.Unlock()
	a := &Service{stateDir: t.TempDir()}
	path := a.hardenRunsPath()

	hs := a.SafeSummary()
	if hs["v"] != 1 {
		t.Fatalf("%v", hs)
	}
	b, _ := json.Marshal(hs)
	if string(b) != `{"runs":[],"v":1}` {
		t.Fatalf("no runs.json: %s", b)
	}

	var runs []hardenRun
	for i := 1; i <= 7; i++ {
		r := hardenRun{ID: "harden-s" + string(rune('0'+i)), Mode: "apply", RequestedAt: "2026-11-17T10:00:00Z", Status: "succeeded", FinishedAt: "2026-11-17T10:05:00Z", BackupID: "b" + string(rune('0'+i))}
		if i == 7 {
			r.Status, r.FinishedAt, r.BackupID = "requested", "", ""
		}
		runs = append(runs, r)
	}
	if err := saveHardenRuns(path, runs); err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(a.SafeSummary())
	want := `{"runs":[{"id":"harden-s7","status":"requested"},{"id":"harden-s6","status":"succeeded","finishedAt":"2026-11-17T10:05:00Z","backupId":"b6"},{"id":"harden-s5","status":"succeeded","finishedAt":"2026-11-17T10:05:00Z","backupId":"b5"},{"id":"harden-s4","status":"succeeded","finishedAt":"2026-11-17T10:05:00Z","backupId":"b4"},{"id":"harden-s3","status":"succeeded","finishedAt":"2026-11-17T10:05:00Z","backupId":"b3"}],"v":1}`
	if string(b) != want {
		t.Fatalf("summary:\n got %s\nwant %s", b, want)
	}

	// cached: same size and mtime, not saved by the agent -> not reread
	st, _ := os.Stat(path)
	orig, _ := os.ReadFile(path)
	same := []byte(strings.Replace(string(orig), `"b6"`, `"b9"`, 1))
	if err := os.WriteFile(path, same, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(path, st.ModTime(), st.ModTime())
	if b2, _ := json.Marshal(a.SafeSummary()); string(b2) != want {
		t.Fatalf("expected the cached summary: %s", b2)
	}
	// a save by the agent always invalidates
	runs[5].BackupID = "b6x"
	if err := saveHardenRuns(path, runs); err != nil {
		t.Fatal(err)
	}
	if b2, _ := json.Marshal(a.SafeSummary()); !strings.Contains(string(b2), `"b6x"`) {
		t.Fatalf("not reread after save: %s", b2)
	}

	// corrupt / unreadable: empty runs, never a failure
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b2, _ := json.Marshal(a.SafeSummary()); string(b2) != `{"runs":[],"v":1}` {
		t.Fatalf("corrupt: %s", b2)
	}
	_ = os.Remove(path)
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil { // runs.json is a directory
		t.Fatal(err)
	}
	if b2, _ := json.Marshal(a.SafeSummary()); string(b2) != `{"runs":[],"v":1}` {
		t.Fatalf("unreadable: %s", b2)
	}
}
