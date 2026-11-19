package agent

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

func TestUnknownCommandCode(t *testing.T) {
	a := &Agent{stateDir: t.TempDir()}
	_, err := a.execute(context.Background(), protocol.Message{Type: "no_such_cmd"})
	if err == nil || err.Error() != `unknown command type "no_such_cmd"` {
		t.Fatalf("text must stay exactly as before: %v", err)
	}
	if !regexp.MustCompile(`(?i)unknown command`).MatchString(err.Error()) { // engine API (byo.ts)
		t.Fatal("byo.ts match broken")
	}
	if c := protocol.ResultCode(err); c != "unknown_command" {
		t.Fatalf("code %q", c)
	}
}

// cmdAgent: an agent whose outgoing messages land on a channel.
func cmdAgent(t *testing.T) (*Agent, chan map[string]any) {
	t.Helper()
	a := New(&config.Config{}, t.TempDir(), "", "", false)
	ch := make(chan map[string]any, 32)
	a.sendHook = func(v any) {
		var b []byte
		if r, ok := v.(json.RawMessage); ok {
			b = r
		} else {
			b, _ = json.Marshal(v)
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		ch <- m
	}
	return a, ch
}

func next(t *testing.T, ch chan map[string]any) map[string]any {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("no message")
		return nil
	}
}

// ranOnce: an ack, then the result of actually executing the (unknown) command.
func ranOnce(t *testing.T, ch chan map[string]any, id string) {
	t.Helper()
	if m := next(t, ch); m["t"] != "ack" || m["id"] != id {
		t.Fatalf("want ack for %s, got %v", id, m)
	}
	if m := next(t, ch); m["t"] != "result" || m["id"] != id || m["code"] != "unknown_command" {
		t.Fatalf("want executed result for %s, got %v", id, m)
	}
}

func TestOnCommandNotAfter(t *testing.T) {
	a, ch := cmdAgent(t)
	past := time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339)

	a.onCommand(protocol.Message{T: "cmd", ID: "c1", Type: "no_such_cmd", NotAfter: past})
	m := next(t, ch)
	errText, _ := m["error"].(string)
	if m["t"] != "result" || m["ok"] != false || m["code"] != "expired" || !strings.Contains(errText, "expired") || !strings.Contains(errText, "not run") {
		t.Fatalf("expired: %v", m)
	}
	a.mu.Lock()
	_, cached := a.done["c1"]
	_, running := a.running["c1"]
	a.mu.Unlock()
	if cached || running {
		t.Fatal("an expired command must not be recorded as executed")
	}
	if _, err := os.Stat(a.donePath()); err == nil {
		t.Fatal("an expired command must not be written to done.json")
	}
	select {
	case extra := <-ch:
		t.Fatalf("expired command sent more (ack/execute?): %v", extra)
	case <-time.After(50 * time.Millisecond):
	}

	// the same id re-sent with a fresh deadline, and a new id, both run normally
	a.onCommand(protocol.Message{T: "cmd", ID: "c1", Type: "no_such_cmd", NotAfter: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
	ranOnce(t, ch, "c1")
	a.onCommand(protocol.Message{T: "cmd", ID: "c2", Type: "no_such_cmd"})
	ranOnce(t, ch, "c2")
	// within the skew, and an invalid deadline: run as today
	a.onCommand(protocol.Message{T: "cmd", ID: "c3", Type: "no_such_cmd", NotAfter: time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339)})
	ranOnce(t, ch, "c3")
	a.onCommand(protocol.Message{T: "cmd", ID: "c4", Type: "no_such_cmd", NotAfter: "not-a-time"})
	ranOnce(t, ch, "c4")
	// an id that already ran gets its cached result even with an expired deadline (dedupe first)
	a.onCommand(protocol.Message{T: "cmd", ID: "c2", Type: "no_such_cmd", NotAfter: past})
	if m := next(t, ch); m["id"] != "c2" || m["code"] != "unknown_command" {
		t.Fatalf("cached result: %v", m)
	}
}
