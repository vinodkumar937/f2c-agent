package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

func agentIn(t *testing.T, dir string) (*Agent, chan map[string]any) {
	t.Helper()
	a := New(&config.Config{}, dir, "", "", false)
	ch := make(chan map[string]any, 64)
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

func setProto(a *Agent, p int) { a.neg.Store(&negotiated{protocol: p}) }

func noMore(t *testing.T, ch chan map[string]any) {
	t.Helper()
	select {
	case m := <-ch:
		t.Fatalf("unexpected extra frame: %v", m)
	case <-time.After(60 * time.Millisecond):
	}
}

// crash simulates an agent that died with the given command in flight: the journal is written, no goroutine exists.
func crash(t *testing.T, dir string, ids map[string]string) {
	t.Helper()
	a, _ := agentIn(t, dir)
	a.mu.Lock()
	for id, typ := range ids {
		a.runRec[id] = runRecord{ID: id, Type: typ, ArgsSha: argsDigest(typ, map[string]any{"name": "x"}), StartedAt: a.now().UTC()}
	}
	a.saveRunning()
	a.mu.Unlock()
}

func TestClassTableMatchesSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "protocol", "schemas", "commands.json"))
	if err != nil {
		t.Skip("spec not in this checkout")
	}
	var c struct {
		Defs map[string]struct {
			Enum []string `json:"enum"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	types := c.Defs["commandType"].Enum
	if len(types) != 21 || len(commandClasses) != 21 {
		t.Fatalf("21 command types expected: schema %d, table %d", len(types), len(commandClasses))
	}
	for _, ty := range types {
		if _, ok := commandClasses[ty]; !ok {
			t.Errorf("command %s has no idempotency class", ty)
		}
	}
	// every type is a case of the dispatcher (read from the source: running them here would execute real commands)
	src, err := os.ReadFile("commands.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, ty := range types {
		if !strings.Contains(string(src), `case "`+ty+`":`) {
			t.Errorf("%s is in the schema but not in execute()", ty)
		}
	}
}

func TestJournalRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a, ch := agentIn(t, dir)
	setProto(a, 1)
	a.execHook = func(ctx context.Context, m protocol.Message) (any, error) {
		return map[string]any{"n": 12345678901234}, nil
	}
	a.onCommand(protocol.Message{T: "cmd", ID: "c1", Type: "logs", Args: map[string]any{"name": "web"}})
	if m := next(t, ch); m["t"] != "ack" {
		t.Fatal(m)
	}
	if m := next(t, ch); m["t"] != "result" || m["ok"] != true {
		t.Fatal(m)
	}
	// files: no secrets in running.json, done.json carries at/type/argsSha
	raw, _ := os.ReadFile(filepath.Join(dir, "done.json"))
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) != 1 || list[0]["type"] != "logs" || list[0]["argsSha"] == "" || list[0]["at"] == "" {
		t.Fatalf("done.json: %s", raw)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "done.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "running.json")); strings.TrimSpace(string(raw)) != "[]" {
		t.Fatalf("running.json should be empty after the command ended: %s", raw)
	}
	// a new process loads it and replays
	b2, ch2 := agentIn(t, dir)
	setProto(b2, 1)
	b2.onCommand(protocol.Message{T: "cmd", ID: "c1", Type: "logs", Args: map[string]any{"name": "web"}})
	m := next(t, ch2)
	if m["t"] != "result" || m["replayed"] != true || m["ok"] != true {
		t.Fatalf("replay after reload: %v", m)
	}
}

func TestRunningFileWrittenBeforeStartHoldsNoArgs(t *testing.T) {
	dir := t.TempDir()
	a, ch := agentIn(t, dir)
	started := make(chan struct{})
	release := make(chan struct{})
	a.execHook = func(ctx context.Context, m protocol.Message) (any, error) {
		close(started)
		<-release
		return map[string]any{"ok": 1}, nil
	}
	a.onCommand(protocol.Message{T: "cmd", ID: "s1", Type: "run", Args: map[string]any{"name": "web", "env": map[string]any{"PASSWORD": "hunter2-secret"}}})
	<-started
	raw, err := os.ReadFile(filepath.Join(dir, "running.json"))
	if err != nil || !strings.Contains(string(raw), `"id":"s1"`) || !strings.Contains(string(raw), `"argsSha"`) {
		t.Fatalf("running.json must exist while the command runs: %v %s", err, raw)
	}
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "PASSWORD") {
		t.Fatalf("args must never be stored: %s", raw)
	}
	close(release)
	next(t, ch)
	next(t, ch)
}

func TestResendRunningAttaches(t *testing.T) {
	a, ch := agentIn(t, t.TempDir())
	setProto(a, 1)
	var runs atomic.Int32
	release := make(chan struct{})
	a.execHook = func(ctx context.Context, m protocol.Message) (any, error) {
		runs.Add(1)
		<-release
		return map[string]any{"done": true}, nil
	}
	msg := protocol.Message{T: "cmd", ID: "r1", Type: "exec", Args: map[string]any{"name": "db", "cmd": []any{"true"}}}
	a.onCommand(msg)
	if m := next(t, ch); m["t"] != "ack" {
		t.Fatal(m)
	}
	a.onCommand(msg) // the resend while it runs: only an ack
	if m := next(t, ch); m["t"] != "ack" || m["id"] != "r1" {
		t.Fatalf("resend of a running id: %v", m)
	}
	noMore(t, ch)
	close(release)
	m := next(t, ch)
	if m["t"] != "result" || m["ok"] != true || m["replayed"] != nil {
		t.Fatalf("the single result: %v", m)
	}
	noMore(t, ch)
	if runs.Load() != 1 {
		t.Fatalf("executed %d times", runs.Load())
	}
	// different args for the same running id: refused at protocol 1, ignored at protocol 0
	b, chb := agentIn(t, t.TempDir())
	setProto(b, 1)
	rel := make(chan struct{})
	b.execHook = func(ctx context.Context, m protocol.Message) (any, error) { <-rel; return nil, nil }
	b.onCommand(msg)
	next(t, chb)
	b.onCommand(protocol.Message{T: "cmd", ID: "r1", Type: "exec", Args: map[string]any{"name": "other"}})
	if m := next(t, chb); m["ok"] != false || m["code"] != "bad_request" || !strings.Contains(m["error"].(string), "already used for a different command") {
		t.Fatalf("reused id: %v", m)
	}
	setProto(b, 0)
	b.onCommand(protocol.Message{T: "cmd", ID: "r1", Type: "exec", Args: map[string]any{"name": "other"}})
	if m := next(t, chb); m["t"] != "ack" {
		t.Fatalf("protocol 0 keeps the old behaviour: %v", m)
	}
	close(rel)
	if m := next(t, chb); m["t"] != "result" { // let the goroutine finish before the temp dir goes
		t.Fatal(m)
	}
}

func TestResendDoneReplayedOnlyAtV1(t *testing.T) {
	for _, proto := range []int{0, 1} {
		a, ch := agentIn(t, t.TempDir())
		setProto(a, proto)
		a.execHook = func(ctx context.Context, m protocol.Message) (any, error) {
			return nil, protocol.WithCode(protocol.CodePortInUse, os.ErrExist)
		}
		msg := protocol.Message{T: "cmd", ID: "d1", Type: "run", Args: map[string]any{"name": "web"}}
		a.onCommand(msg)
		next(t, ch)
		first := next(t, ch)
		a.onCommand(msg)
		again := next(t, ch)
		if proto == 0 {
			if _, has := again["replayed"]; has {
				t.Fatalf("protocol 0 must not carry replayed: %v", again)
			}
			delete(first, "replayed")
		} else {
			if again["replayed"] != true {
				t.Fatalf("protocol 1 replay: %v", again)
			}
			delete(again, "replayed")
		}
		fb, _ := json.Marshal(first)
		ab, _ := json.Marshal(again)
		if string(fb) != string(ab) {
			t.Fatalf("proto %d: the replay must equal the first frame\n%s\n%s", proto, fb, ab)
		}
		noMore(t, ch)
	}
}

// replayFrame must be a text-level insert: the cached bytes keep their order and numbers.
func TestReplayFrameBytes(t *testing.T) {
	in := json.RawMessage(`{"t":"result","id":"x","ok":true,"data":{"big":12345678901234567890,"b":1,"a":2}}`)
	if string(replayFrame(in, 0)) != string(in) {
		t.Fatal("protocol 0 must be byte-identical")
	}
	got := string(replayFrame(in, 1))
	want := `{"t":"result","id":"x","ok":true,"data":{"big":12345678901234567890,"b":1,"a":2},"replayed":true}`
	if got != want {
		t.Fatalf("%s", got)
	}
	if string(replayFrame(json.RawMessage(`nonsense`), 1)) != "nonsense" {
		t.Fatal("a frame that is not an object is left alone")
	}
}

func TestRestartMidRunPerClass(t *testing.T) {
	cases := []struct {
		typ   string
		class string // interrupted | rerun | restart | own
	}{
		{"run", "interrupted"}, {"rename", "interrupted"}, {"build", "interrupted"}, {"load", "interrupted"}, {"exec", "interrupted"},
		{"logs", "rerun"}, {"stats", "rerun"}, {"volumes_list", "rerun"}, {"image_present", "rerun"}, {"tls_warm", "rerun"}, {"http_probe", "rerun"},
		{"pull", "rerun"}, {"caddy_apply", "rerun"}, {"cert_install", "rerun"}, {"rm", "rerun"}, {"stop", "rerun"},
		{"network_rm", "rerun"}, {"volume_rm", "rerun"}, {"self_update", "rerun"},
		{"harden", "own"}, {"restart_agent", "restart"},
	}
	for _, proto := range []int{0, 1} {
		for _, c := range cases {
			dir := t.TempDir()
			crash(t, dir, map[string]string{"k1": c.typ})
			a, ch := agentIn(t, dir)
			setProto(a, proto)
			var ran atomic.Int32
			a.execHook = func(ctx context.Context, m protocol.Message) (any, error) {
				ran.Add(1)
				return map[string]any{"again": true}, nil
			}
			a.onCommand(protocol.Message{T: "cmd", ID: "k1", Type: c.typ, Args: map[string]any{"name": "x"}})
			switch c.class {
			case "interrupted":
				m := next(t, ch)
				if m["t"] != "result" || m["ok"] != false || !strings.HasPrefix(m["error"].(string), "interrupted: the agent restarted") || ran.Load() != 0 {
					t.Fatalf("%s/p%d: %v ran=%d", c.typ, proto, m, ran.Load())
				}
				if proto == 1 && m["code"] != "interrupted" {
					t.Fatalf("%s: code %v", c.typ, m["code"])
				}
				if proto == 0 {
					if _, has := m["code"]; has {
						t.Fatalf("protocol 0 must not carry the new code: %v", m)
					}
				}
				// cached: a further resend gives the same answer without running
				a.onCommand(protocol.Message{T: "cmd", ID: "k1", Type: c.typ, Args: map[string]any{"name": "x"}})
				m2 := next(t, ch)
				if m2["ok"] != false || (proto == 1 && m2["replayed"] != true) || ran.Load() != 0 {
					t.Fatalf("%s: second resend %v", c.typ, m2)
				}
			case "rerun", "own":
				if m := next(t, ch); m["t"] != "ack" {
					t.Fatalf("%s: %v", c.typ, m)
				}
				if m := next(t, ch); m["ok"] != true || ran.Load() != 1 {
					t.Fatalf("%s/p%d: %v ran=%d", c.typ, proto, m, ran.Load())
				}
			case "restart":
				m := next(t, ch)
				d, _ := m["data"].(map[string]any)
				if m["ok"] != true || d["restarting"] != true || ran.Load() != 0 {
					t.Fatalf("%v ran=%d", m, ran.Load())
				}
			}
			a.mu.Lock()
			_, still := a.runRec["k1"]
			a.mu.Unlock()
			if still {
				t.Fatalf("%s: record must be cleared once answered", c.typ)
			}
		}
	}
}

func TestClassTableCoversEveryType(t *testing.T) {
	for typ, c := range map[string]cmdClass{"run": classUnsafe, "rm": classConverge, "logs": classRead, "harden": classOwn, "restart_agent": classRestart, "no_such": classRead} {
		if classOf(typ) != c {
			t.Errorf("%s", typ)
		}
	}
}

func TestTTLAndCaps(t *testing.T) {
	dir := t.TempDir()
	a, _ := agentIn(t, dir)
	clock := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	a.nowFn = func() time.Time { return clock }
	a.mu.Lock()
	a.recordDoneLocked("old", "logs", "s", []byte(`{"t":"result","id":"old","ok":true}`))
	a.mu.Unlock()
	clock = clock.Add(24 * time.Hour)
	a.mu.Lock()
	a.recordDoneLocked("mid", "logs", "s", []byte(`{"t":"result","id":"mid","ok":true}`))
	if a.pruneLocked(a.now()) {
		t.Fatal("nothing is past 25 h yet")
	}
	a.mu.Unlock()
	clock = clock.Add(90 * time.Minute) // old is now 25.5 h, mid 1.5 h
	a.mu.Lock()
	if !a.pruneLocked(a.now()) {
		t.Fatal("old should expire")
	}
	_, hasOld := a.done["old"]
	_, hasMid := a.done["mid"]
	a.mu.Unlock()
	if hasOld || !hasMid {
		t.Fatalf("old=%v mid=%v", hasOld, hasMid)
	}
	// a resend of the expired id runs again as a new command
	a2, ch := agentIn(t, t.TempDir())
	a2.nowFn = a.nowFn
	a2.execHook = func(ctx context.Context, m protocol.Message) (any, error) { return nil, nil }
	a2.mu.Lock()
	a2.recordDoneLocked("e1", "logs", argsDigest("logs", nil), []byte(`{"t":"result","id":"e1","ok":true}`))
	a2.mu.Unlock()
	clock = clock.Add(26 * time.Hour)
	a2.onCommand(protocol.Message{T: "cmd", ID: "e1", Type: "logs"})
	if m := next(t, ch); m["t"] != "ack" {
		t.Fatalf("an id past the TTL is a new command: %v", m)
	}

	// count cap
	b, _ := agentIn(t, t.TempDir())
	b.mu.Lock()
	for i := 0; i < maxDone+20; i++ {
		id := "n" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		b.recordDoneLocked(id, "logs", "s", []byte(`{"t":"result","id":"`+id+`","ok":true}`))
	}
	n := len(b.done)
	b.mu.Unlock()
	if n != maxDone {
		t.Fatalf("count cap: %d", n)
	}
	// byte cap: frames of 200 KiB (under the stub limit), 8 MiB total
	c, _ := agentIn(t, t.TempDir())
	c.mu.Lock()
	pad := strings.Repeat("a", 200<<10)
	for i := 0; i < 60; i++ {
		id := "big" + strings.Repeat("y", i)
		c.recordDoneLocked(id, "logs", "s", []byte(`{"t":"result","id":"`+id+`","ok":true,"data":{"p":"`+pad+`"}}`))
	}
	if c.doneBytes > maxDoneBytes || len(c.done) < 30 {
		t.Fatalf("byte cap: %d bytes, %d entries", c.doneBytes, len(c.done))
	}
	c.mu.Unlock()
}

func TestOversizedResultCachedAsStub(t *testing.T) {
	a, ch := agentIn(t, t.TempDir())
	setProto(a, 1)
	pad := strings.Repeat("z", maxStoredFrame+10)
	a.execHook = func(ctx context.Context, m protocol.Message) (any, error) { return map[string]any{"blob": pad}, nil }
	msg := protocol.Message{T: "cmd", ID: "big1", Type: "logs", Args: map[string]any{"name": "w"}}
	a.onCommand(msg)
	next(t, ch)
	full := next(t, ch)
	if d, _ := full["data"].(map[string]any); d["blob"] != pad {
		t.Fatal("the frame sent when the command ends must be the full one")
	}
	a.onCommand(msg)
	rep := next(t, ch)
	d, _ := rep["data"].(map[string]any)
	if rep["ok"] != true || rep["replayed"] != true || d["replayStub"] != true || d["blob"] != nil {
		t.Fatalf("stub: %v", rep)
	}
	// a failure keeps its text and code in the stub
	b := storedFrame("e", []byte(`{"t":"result","id":"e","ok":false,"error":"`+pad+`","code":"build_failed"}`))
	var f map[string]any
	_ = json.Unmarshal(b, &f)
	if f["ok"] != false || f["code"] != "build_failed" || len(f["error"].(string)) != 4000 {
		t.Fatalf("%v", f)
	}
}

func TestCorruptAndMissingFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"done.json", "running.json"} {
		for _, content := range []string{"", "not json", `{"a":1}`, `[{"id":"","result":null}]`, `[{"id":"x"}]`} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(filepath.Join(dir, "done.json")) // only the file under test exists
			_ = os.Remove(filepath.Join(dir, "running.json"))
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			a, ch := agentIn(t, dir)
			a.execHook = func(ctx context.Context, m protocol.Message) (any, error) { return nil, nil }
			a.onCommand(protocol.Message{T: "cmd", ID: "fresh", Type: "logs"})
			if m := next(t, ch); m["t"] != "ack" {
				t.Fatalf("%s %q: %v", name, content, m)
			}
			next(t, ch)
		}
	}
	// missing files: a fresh state dir works and creates nothing until a command runs
	d := t.TempDir()
	agentIn(t, d)
	if _, err := os.Stat(filepath.Join(d, "running.json")); err == nil {
		t.Fatal("loading must not create files")
	}
	// an old-format done.json (no at/type/argsSha) still replays, with the TTL counted from load time
	if err := os.WriteFile(filepath.Join(d, "done.json"), []byte(`[{"id":"legacy","result":{"t":"result","id":"legacy","ok":true}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	a, ch := agentIn(t, d)
	setProto(a, 1)
	a.onCommand(protocol.Message{T: "cmd", ID: "legacy", Type: "logs", Args: map[string]any{"name": "whatever"}})
	if m := next(t, ch); m["ok"] != true || m["replayed"] != true {
		t.Fatalf("legacy entry (no argsSha: no reuse check): %v", m)
	}
}

// done.json keeps its shape for an older agent: it only gains optional fields.
func TestDoneJSONStaysReadableByOldAgents(t *testing.T) {
	dir := t.TempDir()
	a, ch := agentIn(t, dir)
	a.execHook = func(ctx context.Context, m protocol.Message) (any, error) { return nil, nil }
	a.onCommand(protocol.Message{T: "cmd", ID: "o1", Type: "logs"})
	next(t, ch)
	next(t, ch)
	raw, _ := os.ReadFile(filepath.Join(dir, "done.json"))
	var old []struct {
		ID     string          `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &old); err != nil || len(old) != 1 || old[0].ID != "o1" || len(old[0].Result) == 0 {
		t.Fatalf("%v %s", err, raw)
	}
}
