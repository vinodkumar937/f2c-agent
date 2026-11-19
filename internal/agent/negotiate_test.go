package agent

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

// logCapture swaps the standard logger's output for a buffer for the test.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func captureLog(t *testing.T) *logCapture {
	t.Helper()
	l := &logCapture{}
	log.SetOutput(l)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return l
}

func bare(ver string) *Agent {
	a := &Agent{ver: ver}
	return a
}

func TestNegotiateHelloVariants(t *testing.T) {
	const w = "older than the engine's minimum agent version"
	for _, tc := range []struct {
		name     string
		agentVer string
		hello    string
		proto    int
		caps     []string
		warn     bool
	}{
		{"old engine: no fields", "0.3.1+202611181227", `{"t":"hello_ok","serverId":"srv_EXAMPLE"}`, 0, nil, false},
		{"all fields", "0.4.0", `{"t":"hello_ok","protocol":1,"minAgent":"0.4.0","caps":["notAfter","hardenSummary"]}`, 1, []string{"notAfter", "hardenSummary"}, false},
		{"agent older than minAgent", "0.3.1+202611181227", `{"t":"hello_ok","protocol":1,"minAgent":"0.4.0"}`, 1, nil, true},
		{"agent equal to minAgent (build metadata ignored)", "0.4.0+202701010000", `{"t":"hello_ok","protocol":1,"minAgent":"0.4.0+999"}`, 1, nil, false},
		{"agent newer than minAgent", "0.5.0", `{"t":"hello_ok","protocol":1,"minAgent":"0.4.0"}`, 1, nil, false},
		{"dev build vs pre-release", "0.4.0-dev", `{"t":"hello_ok","minAgent":"0.4.0"}`, 0, nil, true},
		{"unparseable minAgent is ignored", "0.1.0", `{"t":"hello_ok","minAgent":"latest"}`, 0, nil, false},
		{"unparseable agent version is ignored", "weird", `{"t":"hello_ok","minAgent":"9.9.9"}`, 0, nil, false},
		{"protocol as string", "0.4.0", `{"t":"hello_ok","protocol":"1","caps":["notAfter"]}`, 0, []string{"notAfter"}, false},
		{"protocol fractional", "0.4.0", `{"t":"hello_ok","protocol":1.5}`, 0, nil, false},
		{"protocol negative", "0.4.0", `{"t":"hello_ok","protocol":-1}`, 0, nil, false},
		{"protocol null", "0.4.0", `{"t":"hello_ok","protocol":null}`, 0, nil, false},
		{"protocol above ours is clamped", "0.4.0", `{"t":"hello_ok","protocol":7}`, protocol.Version, nil, false},
		{"caps not an array", "0.4.0", `{"t":"hello_ok","protocol":1,"caps":"notAfter"}`, 1, nil, false},
		{"caps object", "0.4.0", `{"t":"hello_ok","caps":{"notAfter":true}}`, 0, nil, false},
		{"caps with junk entries", "0.4.0", `{"t":"hello_ok","caps":[1,null,"notAfter","",["x"],"notAfter","future_cap"]}`, 0, []string{"notAfter", "future_cap"}, false},
		{"minAgent not a string", "0.1.0", `{"t":"hello_ok","minAgent":4}`, 0, nil, false},
		{"unknown fields ignored", "0.4.0", `{"t":"hello_ok","protocol":1,"future":{"a":[1,2]},"serverId":"x"}`, 1, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := captureLog(t)
			a := bare(tc.agentVer)
			a.negotiate([]byte(tc.hello))
			if got := a.SessionProtocol(); got != tc.proto {
				t.Errorf("SessionProtocol = %d, want %d", got, tc.proto)
			}
			for _, c := range tc.caps {
				if !a.EngineHas(c) {
					t.Errorf("EngineHas(%q) = false", c)
				}
			}
			if a.EngineHas("hardenSummary") != contains(tc.caps, "hardenSummary") || a.EngineHas("nope") {
				t.Errorf("EngineHas wrong for caps %v", tc.caps)
			}
			if got := strings.Contains(l.String(), w); got != tc.warn {
				t.Errorf("warning logged = %v, want %v (log %q)", got, tc.warn, l.String())
			}
			if strings.Count(l.String(), "warning") > 1 {
				t.Errorf("more than one warning: %q", l.String())
			}
			if tc.warn && !strings.Contains(l.String(), "minimum agent version") {
				t.Errorf("warning text: %q", l.String())
			}
		})
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Outside a session nothing is negotiated.
func TestSessionAccessorsDefault(t *testing.T) {
	a := bare("1.0.0")
	if a.SessionProtocol() != 0 || a.EngineHas("notAfter") {
		t.Fatal("expected protocol 0 and no caps before hello_ok")
	}
}

// The warning is logged once per session even if hello_ok were repeated.
func TestMinAgentWarnsOncePerSession(t *testing.T) {
	l := captureLog(t)
	a := bare("0.3.0")
	h := []byte(`{"t":"hello_ok","minAgent":"0.4.0"}`)
	a.negotiate(h)
	a.negotiate(h)
	if n := strings.Count(l.String(), "minimum agent version"); n != 1 {
		t.Fatalf("warnings = %d: %q", n, l.String())
	}
	a.neg.Store(nil) // a new session
	a.negotiate(h)
	if n := strings.Count(l.String(), "minimum agent version"); n != 2 {
		t.Fatalf("expected one warning per session, got %d", n)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The dial carries X-F2C-Protocol: 1 (and still the bearer token).
func TestDialSendsProtocolHeader(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		helloThen(w, r, func(c *websocket.Conn) { readUntilClosed(r, c) })
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := testAgent(t, eng.srv.URL, timing{})
	done := runLoop(t, a, ctx)
	waitFor(t, "dial", func() bool { mu.Lock(); defer mu.Unlock(); return got != nil })
	mu.Lock()
	h := got
	mu.Unlock()
	if v := h.Get("X-F2C-Protocol"); v != "1" {
		t.Fatalf("X-F2C-Protocol = %q, want \"1\"", v)
	}
	if protocol.Version != 1 {
		t.Fatalf("protocol.Version = %d", protocol.Version)
	}
	if !strings.HasPrefix(h.Get("Authorization"), "Bearer ") {
		t.Fatal("Authorization header missing")
	}
	cancel()
	waitDone(t, done)
}

// End to end: hello_ok through the real read loop, including malformed field types, must be accepted (session kept) and
// negotiate what it can; the state is cleared when the session ends.
func TestHelloThroughSession(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hello string
		proto int
		cap   string
		warn  bool
	}{
		{"new engine", `{"t":"hello_ok","serverId":"srv_EXAMPLE","protocol":1,"minAgent":"0.0.1","caps":["notAfter"]}`, 1, "notAfter", false},
		{"old engine", `{"t":"hello_ok","serverId":"srv_EXAMPLE"}`, 0, "", false},
		{"malformed types", `{"t":"hello_ok","protocol":"1","minAgent":7,"caps":"notAfter"}`, 0, "", false},
		{"agent too old", `{"t":"hello_ok","protocol":1,"minAgent":"99.0.0"}`, 1, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := captureLog(t)
			release := make(chan struct{})
			eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
				c, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer c.CloseNow()
				_ = c.Write(r.Context(), websocket.MessageText, []byte(tc.hello))
				go readUntilClosed(r, c)
				select {
				case <-release:
					_ = c.Close(websocket.StatusNormalClosure, "bye")
				case <-r.Context().Done():
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rec := &sleeper{max: 1 << 30, cancel: cancel}
			a := testAgent(t, eng.srv.URL, timing{Rand: func() float64 { return 0 }, Sleep: rec.sleep})
			a.ver = "0.3.1+202611181227"
			done := runLoop(t, a, ctx)
			waitFor(t, "hello_ok accepted", func() bool { return strings.Contains(l.String(), "engine accepted server") })
			waitFor(t, "negotiation", func() bool { return a.neg.Load() != nil })
			if got := a.SessionProtocol(); got != tc.proto {
				t.Fatalf("SessionProtocol = %d, want %d", got, tc.proto)
			}
			if tc.cap != "" && !a.EngineHas(tc.cap) {
				t.Fatalf("EngineHas(%s) = false", tc.cap)
			}
			if tc.cap == "" && a.EngineHas("notAfter") {
				t.Fatal("unexpected cap")
			}
			if got := strings.Contains(l.String(), "minimum agent version"); got != tc.warn {
				t.Fatalf("warning = %v, want %v; log %q", got, tc.warn, l.String())
			}
			if n := eng.conns.Load(); n != 1 {
				t.Fatalf("session dropped: %d connections", n)
			}
			close(release) // engine ends the session
			waitFor(t, "state cleared after disconnect", func() bool { return a.SessionProtocol() == 0 && !a.EngineHas(tc.cap) && a.neg.Load() == nil })
			cancel()
			waitDone(t, done)
		})
	}
}

// 4004 uses the slow auth schedule with its own log line; 4001 (idle) stays on the normal jittered schedule.
func TestLoopProtocolUnsupportedVsIdle(t *testing.T) {
	l := captureLog(t)
	closeWith := func(code websocket.StatusCode, reason string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if c, err := websocket.Accept(w, r, nil); err == nil {
				_ = c.Close(code, reason)
			}
		}
	}
	script := []func(w http.ResponseWriter, r *http.Request){
		closeWith(4004, "protocol_unsupported"),
		closeWith(4004, "protocol_unsupported"),
		closeWith(4001, "idle"),
		closeWith(4001, "idle"),
		closeWith(4004, "protocol_unsupported"),
	}
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n <= len(script) {
			script[n-1](w, r)
			return
		}
		http.Error(w, "no", 500)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl := &sleeper{max: len(script), cancel: cancel}
	a := testAgent(t, eng.srv.URL, timing{Rand: func() float64 { return 0 }, Sleep: sl.sleep})
	waitDone(t, runLoop(t, a, ctx))
	// 4004: auth schedule 60 s -> 30 s, 120 s -> 60 s. 4001: normal 1 s -> 0.5 s, 2 s -> 1 s. Then 4004 continues the auth schedule (240 s -> 120 s).
	want := []time.Duration{30 * time.Second, 60 * time.Second, 500 * time.Millisecond, time.Second, 120 * time.Second}
	got := sl.got()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("delays %v, want %v", got, want)
	}
	if !strings.Contains(l.String(), "4004") || !strings.Contains(l.String(), "protocol version 1") {
		t.Fatalf("expected a clear 4004 log line: %q", l.String())
	}
	if strings.Contains(l.String(), "f2cs_") {
		t.Fatal("token in log")
	}
}

func TestClassify4004And4001(t *testing.T) {
	if k, why := classify(websocket.CloseError{Code: 4004, Reason: "protocol_unsupported"}); k != failProtocol || why == "" {
		t.Fatalf("4004 -> %v %q", k, why)
	}
	if k, _ := classify(websocket.CloseError{Code: 4001, Reason: "idle"}); k != failNormal {
		t.Fatalf("4001 -> %v", k)
	}
	rc := newReconnector(func() float64 { return 0 })
	if rc.delay(failProtocol) != 30*time.Second || rc.delay(failAuth) != 60*time.Second {
		t.Fatal("4004 and auth must share one schedule")
	}
}

func withServer(a *Agent, id string) *Agent {
	a.cfg = &config.Config{ServerID: id}
	return a
}

func TestServerIDCheck(t *testing.T) {
	const w = "this session is for server"
	for _, tc := range []struct {
		name, cfgID, hello string
		warn               bool
	}{
		{"matches", "srv_EXAMPLE0000001", `{"t":"hello_ok","serverId":"srv_EXAMPLE0000001"}`, false},
		{"differs", "srv_EXAMPLE0000001", `{"t":"hello_ok","serverId":"srv_EXAMPLE0000002"}`, true},
		{"missing", "srv_EXAMPLE0000001", `{"t":"hello_ok"}`, false},
		{"null", "srv_EXAMPLE0000001", `{"t":"hello_ok","serverId":null}`, false},
		{"empty string", "srv_EXAMPLE0000001", `{"t":"hello_ok","serverId":""}`, false},
		{"wrong type number", "srv_EXAMPLE0000001", `{"t":"hello_ok","serverId":12}`, false},
		{"wrong type object", "srv_EXAMPLE0000001", `{"t":"hello_ok","serverId":{"a":1}}`, false},
		{"absurdly long", "srv_EXAMPLE0000001", `{"t":"hello_ok","serverId":"` + strings.Repeat("x", 300) + `"}`, false},
		{"agent has no configured id", "", `{"t":"hello_ok","serverId":"srv_EXAMPLE0000002"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := captureLog(t)
			a := withServer(bare("1.0.0"), tc.cfgID)
			a.negotiate([]byte(tc.hello))
			if got := strings.Contains(l.String(), w); got != tc.warn {
				t.Fatalf("warning = %v, want %v: %q", got, tc.warn, l.String())
			}
			if a.neg.Load() == nil {
				t.Fatal("negotiation not recorded")
			}
		})
	}
}

// One warning per session even when hello_ok repeats; a new session warns again.
func TestServerIDWarnsOncePerSession(t *testing.T) {
	l := captureLog(t)
	a := withServer(bare("1.0.0"), "srv_A")
	h := []byte(`{"t":"hello_ok","serverId":"srv_B","protocol":1}`)
	a.negotiate(h)
	a.negotiate(h)
	if n := strings.Count(l.String(), "this session is for server"); n != 1 {
		t.Fatalf("warnings = %d", n)
	}
	a.neg.Store(nil)
	a.negotiate(h)
	if n := strings.Count(l.String(), "this session is for server"); n != 2 {
		t.Fatalf("warnings = %d", n)
	}
	if a.SessionProtocol() != 1 {
		t.Fatal("a serverId mismatch must not disturb negotiation")
	}
}

// End to end: a mismatching serverId logs a warning and the session stays open.
func TestServerIDMismatchKeepsSession(t *testing.T) {
	l := captureLog(t)
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"t":"hello_ok","serverId":"srv_EXAMPLE_OTHER","protocol":1}`))
		readUntilClosed(r, c)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := testAgent(t, eng.srv.URL, timing{})
	done := runLoop(t, a, ctx)
	waitFor(t, "warning", func() bool { return strings.Contains(l.String(), "this session is for server") })
	time.Sleep(200 * time.Millisecond)
	if n := eng.conns.Load(); n != 1 || a.SessionProtocol() != 1 {
		t.Fatalf("session dropped or negotiation lost: conns=%d proto=%d", n, a.SessionProtocol())
	}
	if !strings.Contains(l.String(), "engine accepted server") {
		t.Fatal("hello_ok must still be accepted")
	}
	cancel()
	waitDone(t, done)
}
