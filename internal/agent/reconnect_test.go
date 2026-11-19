package agent

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/vinodkumar937/f2c-agent/internal/config"
)

func within(t *testing.T, what string, got, lo, hi time.Duration) {
	t.Helper()
	if got < lo || got > hi {
		t.Fatalf("%s = %s, want within [%s, %s]", what, got, lo, hi)
	}
}

func TestJitterBounds(t *testing.T) {
	rc := newReconnector(rand.New(rand.NewSource(1)).Float64)
	for _, base := range []time.Duration{time.Second, 7 * time.Second, 30 * time.Second, 10 * time.Minute} {
		for i := 0; i < 5000; i++ {
			within(t, "jitter", rc.jitter(base), base/2, base)
		}
	}
	lo, hi := newReconnector(func() float64 { return 0 }), newReconnector(func() float64 { return 0.9999999999 })
	if got := lo.jitter(8 * time.Second); got != 4*time.Second {
		t.Fatalf("rand 0 -> %s", got)
	}
	if got := hi.jitter(8 * time.Second); got < 7999*time.Millisecond || got > 8*time.Second {
		t.Fatalf("rand ~1 -> %s", got)
	}
}

func TestNormalSchedule(t *testing.T) {
	for _, tc := range []struct {
		name string
		rnd  float64
		div  time.Duration // expected = base / div (2 for rand 0, 1 for rand ~1)
	}{{"lower", 0, 2}, {"upper", 0.9999999999, 1}} {
		rc := newReconnector(func() float64 { return tc.rnd })
		for i, base := range []time.Duration{1, 2, 4, 8, 16, 30, 30, 30} {
			base *= time.Second
			got := rc.delay(failNormal)
			within(t, fmt.Sprintf("%s step %d", tc.name, i), got, base/2, base)
			if tc.rnd == 0 && got != base/tc.div {
				t.Fatalf("step %d: %s", i, got)
			}
		}
	}
}

func TestNormalResetAfterLongSession(t *testing.T) {
	rc := newReconnector(func() float64 { return 0 })
	for i := 0; i < 4; i++ {
		rc.delay(failNormal) // base is now 16 s
	}
	rc.sessionEnded(59 * time.Second) // too short: no reset
	if got := rc.delay(failNormal); got != 8*time.Second {
		t.Fatalf("no reset expected, got %s", got)
	}
	rc.sessionEnded(61 * time.Second)
	if got := rc.delay(failNormal); got != 500*time.Millisecond {
		t.Fatalf("reset expected, got %s", got)
	}
}

func TestAuthScheduleAndReset(t *testing.T) {
	rc := newReconnector(func() float64 { return 0 })
	want := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 300 * time.Second, 300 * time.Second}
	for i, w := range want {
		if got := rc.delay(failAuth); got != w {
			t.Fatalf("auth step %d: %s want %s", i, got, w)
		}
	}
	rc.accepted() // hello_ok
	if got := rc.delay(failAuth); got != 30*time.Second {
		t.Fatalf("auth schedule must restart after hello_ok: %s", got)
	}
	// never faster than 30 s, never slower than 10 min, with real randomness
	rr := newReconnector(rand.New(rand.NewSource(2)).Float64)
	for i := 0; i < 50; i++ {
		within(t, "auth delay", rr.delay(failAuth), 30*time.Second, 10*time.Minute)
	}
	// normal failures do not touch the auth schedule and vice versa
	rc2 := newReconnector(func() float64 { return 0 })
	rc2.delay(failNormal)
	rc2.delay(failNormal)
	if got := rc2.delay(failAuth); got != 30*time.Second {
		t.Fatalf("auth schedule disturbed: %s", got)
	}
}

func TestReplacedRange(t *testing.T) {
	rr := newReconnector(rand.New(rand.NewSource(3)).Float64)
	seenLow, seenHigh := false, false
	for i := 0; i < 2000; i++ {
		d := rr.delay(failReplaced)
		within(t, "replaced", d, 30*time.Second, 90*time.Second)
		seenLow = seenLow || d < 45*time.Second
		seenHigh = seenHigh || d > 75*time.Second
	}
	if !seenLow || !seenHigh {
		t.Fatal("replaced delay is not spread over 30..90 s")
	}
	if got := newReconnector(func() float64 { return 0 }).delay(failReplaced); got != 30*time.Second {
		t.Fatalf("lower bound %s", got)
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want failKind
	}{
		{&dialStatusError{Status: 401, Msg: "x"}, failAuth},
		{&dialStatusError{Status: 403, Msg: "x"}, failAuth},
		{&dialStatusError{Status: 404, Msg: "x"}, failNormal},
		{&dialStatusError{Status: 426, Msg: "x"}, failNormal},
		{fmt.Errorf("wrapped: %w", websocket.CloseError{Code: 4003, Reason: "revoked"}), failAuth},
		{websocket.CloseError{Code: 4000, Reason: "replaced by a newer connection"}, failReplaced},
		{websocket.CloseError{Code: 4001, Reason: "idle"}, failNormal},
		{websocket.CloseError{Code: 1009}, failNormal},
		{errDeadLink, failNormal},
		{errors.New("dial tcp: connection refused"), failNormal},
		{nil, failNormal},
	} {
		if got, why := classify(tc.err); got != tc.want {
			t.Errorf("classify(%v) = %v want %v", tc.err, got, tc.want)
		} else if got != failNormal && (why == "" || strings.Contains(why, "f2cs_")) {
			t.Errorf("reason %q", why)
		}
	}
}

// ---- integration against a fake engine --------------------------------------------------------------------------

type fakeEngine struct {
	srv   *httptest.Server
	conns atomic.Int32
	// handler decides what to do with connection number n (1-based) before upgrading.
	handler func(n int, w http.ResponseWriter, r *http.Request)
}

func newFakeEngine(t *testing.T, h func(n int, w http.ResponseWriter, r *http.Request)) *fakeEngine {
	t.Helper()
	f := &fakeEngine{handler: h}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent" {
			http.NotFound(w, r)
			return
		}
		f.handler(int(f.conns.Add(1)), w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// helloThen upgrades, sends hello_ok and then calls fn with the server side conn.
func helloThen(w http.ResponseWriter, r *http.Request, fn func(c *websocket.Conn)) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"t":"hello_ok","serverId":"srv_EXAMPLE"}`))
	fn(c)
}

// readUntilClosed reads (and so answers pings) until the peer goes away.
func readUntilClosed(r *http.Request, c *websocket.Conn) {
	for {
		if _, _, err := c.Read(r.Context()); err != nil {
			return
		}
	}
}

func testAgent(t *testing.T, url string, tm timing) *Agent {
	t.Helper()
	a := New(&config.Config{Engine: url, ServerID: "srv_EXAMPLE", Token: "f2cs_EXAMPLE_NOT_A_REAL_TOKEN"}, t.TempDir(), "", "", false)
	a.tm = tm
	return a
}

// sleeper records every requested delay and returns at once; it cancels the run after max delays.
type sleeper struct {
	mu     sync.Mutex
	delays []time.Duration
	max    int
	cancel context.CancelFunc
}

func (s *sleeper) sleep(ctx context.Context, d time.Duration) bool {
	s.mu.Lock()
	s.delays = append(s.delays, d)
	n := len(s.delays)
	s.mu.Unlock()
	if n >= s.max {
		s.cancel()
		return false
	}
	return ctx.Err() == nil
}

func (s *sleeper) got() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.delays...)
}

func runLoop(t *testing.T, a *Agent, ctx context.Context) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() { a.loop(ctx); close(done) }()
	return done
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("agent loop did not stop")
	}
}

// Auth failures (401, 403, close 4003) and a replaced connection (4000) use their own slow schedules; hello_ok resets the
// auth schedule. Delays are recorded, not slept.
func TestLoopAuthAndReplacedSchedule(t *testing.T) {
	script := []func(w http.ResponseWriter, r *http.Request){
		func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) },
		func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) },
		func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 403) },
		func(w http.ResponseWriter, r *http.Request) { // close 4003 without hello_ok
			if c, err := websocket.Accept(w, r, nil); err == nil {
				_ = c.Close(4003, "revoked")
			}
		},
		func(w http.ResponseWriter, r *http.Request) { // close 4000 without hello_ok
			if c, err := websocket.Accept(w, r, nil); err == nil {
				_ = c.Close(4000, "replaced by a newer connection")
			}
		},
		func(w http.ResponseWriter, r *http.Request) { // accepted, then dropped: resets auth, normal failure
			helloThen(w, r, func(c *websocket.Conn) { _ = c.Close(websocket.StatusGoingAway, "bye") })
		},
		func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) }, // auth restarts at 60 s
	}
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n <= len(script) {
			script[n-1](w, r)
			return
		}
		http.Error(w, "no", 401)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sl := &sleeper{max: len(script), cancel: cancel}
	a := testAgent(t, eng.srv.URL, timing{Rand: func() float64 { return 0 }, Sleep: sl.sleep})
	waitDone(t, runLoop(t, a, ctx))
	want := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 30 * time.Second, 500 * time.Millisecond, 30 * time.Second}
	got := sl.got()
	if len(got) != len(want) {
		t.Fatalf("delays %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delay %d = %s, want %s (all: %v)", i, got[i], want[i], got)
		}
	}
}

// A silent engine (accepts, then never reads, so it never answers pings) is detected by the agent within about
// pingEvery+pingTimeout, and the agent reconnects through the normal path.
func TestDeadLinkDetectedAndReconnects(t *testing.T) {
	var firstAt, secondAt atomic.Int64
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		switch n {
		case 1:
			firstAt.Store(time.Now().UnixNano())
			helloThen(w, r, func(c *websocket.Conn) { <-r.Context().Done() }) // silent: no reads, no pongs
		default:
			if n == 2 {
				secondAt.Store(time.Now().UnixNano())
			}
			helloThen(w, r, func(c *websocket.Conn) { readUntilClosed(r, c) })
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &sleeper{max: 1 << 30, cancel: cancel}
	a := testAgent(t, eng.srv.URL, timing{PingEvery: 100 * time.Millisecond, PingTimeout: 100 * time.Millisecond, Rand: func() float64 { return 0 }, Sleep: rec.sleep})
	done := runLoop(t, a, ctx)
	deadline := time.Now().Add(5 * time.Second)
	for secondAt.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if secondAt.Load() == 0 {
		t.Fatal("agent did not reconnect after the engine went silent")
	}
	took := time.Duration(secondAt.Load() - firstAt.Load())
	within(t, "time to detect and reconnect", took, 150*time.Millisecond, 1500*time.Millisecond) // ~ 100+100 ms plus dial
	if d := rec.got(); len(d) == 0 || d[0] != 500*time.Millisecond {
		t.Fatalf("dead link must use the normal schedule (1 s base, jitter 0.5..1 s): %v", d)
	}
	cancel()
	waitDone(t, done)
}

// A responsive engine is never dropped, however many pings pass.
func TestHealthyLinkKept(t *testing.T) {
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		helloThen(w, r, func(c *websocket.Conn) { readUntilClosed(r, c) })
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &sleeper{max: 1 << 30, cancel: cancel}
	a := testAgent(t, eng.srv.URL, timing{PingEvery: 30 * time.Millisecond, PingTimeout: 100 * time.Millisecond, Sleep: rec.sleep})
	done := runLoop(t, a, ctx)
	time.Sleep(1200 * time.Millisecond) // about 40 ping rounds
	if n := eng.conns.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1 (delays %v)", n, rec.got())
	}
	cancel()
	waitDone(t, done)
}

// A reader that is busy in a synchronous handler must not be mistaken for a dead link: the miss is inconclusive.
func TestBusyReaderIsNotDeadLink(t *testing.T) {
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		helloThen(w, r, func(c *websocket.Conn) {
			// A rotate_token whose handler fails fast is not busy; instead send frames continuously, which proves liveness
			// even though the server never reads (and so never pongs).
			for {
				if c.Write(r.Context(), websocket.MessageText, []byte(`{"t":"noop"}`)) != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &sleeper{max: 1 << 30, cancel: cancel}
	a := testAgent(t, eng.srv.URL, timing{PingEvery: 50 * time.Millisecond, PingTimeout: 50 * time.Millisecond, Sleep: rec.sleep})
	done := runLoop(t, a, ctx)
	time.Sleep(800 * time.Millisecond)
	if n := eng.conns.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1 (inbound frames prove the link is alive)", n)
	}
	cancel()
	waitDone(t, done)
}
