package agent

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestSessionShutdownSendsNormalClosure: cancelling the run ctx makes the agent
// send 1000 "agent stopping"; the engine sees it within about 2 s.
func TestSessionShutdownSendsNormalClosure(t *testing.T) {
	got := make(chan error, 1)
	ready := make(chan struct{})
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		helloThen(w, r, func(c *websocket.Conn) {
			// Read must run concurrently: Ping waits for a pong (proof the
			// agent is in its read loop), and the same Read observes the close.
			// Stay in fn until that Read returns so helloThen's deferred
			// CloseNow cannot cut the connection first.
			readDone := make(chan error, 1)
			go func() {
				_, _, err := c.Read(context.Background())
				readDone <- err
			}()
			pctx, pcancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := c.Ping(pctx)
			pcancel()
			if err != nil {
				t.Errorf("engine ping (wait for agent read loop): %v", err)
				return
			}
			close(ready)
			got <- <-readDone
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := testAgent(t, eng.srv.URL, timing{PingEvery: time.Hour, PingTimeout: time.Hour})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.session(ctx)
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not reach the read loop (engine ping)")
	}
	start := time.Now()
	cancel()
	select {
	case err := <-got:
		var ce websocket.CloseError
		if !errors.As(err, &ce) {
			t.Fatalf("engine read error = %v, want close 1000 %q", err, shutdownCloseReason)
		}
		if ce.Code != websocket.StatusNormalClosure || ce.Reason != shutdownCloseReason {
			t.Fatalf("close = status %d reason %q, want %d %q", ce.Code, ce.Reason, websocket.StatusNormalClosure, shutdownCloseReason)
		}
		if d := time.Since(start); d > shutdownCloseWait {
			t.Fatalf("engine received the close after %s, want within %s", d, shutdownCloseWait)
		}
	case <-time.After(shutdownCloseWait + 500*time.Millisecond):
		t.Fatal("engine did not receive 1000 \"agent stopping\"")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not return after the close handshake")
	}
}

// TestSessionShutdownCloseTimeout: if the engine never replies to the close,
// the agent falls back and session returns in under 3 s.
func TestSessionShutdownCloseTimeout(t *testing.T) {
	ready := make(chan struct{})
	eng := newFakeEngine(t, func(n int, w http.ResponseWriter, r *http.Request) {
		helloThen(w, r, func(c *websocket.Conn) {
			close(ready)
			// Never read, so the close frame is not answered.
			<-r.Context().Done()
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := testAgent(t, eng.srv.URL, timing{PingEvery: time.Hour, PingTimeout: time.Hour})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.session(ctx)
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not connect")
	}
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case <-done:
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("session returned after %s, want under 3s", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session did not return within 3s when the engine sent no close reply")
	}
}
