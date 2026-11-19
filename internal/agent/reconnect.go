package agent

// Reconnect policy and dead-link detection tunables (docs/protocol.md section 7 and 2.6). Nothing here is on the wire:
// the engine sees only a normal dial, normal pings answered with pongs, and (rarely) a close frame from the agent.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/coder/websocket"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

const (
	// Normal failures (network down, engine restarting, idle close): 1 s doubling to 30 s.
	normalBackoffMin = time.Second
	normalBackoffMax = 30 * time.Second
	// A session at least this long resets the normal schedule.
	healthySession = time.Minute
	// Auth failures (HTTP 401/403 on dial, close 4003): slow, 60 s doubling to 10 min. The agent never gives up.
	authBackoffMin = time.Minute
	authBackoffMax = 10 * time.Minute
	// Close 4000 (another connection took over this token): uniform 30..90 s so two agents do not flap.
	replacedMin = 30 * time.Second
	replacedMax = 90 * time.Second

	// Dead-link detection: a WebSocket ping every pingEvery with a pingTimeout deadline, alongside the read loop.
	defaultPingEvery   = 20 * time.Second
	defaultPingTimeout = 10 * time.Second
	defaultDialTimeout = 20 * time.Second

	// Engine close codes (see docs/protocol.md).
	closeReplaced = 4000 // "replaced by a newer connection"
	closeIdle     = 4001 // "idle"
	closeRevoked  = 4003 // token rotated away or server removed
	closeProtocol = 4004 // "protocol_unsupported": the engine cannot speak any version this agent offers
)

// timing holds the knobs tests shrink. The zero value means the production defaults.
type timing struct {
	PingEvery   time.Duration
	PingTimeout time.Duration
	DialTimeout time.Duration
	// Rand returns a float in [0,1); default math/rand.Float64.
	Rand func() float64
	// Sleep waits d or until ctx ends (false when ctx ended). Default is a timer.
	Sleep func(ctx context.Context, d time.Duration) bool
}

func (t timing) pingEvery() time.Duration   { return orDefault(t.PingEvery, defaultPingEvery) }
func (t timing) pingTimeout() time.Duration { return orDefault(t.PingTimeout, defaultPingTimeout) }
func (t timing) dialTimeout() time.Duration { return orDefault(t.DialTimeout, defaultDialTimeout) }

func orDefault(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

func (t timing) rand() func() float64 {
	if t.Rand != nil {
		return t.Rand
	}
	return rand.Float64
}

func (t timing) sleep(ctx context.Context, d time.Duration) bool {
	if t.Sleep != nil {
		return t.Sleep(ctx, d)
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-tm.C:
		return true
	}
}

// failKind classifies why a session ended.
type failKind int

const (
	failNormal   failKind = iota // anything not listed below
	failAuth                     // HTTP 401/403 on dial, close 4003
	failReplaced                 // close 4000
	failProtocol                 // close 4004; uses the auth schedule
)

func (k failKind) String() string {
	switch k {
	case failAuth:
		return "auth"
	case failReplaced:
		return "replaced"
	case failProtocol:
		return "protocol"
	}
	return "normal"
}

// dialStatusError is a dial that the engine answered with an HTTP status instead of upgrading.
type dialStatusError struct {
	Status int
	Msg    string
}

func (e *dialStatusError) Error() string { return e.Msg }

// classify maps a session error to a failKind and a short reason without any secret in it.
func classify(err error) (failKind, string) {
	var ds *dialStatusError
	if errors.As(err, &ds) && (ds.Status == 401 || ds.Status == 403) {
		return failAuth, fmt.Sprintf("engine answered HTTP %d to the dial (server token rejected, revoked or rotated away)", ds.Status)
	}
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		switch int(ce.Code) {
		case closeRevoked:
			return failAuth, fmt.Sprintf("engine closed the connection with 4003 (%s): server revoked or token rotated away", ce.Reason)
		case closeProtocol:
			return failProtocol, fmt.Sprintf("engine closed the connection with 4004 (%s): the engine does not support this agent's protocol version %d", ce.Reason, protocol.Version)
		case closeReplaced:
			return failReplaced, "engine closed the connection with 4000: another connection is using this server token"
		}
	}
	return failNormal, ""
}

// reconnector holds the three schedules. It is used from the single dial loop goroutine only.
type reconnector struct {
	rnd    func() float64
	normal time.Duration // base for the next normal failure
	auth   time.Duration // base for the next auth failure
}

func newReconnector(rnd func() float64) *reconnector {
	return &reconnector{rnd: rnd, normal: normalBackoffMin, auth: authBackoffMin}
}

// jitter is "equal jitter": uniform in [d/2, d].
func (r *reconnector) jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(r.rnd()*float64(d/2))
}

func doubled(d, max time.Duration) time.Duration {
	if d *= 2; d > max {
		return max
	}
	return d
}

// accepted: the engine sent hello_ok, so the token works. The auth schedule restarts at 60 s.
func (r *reconnector) accepted() { r.auth = authBackoffMin }

// sessionEnded resets the normal schedule after a session that lasted longer than a minute.
func (r *reconnector) sessionEnded(lasted time.Duration) {
	if lasted > healthySession {
		r.normal = normalBackoffMin
	}
}

// delay returns how long to wait before the next dial and advances the schedule of that kind.
func (r *reconnector) delay(k failKind) time.Duration {
	switch k {
	case failAuth, failProtocol: // 4004 shares the slow auth schedule
		d := r.jitter(r.auth)
		r.auth = doubled(r.auth, authBackoffMax)
		return d
	case failReplaced:
		return replacedMin + time.Duration(r.rnd()*float64(replacedMax-replacedMin))
	}
	d := r.jitter(r.normal)
	r.normal = doubled(r.normal, normalBackoffMax)
	return d
}
