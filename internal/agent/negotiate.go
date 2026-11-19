package agent

// Version negotiation (docs/protocol.md section 3): the agent sends X-F2C-Protocol on the dial, the engine's hello_ok may
// answer with protocol, minAgent and caps. Today these only feed the log and the accessors below; no behaviour is gated
// on them yet.

import (
	"log"
	"slices"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/version"
)

// negotiated is the immutable result of one session's hello_ok.
type negotiated struct {
	protocol int
	caps     []string
}

// negotiate records the negotiation fields of hello_ok (data is the raw frame). Once per session it logs a warning when this
// agent is older than the engine's minAgent, and one when hello_ok.serverId is present and differs from the configured
// server id. It never changes or closes the connection.
func (a *Agent) negotiate(data []byte) {
	h := protocol.ParseHello(data)
	first := a.neg.Load() == nil // the store below marks the session; a repeated hello_ok must not warn again
	a.neg.Store(&negotiated{protocol: h.Protocol, caps: h.Caps})
	if !first {
		return
	}
	a.checkServerID(h.ServerID)
	if h.MinAgent == "" {
		return
	}
	cmp, ok := version.Compare(a.ver, h.MinAgent)
	if !ok {
		// An unparseable minAgent (or agent version, as in a dev build) is ignored.
		return
	}
	if cmp < 0 {
		log.Printf("warning: this agent (%s) is older than the engine's minimum agent version %s; it keeps running, but update it soon (self-update is not triggered by this)", a.ver, h.MinAgent)
	}
}

// checkServerID warns (once per session, the caller guarantees that) when the engine names a different server than the one
// this agent is configured for. Ids are not secrets. The session stays open: the engine's answer is advisory.
func (a *Agent) checkServerID(got string) {
	if got == "" {
		return
	}
	var want string
	a.mu.Lock()
	if a.cfg != nil {
		want = a.cfg.ServerID
	}
	a.mu.Unlock()
	if want == "" || got == want {
		return
	}
	log.Printf("warning: the engine says this session is for server %q, but this agent is configured for server %q; keeping the session open. Check that agent.json and the token belong to the same server", got, want)
}

// SessionProtocol is the protocol version negotiated for the current session: hello_ok.protocol (at most
// protocol.Version), or 0 when there is no session yet or the engine sent no valid value (an engine without negotiation).
func (a *Agent) SessionProtocol() int {
	if n := a.neg.Load(); n != nil {
		return n.protocol
	}
	return 0
}

// EngineHas reports whether the engine announced the capability in hello_ok.caps for the current session.
func (a *Agent) EngineHas(capability string) bool {
	if n := a.neg.Load(); n != nil {
		return slices.Contains(n.caps, capability)
	}
	return false
}

// gateReplyCode drops the "code" key of the token_rotated, registry_login and dns_token_ok replies unless the session is
// at protocol >= 1, so a protocol 0 engine receives exactly the frames it always did. The handlers set the code
// unconditionally; this is the one place that gates it. Other frames and a nil or code-less reply pass through untouched.
func (a *Agent) gateReplyCode(v any) any {
	m, ok := v.(map[string]any)
	if !ok || a.SessionProtocol() >= 1 {
		return v
	}
	switch m["t"] {
	case "token_rotated", "registry_login", "dns_token_ok":
		if _, has := m["code"]; has {
			c := make(map[string]any, len(m))
			for k, val := range m {
				if k != "code" {
					c[k] = val
				}
			}
			return c
		}
	}
	return v
}
