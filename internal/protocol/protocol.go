// Package protocol holds the wire types shared by the agent's units: the engine-to-agent message (the "cmd" envelope
// and the other frames), the result message and the machine-readable result codes. The wire format is documented in
// docs/protocol.md; JSON field names here must not change.
package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"syscall"
	"time"
)

// Version is the highest protocol version this agent speaks. It is sent as the X-F2C-Protocol header on the WebSocket
// dial. Version 0 means "no negotiation" (an engine whose hello_ok has no valid protocol field).
const Version = 1

// ProtocolHeader is the dial header that carries Version.
const ProtocolHeader = "X-F2C-Protocol"

// Engine capability strings the agent knows about (hello_ok.caps). Unknown strings are kept but have no meaning.
const (
	CapNotAfter      = "notAfter"
	CapHardenSummary = "hardenSummary"
	CapResultCode    = "resultCode"
)

// Result codes: the optional "code" field of a result message (docs/protocol.md, "Result codes").
//
// Two vocabularies. Protocol 0 sessions (an engine that sent no hello_ok.protocol) get exactly the codes the agent has
// always sent: LegacyCodes below, and no code on any other failure. Sessions at protocol >= 1 get the vocabulary in
// V1Codes, and every ok:false result carries one of them (ResultMessageFor).
const (
	// Sent at every protocol.
	CodeExpired               = "expired"
	CodeHardenNotInstalled    = "harden_not_installed"
	CodeHardenBadRequest      = "harden_bad_request"
	CodeHardenStateUnreadable = "harden_state_unreadable"
	CodeHardenScriptFailed    = "harden_script_failed"
	CodeHardenInterrupted     = "harden_interrupted"
	CodeHardenTimeout         = "harden_timeout"
	// CodeUnknownCommand is what protocol 0 sessions get for an unknown command type; protocol >= 1 gets CodeUnknownCmd.
	CodeUnknownCommand = "unknown_command"

	// Protocol >= 1 only.
	CodeUnknownCmd       = "unknown_cmd"
	CodeBadRequest       = "bad_request"
	CodeNotFound         = "not_found"
	CodeNotAllowed       = "not_allowed"
	CodeConflict         = "conflict"
	CodePortInUse        = "port_in_use"
	CodeImageNotFound    = "image_not_found"
	CodeImagePullFailed  = "image_pull_failed"
	CodeTimeout          = "timeout"
	CodeCancelled        = "cancelled"
	CodeInterrupted      = "interrupted"
	CodeDockerUnavail    = "docker_unavailable"
	CodeNoSpace          = "no_space"
	CodeBuildFailed      = "build_failed"
	CodeTransferFailed   = "transfer_failed"
	CodeIntegrityFailed  = "integrity_failed"
	CodeCaddyUnavailable = "caddy_unavailable"
	CodeCaddyRejected    = "caddy_rejected"
	CodeHardenFailed     = "harden_failed"
	CodeInternal         = "internal"

	// Kept codes the engine already knows as text prefixes of the error ("dockerfile_not_found: ..."). They were never in
	// result.code before; protocol >= 1 adds them there too. They are not part of the 27 core codes.
	CodeDockerfileNotFound       = "dockerfile_not_found"
	CodeDockerfileInvalidPath    = "dockerfile_invalid_path"
	CodeDockerfileInvalidTarget  = "dockerfile_invalid_target"
	CodeDockerfileTargetNotFound = "dockerfile_target_not_found"
	CodeBuildArchMismatch        = "build_arch_mismatch"
)

// LegacyCodes are the codes sent at every protocol, exactly as before protocol >= 1 existed.
var LegacyCodes = map[string]bool{
	CodeUnknownCommand: true, CodeExpired: true, CodeHardenNotInstalled: true, CodeHardenBadRequest: true,
	CodeHardenStateUnreadable: true, CodeHardenScriptFailed: true, CodeHardenInterrupted: true, CodeHardenTimeout: true,
}

// V1Codes are the 27 core codes of protocol >= 1, in the order of docs/protocol.md section 5.1.
var V1Codes = []string{
	CodeBadRequest, CodeUnknownCmd, CodeExpired, CodeNotFound, CodeNotAllowed, CodeConflict, CodePortInUse,
	CodeImageNotFound, CodeImagePullFailed, CodeTimeout, CodeCancelled, CodeInterrupted, CodeDockerUnavail, CodeNoSpace,
	CodeBuildFailed, CodeTransferFailed, CodeIntegrityFailed, CodeCaddyUnavailable, CodeCaddyRejected,
	CodeHardenNotInstalled, CodeHardenFailed, CodeHardenBadRequest, CodeHardenStateUnreadable, CodeHardenScriptFailed,
	CodeHardenInterrupted, CodeHardenTimeout, CodeInternal,
}

// KeptV1Codes are the five prefix codes added to result.code at protocol >= 1 (outside the 27).
var KeptV1Codes = []string{CodeDockerfileNotFound, CodeDockerfileInvalidPath, CodeDockerfileInvalidTarget, CodeDockerfileTargetNotFound, CodeBuildArchMismatch}

// Message is one frame from the engine (a "cmd" envelope or any other engine-to-agent frame). Only the fields a frame
// type uses are set.
type Message struct {
	// Console relay (console.go): container + shell command on console_open, base64 input on console_in, size on
	// console_open/console_resize. Input and output are never logged.
	Container string   `json:"container"`
	Cmd       []string `json:"cmd"`
	// f2c console helper (console_open, consoleHelperV): tar for /tmp, its session dir, F2C_* env, and the plain
	// shell to use when the put fails (read-only /tmp).
	Env         []string       `json:"env"`
	HelperTar   string         `json:"helperTar"`
	HelperDir   string         `json:"helperDir"`
	FallbackCmd []string       `json:"fallbackCmd"`
	D           string         `json:"d"`
	Cols        int            `json:"cols"`
	Rows        int            `json:"rows"`
	T           string         `json:"t"`
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Args        map[string]any `json:"args"`
	// NotAfter: optional absolute RFC 3339 deadline on "cmd" envelopes (protocol 2b). A command that arrives more than
	// NotAfterSkew past it is refused unrun (result ok:false, code "expired"); missing = no deadline.
	NotAfter string `json:"notAfter"`
	// Token: only on "rotate_token" (sent over the live connection, never queued or logged).
	Token string `json:"token"`
	// Provider/Domain/Token: only on "dns_token" (M2.9; live connection only, token never logged).
	Provider string `json:"provider"`
	Domain   string `json:"domain"`
	// Config: only on "registry_login" (step 9h docker config with 24 h read creds; never logged).
	Config json.RawMessage `json:"config"`
}

// NotAfterSkew is the clock skew allowed between engine and agent when checking a command's notAfter.
const NotAfterSkew = 60 * time.Second

// CommandExpired: true when now is more than notAfterSkew past notAfter (RFC 3339). "" = no deadline.
func CommandExpired(notAfter string, now time.Time) (bool, error) {
	if notAfter == "" {
		return false, nil
	}
	t, err := time.Parse(time.RFC3339Nano, notAfter)
	if err != nil {
		return false, err
	}
	return now.After(t.Add(NotAfterSkew)), nil
}

// codedError carries a machine-readable code for the result message's optional "code" field; the error text is
// unchanged, so callers that match on it keep working. Whether the code is sent depends on the session's protocol:
// see ResultMessageFor.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// WithCode attaches code to err, replacing any code deeper in the chain.
func WithCode(code string, err error) error { return &codedError{code: code, err: err} }

// DefaultCode attaches code to err unless something in its chain already carries one (the more specific cause wins).
// A nil err stays nil.
func DefaultCode(code string, err error) error {
	if err == nil || ResultCode(err) != "" {
		return err
	}
	// What the chain itself says about the cause beats the caller's general code.
	switch {
	case errors.Is(err, syscall.ENOSPC):
		code = CodeNoSpace
	case errors.Is(err, context.DeadlineExceeded):
		code = CodeTimeout
	case errors.Is(err, context.Canceled):
		code = CodeCancelled
	}
	return &codedError{code: code, err: err}
}

// BadRequest marks err as an argument validation failure (unless it already has a more specific code).
func BadRequest(err error) error { return DefaultCode(CodeBadRequest, err) }

// ResultCode: the code of the first codedError in err's chain, or "" (the code as attached, in either vocabulary).
func ResultCode(err error) string {
	var ce *codedError
	if errors.As(err, &ce) {
		return ce.code
	}
	return ""
}

// ResultMessage builds the result frame of a protocol 0 session: {"t":"result","id","ok"} plus "error" and, only for
// the legacy codes (LegacyCodes), "code"; or "data" on success. It is byte-for-byte what the agent always sent.
func ResultMessage(id string, data any, err error) map[string]any {
	return ResultMessageFor(id, data, err, 0)
}

// ResultMessageFor builds the result frame for a session at the given protocol (SessionProtocol). Below 1 it is the
// legacy frame. From 1 every ok:false carries a code (an unclassified failure gets V1Code's fallback) and unknown_command
// becomes unknown_cmd. The error text is the same at every protocol and "data" is never added to a failure.
func ResultMessageFor(id string, data any, err error, proto int) map[string]any {
	res := map[string]any{"t": "result", "id": id, "ok": err == nil}
	if err != nil {
		res["error"] = err.Error()
		if proto >= 1 {
			res["code"] = V1Code(err)
		} else if c := ResultCode(err); LegacyCodes[c] {
			res["code"] = c
		}
	} else if data != nil {
		res["data"] = data
	}
	return res
}

// V1Code is the protocol >= 1 code for a failure: the attached code (unknown_command renamed unknown_cmd), else a
// classification of what the standard library can tell (disk full, deadline, cancellation, missing executable), else
// internal.
func V1Code(err error) string {
	if c := ResultCode(err); c != "" {
		if c == CodeUnknownCommand {
			return CodeUnknownCmd
		}
		return c
	}
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ENOSPC):
		return CodeNoSpace
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return CodeTimeout
	case errors.Is(err, context.Canceled):
		return CodeCancelled
	case errors.Is(err, exec.ErrNotFound):
		return CodeDockerUnavail // the only external program every handler starts is docker
	}
	return CodeInternal
}

// Hello is the negotiation part of the engine's hello_ok frame. It is decoded on its own and tolerantly (ParseHello),
// not through Message, so a wrong-typed field can never make the agent drop hello_ok.
type Hello struct {
	// Protocol is the session version, 0 when the field is missing or invalid, never above Version.
	Protocol int
	// MinAgent is the engine's minimum agent semver, "" when missing or not a string.
	MinAgent string
	// ServerID is the engine's id for this server, "" when missing, empty or not a string (at most 128 bytes kept).
	ServerID string
	// Caps are the engine's feature strings (duplicates removed, order kept); empty when missing or not an array.
	Caps []string
}

const (
	maxHelloCaps   = 64
	maxHelloCapLen = 64
)

// ParseHello extracts the negotiation fields from a hello_ok frame. Anything missing or of the wrong type falls back to
// the zero value for that field; unknown fields are ignored. A value above Version is clamped to Version.
func ParseHello(data []byte) Hello {
	var raw struct {
		Protocol json.RawMessage `json:"protocol"`
		MinAgent json.RawMessage `json:"minAgent"`
		ServerID json.RawMessage `json:"serverId"`
		Caps     json.RawMessage `json:"caps"`
	}
	var h Hello
	if json.Unmarshal(data, &raw) != nil {
		return h
	}
	var n float64
	if json.Unmarshal(raw.Protocol, &n) == nil && n >= 1 && n == float64(int(n)) {
		h.Protocol = int(n)
		if h.Protocol > Version {
			h.Protocol = Version
		}
	}
	var min string
	if json.Unmarshal(raw.MinAgent, &min) == nil && len(min) <= 64 {
		h.MinAgent = min
	}
	var sid string
	if json.Unmarshal(raw.ServerID, &sid) == nil && len(sid) <= 128 {
		h.ServerID = sid
	}
	var caps []json.RawMessage
	if json.Unmarshal(raw.Caps, &caps) == nil {
		seen := map[string]bool{}
		for _, c := range caps {
			var s string
			if json.Unmarshal(c, &s) != nil || s == "" || len(s) > maxHelloCapLen || seen[s] {
				continue
			}
			seen[s] = true
			h.Caps = append(h.Caps, s)
			if len(h.Caps) == maxHelloCaps {
				break
			}
		}
	}
	return h
}
