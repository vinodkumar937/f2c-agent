package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Follow-ups 9.4 (result "code"), 9.6 (cmd "notAfter") and 9.3 (hb.harden summary).

func TestCommandExpired(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		notAfter string
		expired  bool
		bad      bool
	}{
		{"", false, false},
		{"2026-11-17T12:05:00Z", false, false},     // in the future
		{"2026-11-17T11:59:30Z", false, false},     // 30 s past: within the 60 s skew
		{"2026-11-17T11:59:00Z", false, false},     // exactly 60 s past: still allowed
		{"2026-11-17T11:58:59.5Z", true, false},    // more than 60 s past
		{"2026-11-17T17:20:00+05:30", true, false}, // offsets honoured (= 11:50Z)
		{"yesterday", false, true},
		{"2026-11-17 11:00:00", false, true},
	} {
		got, err := CommandExpired(c.notAfter, now)
		if got != c.expired || (err != nil) != c.bad {
			t.Errorf("%q: got %v, %v; want expired=%v bad=%v", c.notAfter, got, err, c.expired, c.bad)
		}
	}
}

func TestResultMessageCode(t *testing.T) {
	m := ResultMessage("c1", nil, WithCode("harden_timeout", errors.New("harden_timeout: no result")))
	if m["ok"] != false || m["code"] != "harden_timeout" || m["error"] != "harden_timeout: no result" || m["t"] != "result" || m["id"] != "c1" {
		t.Fatalf("coded: %v", m)
	}
	// wrapping keeps the code; the text is the wrapper's
	m = ResultMessage("c1", nil, errors.Join(errors.New("ctx"), WithCode(CodeHardenScriptFailed, errors.New("inner"))))
	if m["code"] != CodeHardenScriptFailed {
		t.Fatalf("wrapped: %v", m)
	}
	m = ResultMessage("c2", nil, errors.New("plain"))
	if _, ok := m["code"]; ok || m["error"] != "plain" {
		t.Fatalf("plain error must omit code: %v", m)
	}
	m = ResultMessage("c3", map[string]any{"x": 1}, nil)
	if _, ok := m["code"]; ok || m["ok"] != true || m["data"] == nil {
		t.Fatalf("success: %v", m)
	}
	b, _ := json.Marshal(ResultMessage("c4", nil, errors.New("plain")))
	if strings.Contains(string(b), `"code"`) {
		t.Fatalf("code must be omitted on the wire: %s", b)
	}
}

// Protocol 0 is byte for byte the old frame: only the eight legacy codes are sent, nothing else gets a code.
func TestResultMessageProtocol0OnlyLegacyCodes(t *testing.T) {
	for _, c := range append(append([]string{}, V1Codes...), KeptV1Codes...) {
		m := ResultMessageFor("c1", nil, WithCode(c, errors.New("text")), 0)
		_, has := m["code"]
		if has != LegacyCodes[c] {
			t.Errorf("protocol 0, code %s: code present = %v, want %v", c, has, LegacyCodes[c])
		}
		if m["error"] != "text" || m["ok"] != false || len(m) != map[bool]int{true: 5, false: 4}[has] {
			t.Errorf("protocol 0, code %s: frame %v", c, m)
		}
	}
	if len(LegacyCodes) != 8 {
		t.Fatalf("the legacy set must stay the eight codes the agent always sent: %v", LegacyCodes)
	}
	// unknown_command stays unknown_command at 0, becomes unknown_cmd at 1; never both
	m0 := ResultMessageFor("c", nil, WithCode(CodeUnknownCommand, errors.New("unknown command type \"x\"")), 0)
	m1 := ResultMessageFor("c", nil, WithCode(CodeUnknownCommand, errors.New("unknown command type \"x\"")), 1)
	if m0["code"] != "unknown_command" || m1["code"] != "unknown_cmd" || m0["error"] != m1["error"] {
		t.Fatalf("%v %v", m0, m1)
	}
}

// From protocol 1 every failure has a code from the list, the text is unchanged and success is unchanged.
func TestResultMessageProtocol1(t *testing.T) {
	known := map[string]bool{}
	for _, c := range append(append([]string{}, V1Codes...), KeptV1Codes...) {
		known[c] = true
	}
	if len(V1Codes) != 27 {
		t.Fatalf("the core list is 27 codes, got %d: %v", len(V1Codes), V1Codes)
	}
	seen := map[string]bool{}
	for _, c := range V1Codes {
		if seen[c] || !regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`).MatchString(c) {
			t.Errorf("bad or duplicate code %q", c)
		}
		seen[c] = true
	}
	for _, e := range []error{
		errors.New("plain"), fmt.Errorf("wrap: %w", syscall.ENOSPC), context.DeadlineExceeded, context.Canceled,
		fmt.Errorf("start: %w", exec.ErrNotFound), WithCode(CodeUnknownCommand, errors.New("u")), BadRequest(errors.New("b")),
		WithCode(CodeExpired, errors.New("e")),
	} {
		m := ResultMessageFor("c", nil, e, 1)
		c, _ := m["code"].(string)
		if !known[c] || m["error"] != e.Error() || m["ok"] != false {
			t.Errorf("%v: frame %v", e, m)
		}
		if _, hasData := m["data"]; hasData {
			t.Errorf("a failure must not carry data: %v", m)
		}
	}
	want := map[string]string{"plain": CodeInternal}
	if got := V1Code(errors.New("plain")); got != want["plain"] {
		t.Errorf("fallback %s", got)
	}
	for err, code := range map[error]string{syscall.ENOSPC: CodeNoSpace, context.DeadlineExceeded: CodeTimeout, context.Canceled: CodeCancelled, exec.ErrNotFound: CodeDockerUnavail} {
		if got := V1Code(fmt.Errorf("x: %w", err)); got != code {
			t.Errorf("%v -> %s, want %s", err, got, code)
		}
	}
	if m := ResultMessageFor("c", map[string]any{"a": 1}, nil, 1); m["ok"] != true || m["data"] == nil || len(m) != 4 {
		t.Fatalf("success frame changed: %v", m)
	}
}

func TestDefaultCode(t *testing.T) {
	if DefaultCode(CodeBadRequest, nil) != nil {
		t.Fatal("nil stays nil")
	}
	inner := WithCode(CodeNotFound, errors.New("gone"))
	if got := ResultCode(DefaultCode(CodeBadRequest, fmt.Errorf("wrap: %w", inner))); got != CodeNotFound {
		t.Fatalf("a more specific code must win, got %s", got)
	}
	if got := ResultCode(DefaultCode(CodeTransferFailed, fmt.Errorf("download: %w", syscall.ENOSPC))); got != CodeNoSpace {
		t.Fatalf("a full disk beats the general code, got %s", got)
	}
	if got := ResultCode(DefaultCode(CodeTransferFailed, fmt.Errorf("download: %w", context.DeadlineExceeded))); got != CodeTimeout {
		t.Fatalf("a deadline beats the general code, got %s", got)
	}
	if got := ResultCode(DefaultCode(CodeBuildFailed, errors.New("boom"))); got != CodeBuildFailed {
		t.Fatalf("got %s", got)
	}
}
