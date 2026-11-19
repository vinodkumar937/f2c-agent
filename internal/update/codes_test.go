package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

func wantCode(t *testing.T, what string, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: want an error with code %s, got none", what, code)
	}
	if got := protocol.V1Code(err); got != code {
		t.Fatalf("%s: code %s, want %s (%v)", what, got, code, err)
	}
	if protocol.LegacyCodes[code] || protocol.ResultCode(err) != code {
		t.Fatalf("%s: code must be a protocol 1 code attached to the error: %q", what, protocol.ResultCode(err))
	}
	if m := protocol.ResultMessage("u", nil, err); m["code"] != nil {
		t.Fatalf("%s: protocol 0 frame must carry no code: %v", what, m)
	}
}

// installUpdate failures at protocol >= 1: the sources of transfer_failed, integrity_failed and conflict.
// The running and the new version used by the update tests (docs/protocol.md section 8.4).
const (
	testCur = "0.3.1+202611181227"
	testNew = "0.4.0+202611201000"
)

func TestSelfUpdateErrorCodes(t *testing.T) {
	pub, priv := newKey(t)
	old := releasePublicKeysB64
	defer func() { releasePublicKeysB64 = old }()
	releasePublicKeysB64 = []string{b64pub(pub)}

	bin := []byte("#!/bin/sh\necho new\n")
	sum := sha256.Sum256(bin)
	want := hex.EncodeToString(sum[:])
	var sums, sha256Body string
	var sig []byte
	var binBody []byte
	var sumsStatus int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			if sumsStatus != 0 {
				http.Error(w, "boom", sumsStatus)
				return
			}
			_, _ = w.Write([]byte(sums))
		case "/SHA256SUMS.sig":
			_, _ = w.Write(sig)
		case "/amd64.sha256":
			_, _ = w.Write([]byte(sha256Body))
		case "/amd64":
			_, _ = w.Write(binBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	reset := func() {
		sums = "# f2c-release 1\n# version " + testNew + "\n" + want + "  f2c-agent-linux-amd64\n"
		sig = ed25519.Sign(priv, []byte(sums))
		sha256Body = want + "\n"
		binBody = bin
		sumsStatus = 0
	}
	run := func(smoke func(string) (string, error)) error {
		exe := filepath.Join(t.TempDir(), "f2c-agent")
		if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := installUpdate(context.Background(), srv.Client(), srv.URL+"/amd64", want, exe, smoke, testCur, t.TempDir(), updateRequest{})
		return err
	}
	ok := func(string) (string, error) { return testNew + "\n", nil }

	reset()
	if err := run(ok); err != nil {
		t.Fatalf("control: %v", err)
	}
	reset()
	sumsStatus = 500
	wantCode(t, "SHA256SUMS 500", run(ok), protocol.CodeTransferFailed)
	reset()
	sig = ed25519.Sign(priv, []byte("something else"))
	wantCode(t, "bad signature", run(ok), protocol.CodeIntegrityFailed)
	reset()
	sums = "# version " + testNew + "\n0000000000000000000000000000000000000000000000000000000000000000  f2c-agent-linux-amd64\n"
	sig = ed25519.Sign(priv, []byte(sums))
	wantCode(t, "signed hash differs from the engine's ask", run(ok), protocol.CodeIntegrityFailed)
	reset()
	sha256Body = "1111111111111111111111111111111111111111111111111111111111111111\n"
	wantCode(t, "engine now serves another hash (decision 7)", run(ok), protocol.CodeConflict)
	reset()
	binBody = []byte("tampered")
	wantCode(t, "downloaded binary hash", run(ok), protocol.CodeIntegrityFailed)
	reset()
	wantCode(t, "smoke test", run(func(string) (string, error) { return "", errors.New("exit 1") }), protocol.CodeIntegrityFailed)
	reset()
	sha256Body = "nonsense"
	wantCode(t, "bad .sha256", run(ok), protocol.CodeTransferFailed)

	// unreachable engine
	exe := filepath.Join(t.TempDir(), "f2c-agent")
	_ = os.WriteFile(exe, []byte("old"), 0o755)
	_, err := installUpdate(context.Background(), &http.Client{}, "http://127.0.0.1:1/amd64", want, exe, ok, testCur, t.TempDir(), updateRequest{})
	wantCode(t, "engine unreachable", err, protocol.CodeTransferFailed)
}

func TestSelfUpdateRefusals(t *testing.T) {
	u := New(t.TempDir(), func() string { return "https://engine.example.com" })
	_, err := u.SelfUpdate(context.Background(), "c1", map[string]any{"sha256": "abc"})
	wantCode(t, "bad sha", err, protocol.CodeBadRequest)
	if err := writeJSONAtomic(markerPath(u.stateDir), updateMarker{ID: "c0"}); err != nil {
		t.Fatal(err)
	}
	_, err = u.SelfUpdate(context.Background(), "c1", map[string]any{"sha256": "00000000000000000000000000000000000000000000000000000000000000ff"})
	wantCode(t, "pending update", err, protocol.CodeConflict)
}
