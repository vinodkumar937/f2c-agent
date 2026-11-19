package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/keys"
)

// All keys in these tests are generated in memory (never written to disk).

// The shared vectors (also run by the engine's TypeScript port) decide the guard.
func TestGuardSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../docs/protocol/testdata/version-compare.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name         string  `json:"name"`
			Cur          string  `json:"cur"`
			Target       string  `json:"target"`
			Rollback     bool    `json:"rollback"`
			Floor        *string `json:"floor"`
			SameSha      bool    `json:"sameSha"`
			TargetSigned bool    `json:"targetSigned"`
			Expect       struct {
				Decision string `json:"decision"`
			} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) != 28 {
		t.Fatalf("want the 28 agreed cases, have %d", len(f.Cases))
	}
	for _, c := range f.Cases {
		floor := ""
		if c.Floor != nil {
			floor = *c.Floor
		}
		got, why := decide(guardInput{Cur: c.Cur, Target: c.Target, TargetSigned: c.TargetSigned, SameSha: c.SameSha, Rollback: c.Rollback, Floor: floor})
		if string(got) != c.Expect.Decision {
			t.Errorf("%s: decision %s (%s), want %s", c.Name, got, why, c.Expect.Decision)
		}
	}
}

func TestParseHeader(t *testing.T) {
	h, err := parseHeader("# f2c-release 1\n# version 0.4.0+202611201000\n# released 2026-11-20T10:00:00Z\n# caddy-tag v2.8.4\n# keys-serial 2\n# floor 0.3.1\n# a free comment\nabc  file\n")
	if err != nil {
		t.Fatal(err)
	}
	if h.Format != 1 || h.Version != "0.4.0+202611201000" || h.CaddyTag != "v2.8.4" || h.KeysSerial != 2 || h.Floor != "0.3.1" || h.Released == "" {
		t.Fatalf("header: %+v", h)
	}
	if h, err := parseHeader("abc  file\n"); err != nil || h.Version != "" || h.Format != 0 {
		t.Fatalf("legacy sums have no header: %+v %v", h, err)
	}
	for name, in := range map[string]string{
		"duplicate":      "# version 1.0.0\n# version 1.0.1\n",
		"newer format":   "# f2c-release 2\n",
		"bad format":     "# f2c-release x\n",
		"bad key serial": "# keys-serial 0\n",
	} {
		if _, err := parseHeader(in); err == nil {
			t.Errorf("%s: want an error", name)
		} else if protocol.V1Code(err) != protocol.CodeIntegrityFailed {
			t.Errorf("%s: code %q", name, protocol.V1Code(err))
		}
	}
}

func TestFloorFile(t *testing.T) {
	dir := t.TempDir()
	if Floor(dir) != "" {
		t.Fatal("no floor yet")
	}
	raiseFloor(dir, "0.3.1", "0.4.0")
	raiseFloor(dir, "0.3.0", "x") // never lowers
	raiseFloor(dir, "garbage", "x")
	raiseFloor(dir, "", "x")
	if Floor(dir) != "0.3.1" {
		t.Fatalf("floor %q", Floor(dir))
	}
	raiseFloor(dir, "0.4.0", "0.4.1")
	if Floor(dir) != "0.4.0" {
		t.Fatalf("floor %q", Floor(dir))
	}
	if err := os.WriteFile(floorPath(dir), []byte("{not json"), 0o600); err != nil || Floor(dir) != "" {
		t.Fatal("an unreadable floor file counts as no floor")
	}
}

func sigsJSON(t *testing.T, sums []byte, entries ...[3]string) []byte {
	t.Helper()
	type e struct {
		KeyID string `json:"keyId"`
		Alg   string `json:"alg"`
		Sig   string `json:"sig"`
	}
	var list []e
	for _, x := range entries {
		list = append(list, e{x[0], x[1], x[2]})
	}
	b, _ := json.Marshal(map[string]any{"v": 1, "signatures": list})
	return b
}

func TestVerifySigsByKeyID(t *testing.T) {
	pubA, privA := newKey(t)
	pubB, privB := newKey(t)
	pubC, privC := newKey(t) // trusted by nobody
	old, oldRev := releasePublicKeysB64, revokedKeyIDs
	defer func() { releasePublicKeysB64, revokedKeyIDs = old, oldRev }()
	releasePublicKeysB64 = []string{b64pub(pubA), b64pub(pubB)}
	revokedKeyIDs = map[string]bool{keys.KeyID(pubC): true}
	sums := []byte("# version 1.0.0\n")
	sg := func(p ed25519.PrivateKey) string { return base64.StdEncoding.EncodeToString(ed25519.Sign(p, sums)) }
	idA, idB, idC := keys.KeyID(pubA), keys.KeyID(pubB), keys.KeyID(pubC)

	if id, why := verifySigs(sigsJSON(t, sums, [3]string{idB, "ed25519", sg(privB)}), sums); id != idB {
		t.Fatalf("B should verify: %q %s", id, why)
	}
	// the first entry is unknown, the second is good
	if id, _ := verifySigs(sigsJSON(t, sums, [3]string{"0000000000000000", "ed25519", sg(privA)}, [3]string{idA, "ed25519", sg(privA)}), sums); id != idA {
		t.Fatal("a later good signature must count")
	}
	// the id is only a selector: a good signature under the wrong id fails
	if id, _ := verifySigs(sigsJSON(t, sums, [3]string{idA, "ed25519", sg(privB)}), sums); id != "" {
		t.Fatal("the signature is always verified against the key the id names")
	}
	id, why := verifySigs(sigsJSON(t, sums, [3]string{idC, "ed25519", sg(privC)}), sums)
	if id != "" || !strings.Contains(why, "revoked") {
		t.Fatalf("revoked key: %q %s", id, why)
	}
	if id, why := verifySigs(sigsJSON(t, sums, [3]string{"ffffffffffffffff", "ed25519", sg(privA)}), sums); id != "" || !strings.Contains(why, "unknown") {
		t.Fatalf("unknown key: %q %s", id, why)
	}
	if id, _ := verifySigs(sigsJSON(t, sums, [3]string{idA, "rsa", sg(privA)}), sums); id != "" {
		t.Fatal("only ed25519")
	}
	if id, _ := verifySigs([]byte(`{"v":2,"signatures":[]}`), sums); id != "" {
		t.Fatal("unknown sigs version")
	}
	if id, _ := verifySigs([]byte("junk"), sums); id != "" {
		t.Fatal("junk")
	}
}

// release is a fake engine serving one signed release.
type release struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	sums     string
	sigs     bool // serve SHA256SUMS.sigs
	legacy   bool // serve the raw .sig
	signWith ed25519.PrivateKey
	bin      []byte
	want     string
	srv      *httptest.Server
}

func newRelease(t *testing.T, header string) *release {
	r := &release{sigs: true, legacy: true, bin: []byte("#!/bin/sh\necho new\n")}
	r.pub, r.priv = newKey(t)
	r.signWith = r.priv
	old := releasePublicKeysB64
	t.Cleanup(func() { releasePublicKeysB64 = old })
	releasePublicKeysB64 = []string{b64pub(r.pub)}
	s := sha256.Sum256(r.bin)
	r.want = hex.EncodeToString(s[:])
	r.sums = header + r.want + "  f2c-agent-linux-amd64\n"
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch q.URL.Path {
		case "/SHA256SUMS":
			_, _ = w.Write([]byte(r.sums))
		case "/SHA256SUMS.sigs":
			if !r.sigs {
				http.NotFound(w, q)
				return
			}
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(r.signWith, []byte(r.sums)))
			_, _ = w.Write(sigsJSON(t, nil, [3]string{keys.KeyID(r.pub), "ed25519", sig}))
		case "/SHA256SUMS.sig":
			if !r.legacy {
				http.NotFound(w, q)
				return
			}
			_, _ = w.Write(ed25519.Sign(r.signWith, []byte(r.sums)))
		case "/amd64.sha256":
			_, _ = w.Write([]byte(r.want + "\n"))
		case "/amd64":
			_, _ = w.Write(r.bin)
		default:
			http.NotFound(w, q)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *release) install(t *testing.T, cur, stateDir string, req updateRequest) (*updateInfo, error) {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "f2c-agent")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	smoke := func(string) (string, error) { return "", nil }
	if i := strings.Index(r.sums, "# version "); i >= 0 {
		v := strings.SplitN(r.sums[i+len("# version "):], "\n", 2)[0]
		smoke = func(string) (string, error) { return v + "\n", nil }
	}
	return installUpdate(context.Background(), r.srv.Client(), r.srv.URL+"/amd64", r.want, exe, smoke, cur, stateDir, req)
}

func TestVerifySignedReleaseSources(t *testing.T) {
	r := newRelease(t, "# f2c-release 1\n# version 0.4.0+202611201000\n")
	ctx := context.Background()
	got, err := verifySignedRelease(ctx, r.srv.Client(), r.srv.URL)
	if err != nil || got.KeyID != keys.KeyID(r.pub) || got.Header.Version != "0.4.0+202611201000" {
		t.Fatalf("sigs path: %+v %v", got, err)
	}
	r.sigs = false // a release with only the legacy raw signature
	got, err = verifySignedRelease(ctx, r.srv.Client(), r.srv.URL)
	if err != nil || got.KeyID != "legacy" {
		t.Fatalf("legacy path: %+v %v", got, err)
	}
	r.sigs, r.legacy = true, false // sigs only
	if got, err = verifySignedRelease(ctx, r.srv.Client(), r.srv.URL); err != nil || got.KeyID != keys.KeyID(r.pub) {
		t.Fatalf("a release with only .sigs verifies: %+v %v", got, err)
	}
	// untrusted signer in both files
	_, other := newKey(t)
	r.legacy, r.signWith = true, other
	_, err = verifySignedRelease(ctx, r.srv.Client(), r.srv.URL)
	if protocol.V1Code(err) != protocol.CodeIntegrityFailed {
		t.Fatalf("untrusted signer: %v", err)
	}
	// the sums bytes changed after signing (header tampered)
	r.signWith = r.priv
	r.sums = strings.Replace(r.sums, "0.4.0", "9.9.9", 1)
	r.sigs, r.legacy = true, true
	// re-sign happens on every request, so tamper by serving a stale signature instead
	stale := ed25519.Sign(r.priv, []byte("something else"))
	r.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch q.URL.Path {
		case "/SHA256SUMS":
			_, _ = w.Write([]byte(r.sums))
		case "/SHA256SUMS.sig":
			_, _ = w.Write(stale)
		default:
			http.NotFound(w, q)
		}
	})
	if _, err = verifySignedRelease(ctx, r.srv.Client(), r.srv.URL); protocol.V1Code(err) != protocol.CodeIntegrityFailed {
		t.Fatalf("tampered header: %v", err)
	}
}

func TestInstallUpdateGuard(t *testing.T) {
	const cur = "0.4.0+202611201000"
	dir := t.TempDir()
	hdr := func(v, floor string) string {
		h := "# f2c-release 1\n# version " + v + "\n"
		if floor != "" {
			h += "# floor " + floor + "\n"
		}
		return h
	}
	// a newer release goes through and reports its signed version and floor
	r := newRelease(t, hdr("0.5.0+202612010900", "0.4.0"))
	info, err := r.install(t, cur, dir, updateRequest{Version: "0.5.0+202612010900"})
	if err != nil || info.Version != "0.5.0+202612010900" || info.Floor != "0.4.0" {
		t.Fatalf("newer: %+v %v", info, err)
	}
	// the engine names another version than the signed one
	if _, err := r.install(t, cur, dir, updateRequest{Version: "0.5.1"}); protocol.V1Code(err) != protocol.CodeIntegrityFailed {
		t.Fatalf("version mismatch: %v", err)
	}
	// a downgrade is refused without rollback, allowed with it
	r = newRelease(t, hdr("0.3.1+202611190800", ""))
	if _, err := r.install(t, cur, dir, updateRequest{}); protocol.V1Code(err) != protocol.CodeNotAllowed {
		t.Fatalf("downgrade: %v", err)
	}
	if _, err := r.install(t, cur, dir, updateRequest{Rollback: true, Reason: "bad release"}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	// the same version and build with other bytes
	r = newRelease(t, hdr(cur, ""))
	if _, err := r.install(t, cur, dir, updateRequest{Rollback: true, Reason: "x"}); protocol.V1Code(err) != protocol.CodeIntegrityFailed {
		t.Fatalf("same build, other bytes: %v", err)
	}
	// an older build of the same version needs rollback
	r = newRelease(t, hdr("0.4.0+202611190000", ""))
	if _, err := r.install(t, cur, dir, updateRequest{}); protocol.V1Code(err) != protocol.CodeNotAllowed {
		t.Fatalf("older build: %v", err)
	}
	// a release without a signed version fails closed unless rollback
	r = newRelease(t, "")
	if _, err := r.install(t, cur, dir, updateRequest{}); protocol.V1Code(err) != protocol.CodeNotAllowed {
		t.Fatalf("headerless: %v", err)
	}
	if _, err := r.install(t, cur, dir, updateRequest{Rollback: true, Reason: "old agent line"}); err != nil {
		t.Fatalf("headerless rollback: %v", err)
	}
	// the floor holds even with rollback, and a headerless release is below any floor
	raiseFloor(dir, "0.4.0", "test")
	r = newRelease(t, hdr("0.3.1+202611190800", ""))
	if _, err := r.install(t, cur, dir, updateRequest{Rollback: true, Reason: "x"}); protocol.V1Code(err) != protocol.CodeNotAllowed {
		t.Fatalf("below floor: %v", err)
	}
	r = newRelease(t, "")
	if _, err := r.install(t, cur, dir, updateRequest{Rollback: true, Reason: "x"}); protocol.V1Code(err) != protocol.CodeNotAllowed {
		t.Fatalf("headerless below floor: %v", err)
	}
	// a floor above the release's own version is a broken release
	r = newRelease(t, hdr("0.5.0+202612010900", "0.6.0"))
	if _, err := r.install(t, cur, t.TempDir(), updateRequest{}); protocol.V1Code(err) != protocol.CodeIntegrityFailed {
		t.Fatalf("floor above version: %v", err)
	}
	// the new binary must report the signed version
	r = newRelease(t, hdr("0.5.0+202612010900", ""))
	exe := filepath.Join(t.TempDir(), "f2c-agent")
	_ = os.WriteFile(exe, []byte("old"), 0o755)
	_, err = installUpdate(context.Background(), r.srv.Client(), r.srv.URL+"/amd64", r.want, exe,
		func(string) (string, error) { return "0.5.0+202612010901\n", nil }, cur, t.TempDir(), updateRequest{})
	if protocol.V1Code(err) != protocol.CodeIntegrityFailed {
		t.Fatalf("smoke version mismatch: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("a refused update must leave the binary alone")
	}
}

func TestSelfUpdateArgsByProtocol(t *testing.T) {
	u := New(t.TempDir(), func() string { return "http://127.0.0.1:1" })
	good := strings.Repeat("a", 64)
	// protocol 0: the new args are ignored (a rollback without reason is not an error, it is not read)
	_, err := u.SelfUpdate(context.Background(), "c1", map[string]any{"sha256": good, "rollback": true})
	if protocol.V1Code(err) == protocol.CodeBadRequest {
		t.Fatalf("protocol 0 must not read rollback: %v", err)
	}
	u.SetProtocol(func() int { return 1 })
	_, err = u.SelfUpdate(context.Background(), "c1", map[string]any{"sha256": good, "rollback": true})
	wantCode(t, "rollback without reason", err, protocol.CodeBadRequest)
	_, err = u.SelfUpdate(context.Background(), "c1", map[string]any{"sha256": good, "rollback": true, "reason": strings.Repeat("x", 201)})
	wantCode(t, "reason too long", err, protocol.CodeBadRequest)
}
