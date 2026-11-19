package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func b64pub(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// The embedded list holds the two current release keys (primary and backup), and a real signed SHA256SUMS from an existing release verifies
// under it (testdata holds only public release artifacts: the sums file and its signature).
func TestEmbeddedKeyVerifiesExistingRelease(t *testing.T) {
	keys, err := releasePublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want exactly the two current keys in the list, got %d", len(keys))
	}
	sums, err := os.ReadFile(filepath.Join("testdata", "release-0.2.1", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join("testdata", "release-0.2.1", "SHA256SUMS.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if !verifyAnyKey(keys, sums, sig) {
		t.Fatal("current release key does not verify the existing release signature")
	}
	tampered := append([]byte("x"), sums...)
	if verifyAnyKey(keys, tampered, sig) {
		t.Fatal("a tampered SHA256SUMS must not verify")
	}
}

func TestVerifyAnyKey(t *testing.T) {
	pubA, privA := newKey(t)
	pubB, privB := newKey(t)
	pubC, _ := newKey(t)
	msg := []byte("abc  f2c-agent-linux-amd64\n")
	sigA := ed25519.Sign(privA, msg)
	sigB := ed25519.Sign(privB, msg)

	if !verifyAnyKey([]ed25519.PublicKey{pubA}, msg, sigA) {
		t.Error("single key: own signature must verify")
	}
	if verifyAnyKey([]ed25519.PublicKey{pubC}, msg, sigA) {
		t.Error("unknown key must not verify")
	}
	if verifyAnyKey(nil, msg, sigA) {
		t.Error("empty key list must not verify")
	}
	both := []ed25519.PublicKey{pubA, pubB}
	if !verifyAnyKey(both, msg, sigA) || !verifyAnyKey(both, msg, sigB) {
		t.Error("a multi-key list must accept a signature from either key")
	}
	if verifyAnyKey(both, []byte("other"), sigA) {
		t.Error("a signature over different bytes must not verify")
	}
}

func TestParseReleaseKeys(t *testing.T) {
	pub, _ := newKey(t)
	if _, err := parseReleaseKeys(nil); err == nil {
		t.Error("empty list must fail")
	}
	if _, err := parseReleaseKeys([]string{b64pub(pub), "not base64!"}); err == nil {
		t.Error("malformed entry must fail")
	}
	if _, err := parseReleaseKeys([]string{base64.StdEncoding.EncodeToString([]byte("short"))}); err == nil {
		t.Error("wrong key length must fail")
	}
	got, err := parseReleaseKeys([]string{b64pub(pub)})
	if err != nil || len(got) != 1 || !pub.Equal(got[0]) {
		t.Errorf("valid key: %v %v", got, err)
	}
}

// End to end through verifySignedSHA256SUMS with throwaway keys: trusted key (first or second in the list) is accepted,
// an unknown signer and a bad signature are refused.
func TestVerifySignedSHA256SUMSKeyList(t *testing.T) {
	pubA, _ := newKey(t)
	pubB, privB := newKey(t)
	_, privX := newKey(t) // never trusted
	sums := []byte("0000000000000000000000000000000000000000000000000000000000000000  f2c-agent-linux-amd64\n")
	var sig []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			_, _ = w.Write(sums)
		case "/SHA256SUMS.sig":
			_, _ = w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	old := releasePublicKeysB64
	defer func() { releasePublicKeysB64 = old }()
	releasePublicKeysB64 = []string{b64pub(pubA), b64pub(pubB)}

	sig = ed25519.Sign(privB, sums) // second key in the list
	if m, err := verifySignedSHA256SUMS(context.Background(), srv.Client(), srv.URL); err != nil || len(m) != 1 {
		t.Fatalf("signature from a listed key must be accepted: %v %v", m, err)
	}
	sig = ed25519.Sign(privX, sums) // unknown signer
	if _, err := verifySignedSHA256SUMS(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("signature from an unknown key must be refused")
	}
	sig = sig[:10] // wrong length
	if _, err := verifySignedSHA256SUMS(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("a malformed signature must be refused")
	}
}

// The 0.3.0 release signs the install files into SHA256SUMS next to the binaries. The signature must verify under the
// embedded key list and parseSHA256SUMS (also used by 0.2.x agents) must accept the longer file.
func TestRelease030SumsVerifyAndParse(t *testing.T) {
	keys, err := releasePublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	sums, err := os.ReadFile(filepath.Join("testdata", "release-0.3.0", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join("testdata", "release-0.3.0", "SHA256SUMS.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if !verifyAnyKey(keys, sums, sig) {
		t.Fatal("0.3.0 SHA256SUMS signature does not verify under the embedded keys")
	}
	m, err := parseSHA256SUMS(string(sums))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"f2c-agent-linux-amd64", "f2c-agent-linux-arm64", "install.sh", "harden.sh", "f2c-agent.service", "f2c-harden.path", "f2c-harden.service", "f2c-caddy-dns-env.path", "f2c-caddy-dns-env.service", "caddy-resume.conf"} {
		if _, ok := m[want]; !ok { // parseSHA256SUMS maps filename -> sha256
			t.Errorf("SHA256SUMS does not list %s", want)
		}
	}
}
