package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vinodkumar937/f2c-agent/keys"
)

// The test key lives only in this process: it is never written to disk.
func memKeys(t *testing.T, status string) (ed25519.PrivateKey, *keys.File) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// a second, active key keeps the file valid when the key under test is retired or revoked
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	keysDoc := map[string]any{"v": 1, "serial": 1, "keys": []map[string]string{
		{"id": keys.KeyID(pub), "alg": "ed25519", "pub": base64.StdEncoding.EncodeToString(pub), "status": status},
		{"id": keys.KeyID(pub2), "alg": "ed25519", "pub": base64.StdEncoding.EncodeToString(pub2), "status": "active"},
	}}
	b, _ := json.Marshal(keysDoc)
	f, err := keys.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return priv, f
}

func TestSignReleaseWith(t *testing.T) {
	dir := t.TempDir()
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte("# version 1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	priv, f := memKeys(t, "active")
	if err := signReleaseWith(priv, f, sums); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	msg, _ := os.ReadFile(sums)
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, raw) {
		t.Fatal("the raw .sig must verify")
	}
	var sigs struct {
		V          int `json:"v"`
		Signatures []struct{ KeyID, Alg, Sig string }
	}
	b, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sigs"))
	if err := json.Unmarshal(b, &sigs); err != nil || sigs.V != 1 || len(sigs.Signatures) != 1 || sigs.Signatures[0].KeyID != keys.KeyID(pub) || sigs.Signatures[0].Alg != "ed25519" {
		t.Fatalf("sigs: %s %v", b, err)
	}
	for _, status := range []string{"retired", "revoked"} {
		priv, f := memKeys(t, status)
		if err := signReleaseWith(priv, f, sums); err == nil || !strings.Contains(err.Error(), "not active") {
			t.Errorf("%s key must not sign: %v", status, err)
		}
	}
	// a key the file does not list
	other, _ := memKeys(t, "active")
	if err := signReleaseWith(other, f, sums); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Errorf("unlisted key: %v", err)
	}
}

func TestLintSums(t *testing.T) {
	h := strings.Repeat("a", 64)
	for name, c := range map[string]struct {
		in string
		ok bool
	}{
		"header and hashes": {"# f2c-release 1\n# version 1.0.0\n" + h + "  install.sh\n", true},
		"bare header":       {"version 1.0.0\n" + h + "  install.sh\n", false},
		"one space":         {h + " install.sh\n", false},
		"short hash":        {"abc  install.sh\n", false},
		"duplicate name":    {h + "  a\n" + h + "  a\n", false},
		"no final newline":  {h + "  a", false},
		"empty":             {"", false},
	} {
		p := filepath.Join(t.TempDir(), "SHA256SUMS")
		_ = os.WriteFile(p, []byte(c.in), 0o644)
		if err := lintSums(p); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
