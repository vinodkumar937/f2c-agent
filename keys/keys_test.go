package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedFile(t *testing.T) {
	f, err := Release()
	if err != nil {
		t.Fatal(err)
	}
	// Key 1 (every release up to 0.3.1 is signed with it): bytes unchanged, id is the first 8 bytes of sha256 as 16 hex.
	// Key 2 is the backup key. Both are active; the list serial is 2.
	if len(f.Keys) != 2 || f.Serial != 2 {
		t.Fatalf("want 2 keys at serial 2: %+v", f)
	}
	if f.Keys[0].Pub != "tsixg7qlWB4qdKyXQHQcCaGqcKXF+OCSspPutkGQ8Ts=" || f.Keys[0].ID != "d5be90e42c884807" || f.Keys[0].Status != StatusActive {
		t.Fatalf("%+v", f.Keys[0])
	}
	if f.Keys[1].Pub != "DtT/M0nfuu5IPKPm5nxabmlmtRZQ9QKJ3R8HeF+GWsI=" || f.Keys[1].ID != "3d4fe084d4acbab8" || f.Keys[1].Status != StatusActive {
		t.Fatalf("%+v", f.Keys[1])
	}
	for _, k := range f.Keys {
		if len(k.ID) != 16 {
			t.Fatal("key id must be 16 hex characters")
		}
	}
	if len(f.Trusted()) != 2 {
		t.Fatal("trusted")
	}
}

func mk(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, KeyID(pub)
}

func file(keys ...Key) []byte {
	b, _ := json.Marshal(File{V: 1, Serial: 2, Keys: keys})
	return b
}

func entry(pub ed25519.PublicKey, id, status string) Key {
	return Key{ID: id, Alg: "ed25519", Pub: base64.StdEncoding.EncodeToString(pub), Status: status}
}

func TestParseRules(t *testing.T) {
	a, ida := mk(t)
	b, idb := mk(t)
	f, err := Parse(file(entry(a, ida, "active"), entry(b, idb, "revoked")))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Trusted()) != 1 || f.Trusted()[0].ID != ida {
		t.Fatalf("a revoked key must not be trusted: %v", f.Trusted())
	}
	if k, ok := f.ByID(idb); !ok || k.Status != StatusRevoked {
		t.Fatal("a revoked key stays listed so its id cannot come back")
	}
	for name, raw := range map[string][]byte{
		"wrong id":      file(entry(a, "0000000000000000", "active")),
		"duplicate":     file(entry(a, ida, "active"), entry(a, ida, "retired")),
		"no active":     file(entry(a, ida, "retired")),
		"bad status":    file(entry(a, ida, "maybe")),
		"short key":     file(Key{ID: ida, Alg: "ed25519", Pub: "AAAA", Status: "active"}),
		"bad alg":       file(Key{ID: ida, Alg: "rsa", Pub: base64.StdEncoding.EncodeToString(a), Status: "active"}),
		"not json":      []byte("{"),
		"wrong version": []byte(`{"v":2,"serial":1,"keys":[]}`),
		"no serial":     []byte(`{"v":1,"serial":0,"keys":[]}`),
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// KeyID is stable: the first 8 bytes of sha256 of the raw key.
func TestKeyID(t *testing.T) {
	raw, _ := base64.StdEncoding.DecodeString("tsixg7qlWB4qdKyXQHQcCaGqcKXF+OCSspPutkGQ8Ts=")
	if KeyID(raw) != "d5be90e42c884807" {
		t.Fatal(KeyID(raw))
	}
}

// Drift check (#20): the block in deploy/install.sh is exactly what the keys file generates. release.sh runs the same check
// (`ed25519tool check-install`). Fix a failure with `go run ./cmd/ed25519tool sync-install`.
func TestInstallScriptBlockMatchesKeysFile(t *testing.T) {
	f, err := Release()
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join("..", "deploy", "install.sh"))
	if err != nil {
		t.Skip("deploy/install.sh not in this checkout")
	}
	_, block, _, err := SplitBlock(string(script))
	if err != nil {
		t.Fatal(err)
	}
	if want := InstallBlock(f); block != want {
		t.Fatalf("deploy/install.sh key block differs from keys/release-keys.json; run `go run ./cmd/ed25519tool sync-install`\nhave:\n%s\nwant:\n%s", block, want)
	}
	if strings.Count(string(script), BlockBegin) != 1 {
		t.Fatal("exactly one key block")
	}
}

func TestSPKI(t *testing.T) {
	f, _ := Release()
	if got := SPKIBase64(f.Keys[0]); got != "MCowBQYDK2VwAyEAtsixg7qlWB4qdKyXQHQcCaGqcKXF+OCSspPutkGQ8Ts=" {
		t.Fatal(got) // the PEM body install.sh carried before this change
	}
}
