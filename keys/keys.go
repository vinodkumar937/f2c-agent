// Package keys is the single source of the trusted release public keys: keys/release-keys.json, embedded in the agent.
// install.sh gets a generated copy (InstallBlock, checked by a test and by release.sh) and the engine reads the same file
// through a signed release. Only public keys belong here; the private keys never enter this repository.
package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

//go:embed release-keys.json
var embedded []byte

// Key statuses. active: verifies, and release.sh may sign with it. retired: verifies, never signs a new release.
// revoked: never verifies; kept in the file so the id cannot come back.
const (
	StatusActive  = "active"
	StatusRetired = "retired"
	StatusRevoked = "revoked"
)

// spkiPrefix is the DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32 raw key bytes follow.
var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// Key is one entry of release-keys.json.
type Key struct {
	ID     string `json:"id"`
	Alg    string `json:"alg"`
	Pub    string `json:"pub"` // base64 of the raw 32-byte public key
	Status string `json:"status"`
	Added  string `json:"added,omitempty"`
	Note   string `json:"note,omitempty"`

	Raw ed25519.PublicKey `json:"-"`
}

// File is the parsed release-keys.json.
type File struct {
	V      int   `json:"v"`
	Serial int   `json:"serial"`
	Keys   []Key `json:"keys"`
}

// KeyID is the first 8 bytes of sha256(raw public key) as 16 lower-case hex characters. It is only a selector: a verifier
// always checks the signature, and an id never grants trust.
func KeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Parse validates a keys file: version 1, a positive serial, unique correct ids, known statuses, 32-byte keys, and at least
// one active key.
func Parse(b []byte) (*File, error) {
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("release keys: %w", err)
	}
	if f.V != 1 {
		return nil, fmt.Errorf("release keys: unsupported version %d", f.V)
	}
	if f.Serial < 1 {
		return nil, errors.New("release keys: serial must be 1 or more")
	}
	seen := map[string]bool{}
	active := 0
	for i := range f.Keys {
		k := &f.Keys[i]
		if k.Alg != "ed25519" {
			return nil, fmt.Errorf("release keys: key %d: alg must be ed25519", i)
		}
		raw, err := base64.StdEncoding.DecodeString(k.Pub)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release keys: key %d: pub must be a base64 raw %d-byte key", i, ed25519.PublicKeySize)
		}
		if want := KeyID(raw); k.ID != want {
			return nil, fmt.Errorf("release keys: key %d: id %q does not match its public key (want %s)", i, k.ID, want)
		}
		if seen[k.ID] {
			return nil, fmt.Errorf("release keys: duplicate id %s", k.ID)
		}
		seen[k.ID] = true
		switch k.Status {
		case StatusActive:
			active++
		case StatusRetired, StatusRevoked:
		default:
			return nil, fmt.Errorf("release keys: key %s: unknown status %q", k.ID, k.Status)
		}
		k.Raw = ed25519.PublicKey(raw)
	}
	if active == 0 {
		return nil, errors.New("release keys: no active key")
	}
	return &f, nil
}

// Release returns the embedded keys file.
func Release() (*File, error) { return Parse(embedded) }

// Embedded returns the raw bytes of the embedded file (a release ships the same bytes as release-keys.json).
func Embedded() []byte { return append([]byte(nil), embedded...) }

// Trusted lists the keys that may verify a signature: active and retired, never revoked.
func (f *File) Trusted() []Key {
	var out []Key
	for _, k := range f.Keys {
		if k.Status != StatusRevoked {
			out = append(out, k)
		}
	}
	return out
}

// ByID finds a key of any status.
func (f *File) ByID(id string) (Key, bool) {
	for _, k := range f.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

// SPKIBase64 is the base64 of the DER SubjectPublicKeyInfo of key k (the body of a PEM "PUBLIC KEY" block).
func SPKIBase64(k Key) string {
	return base64.StdEncoding.EncodeToString(append(append([]byte(nil), spkiPrefix...), k.Raw...))
}

// Markers of the generated block in deploy/install.sh.
const (
	BlockBegin = "# BEGIN F2C_RELEASE_KEYS"
	BlockEnd   = "# END F2C_RELEASE_KEYS"
)

// InstallBlock renders the block that install.sh carries: serial plus one "<id> <status> <SPKI base64>" line per key.
func InstallBlock(f *File) string {
	var b strings.Builder
	b.WriteString(BlockBegin + " (generated from keys/release-keys.json by `go run ./cmd/ed25519tool sync-install`; do not edit)\n")
	fmt.Fprintf(&b, "F2C_RELEASE_KEYS_SERIAL=%d\n", f.Serial)
	b.WriteString("F2C_RELEASE_KEYS=\"")
	for i, k := range f.Keys {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s %s %s", k.ID, k.Status, SPKIBase64(k))
	}
	b.WriteString("\"\n")
	b.WriteString(BlockEnd + "\n")
	return b.String()
}

// SplitBlock cuts the generated block out of an install.sh text: it returns the text before the begin marker, the block
// (markers included, ending in a newline) and the text after the end marker.
func SplitBlock(script string) (before, block, after string, err error) {
	i := strings.Index(script, BlockBegin)
	j := strings.Index(script, BlockEnd)
	if i < 0 || j < i {
		return "", "", "", errors.New("install.sh has no " + BlockBegin + " ... " + BlockEnd + " block")
	}
	j += len(BlockEnd)
	if j < len(script) && script[j] == '\n' {
		j++
	}
	return script[:i], script[i:j], script[j:], nil
}
