package main

// Release helpers used by scripts/release.sh and the drift checks. None of them generates a key: sign-release only reads
// the private key file it is given, and refuses a key that keys/release-keys.json does not list as active.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vinodkumar937/f2c-agent/keys"
)

const defaultInstall = "deploy/install.sh"

var sumsLine = regexp.MustCompile(`^[0-9a-f]{64}  [A-Za-z0-9._-]+$`)

// releaseCommand runs a release helper; it reports false when cmd is not one.
func releaseCommand(cmd string, args []string) bool {
	switch cmd {
	case "sync-install", "check-install":
		path := defaultInstall
		if len(args) > 0 {
			path = args[0]
		}
		syncInstall(path, cmd == "check-install")
	case "lint-sums":
		if len(args) != 1 {
			fail(fmt.Errorf("usage: lint-sums <SHA256SUMS>"))
		}
		if err := lintSums(args[0]); err != nil {
			fail(err)
		}
	case "sign-release":
		if len(args) != 2 {
			fail(fmt.Errorf("usage: sign-release <private.pem> <SHA256SUMS>   (writes SHA256SUMS.sig and SHA256SUMS.sigs beside it)"))
		}
		signRelease(args[0], args[1])
	case "keyid":
		if len(args) != 1 {
			fail(fmt.Errorf("usage: keyid <public.pem>"))
		}
		fmt.Println(keys.KeyID(loadPubPEM(args[0])))
	case "print-keys":
		f := mustKeys()
		fmt.Printf("serial %d\n", f.Serial)
		for _, k := range f.Keys {
			fmt.Printf("%s  %s  %s\n", k.ID, k.Status, k.Pub)
		}
	default:
		return false
	}
	return true
}

func mustKeys() *keys.File {
	f, err := keys.Release()
	if err != nil {
		fail(err)
	}
	return f
}

// syncInstall rewrites (or, with check, only compares) the generated key block of install.sh.
func syncInstall(path string, check bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	before, block, after, err := keys.SplitBlock(string(b))
	if err != nil {
		fail(err)
	}
	want := keys.InstallBlock(mustKeys())
	if block == want {
		return
	}
	if check {
		fail(fmt.Errorf("%s: the F2C_RELEASE_KEYS block differs from keys/release-keys.json; run: go run ./cmd/ed25519tool sync-install", path))
	}
	if err := os.WriteFile(path, []byte(before+want+after), 0o755); err != nil {
		fail(err)
	}
	fmt.Println("ed25519tool: updated", path)
}

// lintSums enforces the SHA256SUMS shape the engine's parser needs: every line is a '#' comment or "<hex>  <name>".
func lintSums(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return fmt.Errorf("%s must end with a newline", path)
	}
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !sumsLine.MatchString(line) {
			return fmt.Errorf("%s line %d is neither a '#' comment nor '<sha256>  <name>': %q", path, i+1, line)
		}
		name := line[66:]
		if seen[name] {
			return fmt.Errorf("%s line %d: %s listed twice", path, i+1, name)
		}
		seen[name] = true
	}
	return nil
}

// signRelease signs sumsPath with the private key at keyPath and writes the legacy raw SHA256SUMS.sig and the key-id list
// SHA256SUMS.sigs next to it.
func signRelease(keyPath, sumsPath string) {
	if err := signReleaseWith(loadPriv(keyPath), mustKeys(), sumsPath); err != nil {
		fail(err)
	}
}

// signReleaseWith refuses a key that the list does not carry as active.
func signReleaseWith(priv ed25519.PrivateKey, list *keys.File, sumsPath string) error {
	pub := priv.Public().(ed25519.PublicKey)
	id := keys.KeyID(pub)
	k, ok := list.ByID(id)
	if !ok {
		return fmt.Errorf("signing key %s is not listed in keys/release-keys.json", id)
	}
	if k.Status != keys.StatusActive {
		return fmt.Errorf("signing key %s is %s, not active", id, k.Status)
	}
	msg, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("self-check of the signature failed")
	}
	dir := filepath.Dir(sumsPath)
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), sig, 0o644); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(map[string]any{
		"v":          1,
		"signatures": []map[string]string{{"keyId": id, "alg": "ed25519", "sig": base64.StdEncoding.EncodeToString(sig)}},
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sigs"), append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println("ed25519tool: signed with key", id)
	return nil
}
