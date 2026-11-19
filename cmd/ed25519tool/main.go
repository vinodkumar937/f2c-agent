// ed25519tool signs or verifies a file with an ed25519 key.
//
//	go run ./cmd/ed25519tool sign <private.pem> <file> <sig.out>
//	go run ./cmd/ed25519tool verify-pem <public.pem> <file> <sig>
//	go run ./cmd/ed25519tool verify-b64 <pub.b64> <file> <sig>
//
// Release helpers (release.go): sync-install, check-install, lint-sums, sign-release, keyid, print-keys.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) >= 2 && releaseCommand(os.Args[1], os.Args[2:]) {
		return
	}
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: ed25519tool sign|verify-pem|verify-b64 <key> <file> <sig>")
		os.Exit(2)
	}
	cmd, keyPath, filePath, sigPath := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	msg, err := os.ReadFile(filePath)
	if err != nil {
		fail(err)
	}
	switch cmd {
	case "sign":
		priv := loadPriv(keyPath)
		sig := ed25519.Sign(priv, msg)
		if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
			fail(err)
		}
	case "verify-pem":
		pub := loadPubPEM(keyPath)
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			fail(err)
		}
		if !ed25519.Verify(pub, msg, sig) {
			fail(fmt.Errorf("signature mismatch"))
		}
	case "verify-b64":
		raw, err := base64.StdEncoding.DecodeString(keyPath)
		if err != nil {
			b, err2 := os.ReadFile(keyPath)
			if err2 != nil {
				fail(err)
			}
			raw, err = base64.StdEncoding.DecodeString(string(trimSpace(b)))
			if err != nil {
				fail(err)
			}
		}
		if len(raw) != ed25519.PublicKeySize {
			fail(fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize))
		}
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			fail(err)
		}
		if !ed25519.Verify(ed25519.PublicKey(raw), msg, sig) {
			fail(fmt.Errorf("signature mismatch"))
		}
	default:
		fail(fmt.Errorf("unknown command %s", cmd))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ed25519tool:", err)
	os.Exit(1)
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

func loadPriv(path string) ed25519.PrivateKey {
	b, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		fail(fmt.Errorf("no PEM block in %s", path))
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fail(err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		fail(fmt.Errorf("not an ed25519 private key"))
	}
	return priv
}

func loadPubPEM(path string) ed25519.PublicKey {
	b, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		fail(fmt.Errorf("no PEM block in %s", path))
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fail(err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		fail(fmt.Errorf("not an ed25519 public key"))
	}
	return pub
}
