package caddy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaddyCertHost(t *testing.T) {
	if g := caddyCertHost("*.ap-south-1.example.com"); g != "wildcard_.ap-south-1.example.com" {
		t.Fatalf("wildcard: %q", g)
	}
	if g := caddyCertHost("app.example.com."); g != "app.example.com" {
		t.Fatalf("host: %q", g)
	}
}

func TestCertEventsOnlyAfterSuccessfulSendSemantics(t *testing.T) {
	certState.Lock()
	certState.seen = map[string]time.Time{}
	certState.Unlock()

	now := time.Now().UTC()
	nb := now.Add(-time.Hour)
	na := now.Add(90 * 24 * time.Hour)
	found := map[string]certMeta{
		"wildcard_.ap-south-1.example.com": {notBefore: nb, notAfter: na},
	}
	ev := certEventsToSend(now, found)
	if len(ev) != 1 {
		t.Fatalf("expected 1 event, got %d", len(ev))
	}
	// Simulate failed send: do not mark seen; should still be pending.
	ev2 := certEventsToSend(now, found)
	if len(ev2) != 1 {
		t.Fatalf("expected retryable event before mark, got %d", len(ev2))
	}
	markCertSeen(ev[0]["host"].(string), ev[0]["issuedAt"].(string))
	ev3 := certEventsToSend(now, found)
	if len(ev3) != 0 {
		t.Fatalf("expected 0 after mark, got %d", len(ev3))
	}
}

func TestScanCertsSkipsLocalIssuer(t *testing.T) {
	dir := t.TempDir()
	leaf := mustTestCert(t, "*.example.com")
	acme := filepath.Join(dir, "acme-v02.api.letsencrypt.org-directory", "wildcard_.example.com")
	local := filepath.Join(dir, "local", "wildcard_.example.com")
	if err := os.MkdirAll(acme, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(acme, "wildcard_.example.com.crt"), leaf, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "wildcard_.example.com.crt"), leaf, 0o644); err != nil {
		t.Fatal(err)
	}
	got := scanCerts(dir)
	if _, ok := got["wildcard_.example.com"]; !ok {
		t.Fatalf("missing acme cert: %#v", got)
	}
	// local issuer must be ignored (internal CA)
	if len(got) != 1 {
		t.Fatalf("expected only acme host, got %#v", got)
	}
}

func mustTestCert(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestDnsProviderPlaceholder(t *testing.T) {
	d := dnsProviderPlaceholder("digitalocean")
	if d["auth_token"] != "{env.DO_AUTH_TOKEN}" || d["name"] != "digitalocean" {
		t.Fatalf("%#v", d)
	}
	c := dnsProviderPlaceholder("cloudflare")
	if c["api_token"] != "{env.CF_API_TOKEN}" || c["name"] != "cloudflare" {
		t.Fatalf("%#v", c)
	}
}
