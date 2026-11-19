package update

// Release format and update guard (docs/protocol.md section 8, protocol items #18 to #20): the signed header of SHA256SUMS,
// signature checking by key id (SHA256SUMS.sigs) with the legacy raw .sig as a fallback, the downgrade and floor decision,
// and the persisted floor.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/version"
	"github.com/vinodkumar937/f2c-agent/keys"
)

// GuardVersion is the value of hb.updateV: this agent understands self_update args version, rollback and reason, and keeps
// the signed floor. The engine sends those args only to agents that report it, at protocol >= 1.
const GuardVersion = 1

// The trusted keys come from keys/release-keys.json (embedded). They stay variables so that tests can swap them; the list
// holds active and retired keys only, and revokedKeyIDs only serves a clearer error message.
var (
	releaseKeyFile       = mustReleaseKeys()
	releasePublicKeysB64 = trustedB64(releaseKeyFile)
	revokedKeyIDs        = revokedIDs(releaseKeyFile)
)

func mustReleaseKeys() *keys.File {
	f, err := keys.Release()
	if err != nil {
		panic("embedded keys/release-keys.json is invalid: " + err.Error())
	}
	return f
}

func trustedB64(f *keys.File) []string {
	var out []string
	for _, k := range f.Trusted() {
		out = append(out, k.Pub)
	}
	return out
}

func revokedIDs(f *keys.File) map[string]bool {
	out := map[string]bool{}
	for _, k := range f.Keys {
		if k.Status == keys.StatusRevoked {
			out[k.ID] = true
		}
	}
	return out
}

// ---- signed header ------------------------------------------------------------------------------------------------

// releaseHeader holds the "# key value" lines at the top of SHA256SUMS. They are comments to every older verifier, and the
// signature covers them like the rest of the file.
type releaseHeader struct {
	Format     int
	Version    string
	Released   string
	CaddyTag   string
	KeysSerial int
	Floor      string
}

const maxReleaseFormat = 1

// parseHeader reads the header lines. Unknown keys and free comments are ignored; a known key twice, a bad number or a
// format major this agent does not know is an error.
func parseHeader(sums string) (releaseHeader, error) {
	var h releaseHeader
	seen := map[string]bool{}
	for _, line := range strings.Split(sums, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		key, val, _ := strings.Cut(strings.TrimSpace(line[2:]), " ")
		val = strings.TrimSpace(val)
		switch key {
		case "f2c-release", "version", "released", "caddy-tag", "keys-serial", "floor":
		default:
			continue
		}
		if seen[key] {
			return h, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("SHA256SUMS header has %q twice", key))
		}
		seen[key] = true
		switch key {
		case "f2c-release":
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 {
				return h, protocol.WithCode(protocol.CodeIntegrityFailed, errors.New("SHA256SUMS header: bad f2c-release value"))
			}
			if n > maxReleaseFormat {
				return h, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("SHA256SUMS release format %d is newer than this agent understands (%d); update the agent first", n, maxReleaseFormat))
			}
			h.Format = n
		case "version":
			h.Version = val
		case "released":
			h.Released = val
		case "caddy-tag":
			h.CaddyTag = val
		case "keys-serial":
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 {
				return h, protocol.WithCode(protocol.CodeIntegrityFailed, errors.New("SHA256SUMS header: bad keys-serial value"))
			}
			h.KeysSerial = n
		case "floor":
			h.Floor = val
		}
	}
	return h, nil
}

// ---- signatures ---------------------------------------------------------------------------------------------------

type sigsFile struct {
	V          int `json:"v"`
	Signatures []struct {
		KeyID string `json:"keyId"`
		Alg   string `json:"alg"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// verifySigs checks SHA256SUMS.sigs: each signature names its key by id, unknown and revoked ids are skipped, and one valid
// signature by a trusted key is enough. It returns the id that verified, or "" with the reasons.
func verifySigs(raw, sums []byte) (string, string) {
	var f sigsFile
	if err := json.Unmarshal(raw, &f); err != nil || f.V != 1 {
		return "", "SHA256SUMS.sigs is not a version 1 signature list"
	}
	pubs, err := releasePublicKeys()
	if err != nil {
		return "", err.Error()
	}
	byID := map[string]ed25519.PublicKey{}
	for _, p := range pubs {
		byID[keys.KeyID(p)] = p
	}
	var why []string
	for _, s := range f.Signatures {
		pub, ok := byID[s.KeyID]
		switch {
		case revokedKeyIDs[s.KeyID]:
			why = append(why, "signed by revoked key "+s.KeyID)
			continue
		case !ok:
			why = append(why, "signed by unknown key "+s.KeyID)
			continue
		case s.Alg != "ed25519":
			why = append(why, "key "+s.KeyID+": unsupported algorithm")
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			why = append(why, "key "+s.KeyID+": malformed signature")
			continue
		}
		if ed25519.Verify(pub, sums, sig) {
			return s.KeyID, ""
		}
		why = append(why, "key "+s.KeyID+": signature does not verify")
	}
	if len(why) == 0 {
		why = append(why, "SHA256SUMS.sigs lists no signature")
	}
	return "", strings.Join(why, "; ")
}

// fetchOptional is fetchBytes where a 404 is "not there" (found=false) rather than an error.
func fetchOptional(ctx context.Context, client *http.Client, url string, max int64) ([]byte, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	res, err := client.Do(req)
	if err != nil {
		return nil, false, protocol.DefaultCode(protocol.CodeTransferFailed, err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("GET %s: %s", url, res.Status))
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil {
		return nil, false, protocol.DefaultCode(protocol.CodeTransferFailed, err)
	}
	if int64(len(b)) > max {
		return nil, false, protocol.WithCode(protocol.CodeTransferFailed, errors.New("response too large"))
	}
	return b, true, nil
}

// signedRelease is a verified SHA256SUMS: its file hashes, its header, and which key signed it ("legacy" for the raw .sig).
type signedRelease struct {
	Files  map[string]string
	Header releaseHeader
	KeyID  string
}

// verifySignedRelease downloads SHA256SUMS and verifies its signature: SHA256SUMS.sigs by key id when the release has one,
// else (or if it yields nothing) the legacy raw 64-byte SHA256SUMS.sig under every trusted key.
func verifySignedRelease(ctx context.Context, client *http.Client, baseURL string) (*signedRelease, error) {
	if _, err := releasePublicKeys(); err != nil {
		return nil, err
	}
	sums, err := fetchBytes(ctx, client, baseURL+"/SHA256SUMS", 1<<20)
	if err != nil {
		return nil, protocol.DefaultCode(protocol.CodeTransferFailed, fmt.Errorf("SHA256SUMS: %w", err))
	}
	by, diag := "", ""
	sigsRaw, found, err := fetchOptional(ctx, client, baseURL+"/SHA256SUMS.sigs", 64<<10)
	if err != nil {
		return nil, protocol.DefaultCode(protocol.CodeTransferFailed, fmt.Errorf("SHA256SUMS.sigs: %w", err))
	}
	if found {
		by, diag = verifySigs(sigsRaw, sums)
	}
	if by == "" {
		sig, err := fetchBytes(ctx, client, baseURL+"/SHA256SUMS.sig", 4096)
		if err != nil {
			return nil, protocol.DefaultCode(protocol.CodeTransferFailed, fmt.Errorf("SHA256SUMS.sig: %w", err))
		}
		if len(sig) != ed25519.SignatureSize {
			return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("SHA256SUMS.sig: want %d bytes, got %d", ed25519.SignatureSize, len(sig)))
		}
		pubs, _ := releasePublicKeys()
		if !verifyAnyKey(pubs, sums, sig) {
			msg := "SHA256SUMS signature verification failed"
			if diag != "" {
				msg += " (" + diag + ")"
			}
			return nil, protocol.WithCode(protocol.CodeIntegrityFailed, errors.New(msg))
		}
		by = "legacy"
	}
	files, err := parseSHA256SUMS(string(sums))
	if err != nil {
		return nil, err
	}
	hdr, err := parseHeader(string(sums))
	if err != nil {
		return nil, err
	}
	return &signedRelease{Files: files, Header: hdr, KeyID: by}, nil
}

// ---- the downgrade and floor decision ----------------------------------------------------------------------------

type decision string

const (
	decAllow      decision = "allow"
	decUpToDate   decision = "up_to_date"
	decNoRollback decision = "refuse_no_rollback"
	decIntegrity  decision = "refuse_integrity"
	decBelowFloor decision = "refuse_floor"
)

// maxReasonLen bounds the free-text reason that must accompany a rollback.
const maxReasonLen = 200

type guardInput struct {
	Cur          string // the running version
	Target       string // the signed version of the target release
	TargetSigned bool   // the release carries a signed version header
	SameSha      bool   // the target is the running binary
	Rollback     bool   // the engine asked for a rollback (protocol >= 1 only)
	Floor        string // the persisted signed floor, "" when none
}

// decide is the self_update guard. Order (the shared vectors docs/protocol/testdata/version-compare.json test it): the same
// binary is up to date; a target below the floor, or one with no signed version while a floor exists, is refused even with
// rollback; a higher precedence is allowed; at equal precedence a newer build is allowed and the same build with other bytes
// is an integrity failure; everything else (a downgrade, an older or unordered build, a missing or unparseable version)
// needs rollback and otherwise fails closed. The string says why.
func decide(in guardInput) (decision, string) {
	if in.SameSha {
		return decUpToDate, "the running binary"
	}
	cmp, ok := 0, false
	if in.TargetSigned {
		cmp, ok = version.Compare(in.Target, in.Cur)
	}
	if in.Floor != "" {
		if fc, fok := version.Compare(in.Target, in.Floor); !in.TargetSigned || !fok || fc < 0 {
			return decBelowFloor, fmt.Sprintf("the signed floor is %s", in.Floor)
		}
	}
	switch {
	case ok && cmp > 0:
		return decAllow, "newer version"
	case ok && cmp == 0:
		switch version.CompareBuild(in.Cur, in.Target) {
		case version.BuildNewer:
			return decAllow, "newer build of the same version"
		case version.BuildSame:
			return decIntegrity, "the same version and build with different bytes"
		}
	}
	why := "a downgrade"
	switch {
	case !in.TargetSigned:
		why = "the release has no signed version"
	case !ok:
		why = "a version that cannot be compared"
	case cmp == 0:
		why = "an older or unordered build of the same version"
	}
	if in.Rollback {
		return decAllow, "rollback requested: " + why
	}
	return decNoRollback, why
}

// ---- the persisted floor -----------------------------------------------------------------------------------------

// The floor is the lowest version this agent will be moved to, even with rollback. Only a signed "# floor" header raises it,
// and only after the update to that release is proven (the new binary connected to the engine). It never goes down.
type floorFile struct {
	Floor string    `json:"floor"`
	SetBy string    `json:"setBy,omitempty"`
	At    time.Time `json:"at"`
}

func floorPath(stateDir string) string { return filepath.Join(stateDir, "update-floor.json") }

func readFloor(stateDir string) string {
	b, err := os.ReadFile(floorPath(stateDir))
	if err != nil {
		return ""
	}
	var f floorFile
	if json.Unmarshal(b, &f) != nil {
		return ""
	}
	if _, ok := version.Compare(f.Floor, f.Floor); !ok {
		return ""
	}
	return f.Floor
}

// raiseFloor stores newFloor if it is a valid version above the current floor.
func raiseFloor(stateDir, newFloor, setBy string) {
	if newFloor == "" {
		return
	}
	if _, ok := version.Compare(newFloor, newFloor); !ok {
		return
	}
	if cur := readFloor(stateDir); cur != "" {
		if c, ok := version.Compare(newFloor, cur); ok && c <= 0 {
			return
		}
	}
	_ = os.MkdirAll(stateDir, 0o700)
	_ = writeJSONAtomic(floorPath(stateDir), floorFile{Floor: newFloor, SetBy: setBy, At: time.Now().UTC()})
}

// Floor reports the persisted floor ("" when none), for the log and tests.
func Floor(stateDir string) string { return readFloor(stateDir) }
