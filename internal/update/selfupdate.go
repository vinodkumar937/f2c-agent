package update

// Self-update: the engine sends {type:"self_update", args:{sha256}}. The agent downloads
// <engine>/agent/bin/SHA256SUMS (+ .sig) and verifies the ed25519 signature with the embedded release public key,
// then downloads <engine>/agent/bin/<arch> (+ .sha256), checks the hash against both the signed SUMS and the
// expected sha256, smoke-tests the new binary (`version`), keeps the running one as <bin>.prev, renames the new
// one over <bin> atomically, writes a pending marker and exits; systemd (Restart=always) starts the new binary.
// At startup a marker means "prove you work": the new binary must be accepted by the engine within
// updateConnectWindow, else it restores <bin>.prev and exits (systemd starts the old one again). A crash loop is
// caught by the boot counter. The outcome is written to update-result.json and reported in every heartbeat
// ("update"), so the engine learns it after reconnecting.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/sysinfo"
	"github.com/vinodkumar937/f2c-agent/internal/util"
	"github.com/vinodkumar937/f2c-agent/internal/version"
)

const (
	updateConnectWindow = 60 * time.Second
	updateMaxBoots      = 3
	updateMaxBytes      = 256 << 20
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The trusted release public keys are keys/release-keys.json (release.go): raw 32-byte ed25519 keys. A SHA256SUMS signature is
// accepted if a trusted key verifies it (by key id, or any key for the legacy raw .sig), so a new key can be added and an old
// one retired or revoked without breaking agents released before the change. The list is compiled in on purpose: it is not
// read from disk or from the engine, so a compromised engine or state dir cannot swap the trust root.

// parseReleaseKeys decodes a list of base64 ed25519 public keys; it fails if the list is empty or any entry is malformed.
func parseReleaseKeys(list []string) ([]ed25519.PublicKey, error) {
	if len(list) == 0 {
		return nil, errors.New("release public keys: none configured")
	}
	keys := make([]ed25519.PublicKey, 0, len(list))
	for i, b64 := range list {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("release public key #%d: %w", i+1, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release public key #%d: want %d bytes, got %d", i+1, ed25519.PublicKeySize, len(raw))
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

func releasePublicKeys() ([]ed25519.PublicKey, error) { return parseReleaseKeys(releasePublicKeysB64) }

// verifyAnyKey reports whether sig is a valid ed25519 signature of msg under at least one of keys.
func verifyAnyKey(keys []ed25519.PublicKey, msg, sig []byte) bool {
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}

// parseSHA256SUMS returns lowercase hex digest -> filename for coreutils-style SUMS lines.
func parseSHA256SUMS(body string) (map[string]string, error) {
	out := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !hex64.MatchString(strings.ToLower(fields[0])) {
			return nil, protocol.WithCode(protocol.CodeIntegrityFailed, errors.New("bad SHA256SUMS line"))
		}
		name := strings.TrimPrefix(fields[1], "*")
		out[filepath.Base(name)] = strings.ToLower(fields[0])
	}
	if len(out) == 0 {
		return nil, protocol.WithCode(protocol.CodeIntegrityFailed, errors.New("SHA256SUMS is empty"))
	}
	return out, nil
}

func fetchBytes(ctx context.Context, client *http.Client, url string, max int64) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	res, err := client.Do(req)
	if err != nil {
		return nil, protocol.DefaultCode(protocol.CodeTransferFailed, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("GET %s: %s", url, res.Status))
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil {
		return nil, protocol.DefaultCode(protocol.CodeTransferFailed, err)
	}
	if int64(len(b)) > max {
		return nil, protocol.WithCode(protocol.CodeTransferFailed, errors.New("response too large"))
	}
	return b, nil
}

// Updater holds what self-update needs from the agent: the state dir and the current engine URL.
type Updater struct {
	stateDir string
	engine   func() string
	proto    func() int // the session protocol; the guard arguments are honoured from protocol 1 (nil: 0)
}

// SetProtocol gives the updater the session protocol. self_update's version, rollback and reason arguments are only read at
// protocol >= 1; below that the engine cannot ask for a rollback.
func (a *Updater) SetProtocol(f func() int) { a.proto = f }

func (a *Updater) protocol() int {
	if a.proto == nil {
		return 0
	}
	return a.proto()
}

type updateMarker struct {
	ID      string    `json:"id"`
	OldHash string    `json:"oldHash"`
	NewHash string    `json:"newHash"`
	Exe     string    `json:"exe"`
	Boots   int       `json:"boots"`
	At      time.Time `json:"at"`
	// Added with the update guard (release.go); empty for an update started by an older agent.
	FromVersion string `json:"fromVersion,omitempty"`
	ToVersion   string `json:"toVersion,omitempty"`
	Floor       string `json:"floor,omitempty"` // the signed "# floor" of the new release, raised once the update is proven
	Rollback    bool   `json:"rollback,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type updateResult struct {
	ID      string    `json:"id"`
	Status  string    `json:"status"` // succeeded | rolled_back | failed
	Message string    `json:"message,omitempty"`
	From    string    `json:"from,omitempty"`
	To      string    `json:"to,omitempty"`
	At      time.Time `json:"at"`
	// Added with the update guard; shown in hb.update.
	FromVersion string `json:"fromVersion,omitempty"`
	ToVersion   string `json:"toVersion,omitempty"`
	Rollback    bool   `json:"rollback,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// resultOf starts the outcome record of a marker.
func resultOf(m *updateMarker) updateResult {
	return updateResult{ID: m.ID, From: m.OldHash, To: m.NewHash, FromVersion: m.FromVersion, ToVersion: m.ToVersion, Rollback: m.Rollback, Reason: m.Reason}
}

var (
	selfHashOnce sync.Once
	selfHashVal  string
	acceptedCh   = make(chan struct{})
	acceptedOnce sync.Once
)

// SelfHash: sha256 of the running binary (reported in heartbeats as agentHash).
func SelfHash() string {
	selfHashOnce.Do(func() {
		if exe, err := selfExe(); err == nil {
			selfHashVal, _ = fileSHA256(exe)
		}
	})
	return selfHashVal
}

func selfExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func MarkAccepted() { acceptedOnce.Do(func() { close(acceptedCh) }) }

func markerPath(stateDir string) string { return filepath.Join(stateDir, "update-pending.json") }
func resultPath(stateDir string) string { return filepath.Join(stateDir, "update-result.json") }

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeJSONAtomic(p string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func readMarker(stateDir string) (*updateMarker, error) {
	b, err := os.ReadFile(markerPath(stateDir))
	if err != nil {
		return nil, err
	}
	var m updateMarker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func LastResult(stateDir string) *updateResult {
	b, err := os.ReadFile(resultPath(stateDir))
	if err != nil {
		return nil
	}
	var r updateResult
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	return &r
}

func finishUpdate(stateDir string, r updateResult) {
	r.At = time.Now().UTC()
	if err := writeJSONAtomic(resultPath(stateDir), r); err != nil {
		log.Printf("self-update: could not write result: %v", err)
	}
	_ = os.Remove(markerPath(stateDir))
	log.Printf("self-update %s: %s %s", r.ID, r.Status, r.Message)
}

// copyFile writes src to dst via a temp file + rename (dst is replaced atomically), mode 0755.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// restorePrev puts <exe>.prev back over <exe> (atomic rename of a copy; .prev is kept).
func restorePrev(exe string) error { return copyFile(exe+".prev", exe) }

// startupAction decides what a starting agent does with a pending marker.
//
//	"none"     no marker
//	"watch"    we are the new binary: must connect within the window (boots counted)
//	"rollback" the new binary keeps restarting without connecting
//	"reverted" we are the old binary again (a rollback already happened, or the swap never did)
//	"unknown"  neither hash: give up on the marker
func startupAction(m *updateMarker, self string) string {
	switch {
	case m == nil:
		return "none"
	case self == m.NewHash && m.Boots >= updateMaxBoots:
		return "rollback"
	case self == m.NewHash:
		return "watch"
	case self == m.OldHash:
		return "reverted"
	}
	return "unknown"
}

// Resume runs once at startup, before the engine loop.
func (a *Updater) Resume(ctx context.Context) {
	if f := readFloor(a.stateDir); f != "" {
		if c, ok := version.Compare(version.Version, f); ok && c < 0 {
			log.Printf("update: WARNING this agent (%s) is below the signed floor %s; update it", version.Version, f)
		}
	}
	m, err := readMarker(a.stateDir)
	if err != nil {
		return
	}
	self := SelfHash()
	res := resultOf(m)
	switch startupAction(m, self) {
	case "reverted":
		res.Status, res.Message = "rolled_back", "the previous agent binary is running again"
		finishUpdate(a.stateDir, res)
	case "unknown":
		res.Status, res.Message = "failed", "running binary matches neither the old nor the new hash"
		finishUpdate(a.stateDir, res)
	case "rollback":
		a.rollbackUpdate(m, fmt.Sprintf("the new agent restarted %d times without connecting", m.Boots))
	case "watch":
		m.Boots++
		if err := writeJSONAtomic(markerPath(a.stateDir), m); err != nil {
			log.Printf("self-update: marker write failed: %v", err)
		}
		go func() {
			select {
			case <-acceptedCh:
				res.Status, res.Message = "succeeded", "new agent connected to the engine"
				raiseFloor(a.stateDir, m.Floor, m.ToVersion) // proven: the signed floor of this release now holds
				finishUpdate(a.stateDir, res)
			case <-time.After(updateConnectWindow):
				a.rollbackUpdate(m, fmt.Sprintf("the new agent did not connect to the engine within %s", updateConnectWindow))
			case <-ctx.Done():
			}
		}()
	}
}

func (a *Updater) rollbackUpdate(m *updateMarker, why string) {
	exe := m.Exe
	if exe == "" {
		exe, _ = selfExe()
	}
	res := resultOf(m)
	res.Status, res.Message = "rolled_back", why
	if err := restorePrev(exe); err != nil {
		res.Status, res.Message = "failed", why+"; restoring the previous binary failed: "+err.Error()
		finishUpdate(a.stateDir, res)
		return // keep running the new binary rather than none
	}
	finishUpdate(a.stateDir, res)
	log.Printf("self-update: restored %s.prev; exiting so systemd starts it", exe)
	os.Exit(1)
}

// fetchVerified downloads url into dst (mode 0755) and returns its sha256.
func fetchVerified(ctx context.Context, client *http.Client, url, dst string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	res, err := client.Do(req)
	if err != nil {
		return "", protocol.DefaultCode(protocol.CodeTransferFailed, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("GET %s: %s", url, res.Status))
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(res.Body, updateMaxBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > updateMaxBytes {
		err = protocol.WithCode(protocol.CodeTransferFailed, errors.New("binary too large"))
	}
	if err != nil {
		os.Remove(dst)
		return "", protocol.DefaultCode(protocol.CodeTransferFailed, err) // a full disk (no_space) or a deadline keeps its own code
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fetchSum(ctx context.Context, client *http.Client, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	res, err := client.Do(req)
	if err != nil {
		return "", protocol.DefaultCode(protocol.CodeTransferFailed, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("GET %s: %s", url, res.Status))
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	f := strings.Fields(string(b))
	if len(f) == 0 || !hex64.MatchString(strings.ToLower(f[0])) {
		return "", protocol.WithCode(protocol.CodeTransferFailed, errors.New("bad .sha256 response"))
	}
	return strings.ToLower(f[0]), nil
}

// updateRequest is what the engine asked for beyond the hash (self_update args version, rollback, reason; protocol >= 1).
type updateRequest struct {
	Version  string
	Rollback bool
	Reason   string
}

// updateInfo is what installUpdate learned from the signed release, for the marker and the reply.
type updateInfo struct {
	Version string // the signed version of the new binary ("" for a release without a header)
	Floor   string // its signed floor, "" when none
}

// installUpdate is the file part of self_update (testable): signed SUMS + guard + download + verify + smoke + .prev + swap.
// binURL is <engine>/agent/bin/<arch>; the signed SHA256SUMS live beside it under <engine>/agent/bin/. cur is the running
// version and stateDir holds the persisted floor. smoke runs the new binary's `version` and returns what it printed.
func installUpdate(ctx context.Context, client *http.Client, binURL, want, exe string, smoke func(string) (string, error), cur, stateDir string, req updateRequest) (*updateInfo, error) {
	arch := filepath.Base(binURL)
	baseURL := strings.TrimSuffix(binURL, "/"+arch)
	rel, err := verifySignedRelease(ctx, client, baseURL)
	if err != nil {
		return nil, protocol.DefaultCode(protocol.CodeIntegrityFailed, fmt.Errorf("release signature: %w", err))
	}
	artifact := "f2c-agent-linux-" + arch
	signedWant, ok := rel.Files[artifact]
	if !ok {
		return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("SHA256SUMS has no entry for %s", artifact))
	}
	if signedWant != want {
		return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("signed SHA256SUMS has %s for %s, engine asked for %s", signedWant[:12], artifact, want[:12]))
	}
	hdr := rel.Header
	if req.Version != "" && hdr.Version != "" && req.Version != hdr.Version {
		return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("engine says version %s, the signed release says %s", req.Version, hdr.Version))
	}
	if hdr.Floor != "" {
		if c, ok := version.Compare(hdr.Version, hdr.Floor); hdr.Version == "" || !ok || c < 0 {
			return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("the signed floor %s is above the release version %q", hdr.Floor, hdr.Version))
		}
	}
	floor := readFloor(stateDir)
	d, why := decide(guardInput{Cur: cur, Target: hdr.Version, TargetSigned: hdr.Version != "", Rollback: req.Rollback, Floor: floor})
	switch d {
	case decNoRollback:
		return nil, protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("self_update: refusing to move from %s to %q (%s) without rollback", cur, hdr.Version, why))
	case decBelowFloor:
		return nil, protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("self_update: refusing to move to %q: %s (rollback cannot go below it)", hdr.Version, why))
	case decIntegrity:
		return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("self_update: %s: %s", hdr.Version, why))
	}
	if req.Rollback && d == decAllow && strings.HasPrefix(why, "rollback requested") {
		log.Printf("self-update: rollback from %s to %q accepted (%s); reason: %s", cur, hdr.Version, why, req.Reason)
	}
	sum, err := fetchSum(ctx, client, binURL+".sha256")
	if err != nil {
		return nil, err
	}
	if sum != want {
		return nil, protocol.WithCode(protocol.CodeConflict, fmt.Errorf("engine now serves %s, expected %s (retry the update)", sum[:12], want[:12]))
	}
	tmp := exe + ".new"
	got, err := fetchVerified(ctx, client, binURL, tmp)
	if err != nil {
		return nil, err
	}
	if got != want {
		os.Remove(tmp)
		return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("downloaded binary sha256 %s does not match %s", got[:12], want[:12]))
	}
	out, err := smoke(tmp)
	if err != nil {
		os.Remove(tmp)
		return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("new binary failed its smoke test: %v", err))
	}
	if hdr.Version != "" && strings.TrimSpace(out) != hdr.Version {
		os.Remove(tmp)
		return nil, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("new binary reports version %q, the signed release says %q", strings.TrimSpace(out), hdr.Version))
	}
	if err := copyFile(exe, exe+".prev"); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("keeping the current binary as .prev: %v", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return &updateInfo{Version: hdr.Version, Floor: hdr.Floor}, nil
}

// smokeVersion runs `<bin> version` and returns what it printed.
func smokeVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// exitForUpdate is replaced in tests.
var exitForUpdate = func() { os.Exit(0) }

func (a *Updater) SelfUpdate(ctx context.Context, id string, args map[string]any) (any, error) {
	want := strings.ToLower(util.Str(args, "sha256"))
	if !hex64.MatchString(want) {
		return nil, protocol.BadRequest(errors.New("self_update: sha256 (64 hex) is required"))
	}
	// version, rollback and reason are read only at protocol >= 1: below it the engine cannot ask for a rollback, and the
	// guard still refuses a downgrade.
	proto := a.protocol()
	var req updateRequest
	if proto >= 1 {
		req.Version = strings.TrimSpace(util.Str(args, "version"))
		req.Rollback, _ = args["rollback"].(bool)
		req.Reason = strings.TrimSpace(util.Str(args, "reason"))
		if req.Rollback && (req.Reason == "" || len(req.Reason) > maxReasonLen) {
			return nil, protocol.BadRequest(fmt.Errorf("self_update: rollback needs a reason of 1 to %d characters", maxReasonLen))
		}
		if !req.Rollback {
			req.Reason = ""
		}
	}
	self := SelfHash()
	if want == self {
		return map[string]any{"upToDate": true, "hash": self}, nil
	}
	if _, err := readMarker(a.stateDir); err == nil {
		return nil, protocol.WithCode(protocol.CodeConflict, errors.New("self_update: an update is already pending on this server"))
	}
	exe, err := selfExe()
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(a.engine(), "/")
	client := &http.Client{Timeout: 5 * time.Minute}
	info, err := installUpdate(ctx, client, base+"/agent/bin/"+sysinfo.HostArch(), want, exe, smokeVersion, version.Version, a.stateDir, req)
	if err != nil {
		return nil, err
	}
	m := updateMarker{ID: id, OldHash: self, NewHash: want, Exe: exe, At: time.Now().UTC(),
		FromVersion: version.Version, ToVersion: info.Version, Floor: info.Floor, Rollback: req.Rollback, Reason: req.Reason}
	if err := writeJSONAtomic(markerPath(a.stateDir), m); err != nil {
		_ = restorePrev(exe)
		return nil, fmt.Errorf("writing the update marker: %v (update undone)", err)
	}
	log.Printf("self-update %s: installed %s (was %s); restarting", id, want[:12], self[:min(12, len(self))])
	go func() {
		time.Sleep(3 * time.Second) // let the result frame go out first
		exitForUpdate()
	}()
	reply := map[string]any{"restarting": true, "from": self, "to": want}
	if proto >= 1 {
		reply["fromVersion"], reply["toVersion"], reply["rollback"] = version.Version, info.Version, req.Rollback
	}
	return reply, nil
}

// New builds the self-updater from the agent's state dir and a reader for the current engine URL.
func New(stateDir string, engine func() string) *Updater {
	return &Updater{stateDir: stateDir, engine: engine}
}
