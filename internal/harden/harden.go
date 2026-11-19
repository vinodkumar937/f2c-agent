package harden

// Optional "Harden server" (admin dashboard -> engine -> agent command "harden"). Off by default.
//
// The agent is non-root (User=f2c-agent, NoNewPrivileges=yes), so it cannot run harden.sh itself and gets no sudo or
// polkit grant. It writes a validated key=value request into its own state dir (<state>/harden/request); the root
// path unit f2c-harden.path starts the oneshot f2c-harden.service, which runs the root-owned
// /usr/local/lib/f2c/harden.sh (re-validates every value, deletes the request) and writes its JSON result to
// /var/lib/f2c-harden/results/<runId>.json (0640 root:f2c-agent). The agent polls for that file and returns it.
//
// Run ids are handled once (H2): every id is recorded in <state>/harden/runs.json (0600, newest 200) before the
// request is written, so a repeat of the same id (engine re-send after a reconnect, agent restart, done.json
// eviction, agent rollback that keeps its state dir) is never run again; it gets the earlier result, unchanged, plus
// "replayed": true (agreed 1d: a replay is not an error code). The agent also watches f2c-harden.service, so a script
// that exits without a result, or a request the unit never picks up, fails within seconds instead of after the
// full wait, and every run is logged as structured "harden event=..." journal lines.
// Needs an agent rebuild (release.sh --install) and install.sh re-run (units + script) at commit time.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

var (
	hardenScript     = "/usr/local/lib/f2c/harden.sh"
	hardenPathUnit   = "/etc/systemd/system/f2c-harden.path"
	hardenResultsDir = "/var/lib/f2c-harden/results"
	hardenPoll       = 2 * time.Second
	hardenTimeout    = 21 * time.Minute // f2c-harden.service TimeoutStartSec=20min; engine waits 22 min
	// After the reply (timeout or cancel) the agent keeps following the run, up to this long in total, to record
	// its outcome: TimeoutStartSec 20 min + TimeoutStopSec 5 min + ExecStopPost rollback.
	hardenFollowMax     = 32 * time.Minute
	hardenTriggerGrace  = 30 * time.Second // the path unit starts the service within ms; 30 s = not triggered
	hardenNoResultGrace = 5 * time.Second  // unit finished but no result file yet: allow for the final rename
	hardenMaxRuns       = 200
	// hardenUnitActive reports whether f2c-harden.path is active (read-only systemctl query; tests replace it).
	hardenUnitActive = func(ctx context.Context) bool {
		return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "f2c-harden.path").Run() == nil
	}
	// hardenUnitState reads f2c-harden.service's state (read-only `systemctl show`; tests replace it).
	hardenUnitState = func(ctx context.Context) (hardenUnit, error) {
		out, err := exec.CommandContext(ctx, "systemctl", "show", "f2c-harden.service",
			"-p", "InvocationID", "-p", "ActiveState", "-p", "Result", "-p", "ExecMainStatus").Output()
		if err != nil {
			return hardenUnit{}, err
		}
		return parseHardenUnit(string(out)), nil
	}
	hardenBusy      sync.Mutex // one new run at a time per agent (harden.sh also takes a root lock)
	hardenRunsMu    sync.Mutex // guards runs.json and hardenActiveRun
	hardenActiveRun string     // the run this agent process is following right now
)

const hardenMaxResult = 1 << 20

var (
	hardenRunID    = regexp.MustCompile(`^harden-[a-z0-9]{1,40}$`)
	hardenBackupID = regexp.MustCompile(`^(last|[0-9]{8}-[0-9]{6})$`)
	hardenEngine   = regexp.MustCompile(`^https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$`)
)

// errHardenNotInstalled: the engine maps this prefix to harden_not_installed.
// Result message code (protocol 2a): "harden_not_installed"; the text is unchanged.
var errHardenNotInstalled = protocol.WithCode(protocol.CodeHardenNotInstalled, errors.New("harden_not_installed: harden.sh or f2c-harden.path missing or inactive; re-run install.sh on this server"))

type hardenRequest struct {
	RunID       string
	Mode        string // dry_run | apply | rollback
	AllowIPs    []string
	SwapGB      int
	SSHKeysOnly bool
	Engine      string
	BackupID    string
}

func validHardenIP(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// parseHardenArgs validates the engine's args (the root script validates again).
func parseHardenArgs(args map[string]any, engine string) (hardenRequest, error) {
	r := hardenRequest{RunID: util.Str(args, "runId"), Mode: util.Str(args, "mode"), SwapGB: 2, SSHKeysOnly: true, BackupID: util.Str(args, "backupId")}
	if !hardenRunID.MatchString(r.RunID) {
		return r, errors.New("harden: runId must match harden-[a-z0-9]{1,40}")
	}
	switch r.Mode {
	case "dry_run", "apply", "rollback":
	default:
		return r, errors.New("harden: mode must be dry_run, apply or rollback")
	}
	if v, ok := args["allowIps"]; ok && v != nil {
		list, ok := v.([]any)
		if !ok || len(list) > 16 {
			return r, errors.New("harden: allowIps must be a list of at most 16 IPs/CIDRs")
		}
		for _, x := range list {
			s, _ := x.(string)
			if !validHardenIP(s) {
				return r, fmt.Errorf("harden: bad allowIps entry %q", s)
			}
			r.AllowIPs = append(r.AllowIPs, s)
		}
	}
	if _, ok := args["swapGb"]; ok {
		f := util.Num(args, "swapGb")
		if f < 0 || f > 16 || f != float64(int(f)) {
			return r, errors.New("harden: swapGb must be an integer 0-16")
		}
		r.SwapGB = int(f)
	}
	if v, ok := args["sshKeysOnly"].(bool); ok {
		r.SSHKeysOnly = v
	}
	if r.BackupID != "" && !hardenBackupID.MatchString(r.BackupID) {
		return r, errors.New("harden: bad backupId")
	}
	engine = strings.TrimRight(engine, "/")
	if hardenEngine.MatchString(engine) {
		r.Engine = engine
	}
	return r, nil
}

func (r hardenRequest) encode() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "id=%s\nmode=%s\n", r.RunID, r.Mode)
	for _, ip := range r.AllowIPs {
		fmt.Fprintf(&b, "allow_ip=%s\n", ip)
	}
	keys := "0"
	if r.SSHKeysOnly {
		keys = "1"
	}
	fmt.Fprintf(&b, "swap_gb=%s\nssh_keys_only=%s\n", strconv.Itoa(r.SwapGB), keys)
	if r.Engine != "" {
		fmt.Fprintf(&b, "engine=%s\n", r.Engine)
	}
	if r.BackupID != "" {
		fmt.Fprintf(&b, "backup_id=%s\n", r.BackupID)
	}
	return []byte(b.String())
}

func (a *Service) Run(ctx context.Context, args map[string]any) (any, error) {
	req, err := parseHardenArgs(args, a.engine())
	if err != nil {
		return nil, protocol.WithCode(protocol.CodeHardenBadRequest, err)
	}
	if _, err := os.Stat(hardenScript); err != nil {
		return nil, errHardenNotInstalled
	}
	if _, err := os.Stat(hardenPathUnit); err != nil || !hardenUnitActive(ctx) {
		return nil, errHardenNotInstalled
	}
	dir := filepath.Join(a.stateDir, "harden")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, protocol.WithCode(protocol.CodeHardenStateUnreadable, fmt.Errorf("harden: %w", err))
	}
	runsPath := a.hardenRunsPath()
	resultPath := filepath.Join(hardenResultsDir, req.RunID+".json")
	runs, err := loadHardenRuns(runsPath)
	if err != nil {
		return nil, errHardenState(runsPath, err)
	}
	if prev, ok := findHardenRun(runs, req.RunID); ok {
		return a.hardenDuplicate(ctx, req, prev, resultPath)
	}
	if !hardenBusy.TryLock() {
		hardenLog("refused", req.RunID, "mode=%s reason=agent_busy", req.Mode)
		return a.detected(hardenFailedResult(req.RunID, req.Mode, "harden_running: another harden run is still in progress on this agent; nothing changed", time.Now()), protocol.CodeConflict)
	}
	prev, err := claimHardenRun(runsPath, req)
	if err != nil || prev != nil {
		hardenBusy.Unlock()
		if err != nil {
			return nil, errHardenState(runsPath, err)
		}
		return a.hardenDuplicate(ctx, req, *prev, resultPath)
	}
	setHardenActive(req.RunID)
	hardenLog("start", req.RunID, "mode=%s allow_ips=%d swap_gb=%d ssh_keys_only=%v backup=%q", req.Mode, len(req.AllowIPs), req.SwapGB, req.SSHKeysOnly, req.BackupID)
	w := &hardenWait{path: resultPath, runID: req.RunID, mode: req.Mode, request: filepath.Join(dir, "request"), queuedAt: time.Now()}
	w.before, _ = hardenUnitState(ctx)
	tmp := filepath.Join(dir, ".request.tmp")
	if err := os.WriteFile(tmp, req.encode(), 0o600); err == nil {
		err = os.Rename(tmp, w.request) // the rename triggers f2c-harden.path
	} else {
		err = fmt.Errorf("write request: %w", err)
	}
	if err != nil {
		setHardenActive("")
		hardenBusy.Unlock()
		out := hardenFailedResult(req.RunID, req.Mode, "harden_script_failed: could not queue the request: "+err.Error(), w.queuedAt)
		recordHardenOutcome(runsPath, req.RunID, out)
		return nil, protocol.WithCode(protocol.CodeHardenScriptFailed, fmt.Errorf("harden: queue request: %w", err))
	}
	// Followed in the background, so the outcome is recorded (and logged) even after this command gave up waiting.
	type followed struct {
		out  map[string]any
		code string // set when the agent itself detected the failure (waitHardenResultC)
	}
	done := make(chan followed, 1)
	go func() {
		defer hardenBusy.Unlock()
		defer setHardenActive("")
		fctx, cancel := context.WithTimeout(context.Background(), hardenFollowMax)
		defer cancel()
		out, code, err := waitHardenResultC(fctx, w)
		if err != nil {
			out = hardenFailedResult(req.RunID, req.Mode, fmt.Sprintf("harden: no result from f2c-harden.service within %s (%v); outcome unknown", hardenFollowMax, err), w.queuedAt)
			out["status"] = "unknown" // only in runs.json: never returned as a result
		}
		addAgentAudit(out, w)
		logHardenOutcome(req.RunID, out)
		recordHardenOutcome(runsPath, req.RunID, out)
		done <- followed{out, code}
	}()
	timer := time.NewTimer(hardenTimeout)
	defer timer.Stop()
	select {
	case f := <-done:
		out := f.out
		if out["status"] == "unknown" {
			return nil, protocol.WithCode(protocol.CodeHardenFailed, fmt.Errorf("harden: %v", out["message"]))
		}
		if f.code != "" {
			return a.detected(out, f.code)
		}
		return out, nil
	case <-ctx.Done():
		hardenLog("cancelled", req.RunID, "still following the run to record its outcome")
		// code harden_interrupted (agreed 1f): the engine stops waiting; the root run itself is not interrupted
		return nil, protocol.WithCode(protocol.CodeHardenInterrupted, errors.New("harden: cancelled while waiting for the result (the run may still finish on the server; the agent keeps following it and a re-send of this run id returns its outcome)"))
	case <-timer.C:
		hardenLog("timeout", req.RunID, "no result after %s; still following the run", hardenTimeout)
		return nil, protocol.WithCode(protocol.CodeHardenTimeout, errors.New("harden: timed out waiting for f2c-harden.service (the agent keeps following it; a re-send of this run id returns its outcome)"))
	}
}

func setHardenActive(id string) {
	hardenRunsMu.Lock()
	hardenActiveRun = id
	hardenRunsMu.Unlock()
}

func isHardenActive(id string) bool {
	hardenRunsMu.Lock()
	defer hardenRunsMu.Unlock()
	return hardenActiveRun == id
}

func errHardenState(path string, err error) error {
	return protocol.WithCode(protocol.CodeHardenStateUnreadable, fmt.Errorf("harden_state_unreadable: %s cannot be read (%v); not running, so that no run id is ever run twice. Move the file away to reset the run history", path, err))
}

// ---------- run id history (H2) ----------

type hardenRun struct {
	ID          string `json:"id"`
	Mode        string `json:"mode"`
	RequestedAt string `json:"requestedAt"`
	Status      string `json:"status"` // requested | succeeded | failed | rolled_back | unknown
	Message     string `json:"message,omitempty"`
	BackupID    string `json:"backupId,omitempty"`
	FinishedAt  string `json:"finishedAt,omitempty"`
}

type hardenRunsFile struct {
	Version int         `json:"version"`
	Runs    []hardenRun `json:"runs"`
}

func (a *Service) hardenRunsPath() string { return filepath.Join(a.stateDir, "harden", "runs.json") }

func loadHardenRuns(path string) ([]hardenRun, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f hardenRunsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unknown version %d", f.Version)
	}
	return f.Runs, nil
}

// saveHardenRuns keeps the newest hardenMaxRuns records (0600, atomic).
func saveHardenRuns(path string, runs []hardenRun) error {
	if len(runs) > hardenMaxRuns {
		runs = runs[len(runs)-hardenMaxRuns:]
	}
	b, err := json.Marshal(hardenRunsFile{Version: 1, Runs: runs})
	if err != nil {
		return err
	}
	defer hardenSummaryGen.Add(1) // the heartbeat summary rereads runs.json on its next beat
	return config.WriteFile0600(path, b)
}

func findHardenRun(runs []hardenRun, id string) (hardenRun, bool) {
	for i := len(runs) - 1; i >= 0; i-- {
		if runs[i].ID == id {
			return runs[i], true
		}
	}
	return hardenRun{}, false
}

// claimHardenRun records req's run id before anything is queued. When the id was seen before it returns that record
// and records nothing.
func claimHardenRun(path string, req hardenRequest) (*hardenRun, error) {
	hardenRunsMu.Lock()
	defer hardenRunsMu.Unlock()
	runs, err := loadHardenRuns(path)
	if err != nil {
		return nil, err
	}
	if r, ok := findHardenRun(runs, req.RunID); ok {
		return &r, nil
	}
	runs = append(runs, hardenRun{ID: req.RunID, Mode: req.Mode, RequestedAt: time.Now().UTC().Format(time.RFC3339), Status: "requested"})
	return nil, saveHardenRuns(path, runs)
}

func recordHardenOutcome(path, id string, out map[string]any) {
	hardenRunsMu.Lock()
	defer hardenRunsMu.Unlock()
	runs, err := loadHardenRuns(path)
	if err != nil {
		log.Printf("harden event=state_error run=%s err=%q", id, err.Error())
		return
	}
	for i := range runs {
		if runs[i].ID != id {
			continue
		}
		r := &runs[i]
		r.Status, _ = out["status"].(string)
		r.Message, _ = out["message"].(string)
		if len(r.Message) > 500 {
			r.Message = r.Message[:500]
		}
		r.BackupID, _ = out["backupId"].(string)
		if r.FinishedAt, _ = out["finishedAt"].(string); r.FinishedAt == "" {
			r.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	if err := saveHardenRuns(path, runs); err != nil {
		log.Printf("harden event=state_error run=%s err=%q", id, err.Error())
	}
}

// hardenDuplicate answers a run id that was already handled: never runs it again; returns the earlier result (root
// result file, else rebuilt from the recorded outcome) in the same shape plus "replayed": true. Status and message
// are the earlier ones (no harden_ prefix is added). A run still in progress (also one started before an agent
// restart) is followed to its result. Earlier outcome unknown: status "failed", replayed true, a plain message
// (the engine never changes "hardened" for any replayed run).
func (a *Service) hardenDuplicate(ctx context.Context, req hardenRequest, prev hardenRun, resultPath string) (any, error) {
	hardenLog("duplicate", req.RunID, "earlier_status=%s requested_at=%s; not run again", prev.Status, prev.RequestedAt)
	if out := readHardenResult(resultPath, req.RunID); out != nil {
		return replayed(out), nil
	}
	if prev.Status == "requested" || prev.Status == "unknown" {
		wctx, cancel := context.WithTimeout(ctx, hardenTimeout)
		defer cancel()
		// still followed by this agent process: wait for the result file only (that follower records the outcome)
		following := isHardenActive(req.RunID)
		w := &hardenWait{path: resultPath, runID: req.RunID, mode: req.Mode, queuedAt: time.Now(), started: true, resultOnly: following, duplicate: true}
		if out, err := waitHardenResult(wctx, w); err == nil {
			if !following {
				recordHardenOutcome(a.hardenRunsPath(), req.RunID, out)
			}
			return replayed(out), nil
		}
		out := hardenFailedResult(req.RunID, req.Mode, fmt.Sprintf("run %s was already requested at %s, but its outcome is unknown (no result from the server); it was not run again. Check the server, then start a new run", req.RunID, prev.RequestedAt), time.Now())
		if a.v1() { // the agent itself could not find the outcome: a failure of this command, not a replayed result
			return a.detected(out, protocol.CodeHardenFailed)
		}
		setStartedAt(out, prev.RequestedAt)
		return replayed(out), nil
	}
	out := hardenFailedResult(req.RunID, req.Mode, prev.Message, time.Now())
	setStartedAt(out, prev.RequestedAt)
	switch prev.Status {
	case "succeeded", "failed", "rolled_back":
		out["status"] = prev.Status
	}
	if prev.BackupID != "" {
		out["backupId"] = prev.BackupID
	}
	if prev.FinishedAt != "" {
		out["finishedAt"] = prev.FinishedAt
	}
	return replayed(out), nil
}

// replayed marks a result as the answer to a repeated run id (protocol: result data "replayed": true).
func replayed(out map[string]any) map[string]any {
	out["replayed"] = true
	return out
}

func setStartedAt(out map[string]any, requestedAt string) {
	if requestedAt != "" {
		out["startedAt"] = requestedAt
	}
}

// ---------- waiting for the root unit ----------

type hardenUnit struct {
	InvocationID, ActiveState, Result string
	ExecMainStatus                    int
}

func parseHardenUnit(s string) hardenUnit {
	var u hardenUnit
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		switch k {
		case "InvocationID":
			u.InvocationID = v
		case "ActiveState":
			u.ActiveState = v
		case "Result":
			u.Result = v
		case "ExecMainStatus":
			u.ExecMainStatus, _ = strconv.Atoi(v)
		}
	}
	return u
}

// busy: starting, running the oneshot (a oneshot is "activating" while it runs) or running ExecStopPost.
func (u hardenUnit) busy() bool {
	switch u.ActiveState {
	case "activating", "deactivating", "active", "reloading":
		return true
	}
	return false
}

type hardenWait struct {
	path, runID, mode string
	request           string     // the queued request file ("" = not ours to withdraw)
	before            hardenUnit // f2c-harden.service before the request was written
	queuedAt          time.Time
	started           bool      // the unit has taken the request
	resultOnly        bool      // only poll the result file (no unit checks)
	duplicate         bool      // a re-sent id: an idle unit without a result means "unknown", not a failure
	startedAt         time.Time // when the agent saw that
}

func readHardenResult(path, runID string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 || len(b) > hardenMaxResult {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil || out["id"] != runID {
		return nil
	}
	return out
}

// waitHardenResult polls for the root unit's JSON result (matching run id) until ctx ends. It also watches
// f2c-harden.service: a request the unit does not take within hardenTriggerGrace is withdrawn (harden_not_triggered,
// or harden_running when another run held the unit), and a unit that finished without writing this run's result
// fails the run after hardenNoResultGrace (harden_script_failed) instead of after the full timeout.
func waitHardenResult(ctx context.Context, w *hardenWait) (map[string]any, error) {
	out, _, err := waitHardenResultC(ctx, w)
	return out, err
}

// waitHardenResultC is waitHardenResult plus the result code of an outcome the agent itself detected (the three
// hardenFailedResult returns below), "" for a result that harden.sh wrote.
func waitHardenResultC(ctx context.Context, w *hardenWait) (map[string]any, string, error) {
	tick := time.NewTicker(hardenPoll)
	defer tick.Stop()
	var idleSince time.Time
	for {
		if out := readHardenResult(w.path, w.runID); out != nil {
			return out, "", nil
		}
		if st, err := hardenUnitState(ctx); err == nil && !w.resultOnly {
			if !w.started {
				_, reqErr := os.Stat(w.request)
				switch {
				case st.InvocationID != "" && st.InvocationID != w.before.InvocationID,
					w.request != "" && errors.Is(reqErr, os.ErrNotExist),
					st.busy() && !w.before.busy():
					w.started, w.startedAt = true, time.Now()
					hardenLog("triggered", w.runID, "unit=%s", st.ActiveState)
				}
			}
			if !w.started && time.Since(w.queuedAt) > hardenTriggerGrace {
				if w.request != "" && os.Remove(w.request) == nil {
					if w.before.busy() || st.busy() {
						return hardenFailedResult(w.runID, w.mode, "harden_running: another harden run held f2c-harden.service; request withdrawn, nothing changed", w.queuedAt), protocol.CodeConflict, nil
					}
					return hardenFailedResult(w.runID, w.mode, fmt.Sprintf("harden_not_triggered: f2c-harden.service did not pick up the request within %s (is f2c-harden.path active?); request withdrawn, nothing changed", hardenTriggerGrace), w.queuedAt), protocol.CodeHardenFailed, nil
				}
				w.started, w.startedAt = true, time.Now() // gone meanwhile: the unit took it
			}
			if w.started && !st.busy() {
				if idleSince.IsZero() {
					idleSince = time.Now()
				} else if time.Since(idleSince) >= hardenNoResultGrace {
					if out := readHardenResult(w.path, w.runID); out != nil {
						return out, "", nil
					}
					if w.duplicate {
						return nil, "", errors.New("f2c-harden.service is idle and has no result for this run")
					}
					return hardenFailedResult(w.runID, w.mode, fmt.Sprintf("harden_script_failed: f2c-harden.service ended (result %s, exit status %d) without writing a result for this run; see journalctl -u f2c-harden.service", orDash(st.Result), st.ExecMainStatus), w.queuedAt), protocol.CodeHardenScriptFailed, nil
				}
			} else {
				idleSince = time.Time{}
			}
		}
		select {
		case <-ctx.Done():
			return nil, "", fmt.Errorf("stopped waiting: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// hardenFailedResult: a failed result in harden.sh's own shape, for outcomes the agent detects itself.
func hardenFailedResult(runID, mode, msg string, started time.Time) map[string]any {
	return map[string]any{
		"version": 1, "id": runID, "mode": mode, "status": "failed", "message": msg,
		"startedAt": started.UTC().Format(time.RFC3339), "finishedAt": time.Now().UTC().Format(time.RFC3339),
		"backupId": nil, "sshKeysPresent": nil, "sshPorts": []any{}, "warnings": []any{},
		"prechecks": []any{}, "postchecks": []any{}, "steps": []any{}, "audit": []any{},
	}
}

// ---------- audit (journal + result) ----------

func hardenLog(event, run, format string, args ...any) {
	log.Printf("harden event=%s run=%s %s", event, run, fmt.Sprintf(format, args...))
}

// addAgentAudit appends the agent's own events (queued, triggered, outcome) to the result's "audit" list, next to
// the root script's.
func addAgentAudit(out map[string]any, w *hardenWait) {
	list, _ := out["audit"].([]any)
	ev := func(t time.Time, event, detail string) map[string]any {
		return map[string]any{"ts": t.UTC().Format(time.RFC3339), "run": w.runID, "source": "agent", "event": event, "detail": detail}
	}
	list = append(list, ev(w.queuedAt, "queued", "request written to the agent state dir"))
	if !w.startedAt.IsZero() {
		list = append(list, ev(w.startedAt, "triggered", "f2c-harden.service took the request"))
	}
	st, _ := out["status"].(string)
	list = append(list, ev(time.Now(), "outcome", st))
	out["audit"] = list
}

// logHardenOutcome writes one structured journal line per step, failed check and rollback, then the outcome.
func logHardenOutcome(run string, out map[string]any) {
	steps, _ := out["steps"].([]any)
	for _, x := range steps {
		s, _ := x.(map[string]any)
		hardenLog("step", run, "step=%v status=%v reason=%v", s["id"], s["status"], s["reason"])
	}
	for _, phase := range []string{"prechecks", "postchecks"} {
		checks, _ := out[phase].([]any)
		for _, x := range checks {
			c, _ := x.(map[string]any)
			if ok, _ := c["ok"].(bool); !ok || c["name"] == "rollback_verified" {
				hardenLog("check", run, "phase=%s name=%v ok=%v detail=%q", phase, c["name"], c["ok"], fmt.Sprint(c["detail"]))
			}
		}
	}
	msg, _ := out["message"].(string)
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if out["status"] == "rolled_back" {
		hardenLog("rollback", run, "backup=%v", out["backupId"])
	}
	hardenLog("outcome", run, "mode=%v status=%v backup=%v message=%q", out["mode"], out["status"], out["backupId"], msg)
}

// LinkMonitor proves the accepted authenticated wss session is responsive (Ping/Pong, not merely a TCP
// socket). No credentials are written. The root hardener checks timestamp + mode; stale/missing proof fails closed.
// Started only after hello_ok. The context ends on disconnect; the next wss session refreshes the proof.
func (a *Service) LinkMonitor(ctx context.Context, conn *websocket.Conn) {
	secure := strings.HasPrefix(a.engine(), "https://") && !a.insecure
	if !secure {
		return
	} // fail closed for ws/insecure engines; they cannot trigger host security changes
	dir := filepath.Join(a.stateDir, "harden")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := conn.Ping(pingCtx)
		cancel()
		if err == nil && ctx.Err() == nil {
			// State dir is agent-only (0700), as is the atomic temporary proof.
			tmp := filepath.Join(dir, ".link-proof.tmp")
			if os.WriteFile(tmp, []byte(fmt.Sprintf("%d wss\n", time.Now().Unix())), 0o600) == nil {
				_ = os.Rename(tmp, filepath.Join(dir, "link-proof"))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Service holds what the harden command needs from the agent: the state dir, the current engine URL and the
// (deprecated) insecure flag.
type Service struct {
	stateDir string
	engine   func() string // the engine URL from agent.json (read under the agent's lock)
	insecure bool
	codes    func() bool // true when the session is at protocol >= 1 (SetCodes); nil = protocol 0
}

// SetCodes tells the service how to ask whether the session is at protocol >= 1. From there a failure the agent detects
// itself (not one harden.sh reported) is an ok:false result with a code and no data, instead of ok:true with a failed
// result (docs/protocol.md section 5). Without it, or below protocol 1, nothing changes.
func (a *Service) SetCodes(f func() bool) { a.codes = f }

func (a *Service) v1() bool { return a.codes != nil && a.codes() }

// detected turns an outcome the agent itself found (out is hardenFailedResult's map) into the protocol >= 1 reply: an
// error carrying code with the same message as text. Below protocol 1 it is the old ok:true result.
func (a *Service) detected(out map[string]any, code string) (any, error) {
	if !a.v1() {
		return out, nil
	}
	msg, _ := out["message"].(string)
	return nil, protocol.WithCode(code, errors.New(msg))
}

// SafeSummary never lets the harden summary break a heartbeat (a panic drops only the field).
func (a *Service) SafeSummary() (hs map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("harden: heartbeat summary panicked: %v (field omitted)", r)
			hs = nil
		}
	}()
	return a.hardenSummary()
}

// ---------- heartbeat summary (follow-up 9.3) ----------

// SummaryVersion is sent as hb.hardenV and hb.harden.v.
const (
	SummaryVersion    = 1
	hardenSummaryRuns = 5
)

// hardenRunSummary is one entry of hb.harden.runs (newest first). finishedAt and backupId are omitted when empty;
// status is the runs.json status: requested | succeeded | failed | rolled_back | unknown.
type hardenRunSummary struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	FinishedAt string `json:"finishedAt,omitempty"`
	BackupID   string `json:"backupId,omitempty"`
}

var (
	hardenSummaryGen atomic.Uint64 // bumped by saveHardenRuns
	hardenSummaryMu  sync.Mutex
	hardenSummaryC   struct {
		ok      bool
		path    string
		gen     uint64
		modTime time.Time
		size    int64
		runs    []hardenRunSummary
		lastErr string
	}
)

// hardenSummary returns hb.harden: {"v":1,"runs":[...last 5, newest first...]}. Cheap: runs.json (written by
// atomic rename) is reread only when this agent saved it or its mtime/size changed. Never fails: a missing,
// unreadable or corrupt file gives an empty runs list (the error is logged once per distinct error).
func (a *Service) hardenSummary() map[string]any {
	runs := hardenSummaryFor(a.hardenRunsPath())
	return map[string]any{"v": SummaryVersion, "runs": runs}
}

func hardenSummaryFor(path string) []hardenRunSummary {
	hardenSummaryMu.Lock()
	defer hardenSummaryMu.Unlock()
	c := &hardenSummaryC
	gen := hardenSummaryGen.Load()
	var modTime time.Time
	var size int64 = -1
	if st, err := os.Stat(path); err == nil {
		modTime, size = st.ModTime(), st.Size()
	}
	if c.ok && c.path == path && c.gen == gen && c.modTime.Equal(modTime) && c.size == size {
		return c.runs
	}
	runs, err := loadHardenRuns(path)
	out := []hardenRunSummary{}
	if err != nil {
		if msg := err.Error(); msg != c.lastErr {
			log.Printf("harden: heartbeat summary: cannot read %s: %v (sending no runs)", path, err)
			c.lastErr = msg
		}
	} else {
		c.lastErr = ""
		for i := len(runs) - 1; i >= 0 && len(out) < hardenSummaryRuns; i-- {
			r := runs[i]
			out = append(out, hardenRunSummary{ID: r.ID, Status: r.Status, FinishedAt: r.FinishedAt, BackupID: r.BackupID})
		}
	}
	c.ok, c.path, c.gen, c.modTime, c.size, c.runs = true, path, gen, modTime, size, out
	return out
}

// New builds the harden service from the agent's state dir, a reader for the current engine URL and the
// insecure flag.
func New(stateDir string, engine func() string, insecure bool) *Service {
	return &Service{stateDir: stateDir, engine: engine, insecure: insecure}
}
