package agent

// Resend safety (docs/protocol.md 6.3, protocol item #10): a persisted record of commands in flight (running.json) and of
// finished results (done.json), so that a re-sent command id is never executed twice by accident.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

const (
	doneTTL        = 25 * time.Hour // the engine keeps a command for 24 h (spec 6.5), plus one hour of slack
	maxDone        = 500
	maxDoneBytes   = 8 << 20   // all cached frames together
	maxStoredFrame = 256 << 10 // a larger result is cached as a stub (see storedFrame)
)

// cmdClass says what the agent does with a command whose id is re-sent after the agent restarted while it ran.
type cmdClass int

const (
	// classRead: no side effects; it simply runs again.
	classRead cmdClass = iota
	// classConverge: a second run reaches the same end state (a no-op or a whole-state replace); it runs again.
	classConverge
	// classUnsafe: a second run can double an effect or report a false failure; the answer is ok:false "interrupted".
	classUnsafe
	// classOwn: the command has its own exactly-once handling (harden: runs.json); it runs again and that decides.
	classOwn
	// classRestart: the restart itself is the effect; the answer is ok:true {restarting:true}.
	classRestart
)

// commandClasses is the idempotency table of docs/protocol.md 6.3: every command type the agent handles. A test keeps it
// equal to the commandType enum of the schema.
var commandClasses = map[string]cmdClass{
	"logs": classRead, "stats": classRead, "volumes_list": classRead, "image_present": classRead, "tls_warm": classRead, "http_probe": classRead,
	"pull": classConverge, "caddy_apply": classConverge, "cert_install": classConverge, "rm": classConverge, "stop": classConverge,
	"network_rm": classConverge, "volume_rm": classConverge, "self_update": classConverge,
	"run": classUnsafe, "rename": classUnsafe, "build": classUnsafe, "load": classUnsafe, "exec": classUnsafe,
	"harden": classOwn, "restart_agent": classRestart,
}

// classOf: an unknown type is treated as a read, because running it again only produces the same unknown-command failure.
func classOf(typ string) cmdClass {
	if c, ok := commandClasses[typ]; ok {
		return c
	}
	return classRead
}

// runRecord is one entry of running.json. Only a hash of the arguments is stored: args can hold secrets.
type runRecord struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	ArgsSha   string    `json:"argsSha"`
	NotAfter  string    `json:"notAfter,omitempty"`
	StartedAt time.Time `json:"startedAt"`
}

// doneMeta is what done.json keeps next to a cached frame. Old files have none of it.
type doneMeta struct {
	At      time.Time
	Type    string
	ArgsSha string
}

// argsDigest identifies a command: sha256 over its type and its canonical JSON arguments (Go sorts map keys).
func argsDigest(typ string, args map[string]any) string {
	b, _ := json.Marshal(args)
	h := sha256.New()
	h.Write([]byte(typ))
	h.Write([]byte{0})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func (a *Agent) now() time.Time {
	if a.nowFn != nil {
		return a.nowFn()
	}
	return time.Now()
}

func (a *Agent) runningPath() string { return filepath.Join(a.stateDir, "running.json") }

// loadRunning reads running.json (a missing or corrupt file means nothing was in flight) and drops entries past the TTL.
func (a *Agent) loadRunning() {
	b, err := os.ReadFile(a.runningPath())
	if err != nil {
		return
	}
	var list []runRecord
	if err := json.Unmarshal(b, &list); err != nil {
		log.Printf("running.json is unreadable (%v); ignoring it", err)
		return
	}
	now := a.now()
	for _, r := range list {
		if r.ID == "" || r.ArgsSha == "" || now.Sub(r.StartedAt) > doneTTL {
			continue
		}
		a.runRec[r.ID] = r
	}
}

// saveRunning writes running.json atomically (called with a.mu held). A failed write is logged, never fatal.
func (a *Agent) saveRunning() {
	list := make([]runRecord, 0, len(a.runRec))
	for _, r := range a.runRec {
		list = append(list, r)
	}
	b, _ := json.Marshal(list)
	if err := config.WriteFile0600(a.runningPath(), b); err != nil {
		log.Printf("save running.json: %v", err)
	}
}

// pruneLocked drops finished results past the TTL (the order list is oldest first) and in-flight records past the TTL.
// It reports whether anything was removed. Called with a.mu held.
func (a *Agent) pruneLocked(now time.Time) bool {
	changed := false
	for len(a.order) > 0 {
		id := a.order[0]
		if meta, ok := a.doneMeta[id]; ok && now.Sub(meta.At) <= doneTTL {
			break
		}
		a.dropDoneLocked(id)
		a.order = a.order[1:]
		changed = true
	}
	runChanged := false
	for id, r := range a.runRec {
		if _, live := a.running[id]; !live && now.Sub(r.StartedAt) > doneTTL {
			delete(a.runRec, id)
			runChanged = true
		}
	}
	if runChanged {
		a.saveRunning()
	}
	return changed
}

func (a *Agent) dropDoneLocked(id string) {
	a.doneBytes -= len(a.done[id])
	delete(a.done, id)
	delete(a.doneMeta, id)
}

// recordDoneLocked caches the frame b as the result of id, enforcing the count and byte bounds, and persists done.json
// and running.json. Called with a.mu held.
func (a *Agent) recordDoneLocked(id, typ, sha string, b []byte) {
	stored := storedFrame(id, b)
	if _, dup := a.done[id]; dup { // never happens for a live id; keep the order list free of repeats
		a.dropDoneLocked(id)
		for i, o := range a.order {
			if o == id {
				a.order = append(a.order[:i], a.order[i+1:]...)
				break
			}
		}
	}
	a.done[id] = stored
	a.doneBytes += len(stored)
	a.doneMeta[id] = doneMeta{At: a.now(), Type: typ, ArgsSha: sha}
	a.order = append(a.order, id)
	for len(a.order) > maxDone || (a.doneBytes > maxDoneBytes && len(a.order) > 1) {
		a.dropDoneLocked(a.order[0])
		a.order = a.order[1:]
	}
	delete(a.running, id)
	delete(a.runRec, id)
	a.saveDone()
	a.saveRunning()
}

// storedFrame is the copy kept for replays. A result over maxStoredFrame is cached as a stub that keeps ok, error (cut to
// 4000 bytes, which is all the engine keeps) and code, with a small marker instead of data, so one large result cannot evict
// the rest. The frame that is sent when the command ends is always the full one.
func storedFrame(id string, b []byte) json.RawMessage {
	if len(b) <= maxStoredFrame {
		return json.RawMessage(b)
	}
	var f struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	_ = json.Unmarshal(b, &f)
	stub := map[string]any{"t": "result", "id": id, "ok": f.OK}
	if f.OK {
		stub["data"] = map[string]any{"replayStub": true, "reason": "result too large to replay"}
	} else {
		e := f.Error
		if len(e) > 4000 {
			e = e[:4000]
		}
		stub["error"] = e
		if f.Code != "" {
			stub["code"] = f.Code
		}
	}
	out, _ := json.Marshal(stub)
	return out
}

// replayFrame is what a resend of a finished id gets: the cached frame, plus "replayed":true at protocol >= 1. Below that
// the frame is exactly what was cached. The frame is cut open and re-closed as text so that numbers and key order inside
// it are untouched.
func replayFrame(cached json.RawMessage, proto int) json.RawMessage {
	if proto < 1 {
		return cached
	}
	n := len(cached)
	for n > 0 && (cached[n-1] == ' ' || cached[n-1] == '\n' || cached[n-1] == '\r' || cached[n-1] == '\t') {
		n--
	}
	if n < 2 || cached[n-1] != '}' || cached[0] != '{' {
		return cached
	}
	out := make([]byte, 0, n+16)
	out = append(out, cached[:n-1]...)
	out = append(out, `,"replayed":true}`...)
	return out
}

// interruptedResult: the answer for an UNSAFE command whose agent restarted while it ran. The text is the same at every
// protocol; the code is added from protocol 1 by ResultMessageFor.
func interruptedResult(id, typ string, proto int) []byte {
	err := protocol.WithCode(protocol.CodeInterrupted, fmt.Errorf("interrupted: the agent restarted while %s was running; it may have partly run, check the state and retry with a new id", typ))
	b, _ := json.Marshal(protocol.ResultMessageFor(id, nil, err, proto))
	return b
}
