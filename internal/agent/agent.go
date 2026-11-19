package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/vinodkumar937/f2c-agent/internal/build"
	"github.com/vinodkumar937/f2c-agent/internal/caddy"
	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/databases"
	"github.com/vinodkumar937/f2c-agent/internal/docker"
	"github.com/vinodkumar937/f2c-agent/internal/harden"
	"github.com/vinodkumar937/f2c-agent/internal/metrics"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/sysinfo"
	"github.com/vinodkumar937/f2c-agent/internal/update"
	"github.com/vinodkumar937/f2c-agent/internal/version"
)

const heartbeatEvery = 15 * time.Second

// doneEntry is a finished command's result, kept so a re-sent id is answered without running it again. At, Type and ArgsSha
// are optional additions (journal.go); a file without them, and an older agent reading a file with them, both work.
type doneEntry struct {
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result"`
	At      string          `json:"at,omitempty"`
	Type    string          `json:"type,omitempty"`
	ArgsSha string          `json:"argsSha,omitempty"`
}

type Agent struct {
	cfg      *config.Config
	stateDir string
	insecure bool

	// The parts of the agent that live in their own units; each gets only the pieces of agent state it needs.
	caddy     caddy.Router
	harden    *harden.Service
	update    *update.Updater
	build     *build.Builder
	databases *databases.Service
	registry  *docker.Registry

	mu      sync.Mutex
	conn    *websocket.Conn
	running map[string]context.CancelFunc
	done    map[string]json.RawMessage
	order   []string
	// Resend safety (journal.go): what is known about each id besides its result, the in-flight records (running.json,
	// including ids from before a restart that have no goroutine), and the size of the cached frames.
	doneMeta  map[string]doneMeta
	runRec    map[string]runRecord
	doneBytes int
	// nowFn and execHook are test seams: a clock, and a replacement for the command dispatcher.
	nowFn    func() time.Time
	execHook func(ctx context.Context, m protocol.Message) (any, error)
	// sendHook, when set (tests only), receives every outgoing message instead of the websocket.
	sendHook func(any)
	// tm: reconnect jitter, ping and dial timing (reconnect.go); the zero value is the production setting.
	tm timing
	// ver is this agent's version (version.Version; tests override it) for the minAgent check.
	ver string
	// neg is the negotiation result of the current session (nil outside a session or before hello_ok), see negotiate.go.
	neg atomic.Pointer[negotiated]
}

func New(cfg *config.Config, stateDir, caddyAdmin, certDir string, insecure bool) *Agent {
	a := &Agent{cfg: cfg, stateDir: stateDir, insecure: insecure,
		running: map[string]context.CancelFunc{}, done: map[string]json.RawMessage{}, ver: version.Version,
		doneMeta: map[string]doneMeta{}, runRec: map[string]runRecord{}}
	engine := func() string { // the engine URL, read under the lock because token rotation rewrites cfg
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.cfg.Engine
	}
	a.caddy = caddy.New(stateDir, caddyAdmin, certDir, a.send, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.conn != nil
	})
	a.harden = harden.New(stateDir, engine, insecure)
	a.harden.SetCodes(func() bool { return a.SessionProtocol() >= 1 }) // agent-detected harden failures: ok:false + code from protocol 1
	a.update = update.New(stateDir, engine)
	a.update.SetProtocol(a.SessionProtocol) // self_update version/rollback/reason are read from protocol 1
	a.build = build.New(stateDir, a.send)
	a.databases = databases.New(stateDir, a.send)
	a.registry = docker.New(a.send)
	a.loadDone()
	a.loadRunning()
	return a
}

func (a *Agent) donePath() string { return filepath.Join(a.stateDir, "done.json") }

func (a *Agent) loadDone() {
	b, err := os.ReadFile(a.donePath())
	if err != nil {
		return
	}
	var list []doneEntry
	if err := json.Unmarshal(b, &list); err != nil {
		log.Printf("done.json is unreadable (%v); starting with no cached results", err)
		return
	}
	now := a.now()
	for _, e := range list {
		if e.ID == "" || len(e.Result) == 0 {
			continue
		}
		at := now // entries written before the TTL existed count from now
		if t, err := time.Parse(time.RFC3339Nano, e.At); err == nil {
			at = t
		}
		if now.Sub(at) > doneTTL {
			continue
		}
		if _, dup := a.done[e.ID]; dup {
			continue
		}
		a.done[e.ID] = e.Result
		a.doneBytes += len(e.Result)
		a.doneMeta[e.ID] = doneMeta{At: at, Type: e.Type, ArgsSha: e.ArgsSha}
		a.order = append(a.order, e.ID)
	}
	for len(a.order) > maxDone || (a.doneBytes > maxDoneBytes && len(a.order) > 1) {
		a.dropDoneLocked(a.order[0])
		a.order = a.order[1:]
	}
}

// saveDone persists the cached results (called with a.mu held).
func (a *Agent) saveDone() {
	list := make([]doneEntry, 0, len(a.order))
	for _, id := range a.order {
		m := a.doneMeta[id]
		list = append(list, doneEntry{ID: id, Result: a.done[id], At: m.At.UTC().Format(time.RFC3339Nano), Type: m.Type, ArgsSha: m.ArgsSha})
	}
	b, _ := json.Marshal(list)
	if err := config.WriteFile0600(a.donePath(), b); err != nil {
		log.Printf("save done.json: %v", err)
	}
}

// send writes one JSON frame on the current connection; false when disconnected.
func (a *Agent) send(v any) bool {
	v = a.gateReplyCode(v)
	a.mu.Lock()
	c := a.conn
	hook := a.sendHook
	a.mu.Unlock()
	if hook != nil {
		hook(v)
		return true
	}
	if c == nil {
		return false
	}
	b, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.Write(ctx, websocket.MessageText, b) == nil
}

func (a *Agent) wsURL() string {
	u := a.cfg.Engine
	u = strings.Replace(u, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	return strings.TrimRight(u, "/") + "/agent"
}

// Run starts the agent's background parts (the TLS ask endpoint, the access-log listener, the certificate watcher,
// the database scheduler, the image sweeper), settles a pending self-update, then serves the engine connection until
// ctx ends.
func (a *Agent) Run(ctx context.Context, askListen, accessListen, caddyCerts string) {
	go a.caddy.ServeAsk(ctx, askListen)
	go caddy.ServeAccessLog(ctx, accessListen) // feature C
	go a.caddy.Watch(ctx, caddyCerts)
	go a.databases.Scheduler(ctx)
	a.build.StartSweeper(ctx)
	a.update.Resume(ctx) // pending self-update: confirm on connect or roll back (selfupdate.go)
	a.loop(ctx)
}

// loop connects and reconnects until ctx is cancelled; it never gives up. The delay depends on why the last session ended
// (reconnect.go): normal failures 1 s doubling to 30 s, auth failures (401/403, close 4003) 60 s doubling to 10 min, and a
// replaced connection (close 4000) 30 to 90 s. All delays are jittered. A session of more than 60 s resets the normal
// schedule; hello_ok resets the auth schedule.
func (a *Agent) loop(ctx context.Context) {
	if _, err := config.CheckEngineURL(a.cfg.Engine, a.insecure); err != nil {
		log.Fatal(err)
	}
	rc := newReconnector(a.tm.rand())
	for ctx.Err() == nil {
		start := time.Now()
		accepted, err := a.session(ctx)
		if ctx.Err() != nil {
			break
		}
		if accepted {
			rc.accepted()
		}
		rc.sessionEnded(time.Since(start))
		kind, why := classify(err)
		d := rc.delay(kind)
		next := time.Now().Add(d).Format("15:04:05")
		switch kind {
		case failAuth:
			log.Printf("auth failure: %s. Not stopping; retrying slowly in %s (at %s). If this persists, re-join this server with a new join token", why, d.Round(time.Second), next)
		case failProtocol:
			log.Printf("%s. Not stopping; retrying slowly in %s (at %s). Update this agent (or ask the operator to check the engine version)", why, d.Round(time.Second), next)
		case failReplaced:
			log.Printf("%s; another agent may be running with this token. Waiting %s before reconnecting (at %s)", why, d.Round(time.Second), next)
		default:
			log.Printf("disconnected: %v; reconnecting in %s", err, d.Round(time.Millisecond))
		}
		if !a.tm.sleep(ctx, d) {
			break
		}
	}
	log.Print("agent stopped")
}

// errDeadLink ends a session whose pings went unanswered.
var errDeadLink = errors.New("dead link: no pong from the engine")

// session dials, serves one connection and returns whether the engine accepted it (hello_ok) and why it ended.
func (a *Agent) session(ctx context.Context) (accepted bool, _ error) {
	dctx, cancel := context.WithTimeout(ctx, a.tm.dialTimeout())
	a.mu.Lock()
	tok := a.cfg.Token
	a.mu.Unlock()
	c, res, err := websocket.Dial(dctx, a.wsURL(), &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":         {"Bearer " + tok},
			protocol.ProtocolHeader: {strconv.Itoa(protocol.Version)},
		},
	})
	cancel()
	if err != nil {
		if res != nil {
			switch res.StatusCode {
			case http.StatusUnauthorized:
				return false, &dialStatusError{Status: res.StatusCode, Msg: "engine rejected the server token (401: revoked or rotated away); re-join with a new join token"}
			case http.StatusForbidden:
				return false, &dialStatusError{Status: res.StatusCode, Msg: "engine refused this server (403)"}
			}
		}
		return false, err
	}
	c.SetReadLimit(16 << 20)
	a.neg.Store(nil) // nothing is negotiated until this session's hello_ok
	a.mu.Lock()
	a.conn = c
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.conn == c {
			a.conn = nil
		}
		a.mu.Unlock()
		a.neg.Store(nil)
		c.CloseNow()
	}()
	log.Printf("connected to %s", a.wsURL())

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		a.heartbeat()
		t := time.NewTicker(heartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				a.heartbeat()
			}
		}
	}()

	// Dead-link detection (reconnect.go). Ping needs a concurrent reader, which is the loop below; the first ping is one
	// interval away, so the reader is running by then. A miss is only believed when the reader was neither busy in a
	// synchronous handler nor delivering frames during the ping window (frames arriving prove the link is alive).
	var seq atomic.Int64
	var busy atomic.Bool
	var dead atomic.Bool
	go func() {
		t := time.NewTicker(a.tm.pingEvery())
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
			}
			before := seq.Load()
			pctx, pcancel := context.WithTimeout(sctx, a.tm.pingTimeout())
			err := c.Ping(pctx)
			pcancel()
			if err == nil || sctx.Err() != nil {
				continue
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				return // the connection is already closed or a write failed; the reader reports the real reason
			}
			if busy.Load() || seq.Load() != before {
				continue // inconclusive: the reader was occupied or the link delivered data
			}
			log.Printf("dead link: no pong within %s; closing the connection", a.tm.pingTimeout())
			dead.Store(true)
			go func() { _ = c.Close(websocket.StatusGoingAway, "ping timeout") }()
			stop()
			return
		}
	}()

	for {
		_, data, err := c.Read(sctx)
		if err != nil {
			if dead.Load() {
				return accepted, errDeadLink
			}
			return accepted, err
		}
		seq.Add(1)
		var m protocol.Message
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		busy.Store(true)
		switch m.T {
		case "hello_ok":
			accepted = true
			a.negotiate(data)
			// Root harden pre/post-checks use this fresh Ping/Pong proof of the authenticated wss session.
			go a.harden.LinkMonitor(sctx, c)
			log.Printf("engine accepted server %s", a.cfg.ServerID)
			update.MarkAccepted() // a pending self-update is now proven (selfupdate.go)
		case "cmd":
			a.onCommand(m)
		case "rotate_token":
			a.rotateToken(m)
		case "registry_login":
			a.registry.Login(m)
		case "dns_token":
			a.caddy.DNSToken(m)
		case "db_request":
			go a.databases.Request(m)
		case "db_socket_open":
			go a.databases.Socket(m)
		case "db_socket_in", "db_socket_close":
			a.databases.SocketInput(m)
		case "console_open", "console_in", "console_resize", "console_close":
			a.onConsole(m)
		case "cancel":
			a.mu.Lock()
			if fn := a.running[m.ID]; fn != nil {
				fn()
			}
			a.mu.Unlock()
		}
		busy.Store(false)
	}
}

// rotateToken (step 9g): persist the new server token, switch to it for the next connection, then confirm.
// The engine invalidates the old token only after this confirmation (or when the new one is first used), so a
// lost reply can't lock the agent out; the current connection stays up throughout.
func (a *Agent) rotateToken(m protocol.Message) {
	reply := map[string]any{"t": "token_rotated", "id": m.ID, "ok": false}
	if m.ID == "" || !strings.HasPrefix(m.Token, "f2cs_") || len(m.Token) > 256 {
		reply["error"] = "invalid rotation message"
		reply["code"] = protocol.CodeBadRequest // sent only at protocol >= 1 (send drops it below)
		a.send(reply)
		return
	}
	a.mu.Lock()
	cfg := *a.cfg
	a.mu.Unlock()
	if err := config.SaveToken(a.stateDir, cfg, m.Token); err != nil {
		reply["error"] = "could not save the new token: " + err.Error()
		reply["code"] = protocol.V1Code(err)
		a.send(reply)
		return
	}
	a.mu.Lock()
	a.cfg.Token = m.Token
	a.mu.Unlock()
	log.Printf("server token rotated (saved to agent.json)")
	reply["ok"] = true
	a.send(reply)
}

// onCommand answers a command frame. Dedupe by id (journal.go): a finished id gets its cached result again (plus "replayed" at
// protocol >= 1); a running id gets an ack and its single result when it ends; an id that was running when the agent
// restarted is answered by class (UNSAFE: "interrupted"; restart_agent: ok; the others run again); a new id is written to
// running.json, acked and run.
func (a *Agent) onCommand(m protocol.Message) {
	if m.ID == "" {
		return
	}
	proto := a.SessionProtocol()
	sha := argsDigest(m.Type, m.Args)
	// A known id that comes back with a different command is a bug on the sender's side: never run it, never touch the record
	// (protocol >= 1 only; below it the cached or running command wins silently, as before).
	reused := func(have string) bool { return proto >= 1 && have != "" && have != sha }
	a.mu.Lock()
	if a.pruneLocked(a.now()) {
		a.saveDone()
	}
	if r, ok := a.done[m.ID]; ok {
		meta := a.doneMeta[m.ID]
		a.mu.Unlock()
		if reused(meta.ArgsSha) {
			a.sendReused(m.ID, proto)
			return
		}
		log.Printf("cmd %s (%s): duplicate, re-sending cached result", m.ID, m.Type)
		a.send(replayFrame(r, proto))
		return
	}
	if _, ok := a.running[m.ID]; ok {
		rec := a.runRec[m.ID]
		a.mu.Unlock()
		if reused(rec.ArgsSha) {
			a.sendReused(m.ID, proto)
			return
		}
		a.send(map[string]any{"t": "ack", "id": m.ID})
		return
	}
	if rec, ok := a.runRec[m.ID]; ok { // in flight before a restart: no goroutine, no result
		if reused(rec.ArgsSha) {
			a.mu.Unlock()
			a.sendReused(m.ID, proto)
			return
		}
		switch classOf(rec.Type) {
		case classUnsafe:
			b := interruptedResult(m.ID, rec.Type, proto)
			a.recordDoneLocked(m.ID, rec.Type, rec.ArgsSha, b)
			a.mu.Unlock()
			log.Printf("cmd %s (%s): the agent restarted while it was running; answering interrupted", m.ID, rec.Type)
			a.send(json.RawMessage(b))
			return
		case classRestart:
			b, _ := json.Marshal(protocol.ResultMessageFor(m.ID, map[string]any{"restarting": true}, nil, proto))
			a.recordDoneLocked(m.ID, rec.Type, rec.ArgsSha, b)
			a.mu.Unlock()
			log.Printf("cmd %s (%s): the agent restarted while it was running; the restart happened, answering ok", m.ID, rec.Type)
			a.send(json.RawMessage(b))
			return
		}
		log.Printf("cmd %s (%s): the agent restarted while it was running; running it again (safe to repeat)", m.ID, rec.Type)
	}
	// Past its notAfter: refuse without running and without caching, so nothing marks the id as executed (a re-send
	// is checked again; a fresh id is never affected). A missing deadline behaves as before; an invalid one is logged.
	if expired, err := protocol.CommandExpired(m.NotAfter, time.Now()); err != nil {
		log.Printf("cmd %s (%s): ignoring invalid notAfter %q: %v", m.ID, m.Type, m.NotAfter, err)
	} else if expired {
		a.mu.Unlock()
		log.Printf("cmd %s (%s): expired (notAfter %s, now %s); not run", m.ID, m.Type, m.NotAfter, time.Now().UTC().Format(time.RFC3339))
		a.send(protocol.ResultMessageFor(m.ID, nil, protocol.WithCode(protocol.CodeExpired, fmt.Errorf("command %s expired: notAfter %s has passed (agent clock %s, %s skew allowed); not run", m.ID, m.NotAfter, time.Now().UTC().Format(time.RFC3339), protocol.NotAfterSkew)), proto))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.running[m.ID] = cancel
	a.runRec[m.ID] = runRecord{ID: m.ID, Type: m.Type, ArgsSha: sha, NotAfter: m.NotAfter, StartedAt: a.now().UTC()}
	a.saveRunning() // before anything runs, so that a crash leaves the record behind
	a.mu.Unlock()
	a.send(map[string]any{"t": "ack", "id": m.ID})

	go func() {
		defer cancel()
		data, err := a.execute(ctx, m)
		b, _ := json.Marshal(protocol.ResultMessageFor(m.ID, data, err, a.SessionProtocol()))
		a.mu.Lock()
		a.recordDoneLocked(m.ID, m.Type, sha, b)
		a.mu.Unlock()
		log.Printf("cmd %s (%s): ok=%v", m.ID, m.Type, err == nil)
		a.send(json.RawMessage(b)) // if disconnected, the engine re-sends the id on reconnect and gets this cached result
	}()
}

// sendReused answers an id that was already used for a different command (protocol >= 1). It is not cached.
func (a *Agent) sendReused(id string, proto int) {
	log.Printf("cmd %s: id already used for a different command; refusing", id)
	a.send(protocol.ResultMessageFor(id, nil, protocol.BadRequest(fmt.Errorf("command id %s was already used for a different command", id)), proto))
}

func (a *Agent) heartbeat() {
	m := metrics.Collect(a.stateDir)
	containers, _ := docker.ManagedContainers(context.Background())
	hb := map[string]any{
		"t": "hb", "agentVersion": version.Version, "agentHash": update.SelfHash(), "updateV": update.GuardVersion, "update": update.LastResult(a.stateDir), "cpuCount": runtime.NumCPU(), "arch": sysinfo.HostArch(),
		"memoryMb": m.MemTotalMb, "diskGb": m.DiskTotalGb,
		"cpuPct": m.CPUPct, "memUsedMb": m.MemUsedMb, "diskUsedGb": m.DiskUsedGb,
		"containers": containers,
	}
	// Per-app usage (usage.go): capability flag on every beat, the batch on every 4th (~60s).
	hb["usageV"] = metrics.UsageVersion
	hb["consoleV"] = 1                        // console_* messages (console.go)
	hb["consoleHelperV"] = 1                  // f2c helper put into /tmp on console_open (console.go)
	hb["accessV"] = 1                         // Caddy access-log listener on 127.0.0.1:9181 (accesslog.go)
	hb["dockerBuildV"] = build.DockerBuildCap // buildPack "dockerfile" builds (dockerbuild.go); older agents would silently run railpack
	hb["composeV"] = docker.ComposeCap        // Docker Compose stacks (compose.go): stack run options, stack-v1 caps, network_rm, volume_rm, stats detail
	hb["proxyV"] = 1                          // step 45: per-app proxy routes (subroute/authentication/headers/request_body) in caddy_apply
	hb["hardenV"] = harden.SummaryVersion     // follow-up 9.3: hb.harden = {v, runs: last 5 harden runs, newest first} (harden.go)
	if hs := a.harden.SafeSummary(); hs != nil {
		hb["harden"] = hs
	}
	if metrics.UsageDue() {
		hb["apps"] = metrics.AppUsage(context.Background())
	}
	if rows := caddy.TakeAccessMinutes(time.Now()); len(rows) > 0 { // feature C: finished access-log minutes
		hb["access"] = rows
	}
	a.send(hb)
}
