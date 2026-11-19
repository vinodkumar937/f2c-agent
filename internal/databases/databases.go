package databases

// Database operations use live frames, never the persistent command/result queue.
// The engine is the authenticated authority for org->resource assignment; first registration
// pins that assignment to a managed, labelled container and its inspected named volume.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

const databaseMaxDump int64 = 2 << 30

var databasePart = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var databaseKey = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}\.dump$`)
var databaseLocks sync.Map
var databaseSockets sync.Map
var databaseDownloads sync.Map
var databaseDownloadsMu sync.Mutex

type databaseDownload struct {
	file   *os.File
	path   string
	offset int64
	timer  *time.Timer
	once   sync.Once
}

func closeDatabaseDownload(id string, d *databaseDownload) {
	d.once.Do(func() {
		if d.timer != nil {
			d.timer.Stop()
		}
		d.file.Close()
		databaseDownloads.Delete(id)
	})
}

type Spec struct {
	Generation      string     `json:"generation"`
	Type            string     `json:"type"`
	Org             string     `json:"orgId"`
	Name            string     `json:"databaseName"`
	Container       string     `json:"container"`
	Volume          string     `json:"volume"`
	User            string     `json:"user"`
	Database        string     `json:"database"`
	Next            time.Time  `json:"nextBackupAt"`
	LastBackupAt    *time.Time `json:"lastBackupAt,omitempty"`
	LastBackupError string     `json:"lastBackupError,omitempty"`
	Deleted         bool       `json:"deleted"`
}
type databaseInspect struct {
	Config struct {
		Labels map[string]string
		Env    []string
	}
	Mounts          []struct{ Type, Name string }
	State           struct{ Running bool }
	NetworkSettings struct {
		Ports map[string][]struct{ HostIP, HostPort string }
	}
}
type databaseBackup struct {
	Key       string `json:"key"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"createdAt"`
	Location  string `json:"location"`
	SHA256    string `json:"sha256"`
}

func databaseLock(key string) func() {
	v, _ := databaseLocks.LoadOrStore(key, &sync.Mutex{})
	m := v.(*sync.Mutex)
	if !m.TryLock() {
		return nil
	}
	return m.Unlock
}
func databaseError(code string) error { return errors.New(code) }

// Service runs the managed-database commands (db_request, db_socket_*, backups and the scheduler): the state dir and a
// way to send frames.
type Service struct {
	stateDir string
	send     func(any) bool
}

func (a *Service) databaseDir(s Spec) string {
	return filepath.Join(a.stateDir, "databases", s.Org, s.Name)
}
func (a *Service) databaseSpec(args map[string]any) (Spec, error) {
	var s Spec
	b, _ := json.Marshal(args)
	if json.Unmarshal(b, &s) != nil {
		return s, databaseError("invalid_input")
	}
	if (s.Type != "postgres" && s.Type != "redis") || !databasePart.MatchString(s.Org) || !databasePart.MatchString(s.Name) || s.Container != "f2c-db-"+s.Name || s.Volume != s.Container+"-data" {
		return s, databaseError("invalid_input")
	}
	if s.Generation == "" || len(s.Generation) > 80 || s.User == "" || s.Database == "" || len(s.User) > 63 || len(s.Database) > 63 {
		return s, databaseError("invalid_input")
	}
	return s, nil
}
func databaseContainer(ctx context.Context, s Spec) (*databaseInspect, error) {
	b, err := exec.CommandContext(ctx, "docker", "inspect", s.Container).Output()
	if err != nil {
		return nil, databaseError("database_not_running")
	}
	var rows []databaseInspect
	if json.Unmarshal(b, &rows) != nil || len(rows) != 1 {
		return nil, databaseError("failed")
	}
	d := rows[0]
	if d.Config.Labels["f2c.agent"] != "1" || d.Config.Labels["f2c.db"] != s.Name {
		return nil, databaseError("not_allowed")
	}
	if org := d.Config.Labels["f2c.org"]; org != "" && org != s.Org {
		return nil, databaseError("not_allowed")
	}
	if gen := d.Config.Labels["f2c.generation"]; gen != "" && gen != s.Generation {
		return nil, databaseError("resource_identity_conflict")
	}
	found := false
	for _, m := range d.Mounts {
		if m.Type == "volume" && m.Name == s.Volume {
			found = true
		}
	}
	if !found {
		return nil, databaseError("not_allowed")
	}
	env := map[string]string{}
	for _, v := range d.Config.Env {
		p := strings.SplitN(v, "=", 2)
		if len(p) == 2 {
			env[p[0]] = p[1]
		}
	}
	if s.Type != "redis" && (env["POSTGRES_USER"] != s.User || env["POSTGRES_DB"] != s.Database) {
		return nil, databaseError("unsupported")
	}
	return &d, nil
}
func (a *Service) pinDatabase(ctx context.Context, s Spec) (Spec, error) {
	ownerPath := filepath.Join(a.stateDir, "database-owners", s.Container+".json")
	p := filepath.Join(a.databaseDir(s), "database.json")
	oldBytes, readErr := os.ReadFile(p)
	var old Spec
	if readErr == nil {
		if json.Unmarshal(oldBytes, &old) != nil {
			return s, databaseError("failed")
		}
		if old.Org != s.Org || old.Container != s.Container || old.Volume != s.Volume {
			return s, databaseError("not_allowed")
		}
		if old.Generation != s.Generation {
			// A name may be reused only after completed deletion and a NEW generation-labelled container.
			if !old.Deleted {
				return s, databaseError("resource_identity_conflict")
			}
			d, e := databaseContainer(ctx, s)
			if e != nil || d.Config.Labels["f2c.generation"] != s.Generation {
				return s, databaseError("resource_identity_conflict")
			}
			if e = os.Remove(filepath.Join(a.databaseDir(s), "delete-authorized.json")); e != nil && !os.IsNotExist(e) {
				return s, databaseError("failed")
			}
			s.Next = databaseNext()
			b, _ := json.Marshal(s)
			if databaseWrite0600(ownerPath, b) != nil || databaseWrite0600(p, b) != nil {
				return s, databaseError("failed")
			}
			return s, nil
		}
		if old.Database != s.Database || old.User != s.User || old.Type != s.Type {
			return s, databaseError("not_allowed")
		}
		return old, nil
	}
	if !os.IsNotExist(readErr) {
		return s, databaseError("failed")
	}
	if b, e := os.ReadFile(ownerPath); e == nil {
		var owner Spec
		if json.Unmarshal(b, &owner) != nil || owner.Org != s.Org || owner.Generation != s.Generation {
			return s, databaseError("not_allowed")
		}
	} else if !os.IsNotExist(e) {
		return s, databaseError("failed")
	}
	if _, e := databaseContainer(ctx, s); e != nil {
		return s, e
	}
	s.Next = databaseNext()
	b, _ := json.Marshal(s)
	if databaseWrite0600(ownerPath, b) != nil || databaseWrite0600(p, b) != nil {
		return s, databaseError("failed")
	}
	return s, nil
}

func databaseNext() time.Time {
	n := time.Now().UTC()
	t := time.Date(n.Year(), n.Month(), n.Day(), 2, 0, 0, 0, time.UTC)
	if !t.After(n) {
		t = t.AddDate(0, 0, 1)
	}
	return t
}
func (a *Service) saveDatabase(s Spec) error {
	b, _ := json.Marshal(s)
	return databaseWrite0600(filepath.Join(a.databaseDir(s), "database.json"), b)
}
func (a *Service) Request(m protocol.Message) {
	data, err := a.databaseOperation(m.Type, m.Args)
	response := map[string]any{"t": "db_result", "id": m.ID, "ok": err == nil}
	if err != nil {
		code := err.Error()
		if !regexp.MustCompile(`^[a-z_]{1,64}$`).MatchString(code) {
			code = "failed"
		}
		status := 409
		switch code {
		case "invalid_input", "invalid_backup":
			status = 400
		case "not_allowed":
			status = 403
		case "not_found", "backup_not_found":
			status = 404
		case "backup_failed", "restore_failed":
			status = 500
		}
		response["code"] = code
		response["status"] = status
	} else {
		response["data"] = data
	}
	a.send(response)
}
func (a *Service) databaseOperation(op string, args map[string]any) (any, error) {
	if op == "capabilities" {
		return map[string]any{"protocol": 1, "volumeDelete": true, "backups": true, "query": true, "writeQuery": true, "restoreUpload": true, "offsitePut": true, "volumeBackup": true}, nil
	}
	if op == "volume_backup_create" || op == "volume_backup_offsite" {
		return a.volumeBackupOp(op, args)
	}
	s, err := a.databaseSpec(args)
	if err != nil {
		return nil, err
	}
	unlock := databaseLock(s.Container)
	if unlock == nil {
		return nil, databaseError("operation_busy")
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	s, err = a.pinDatabase(ctx, s)
	if err != nil {
		return nil, err
	}
	if op == "delete" {
		return a.deleteDatabase(ctx, s)
	}
	if s.Deleted {
		return nil, databaseError("not_found")
	}
	if s.Type == "redis" && op != "register" {
		return nil, databaseError("unsupported")
	}
	switch op {
	case "register":
		return map[string]any{"nextBackupAt": s.Next}, nil
	case "backup_list":
		rows, e := a.listDatabaseBackups(s)
		if e != nil {
			return nil, e
		}
		return map[string]any{"backups": rows, "nextBackupAt": s.Next, "lastBackupAt": s.LastBackupAt, "lastBackupError": s.LastBackupError}, nil
	case "backup_create":
		if d, e := databaseContainer(ctx, s); e != nil || !d.State.Running {
			return nil, databaseError("database_not_running")
		}
		r, p, e := a.dumpDatabase(ctx, s, "")
		if e != nil {
			return nil, e
		}
		return map[string]any{"key": r.Key, "size": r.Size, "createdAt": r.CreatedAt, "location": "server", "uploaded": false, "pruned": p}, nil
	case "backup_offsite_put":
		return a.backupOffsitePut(ctx, s, args)
	case "backup_offsite_restore":
		return a.backupOffsiteRestore(ctx, s, args)
	case "backup_close":
		id, _ := args["downloadId"].(string)
		if v, ok := databaseDownloads.Load(id); ok {
			d := v.(*databaseDownload)
			if strings.HasPrefix(d.path, a.databaseDir(s)+string(os.PathSeparator)) {
				closeDatabaseDownload(id, d)
			}
		}
		return map[string]any{"closed": true}, nil
	case "backup_read":
		key, _ := args["key"].(string)
		id, _ := args["downloadId"].(string)
		if !databaseKey.MatchString(key) || !databasePart.MatchString(id) {
			return nil, databaseError("invalid_backup")
		}
		off := int64(util.Num(args, "offset"))
		if off < 0 {
			return nil, databaseError("invalid_input")
		}
		path := filepath.Join(a.databaseDir(s), "backups", key)
		var d *databaseDownload
		if v, ok := databaseDownloads.Load(id); ok {
			d = v.(*databaseDownload)
			if d.path != path || d.offset != off {
				return nil, databaseError("invalid_input")
			}
		} else {
			if off != 0 {
				return nil, databaseError("backup_not_found")
			}
			databaseDownloadsMu.Lock()
			count := 0
			databaseDownloads.Range(func(_, _ any) bool { count++; return true })
			if count >= 16 {
				databaseDownloadsMu.Unlock()
				return nil, databaseError("operation_busy")
			}
			f, e := os.Open(path)
			if e != nil {
				databaseDownloadsMu.Unlock()
				return nil, databaseError("backup_not_found")
			}
			d = &databaseDownload{file: f, path: path}
			databaseDownloads.Store(id, d)
			d.timer = time.AfterFunc(15*time.Minute, func() { closeDatabaseDownload(id, d) })
			databaseDownloadsMu.Unlock()
		}
		info, e := d.file.Stat()
		if e != nil || off > info.Size() {
			closeDatabaseDownload(id, d)
			return nil, databaseError("invalid_input")
		}
		b := make([]byte, 128*1024)
		n, e := d.file.ReadAt(b, off)
		if e != nil && e != io.EOF {
			closeDatabaseDownload(id, d)
			return nil, databaseError("backup_failed")
		}
		d.offset = off + int64(n)
		eof := d.offset >= info.Size()
		if eof {
			closeDatabaseDownload(id, d)
		}
		return map[string]any{"data": base64.StdEncoding.EncodeToString(b[:n]), "offset": off, "size": info.Size(), "eof": eof}, nil

	case "restore":
		return a.restoreDatabase(ctx, s, args)
	case "upload_start", "upload_chunk", "upload_finish", "upload_abort":
		return a.uploadDatabaseBackup(ctx, s, op, args)
	default:
		return nil, databaseError("unsupported")
	}
}
func (a *Service) deleteDatabase(ctx context.Context, s Spec) (any, error) {
	if s.Deleted {
		out, e := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "name=^/"+s.Container+"$").Output()
		if e != nil || strings.TrimSpace(string(out)) != "" {
			return nil, databaseError("resource_identity_conflict")
		}
		out, e = exec.CommandContext(ctx, "docker", "volume", "ls", "-q", "--filter", "name=^"+s.Volume+"$").Output()
		if e != nil || strings.TrimSpace(string(out)) != "" {
			return nil, databaseError("resource_identity_conflict")
		}
		return map[string]any{"deleted": true}, nil
	}
	// Persist a verified manifest BEFORE removing the container; subsequent retries can finish
	// its exact owned volume even if the process crashes after docker rm.
	manifest := filepath.Join(a.databaseDir(s), "delete-authorized.json")
	if _, e := os.Stat(manifest); os.IsNotExist(e) {
		if _, e = databaseContainer(ctx, s); e != nil {
			return nil, e
		}
		b, _ := json.Marshal(s)
		if databaseWrite0600(manifest, b) != nil {
			return nil, databaseError("failed")
		}
	}
	// An existing manifest must exactly match this immutable pinned identity.
	b, e := os.ReadFile(manifest)
	var pinned Spec
	if e != nil || json.Unmarshal(b, &pinned) != nil || pinned.Org != s.Org || pinned.Generation != s.Generation || pinned.Volume != s.Volume || pinned.Container != s.Container {
		return nil, databaseError("not_allowed")
	}
	if out, e := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "name=^/"+s.Container+"$").Output(); e != nil {
		return nil, databaseError("delete_incomplete")
	} else if strings.TrimSpace(string(out)) != "" {
		if _, e := databaseContainer(ctx, s); e != nil {
			return nil, e
		}
		if exec.CommandContext(ctx, "docker", "rm", "-f", s.Container).Run() != nil {
			return nil, databaseError("delete_incomplete")
		}
	}
	// CLI volume ls distinguishes an absent volume from daemon/transport failure.
	out, e := exec.CommandContext(ctx, "docker", "volume", "ls", "-q", "--filter", "name=^"+s.Volume+"$").Output()
	if e != nil {
		return nil, databaseError("delete_incomplete")
	}
	if strings.TrimSpace(string(out)) != "" && exec.CommandContext(ctx, "docker", "volume", "rm", s.Volume).Run() != nil {
		return nil, databaseError("delete_incomplete")
	}
	s.Deleted = true
	if a.saveDatabase(s) != nil {
		return nil, databaseError("delete_incomplete")
	}
	// Retained archives are NOT erased by deleting the live DB volume.
	return map[string]any{"deleted": true}, nil
}
func databaseNewKey() string {
	b := make([]byte, 8)
	f, e := os.Open("/dev/urandom")
	if e == nil {
		_, _ = io.ReadFull(f, b)
		f.Close()
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b) + ".dump"
}
func (a *Service) listDatabaseBackups(s Spec) ([]databaseBackup, error) {
	dir := filepath.Join(a.databaseDir(s), "backups")
	es, e := os.ReadDir(dir)
	if os.IsNotExist(e) {
		return []databaseBackup{}, nil
	}
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	rows := []databaseBackup{}
	for _, entry := range es {
		if !databaseKey.MatchString(entry.Name()) {
			continue
		}
		b, e := os.ReadFile(filepath.Join(dir, entry.Name()+".json"))
		var r databaseBackup
		if e != nil || json.Unmarshal(b, &r) != nil {
			return nil, databaseError("backup_failed")
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, rows[i].CreatedAt)
		b, _ := time.Parse(time.RFC3339Nano, rows[j].CreatedAt)
		if a.Equal(b) {
			return rows[i].Key > rows[j].Key
		}
		return a.After(b)
	})
	return rows, nil
}
func (a *Service) pruneDatabase(s Spec, pin string) ([]string, error) {
	rows, e := a.listDatabaseBackups(s)
	if e != nil {
		return nil, e
	}
	pruned := []string{}
	keep := map[string]bool{}
	if pin != "" {
		keep[pin] = true
	}
	for _, r := range rows {
		if len(keep) >= 7 {
			break
		}
		keep[r.Key] = true
	}
	for _, r := range rows {
		if keep[r.Key] {
			continue
		}
		p := filepath.Join(a.databaseDir(s), "backups", r.Key)
		if os.Remove(p) != nil {
			return nil, databaseError("backup_failed")
		}
		_ = os.Remove(p + ".json")
		pruned = append(pruned, r.Key)
	}
	return pruned, nil
}
func (a *Service) dumpDatabase(ctx context.Context, s Spec, pin string) (databaseBackup, []string, error) {
	var r databaseBackup
	dir := filepath.Join(a.databaseDir(s), "backups")
	if os.MkdirAll(dir, 0700) != nil {
		return r, nil, databaseError("backup_failed")
	}
	if !databaseSpaceAvailable(dir, databaseMaxDump+(1<<30)) {
		return r, nil, databaseError("insufficient_storage")
	}
	key := databaseNewKey()
	path := filepath.Join(dir, key)
	f, e := os.OpenFile(path+".partial", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return r, nil, databaseError("backup_failed")
	}
	defer os.Remove(path + ".partial")
	cmd := exec.CommandContext(ctx, "docker", "exec", s.Container, "pg_dump", "-U", s.User, "-d", s.Database, "-Fc", "--no-owner", "--no-acl")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		f.Close()
		return r, nil, databaseError("backup_failed")
	}
	if cmd.Start() != nil {
		f.Close()
		return r, nil, databaseError("backup_failed")
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(stdout, databaseMaxDump+1))
	if e != nil || n > databaseMaxDump {
		_ = cmd.Process.Kill()
	}
	wait := cmd.Wait()
	syncErr := f.Sync()
	closeErr := f.Close()
	if e != nil || wait != nil || syncErr != nil || closeErr != nil || n == 0 || n > databaseMaxDump {
		return r, nil, databaseError("backup_failed")
	}
	r = databaseBackup{key, n, time.Now().UTC().Format(time.RFC3339Nano), "server", hex.EncodeToString(h.Sum(nil))}
	b, _ := json.Marshal(r)
	if databaseWrite0600(path+".json", b) != nil || os.Rename(path+".partial", path) != nil {
		return r, nil, databaseError("backup_failed")
	}
	if databaseSyncPath(path) != nil {
		return r, nil, databaseError("backup_failed")
	}
	pruned, e := a.pruneDatabase(s, pin)
	if e != nil {
		return r, pruned, e
	}
	now := time.Now().UTC()
	s.LastBackupAt = &now
	s.LastBackupError = ""
	if a.saveDatabase(s) != nil {
		return r, pruned, databaseError("backup_failed")
	}
	return r, pruned, nil
}
func databaseArchive(ctx context.Context, s Spec, path string) error {
	f, e := os.Open(path)
	if e != nil {
		return databaseError("backup_not_found")
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", s.Container, "pg_restore", "--list")
	cmd.Stdin = f
	if cmd.Run() != nil {
		return databaseError("invalid_backup")
	}
	return nil
}
func (a *Service) restoreDatabase(ctx context.Context, s Spec, args map[string]any) (any, error) {
	if d, e := databaseContainer(ctx, s); e != nil || !d.State.Running {
		return nil, databaseError("database_not_running")
	}
	key, _ := args["key"].(string)
	if !databaseKey.MatchString(key) {
		return nil, databaseError("invalid_backup")
	}
	path := filepath.Join(a.databaseDir(s), "backups", key)
	if e := databaseArchive(ctx, s, path); e != nil {
		return nil, e
	}
	b, e := os.ReadFile(path + ".json")
	var meta databaseBackup
	if e != nil || json.Unmarshal(b, &meta) != nil {
		return nil, databaseError("invalid_backup")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, databaseError("backup_not_found")
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	f.Close()
	if e != nil || hex.EncodeToString(h.Sum(nil)) != meta.SHA256 {
		return nil, databaseError("invalid_backup")
	}
	// Safety snapshot succeeds before any destructive restore; pin selected archive during pruning.
	if _, _, e = a.dumpDatabase(ctx, s, key); e != nil {
		return nil, e
	}
	f, e = os.Open(path)
	if e != nil {
		return nil, databaseError("backup_not_found")
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", s.Container, "pg_restore", "-U", s.User, "-d", s.Database, "--clean", "--if-exists", "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl")
	cmd.Stdin = f
	if e := cmd.Run(); e != nil {
		if ctx.Err() != nil {
			return nil, databaseError("restore_timeout")
		}
		log.Printf("[database-restore] pg_restore exited unsuccessfully")
		return nil, databaseError("restore_failed")
	}
	_, e = a.pruneDatabase(s, key)
	if e != nil {
		return nil, e
	}
	return map[string]any{"restored": key, "downloaded": false}, nil
}
func (a *Service) uploadDatabaseBackup(ctx context.Context, s Spec, op string, args map[string]any) (any, error) {
	dir := filepath.Join(a.databaseDir(s), "backups")
	if os.MkdirAll(dir, 0700) != nil {
		return nil, databaseError("backup_failed")
	}
	if op == "upload_start" {
		entries, e := os.ReadDir(dir)
		if e != nil {
			return nil, databaseError("backup_failed")
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".upload") {
				return nil, databaseError("operation_busy")
			}
		}
		if !databaseSpaceAvailable(dir, (1 << 30)) {
			return nil, databaseError("insufficient_storage")
		}
		key := databaseNewKey()
		f, e := os.OpenFile(filepath.Join(dir, key+".upload"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, databaseError("backup_failed")
		}
		f.Close()
		return map[string]any{"key": key}, nil
	}
	key, _ := args["key"].(string)
	if !databaseKey.MatchString(key) {
		return nil, databaseError("invalid_backup")
	}
	p := filepath.Join(dir, key)
	if op == "upload_abort" {
		if e := os.Remove(p + ".upload"); e != nil && !os.IsNotExist(e) {
			return nil, databaseError("backup_failed")
		}
		return map[string]any{"aborted": true, "key": key}, nil
	}
	if op == "upload_chunk" {
		data, _ := args["data"].(string)
		if len(data) > 180000 {
			return nil, databaseError("invalid_input")
		}
		b, e := base64.StdEncoding.DecodeString(data)
		if e != nil {
			return nil, databaseError("invalid_input")
		}
		if !databaseSpaceAvailable(dir, int64(len(b))+(1<<30)) {
			return nil, databaseError("insufficient_storage")
		}
		f, e := os.OpenFile(p+".upload", os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			return nil, databaseError("backup_not_found")
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || st.Size() != int64(util.Num(args, "offset")) || st.Size()+int64(len(b)) > databaseMaxDump {
			return nil, databaseError("invalid_input")
		}
		_, e = f.Write(b)
		if e != nil {
			return nil, databaseError("backup_failed")
		}
		return map[string]any{"offset": st.Size() + int64(len(b))}, nil
	}
	if d, e := databaseContainer(ctx, s); e != nil || !d.State.Running {
		return nil, databaseError("database_not_running")
	}
	if e := databaseArchive(ctx, s, p+".upload"); e != nil {
		return nil, e
	}
	f, e := os.Open(p + ".upload")
	if e != nil {
		return nil, databaseError("backup_not_found")
	}
	h := sha256.New()
	n, e := io.Copy(h, f)
	f.Close()
	expected, _ := args["sha256"].(string)
	if e != nil || hex.EncodeToString(h.Sum(nil)) != expected {
		return nil, databaseError("invalid_backup")
	}
	r := databaseBackup{key, n, time.Now().UTC().Format(time.RFC3339Nano), "server", expected}
	b, _ := json.Marshal(r)
	if databaseWrite0600(p+".json", b) != nil || os.Rename(p+".upload", p) != nil {
		return nil, databaseError("backup_failed")
	}
	if databaseSyncPath(p) != nil {
		return nil, databaseError("backup_failed")
	}
	if _, e = a.pruneDatabase(s, ""); e != nil {
		return nil, e
	}
	return r, nil
}
func (a *Service) Scheduler(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			base := filepath.Join(a.stateDir, "databases")
			walkErr := filepath.WalkDir(base, func(path string, d os.DirEntry, e error) error {
				if e != nil {
					if os.IsNotExist(e) {
						return nil
					}
					log.Printf("[database-backup] directory traversal failed")
					return nil // continue sibling schedules; report inaccessible subtree without starving all backups
				}
				if d.IsDir() && d.Name() == "backups" {
					return filepath.SkipDir
				}
				if d.Name() != "database.json" {
					return nil
				}
				b, e := os.ReadFile(path)
				var s Spec
				if e != nil {
					log.Printf("[database-backup] schedule read failed")
					return nil
				}
				if json.Unmarshal(b, &s) != nil {
					log.Printf("[database-backup] invalid schedule metadata")
					return nil
				}
				if s.Deleted || s.Type == "redis" || s.Next.After(time.Now()) {
					return nil
				}
				unlock := databaseLock(s.Container)
				if unlock == nil {
					return nil
				}
				defer unlock()
				task, cancel := context.WithTimeout(ctx, 30*time.Minute)
				defer cancel()
				s.LastBackupError = "database_not_running"
				if d, e := databaseContainer(task, s); e == nil && d.State.Running {
					if _, _, e = a.dumpDatabase(task, s, ""); e == nil {
						now := time.Now().UTC()
						s.LastBackupAt = &now
						s.LastBackupError = ""
					} else {
						s.LastBackupError = "backup_failed"
					}
				}
				dir := filepath.Join(a.databaseDir(s), "backups")
				if entries, e := os.ReadDir(dir); e == nil {
					for _, entry := range entries {
						if strings.HasSuffix(entry.Name(), ".upload") || strings.HasSuffix(entry.Name(), ".partial") {
							if info, e := entry.Info(); e == nil && time.Since(info.ModTime()) > 24*time.Hour {
								_ = os.Remove(filepath.Join(dir, entry.Name()))
							}
						}
					}
				}
				s.Next = databaseNext()
				if s.LastBackupError != "" {
					s.Next = time.Now().Add(15 * time.Minute)
					log.Printf("[database-backup] backup did not complete: %s", s.LastBackupError)
				}
				if e := a.saveDatabase(s); e != nil {
					log.Printf("[database-backup] schedule persistence failed")
				}
				return nil
			})
			if walkErr != nil {
				log.Printf("[database-backup] traversal incomplete")
			}
		}
	}
}
func (a *Service) Socket(m protocol.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, e := a.databaseSpec(m.Args)
	if e != nil {
		a.send(map[string]any{"t": "db_socket_end", "id": m.ID, "error": true})
		return
	}
	unlock := databaseLock(s.Container)
	if unlock == nil {
		a.send(map[string]any{"t": "db_socket_end", "id": m.ID, "error": "operation_busy"})
		return
	}
	defer unlock()
	s, e = a.pinDatabase(ctx, s)
	if e != nil || s.Deleted {
		a.send(map[string]any{"t": "db_socket_end", "id": m.ID, "error": true})
		return
	}
	d, e := databaseContainer(ctx, s)
	if e != nil || !d.State.Running {
		a.send(map[string]any{"t": "db_socket_end", "id": m.ID, "error": "database_not_running"})
		return
	}
	// No arbitrary target: derive the loopback port from the exact managed DB container.
	ports := d.NetworkSettings.Ports["5432/tcp"]
	port := ""
	for _, p := range ports {
		if p.HostIP == "127.0.0.1" {
			if n, e := strconv.Atoi(p.HostPort); e == nil && n > 0 && n < 65536 {
				port = p.HostPort
			}
		}
	}
	if port == "" {
		a.send(map[string]any{"t": "db_socket_end", "id": m.ID, "error": true})
		return
	}
	conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
	if e != nil {
		a.send(map[string]any{"t": "db_socket_end", "id": m.ID, "error": true})
		return
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	databaseSockets.Store(m.ID, conn)
	defer databaseSockets.Delete(m.ID)
	defer conn.Close()
	a.send(map[string]any{"t": "db_socket_ready", "id": m.ID})
	buf := make([]byte, 128*1024)
	total := 0
	for {
		n, e := conn.Read(buf)
		total += n
		if total > 4*1024*1024 {
			a.send(map[string]any{"t": "db_socket_end", "id": m.ID, "error": "query_too_large"})
			return
		}
		if n > 0 && !a.send(map[string]any{"t": "db_socket_out", "id": m.ID, "d": base64.StdEncoding.EncodeToString(buf[:n])}) {
			break
		}
		if e != nil {
			break
		}
	}
	a.send(map[string]any{"t": "db_socket_end", "id": m.ID})
}
func (a *Service) SocketInput(m protocol.Message) {
	v, ok := databaseSockets.Load(m.ID)
	if !ok {
		return
	}
	c := v.(net.Conn)
	if m.T == "db_socket_close" {
		c.Close()
		return
	}
	if len(m.D) > 180000 {
		c.Close()
		return
	}
	b, e := base64.StdEncoding.DecodeString(m.D)
	if e != nil {
		c.Close()
		return
	}
	if _, e = c.Write(b); e != nil {
		c.Close()
	}
}

func databaseWrite0600(path string, b []byte) error {
	if e := config.WriteFile0600(path, b); e != nil {
		return e
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

func databaseSpaceAvailable(dir string, needed int64) bool {
	var s syscall.Statfs_t
	if syscall.Statfs(dir, &s) != nil {
		return false
	}
	return uint64(s.Bavail)*uint64(s.Bsize) >= uint64(needed)
}
func databaseSyncPath(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// backupOffsitePut streams a local on-server dump to a presigned PUT URL (engine holds S3 creds).
func (a *Service) backupOffsitePut(ctx context.Context, s Spec, args map[string]any) (any, error) {
	key, _ := args["key"].(string)
	url, _ := args["url"].(string)
	objectKey, _ := args["objectKey"].(string)
	if !databaseKey.MatchString(key) || url == "" || objectKey == "" {
		return nil, databaseError("invalid_input")
	}
	path := filepath.Join(a.databaseDir(s), "backups", key)
	f, e := os.Open(path)
	if e != nil {
		return nil, databaseError("backup_not_found")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPut, url, f)
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Type", "application/octet-stream")
	if h, ok := args["headers"].(map[string]any); ok {
		for k, v := range h {
			if s, ok := v.(string); ok {
				req.Header.Set(k, s)
			}
		}
	}
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, databaseError("backup_failed")
	}
	return map[string]any{"uploaded": true, "objectKey": objectKey, "size": info.Size()}, nil
}

// backupOffsiteRestore downloads a dump from a presigned GET URL and restores it (cross-server).
func (a *Service) backupOffsiteRestore(ctx context.Context, s Spec, args map[string]any) (any, error) {
	url, _ := args["url"].(string)
	objectKey, _ := args["objectKey"].(string)
	if url == "" || objectKey == "" {
		return nil, databaseError("invalid_input")
	}
	if d, e := databaseContainer(ctx, s); e != nil || !d.State.Running {
		return nil, databaseError("database_not_running")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return nil, databaseError("restore_failed")
	}
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		return nil, databaseError("restore_failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		io.Copy(io.Discard, res.Body)
		return nil, databaseError("restore_failed")
	}
	dir := filepath.Join(a.databaseDir(s), "backups")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, databaseError("restore_failed")
	}
	key := databaseNewKey()
	path := filepath.Join(dir, key)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, databaseError("restore_failed")
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, databaseMaxDump+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if e != nil || syncErr != nil || closeErr != nil || n == 0 || n > databaseMaxDump {
		os.Remove(path)
		return nil, databaseError("restore_failed")
	}
	meta := databaseBackup{key, n, time.Now().UTC().Format(time.RFC3339Nano), "server", hex.EncodeToString(h.Sum(nil))}
	b, _ := json.Marshal(meta)
	_ = os.WriteFile(path+".json", b, 0600)
	return a.restoreDatabase(ctx, s, map[string]any{"key": key})
}

// volumeBackupOp tars an f2c-* Docker volume; optionally PUTs to a presigned URL.
func (a *Service) volumeBackupOp(op string, args map[string]any) (any, error) {
	volume, _ := args["volume"].(string)
	if volume == "" || !strings.HasPrefix(volume, "f2c-") || strings.ContainsAny(volume, "/\\:") {
		return nil, databaseError("invalid_input")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	tmp, e := os.MkdirTemp("", "f2c-volbak-*")
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "volume.tar.gz")
	// Alpine helper: tar the volume contents via a short-lived container.
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"-v", volume+":/data:ro",
		"-v", tmp+":/out",
		"alpine:3.20",
		"sh", "-c", "tar -czf /out/volume.tar.gz -C /data .")
	if e := cmd.Run(); e != nil {
		return nil, databaseError("backup_failed")
	}
	info, e := os.Stat(out)
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	if op == "volume_backup_create" {
		return map[string]any{"volume": volume, "size": info.Size(), "location": "server", "uploaded": false}, nil
	}
	url, _ := args["url"].(string)
	objectKey, _ := args["objectKey"].(string)
	if url == "" || objectKey == "" {
		return nil, databaseError("invalid_input")
	}
	f, e := os.Open(out)
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	defer f.Close()
	req, e := http.NewRequestWithContext(ctx, http.MethodPut, url, f)
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Type", "application/octet-stream")
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		return nil, databaseError("backup_failed")
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, databaseError("backup_failed")
	}
	return map[string]any{"volume": volume, "size": info.Size(), "uploaded": true, "objectKey": objectKey, "location": "both"}, nil
}

// New builds the database service from the agent's state dir and a frame sender.
func New(stateDir string, send func(any) bool) *Service {
	return &Service{stateDir: stateDir, send: send}
}
