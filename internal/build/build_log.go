package build

// Build log streaming (batched, size-limited, redacted) and process-group control for builds.
// Lines go to the engine as the existing {t:"stream", id, data} frames, the same ones `logs` uses.

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	buildLogFlushEvery = 250 * time.Millisecond
	buildLogBatchBytes = 32 << 10 // one stream frame
	buildLogLineBytes  = 4 << 10  // longer lines are cut
	buildLogMaxBytes   = 4 << 20  // total streamed per build; then one "truncated" notice
	buildLogTailLines  = 200      // kept for the result / error
	buildKillGrace     = 5 * time.Second
)

var buildLogRedactors = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic)\s+)\S+`), "${1}[redacted]"},
	{regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[a-z0-9_]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`), "${1}${2}[redacted]"},
	{regexp.MustCompile(`([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`), "${1}[redacted]@"},
	{regexp.MustCompile(`\b(?:f2c[a-z]?_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})`), "[redacted]"},
}

// buildLog collects build output, redacts it, and streams it in batches. Safe for concurrent writers.
type buildLog struct {
	mu        sync.Mutex
	emit      func(string) // nil: no streaming (tail only)
	secrets   []string
	partial   strings.Builder
	batch     strings.Builder
	sent      int
	truncated bool
	tail      []string
	stop      chan struct{}
	done      chan struct{}
}

func newBuildLog(emit func(string), secrets ...string) *buildLog {
	b := &buildLog{emit: emit, stop: make(chan struct{}), done: make(chan struct{})}
	for _, s := range secrets {
		if len(s) >= 6 {
			b.secrets = append(b.secrets, s)
		}
	}
	go func() {
		defer close(b.done)
		t := time.NewTicker(buildLogFlushEvery)
		defer t.Stop()
		for {
			select {
			case <-b.stop:
				return
			case <-t.C:
				b.mu.Lock()
				b.flushLocked()
				b.mu.Unlock()
			}
		}
	}()
	return b
}

func (b *buildLog) redact(s string) string {
	for _, sec := range b.secrets {
		s = strings.ReplaceAll(s, sec, "[redacted]")
	}
	for _, r := range buildLogRedactors {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// Write takes raw output; \n and \r both end a line (progress output).
func (b *buildLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range string(p) {
		if c == '\n' || c == '\r' {
			b.lineLocked(b.partial.String())
			b.partial.Reset()
			continue
		}
		if b.partial.Len() <= buildLogLineBytes { // one extra byte so lineLocked marks the cut
			b.partial.WriteRune(c)
		}
	}
	return len(p), nil
}

// Line adds one agent-side status line.
func (b *buildLog) Line(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lineLocked(s)
}

func (b *buildLog) lineLocked(s string) {
	s = strings.TrimRight(s, " \t")
	if s == "" {
		return
	}
	if len(s) > buildLogLineBytes {
		s = s[:buildLogLineBytes] + " [line cut]"
	}
	s = b.redact(s)
	b.tail = append(b.tail, s)
	if len(b.tail) > buildLogTailLines {
		b.tail = b.tail[len(b.tail)-buildLogTailLines:]
	}
	if b.emit == nil || b.truncated {
		return
	}
	if b.sent+b.batch.Len()+len(s)+1 > buildLogMaxBytes {
		b.batch.WriteString("[build log truncated: over 4 MB; the end of the log is in the result]\n")
		b.truncated = true
		b.flushLocked()
		return
	}
	b.batch.WriteString(s + "\n")
	if b.batch.Len() >= buildLogBatchBytes {
		b.flushLocked()
	}
}

func (b *buildLog) flushLocked() {
	if b.batch.Len() == 0 || b.emit == nil {
		return
	}
	b.sent += b.batch.Len()
	b.emit(b.batch.String())
	b.batch.Reset()
}

// Close flushes the last partial line and batch and stops the ticker (idempotent).
func (b *buildLog) Close() {
	b.mu.Lock()
	select {
	case <-b.stop:
		b.mu.Unlock()
		return
	default:
	}
	if b.partial.Len() > 0 {
		b.lineLocked(b.partial.String())
		b.partial.Reset()
	}
	b.flushLocked()
	close(b.stop)
	b.mu.Unlock()
	<-b.done
}

// Tail returns the last n kept lines (already redacted).
func (b *buildLog) Tail(n int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.tail
	if len(t) > n {
		t = t[len(t)-n:]
	}
	return strings.Join(t, "\n")
}

// runGroup runs cmd in its own process group. When ctx ends, the whole group (railpack, buildctl/docker
// helpers, docker load) gets SIGTERM, then SIGKILL after a grace period; stragglers are killed on exit too.
func runGroup(ctx context.Context, cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		pgid := cmd.Process.Pid
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		go func() {
			time.Sleep(buildKillGrace)
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}()
		return nil
	}
	cmd.WaitDelay = buildKillGrace + 2*time.Second
	if err := cmd.Start(); err != nil {
		return err
	}
	err := cmd.Wait()
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // leftover children of a finished/killed group
	if ctx.Err() != nil {
		return errors.Join(ctx.Err(), err)
	}
	return err
}
