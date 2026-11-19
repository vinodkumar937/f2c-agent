package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/build"
	"github.com/vinodkumar937/f2c-agent/internal/docker"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

func (a *Agent) execute(ctx context.Context, m protocol.Message) (any, error) {
	if a.execHook != nil { // tests only
		return a.execHook(ctx, m)
	}
	args := m.Args
	if args == nil {
		args = map[string]any{}
	}
	switch m.Type {
	case "pull":
		return docker.Pull(ctx, args)
	case "run":
		return docker.Run(ctx, args)
	case "stop":
		return docker.Stop(ctx, args)
	case "rm":
		return docker.Remove(ctx, args)
	case "logs":
		return a.cmdLogs(ctx, m.ID, args)
	case "stats":
		return docker.Stats(ctx, args)
	case "exec":
		return a.cmdExec(ctx, m.ID, args)
	case "caddy_apply":
		return a.caddy.Apply(ctx, args)
	case "cert_install":
		return a.caddy.CertInstall(args)
	case "tls_warm": // step 4 (certwatch.go)
		return a.caddy.TLSWarm(ctx, args)
	case "http_probe":
		return a.caddy.HTTPProbe(ctx, args)
	case "build": // engine-multimode M2.1 (build.go)
		return a.build.Build(ctx, m.ID, args)
	case "load": // engine-multimode M2.5 (transfer.go)
		return a.build.Load(ctx, m.ID, args)
	case "image_present": // engine-multimode M2.6 (load.go)
		return build.ImagePresent(ctx, args)
	case "self_update": // admin "Update agent" (selfupdate.go)
		return a.update.SelfUpdate(ctx, m.ID, args)
	case "rename": // zero-downtime deploys: <app>-next -> <app> after the swap
		return docker.Rename(ctx, args)
	case "restart_agent": // dashboard "Restart agent": reply, then exit; systemd (Restart=always) starts it again
		scheduleAgentRestart()
		return map[string]any{"restarting": true}, nil
	case "network_rm": // composeV: remove a stack network (compose.go)
		return docker.NetworkRm(ctx, args)
	case "volume_rm": // composeV: remove one stack volume on an explicit delete (compose.go)
		return docker.VolumeRm(ctx, args)
	case "volumes_list": // item 6c: admin volume inventory (volumes.go); needs agent rebuild
		return docker.VolumesList(ctx, args)
	case "harden": // optional "Harden server" (harden.go): request -> root f2c-harden.path/.service -> JSON result
		return a.harden.Run(ctx, args)
	}
	// Text kept exactly: packages/core byo.ts and the engine match /unknown command/ until they read "code".
	return nil, protocol.WithCode(protocol.CodeUnknownCommand, fmt.Errorf("unknown command type %q", m.Type))
}

// cmdLogs streams `docker logs` lines (batched ~every 250ms or 32KB) as stream frames; follow stops on cancel or followSeconds.
func (a *Agent) cmdLogs(ctx context.Context, id string, args map[string]any) (any, error) {
	name, err := docker.ValidName(args)
	if err != nil {
		return nil, err
	}
	if err := docker.RequireManaged(ctx, name); err != nil {
		return nil, err
	}
	n := int(util.Num(args, "tail"))
	if n <= 0 || n > 5000 {
		n = 100
	}
	follow, _ := args["follow"].(bool)
	secs := int(util.Num(args, "followSeconds"))
	if secs <= 0 || secs > 300 {
		secs = 30
	}
	da := []string{"logs", "--tail", strconv.Itoa(n), "--timestamps"}
	if follow {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(secs)*time.Second)
		defer cancel()
		da = append(da, "-f")
	}
	cmd := exec.CommandContext(ctx, "docker", append(da, name)...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait(); pw.Close() }()

	lines, bytesOut := 0, 0
	var recent strings.Builder // the last ~4 KB of output, the error text when docker logs fails
	var buf strings.Builder
	last := time.Now()
	flush := func() {
		if buf.Len() > 0 {
			a.send(map[string]any{"t": "stream", "id": id, "data": buf.String()})
			buf.Reset()
		}
		last = time.Now()
	}
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		buf.WriteString(sc.Text() + "\n")
		recent.WriteString(sc.Text() + "\n")
		if recent.Len() > 8192 {
			t := util.Tail(recent.String(), 4096)
			recent.Reset()
			recent.WriteString(t)
		}
		lines++
		bytesOut += len(sc.Text()) + 1
		if buf.Len() > 32*1024 || time.Since(last) > 250*time.Millisecond {
			flush()
		}
	}
	flush()
	// Protocol >= 1: a non-zero exit of `docker logs` is a failure (a follow that ran out its time, or a cancel, is not).
	// Protocol 0 keeps the old behaviour: ok:true with whatever was streamed.
	if werr := <-waited; werr != nil && ctx.Err() == nil && a.SessionProtocol() >= 1 {
		msg := strings.TrimSpace(recent.String())
		if msg == "" {
			msg = werr.Error()
		}
		return nil, docker.CommandError(ctx, "logs", msg)
	}
	return map[string]any{"lines": lines, "bytes": bytesOut, "followed": follow}, nil
}

// cmdExec runs a command in a managed container (e.g. pg_dump). stdout streams as base64 chunks; stderr tail in the result.
func (a *Agent) cmdExec(ctx context.Context, id string, args map[string]any) (any, error) {
	name, err := docker.ValidName(args)
	if err != nil {
		return nil, err
	}
	if err := docker.RequireManaged(ctx, name); err != nil {
		return nil, err
	}
	raw, _ := args["cmd"].([]any)
	if len(raw) == 0 {
		return nil, protocol.BadRequest(errors.New("cmd must be a non-empty string array"))
	}
	argv := []string{"exec", name}
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			return nil, protocol.BadRequest(errors.New("cmd must be a string array"))
		}
		argv = append(argv, s)
	}
	t := int(util.Num(args, "timeoutSeconds"))
	if t <= 0 || t > 3600 {
		t = 600
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(t)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", argv...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	total := 0
	chunk := make([]byte, 256*1024)
	for {
		n, rerr := stdout.Read(chunk)
		if n > 0 {
			total += n
			a.send(map[string]any{"t": "stream", "id": id, "data": base64.StdEncoding.EncodeToString(chunk[:n])})
		}
		if rerr != nil {
			break
		}
	}
	werr := cmd.Wait()
	code := 0
	if werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			code = ee.ExitCode()
		} else {
			return nil, werr
		}
	}
	return map[string]any{"exitCode": code, "stdoutBytes": total, "stderr": util.Tail(stderr.String(), 4000), "encoding": "base64"}, nil
}

// restartDelay leaves time for the "done" reply to reach the engine before the process exits.
var restartDelay = 2 * time.Second
var exitForRestart = func() { os.Exit(0) }

func scheduleAgentRestart() {
	go func() {
		time.Sleep(restartDelay)
		exitForRestart()
	}()
}
