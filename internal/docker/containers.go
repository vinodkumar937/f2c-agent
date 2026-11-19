package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

const ManagedLabel = "f2c.agent"

var (
	NameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	imageRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$`)
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	DomainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	// Networks and volumes the agent may use: f2c-* names only (e.g. the per-server f2c-net).
	f2cNameRe  = regexp.MustCompile(`^f2c-[a-z0-9][a-z0-9_.-]{0,58}$`)
	labelKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

const (
	maxVolumes     = 8
	maxLabels      = 32
	maxCmdArgs     = 64
	maxCmdArgLen   = 4096
	maxLabelValLen = 1024
)

// runArgKeys is the full set of `run` args; anything else (privileged, binds, networkMode, ...) is refused.
var runArgKeys = map[string]bool{
	"name": true, "image": true, "env": true, "memoryMb": true, "cpus": true, "port": true, "hostPort": true,
	"network": true, "volumes": true, "cmd": true, "labels": true,
}

type volumeMount struct {
	Name     string
	Target   string
	ReadOnly bool
}

// runOptions are the step 9d `run` options: an f2c-* network, named f2c-* volumes, cmd and labels.
type runOptions struct {
	Network string
	Volumes []volumeMount
	Cmd     []string
	Labels  map[string]string
	// Stack: the composeV options (compose.go); zero value = a plain app container.
	Stack stackOptions
}

// parseRunOptions validates the optional `run` args. Pure (no docker), so commands_test.go covers it.
// The engine applies the same rules with the same messages.
func parseRunOptions(args map[string]any) (runOptions, error) {
	o, err := parseRunOptionsRaw(args)
	return o, protocol.BadRequest(err) // policy refusals inside carry not_allowed and keep it
}

// denied is a policy refusal (code not_allowed at protocol >= 1).
func denied(msg string) error { return protocol.WithCode(protocol.CodeNotAllowed, errors.New(msg)) }

func parseRunOptionsRaw(args map[string]any) (runOptions, error) {
	var o runOptions
	for k := range args {
		if runArgKeys[k] {
			continue
		}
		switch k {
		case "privileged":
			return o, denied("privileged containers are not allowed")
		case "networkMode", "hostNetwork", "pid", "ipc":
			return o, denied("host network or namespaces are not allowed")
		case "binds", "mounts", "bind":
			return o, denied("bind mounts are not allowed")
		}
		return o, fmt.Errorf("unknown run option %q", k)
	}

	if v, ok := args["network"]; ok && v != nil {
		s, _ := v.(string)
		switch {
		case s == "host":
			return o, denied("host network or namespaces are not allowed")
		case !f2cNameRe.MatchString(s):
			return o, errors.New("network must be an f2c-* name (e.g. f2c-net)")
		}
		o.Network = s
	}

	if v, ok := args["volumes"]; ok && v != nil {
		list, ok := v.([]any)
		if !ok {
			return o, errors.New("volumes must be an array of {name, target, readOnly}")
		}
		if len(list) > maxVolumes {
			return o, fmt.Errorf("at most %d volumes", maxVolumes)
		}
		targets := map[string]bool{}
		for _, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				return o, errors.New("volumes must be an array of {name, target, readOnly}")
			}
			for k := range m {
				if k == "type" && m[k] != "volume" {
					return o, denied("bind mounts are not allowed")
				}
				if k != "name" && k != "target" && k != "readOnly" && k != "type" {
					return o, fmt.Errorf("unknown volume option %q", k)
				}
			}
			name, target := util.Str(m, "name"), util.Str(m, "target")
			if strings.ContainsAny(name, `/\~`) || strings.HasPrefix(name, ".") {
				return o, denied("bind mounts are not allowed")
			}
			if !f2cNameRe.MatchString(name) {
				return o, errors.New("volume name must be an f2c-* name")
			}
			if !strings.HasPrefix(target, "/") || target == "/" || filepath.Clean(target) != target || strings.ContainsAny(target, ",:\n") {
				return o, errors.New("volume target must be an absolute, clean path other than /")
			}
			if targets[target] {
				return o, fmt.Errorf("duplicate volume target %s", target)
			}
			targets[target] = true
			ro, _ := m["readOnly"].(bool)
			o.Volumes = append(o.Volumes, volumeMount{name, target, ro})
		}
	}

	if v, ok := args["cmd"]; ok && v != nil {
		list, ok := v.([]any)
		if !ok || len(list) == 0 || len(list) > maxCmdArgs {
			return o, fmt.Errorf("cmd must be a non-empty string array (at most %d items)", maxCmdArgs)
		}
		for _, item := range list {
			s, ok := item.(string)
			if !ok || len(s) > maxCmdArgLen || strings.ContainsRune(s, 0) {
				return o, fmt.Errorf("cmd must be a non-empty string array (at most %d items)", maxCmdArgs)
			}
			o.Cmd = append(o.Cmd, s)
		}
	}

	if v, ok := args["labels"]; ok && v != nil {
		m, ok := v.(map[string]any)
		if !ok {
			return o, errors.New("labels must be an object of strings")
		}
		if len(m) > maxLabels {
			return o, fmt.Errorf("at most %d labels", maxLabels)
		}
		o.Labels = map[string]string{}
		for k, val := range m {
			s, ok := val.(string)
			if !ok {
				return o, errors.New("labels must be an object of strings")
			}
			if !labelKeyRe.MatchString(k) {
				return o, fmt.Errorf("invalid label key %q", k)
			}
			if k == ManagedLabel || k == "f2c.app" {
				return o, protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("label %q is reserved", k))
			}
			if len(s) > maxLabelValLen || strings.ContainsAny(s, "\n\r") {
				return o, fmt.Errorf("label values must be at most %d characters without newlines", maxLabelValLen)
			}
			o.Labels[k] = s
		}
	}
	if err := parseStackOptions(args, &o); err != nil {
		return o, err
	}
	return o, nil
}

// dockerRunOptionArgs turns validated options into `docker run` flags (cmd goes after the image).
func dockerRunOptionArgs(o runOptions) []string {
	var ra []string
	if o.Network != "" {
		ra = append(ra, "--network", o.Network)
	}
	for _, v := range o.Volumes {
		m := "type=volume,src=" + v.Name + ",dst=" + v.Target
		if v.ReadOnly {
			m += ",readonly"
		}
		ra = append(ra, "--mount", m)
	}
	keys := make([]string, 0, len(o.Labels))
	for k := range o.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ra = append(ra, "--label", k+"="+o.Labels[k])
	}
	ra = append(ra, stackDockerArgs(o)...)
	return ra
}

// ensureNetwork creates the f2c-* bridge network if it doesn't exist yet (labelled as the agent's).
func ensureNetwork(ctx context.Context, name string) error {
	if _, err := CLI(ctx, "network", "inspect", "-f", "{{.Name}}", name); err == nil {
		return nil
	}
	if _, err := CLI(ctx, "network", "create", "--driver", "bridge", "--label", ManagedLabel+"=1", name); err != nil {
		// Lost a race with a concurrent run: fine if it exists now.
		if _, ierr := CLI(ctx, "network", "inspect", "-f", "{{.Name}}", name); ierr == nil {
			return nil
		}
		return err
	}
	return nil
}

func CLI(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if args[0] == "pull" {
		cmd.Env = pullEnv() // nil = inherit
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", CommandError(ctx, args[0], msg)
	}
	return strings.TrimSpace(out.String()), nil
}

// CommandError is the error of a failed `docker <verb>`: the text "docker <verb>: <stderr tail>" (unchanged) carrying the
// code classifyCLI finds, which only reaches the engine at protocol >= 1 (protocol.ResultMessageFor).
func CommandError(ctx context.Context, verb, msg string) error {
	e := fmt.Errorf("docker %s: %s", verb, util.Tail(msg, 2000))
	if code := classifyCLI(ctx, verb, msg); code != "" {
		return protocol.WithCode(code, e)
	}
	return e
}

func ValidName(args map[string]any) (string, error) {
	n := util.Str(args, "name")
	if !NameRe.MatchString(n) {
		return "", protocol.BadRequest(errors.New("name must match [a-z0-9][a-z0-9_.-]{0,62}"))
	}
	return n, nil
}

// managed reports whether the container exists and whether the agent created it.
func managed(ctx context.Context, name string) (exists, ours bool) {
	out, err := CLI(ctx, "inspect", "-f", `{{index .Config.Labels "`+ManagedLabel+`"}}`, name)
	if err != nil {
		return false, false
	}
	return true, out == "1"
}

func RequireManaged(ctx context.Context, name string) error {
	exists, ours := managed(ctx, name)
	if !exists {
		return protocol.WithCode(protocol.CodeNotFound, fmt.Errorf("container %s not found", name))
	}
	if !ours {
		return protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("container %s is not managed by the agent", name))
	}
	return nil
}

type containerInfo struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Image  string `json:"image"`
	Status string `json:"status"`
	// HostPort: the loopback port the app's container port is published on (0 = none or unknown).
	HostPort int `json:"hostPort,omitempty"`
}

// Fixed host ports: the engine allocates one per app and server inside this range (below Docker's random
// range 32768+), so Docker restarts (restart policy, OOM kill) keep the same port. 0 = legacy random port.
// The engine allocates from the same range (docs/protocol.md); keep the two identical.
const (
	hostPortMin = 20000
	hostPortMax = 29999
)

var publishedRe = regexp.MustCompile(`127\.0\.0\.1:(\d+)->\d+/tcp`)

// parseHostPort reads the first loopback host port from `docker ps` Ports, e.g. "127.0.0.1:20001->3000/tcp".
func parseHostPort(ports string) int {
	m := publishedRe.FindStringSubmatch(ports)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func validHostPort(p int) bool {
	return p == 0 || (p >= hostPortMin && p <= hostPortMax)
}

func ManagedContainers(ctx context.Context) ([]containerInfo, error) {
	out, err := CLI(ctx, "ps", "-a", "--filter", "label="+ManagedLabel+"=1", "--format", "{{.Names}}\t{{.State}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}")
	if err != nil {
		return nil, err
	}
	list := []containerInfo{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 5 {
			list = append(list, containerInfo{Name: f[0], State: f[1], Image: f[2], Status: f[3], HostPort: parseHostPort(f[4])})
		}
	}
	return list, nil
}

// --- commands --------------------------------------------------------------------------------

func Pull(ctx context.Context, args map[string]any) (any, error) {
	img := util.Str(args, "image")
	if !imageRe.MatchString(img) {
		return nil, protocol.BadRequest(errors.New("invalid image reference"))
	}
	if _, err := CLI(ctx, "pull", "-q", img); err != nil {
		return nil, err
	}
	id, _ := CLI(ctx, "image", "inspect", "-f", "{{.Id}}", img)
	return map[string]any{"image": img, "id": id}, nil
}

func Run(ctx context.Context, args map[string]any) (any, error) {
	name, err := ValidName(args)
	if err != nil {
		return nil, err
	}
	img := util.Str(args, "image")
	if !imageRe.MatchString(img) {
		return nil, protocol.BadRequest(errors.New("invalid image reference"))
	}
	port := int(util.Num(args, "port"))
	if port <= 0 || port > 65535 {
		port = 3000
	}
	hostPort := int(util.Num(args, "hostPort"))
	if !validHostPort(hostPort) {
		return nil, protocol.BadRequest(fmt.Errorf("invalid hostPort: must be 0 or %d-%d", hostPortMin, hostPortMax))
	}
	opts, err := parseRunOptions(args)
	if err != nil {
		return nil, err
	}
	if exists, ours := managed(ctx, name); exists {
		if !ours {
			return nil, protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("container %s exists and is not managed by the agent", name))
		}
		if _, err := CLI(ctx, "rm", "-f", name); err != nil {
			return nil, err
		}
	}

	// Env goes through a 0600 temp file, never the command line.
	dir, err := os.MkdirTemp("", "f2c-agent-env-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	var envb strings.Builder
	if env, ok := args["env"].(map[string]any); ok {
		for k, v := range env {
			s, _ := v.(string)
			if !envKeyRe.MatchString(k) {
				return nil, protocol.BadRequest(fmt.Errorf("invalid env key %q", k))
			}
			envb.WriteString(k + "=" + strings.ReplaceAll(s, "\n", `\n`) + "\n")
		}
	}
	envFile := filepath.Join(dir, "env")
	if err := os.WriteFile(envFile, []byte(envb.String()), 0o600); err != nil {
		return nil, err
	}

	hp := ""
	if hostPort > 0 {
		hp = strconv.Itoa(hostPort)
	}
	restartPolicy := "unless-stopped"
	if opts.Stack.OneShot {
		restartPolicy = "no" // a one-shot job must not be restarted after it exits 0
	}
	ra := []string{"run", "-d", "--name", name, "--restart", restartPolicy,
		"--label", ManagedLabel + "=1", "--label", "f2c.app=" + name,
		"--log-opt", "max-size=10m", "--log-opt", "max-file=3",
		"--env-file", envFile}
	if !opts.Stack.NoPublish { // a private stack service publishes nothing and gets no PORT (composeV noPublish)
		ra = append(ra, "-p", "127.0.0.1:"+hp+":"+strconv.Itoa(port), // loopback only: the server's Caddy is the way in
			"-e", "PORT="+strconv.Itoa(port))
	}
	if mb := int(util.Num(args, "memoryMb")); mb > 0 {
		ra = append(ra, "--memory", fmt.Sprintf("%dm", mb), "--memory-swap", fmt.Sprintf("%dm", mb))
	}
	if c := util.Num(args, "cpus"); c > 0 {
		ra = append(ra, "--cpus", strconv.FormatFloat(c, 'f', -1, 64))
	}
	if opts.Network != "" {
		if err := ensureNetwork(ctx, opts.Network); err != nil {
			return nil, err
		}
	}
	ra = append(ra, dockerRunOptionArgs(opts)...)
	ra = append(ra, img)
	ra = append(ra, runTailArgs(opts)...)
	id, err := CLI(ctx, ra...)
	if err != nil {
		return nil, err
	}
	logRunCaps(name, opts)
	got := 0
	if !opts.Stack.NoPublish {
		mapped, _ := CLI(ctx, "port", name, strconv.Itoa(port)+"/tcp")
		if i := strings.LastIndex(strings.Split(mapped, "\n")[0], ":"); i >= 0 {
			got, _ = strconv.Atoi(strings.Split(mapped, "\n")[0][i+1:])
		}
	}
	return map[string]any{"containerId": util.Tail(id, 64), "hostPort": got, "caps": capsReport(opts)}, nil
}

func Stop(ctx context.Context, args map[string]any) (any, error) {
	name, err := ValidName(args)
	if err != nil {
		return nil, err
	}
	if err := RequireManaged(ctx, name); err != nil {
		return nil, err
	}
	t := int(util.Num(args, "timeout"))
	if t <= 0 || t > 120 {
		t = 10
	}
	_, err = CLI(ctx, "stop", "-t", strconv.Itoa(t), name)
	return map[string]any{"stopped": name}, err
}

func Remove(ctx context.Context, args map[string]any) (any, error) {
	name, err := ValidName(args)
	if err != nil {
		return nil, err
	}
	exists, ours := managed(ctx, name)
	if !exists {
		return map[string]any{"removed": name, "existed": false}, nil // idempotent
	}
	if !ours {
		return nil, protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("container %s is not managed by the agent", name))
	}
	_, err = CLI(ctx, "rm", "-f", name)
	return map[string]any{"removed": name, "existed": true}, err
}

// parseRenameArgs validates {name, to}: both valid container names and different.
func parseRenameArgs(args map[string]any) (from, to string, err error) {
	from, err = ValidName(args)
	if err != nil {
		return "", "", err
	}
	to = util.Str(args, "to")
	if !NameRe.MatchString(to) {
		return "", "", errors.New("to must match [a-z0-9][a-z0-9_.-]{0,62}")
	}
	if to == from {
		return "", "", errors.New("to must differ from name")
	}
	return from, to, nil
}

// Rename renames an agent-managed container (the published port and labels are unchanged). The target name
// must be free, so a rename can never replace another container.
func Rename(ctx context.Context, args map[string]any) (any, error) {
	from, to, err := parseRenameArgs(args)
	if err != nil {
		return nil, protocol.BadRequest(err)
	}
	if err := RequireManaged(ctx, from); err != nil {
		return nil, err
	}
	if exists, _ := managed(ctx, to); exists {
		return nil, protocol.WithCode(protocol.CodeConflict, fmt.Errorf("container %s already exists", to))
	}
	if _, err := CLI(ctx, "rename", from, to); err != nil {
		return nil, err
	}
	return map[string]any{"renamed": from, "to": to}, nil
}

func Stats(ctx context.Context, args map[string]any) (any, error) {
	list, err := ManagedContainers(ctx)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	if names, ok := args["names"].([]any); ok {
		for _, n := range names {
			if s, _ := n.(string); s != "" {
				want[s] = true
			}
		}
	}
	type row struct {
		containerInfo
		CPUPct   string `json:"cpuPct,omitempty"`
		MemUsage string `json:"memUsage,omitempty"`
		// composeV (args.detail=true): health ("healthy"/"unhealthy"/"starting"/""), restart count, exit code, start time.
		Health    string `json:"health,omitempty"`
		Restarts  int    `json:"restarts,omitempty"`
		ExitCode  int    `json:"exitCode,omitempty"`
		StartedAt string `json:"startedAt,omitempty"`
	}
	rows := []row{}
	var running []string
	for _, c := range list {
		if len(want) > 0 && !want[c.Name] {
			continue
		}
		rows = append(rows, row{containerInfo: c})
		if c.State == "running" {
			running = append(running, c.Name)
		}
	}
	if detail, _ := args["detail"].(bool); detail && len(rows) > 0 {
		names := make([]string, len(rows))
		for i := range rows {
			names[i] = rows[i].Name
		}
		d := inspectDetail(ctx, names)
		for i := range rows {
			if x, ok := d[rows[i].Name]; ok {
				rows[i].Health, rows[i].Restarts, rows[i].ExitCode, rows[i].StartedAt = x.Health, x.Restarts, x.ExitCode, x.StartedAt
			}
		}
	}
	if len(running) > 0 {
		out, err := CLI(ctx, append([]string{"stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"}, running...)...)
		if err == nil {
			for _, l := range strings.Split(out, "\n") {
				f := strings.Split(l, "\t")
				for i := range rows {
					if len(f) == 3 && rows[i].Name == f[0] {
						rows[i].CPUPct, rows[i].MemUsage = f[1], f[2]
					}
				}
			}
		}
	}
	if len(want) > 0 {
		for n := range want {
			found := false
			for _, r := range rows {
				found = found || r.Name == n
			}
			if !found {
				rows = append(rows, row{containerInfo: containerInfo{Name: n, State: "missing"}})
			}
		}
	}
	return map[string]any{"containers": rows}, nil
}
