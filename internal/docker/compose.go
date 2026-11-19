package docker

// Docker Compose stacks (agent side). The engine translates a compose file into plain `run` specs (never `docker compose up`);
// this file adds what those specs need on top of the step 9d `run` options in commands.go:
//   - heartbeat capability "composeV" (composeCap): the engine refuses to send stack specs to an agent without it;
//   - stack `run` options: noPublish, aliases, health, entrypoint, user, workdir, readOnly, init, stopTimeoutS, capProfile, capAdd;
//   - the stack-v1 hardening profile: --cap-drop ALL, --security-opt no-new-privileges, and an add-back limited to the five
//     capabilities the official database images need (the engine chooses the per-image list; the agent only enforces that nothing outside stackCapAllow can ever be added);
//   - network_rm / volume_rm for stack deletes, and `stats` detail (health, restarts, exit code, start time).
// Default deny stays: parseRunOptions refuses every key that is not in runArgKeys.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

const ComposeCap = 1 // heartbeat "composeV": `run` stack options, stack-v1 caps, network_rm, volume_rm, stats detail

// stackCapProfile is the only capability profile; with it every container runs `--cap-drop ALL --security-opt no-new-privileges`.
const stackCapProfile = "stack-v1"

// stackCapAllow is the union of capabilities any stack container may get back (never ALL, never anything else).
var stackCapAllow = map[string]bool{"CHOWN": true, "DAC_OVERRIDE": true, "SETGID": true, "SETUID": true}

var (
	aliasRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	userRe    = regexp.MustCompile(`^[0-9a-z_][0-9a-z_.-]{0,31}(:[0-9a-z_][0-9a-z_.-]{0,31})?$`)
	stackNet  = regexp.MustCompile(`^f2c-stk-[a-z0-9][a-z0-9_.-]{0,50}$`)
	maxAlias  = 8
	maxHealth = 3600
)

// stackVolumePrefix: stack volumes are f2c-<engineApp>-<volume> and every engine app name starts with f2c-, so volume_rm is
// limited to this namespace and can never touch the platform's own volumes (f2c-pgdata, f2c-net data, ...).
const stackVolumePrefix = "f2c-f2c-"

type healthSpec struct {
	Cmd          []string
	Shell        string
	IntervalS    int
	TimeoutS     int
	Retries      int
	StartPeriodS int
}

type stackOptions struct {
	NoPublish    bool
	Aliases      []string
	Health       *healthSpec
	Entrypoint   []string
	User         string
	Workdir      string
	ReadOnly     bool
	Init         bool
	OneShot      bool // a one-shot job (depends_on service_completed_successfully): --restart no instead of unless-stopped
	StopTimeoutS int
	CapProfile   string
	CapAdd       []string
}

// stackArgKeys are the `run` args added by composeV.
var stackArgKeys = []string{"noPublish", "aliases", "health", "entrypoint", "user", "workdir", "readOnly", "init", "oneShot", "stopTimeoutS", "capProfile", "capAdd"}

func init() {
	for _, k := range stackArgKeys {
		runArgKeys[k] = true
	}
}

func intArg(m map[string]any, k string, lo, hi int) (int, bool, error) {
	v, ok := m[k]
	if !ok || v == nil {
		return 0, false, nil
	}
	f, isNum := v.(float64)
	if !isNum || f != float64(int(f)) || int(f) < lo || int(f) > hi {
		return 0, false, fmt.Errorf("%s must be a whole number from %d to %d", k, lo, hi)
	}
	return int(f), true, nil
}

func stringList(v any, what string, max int) ([]string, error) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 || len(list) > max {
		return nil, fmt.Errorf("%s must be a non-empty string array (at most %d items)", what, max)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok || len(s) > maxCmdArgLen || strings.ContainsRune(s, 0) {
			return nil, fmt.Errorf("%s must be a non-empty string array (at most %d items)", what, max)
		}
		out = append(out, s)
	}
	return out, nil
}

// parseStackOptions validates the composeV `run` args. Pure (no docker).
func parseStackOptions(args map[string]any, o *runOptions) error {
	var s stackOptions
	if v, ok := args["noPublish"]; ok && v != nil {
		b, isBool := v.(bool)
		if !isBool {
			return errors.New("noPublish must be true or false")
		}
		s.NoPublish = b
	}
	if v, ok := args["aliases"]; ok && v != nil {
		list, err := stringList(v, "aliases", maxAlias)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, a := range list {
			if !aliasRe.MatchString(a) {
				return fmt.Errorf("invalid network alias %q", a)
			}
			if seen[a] {
				return fmt.Errorf("duplicate network alias %q", a)
			}
			seen[a] = true
		}
		if o.Network == "" {
			return errors.New("aliases need a network")
		}
		s.Aliases = list
	}
	if v, ok := args["health"]; ok && v != nil {
		m, ok := v.(map[string]any)
		if !ok {
			return errors.New("health must be an object")
		}
		for k := range m {
			switch k {
			case "cmd", "shell", "intervalS", "timeoutS", "retries", "startPeriodS":
			default:
				return fmt.Errorf("unknown health option %q", k)
			}
		}
		h := &healthSpec{}
		_, hasCmd := m["cmd"]
		_, hasShell := m["shell"]
		if hasCmd == hasShell {
			return errors.New("health needs exactly one of cmd or shell")
		}
		if hasCmd {
			c, err := stringList(m["cmd"], "health.cmd", 32)
			if err != nil {
				return err
			}
			h.Cmd = c
		} else {
			sh, isStr := m["shell"].(string)
			if !isStr || sh == "" || len(sh) > maxCmdArgLen || strings.ContainsRune(sh, 0) {
				return errors.New("health.shell must be a non-empty string")
			}
			h.Shell = sh
		}
		var err error
		if h.IntervalS, _, err = intArg(m, "intervalS", 1, maxHealth); err != nil {
			return err
		}
		if h.TimeoutS, _, err = intArg(m, "timeoutS", 1, maxHealth); err != nil {
			return err
		}
		if h.Retries, _, err = intArg(m, "retries", 1, 100); err != nil {
			return err
		}
		if h.StartPeriodS, _, err = intArg(m, "startPeriodS", 0, maxHealth); err != nil {
			return err
		}
		s.Health = h
	}
	if v, ok := args["entrypoint"]; ok && v != nil {
		e, err := stringList(v, "entrypoint", maxCmdArgs)
		if err != nil {
			return err
		}
		if e[0] == "" {
			return errors.New("entrypoint must start with the program to run")
		}
		s.Entrypoint = e
	}
	if v, ok := args["user"]; ok && v != nil {
		u, isStr := v.(string)
		if !isStr || !userRe.MatchString(u) {
			return errors.New("user must be uid, uid:gid, name or name:group")
		}
		s.User = u
	}
	if v, ok := args["workdir"]; ok && v != nil {
		w, isStr := v.(string)
		if !isStr || !strings.HasPrefix(w, "/") || filepath.Clean(w) != w || len(w) > 4096 || strings.ContainsAny(w, "\n\r\x00") {
			return errors.New("workdir must be an absolute, clean path")
		}
		s.Workdir = w
	}
	for k, dst := range map[string]*bool{"readOnly": &s.ReadOnly, "init": &s.Init, "oneShot": &s.OneShot} {
		if v, ok := args[k]; ok && v != nil {
			b, isBool := v.(bool)
			if !isBool {
				return fmt.Errorf("%s must be true or false", k)
			}
			*dst = b
		}
	}
	if n, ok, err := intArg(args, "stopTimeoutS", 1, 120); err != nil {
		return err
	} else if ok {
		s.StopTimeoutS = n
	}
	if v, ok := args["capProfile"]; ok && v != nil {
		p, isStr := v.(string)
		if !isStr || p != stackCapProfile {
			return fmt.Errorf("capProfile must be %q", stackCapProfile)
		}
		s.CapProfile = p
	}
	if v, ok := args["capAdd"]; ok && v != nil {
		list, isList := v.([]any)
		if !isList || len(list) > len(stackCapAllow) {
			return errors.New("capAdd must be an array of capability names")
		}
		if s.CapProfile != stackCapProfile {
			return fmt.Errorf("capAdd needs capProfile %q", stackCapProfile)
		}
		seen := map[string]bool{}
		for _, item := range list {
			c, isStr := item.(string)
			if !isStr || !stackCapAllow[c] {
				return protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("capability %v is not allowed (allowed: CHOWN, DAC_OVERRIDE, SETGID, SETUID)", item))
			}
			if seen[c] {
				return fmt.Errorf("duplicate capability %s", c)
			}
			seen[c] = true
			s.CapAdd = append(s.CapAdd, c)
		}
	}
	if s.NoPublish {
		if hp, ok := args["hostPort"]; ok && hp != nil && util.Num(args, "hostPort") != 0 {
			return errors.New("noPublish cannot be combined with hostPort")
		}
	}
	o.Stack = s
	return nil
}

// shellQuote single-quotes one word for `--health-cmd` (docker runs the string through the container's shell).
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// stackDockerArgs turns the validated stack options into `docker run` flags (before the image).
func stackDockerArgs(o runOptions) []string {
	s := o.Stack
	var ra []string
	if s.User != "" {
		ra = append(ra, "--user", s.User)
	}
	if s.Workdir != "" {
		ra = append(ra, "--workdir", s.Workdir)
	}
	if s.ReadOnly {
		ra = append(ra, "--read-only")
	}
	if s.Init {
		ra = append(ra, "--init")
	}
	if s.StopTimeoutS > 0 {
		ra = append(ra, "--stop-timeout", strconv.Itoa(s.StopTimeoutS))
	}
	if len(s.Entrypoint) > 0 {
		ra = append(ra, "--entrypoint", s.Entrypoint[0])
	}
	for _, a := range s.Aliases {
		ra = append(ra, "--network-alias", a)
	}
	if h := s.Health; h != nil {
		cmd := h.Shell
		if h.Shell == "" {
			q := make([]string, len(h.Cmd))
			for i, w := range h.Cmd {
				q[i] = shellQuote(w)
			}
			cmd = strings.Join(q, " ")
		}
		ra = append(ra, "--health-cmd", cmd)
		if h.IntervalS > 0 {
			ra = append(ra, "--health-interval", strconv.Itoa(h.IntervalS)+"s")
		}
		if h.TimeoutS > 0 {
			ra = append(ra, "--health-timeout", strconv.Itoa(h.TimeoutS)+"s")
		}
		if h.Retries > 0 {
			ra = append(ra, "--health-retries", strconv.Itoa(h.Retries))
		}
		if h.StartPeriodS > 0 {
			ra = append(ra, "--health-start-period", strconv.Itoa(h.StartPeriodS)+"s")
		}
	}
	if s.CapProfile == stackCapProfile {
		ra = append(ra, "--cap-drop", "ALL")
		for _, c := range s.CapAdd {
			ra = append(ra, "--cap-add", c)
		}
		ra = append(ra, "--security-opt", "no-new-privileges")
	}
	return ra
}

// runTailArgs are the arguments after the image: the rest of a compose entrypoint (its first word is --entrypoint), then cmd.
func runTailArgs(o runOptions) []string {
	var t []string
	if len(o.Stack.Entrypoint) > 1 {
		t = append(t, o.Stack.Entrypoint[1:]...)
	}
	return append(t, o.Cmd...)
}

// capsReport is what `run` returns and logs for every container: the capabilities it actually got.
func capsReport(o runOptions) map[string]any {
	if o.Stack.CapProfile != stackCapProfile {
		return map[string]any{"profile": "", "drop": "", "add": []string{}, "noNewPrivileges": false}
	}
	add := o.Stack.CapAdd
	if add == nil {
		add = []string{}
	}
	return map[string]any{"profile": stackCapProfile, "drop": "ALL", "add": add, "noNewPrivileges": true}
}

func logRunCaps(name string, o runOptions) {
	r := capsReport(o)
	log.Printf("run %s: caps profile=%v drop=%v add=[%s] no-new-privileges=%v", name, r["profile"], r["drop"], strings.Join(o.Stack.CapAdd, ","), r["noNewPrivileges"])
}

// --- network_rm / volume_rm ------------------------------------------------------------------

func validateNetworkRm(args map[string]any) (string, error) {
	n := util.Str(args, "name")
	if !f2cNameRe.MatchString(n) || !stackNet.MatchString(n) {
		return "", protocol.BadRequest(errors.New("network_rm only removes stack networks (f2c-stk-*)"))
	}
	return n, nil
}

func validateVolumeRm(args map[string]any) (string, error) {
	n := util.Str(args, "name")
	if !f2cNameRe.MatchString(n) || !strings.HasPrefix(n, stackVolumePrefix) {
		return "", protocol.BadRequest(fmt.Errorf("volume_rm only removes stack volumes (%s*)", stackVolumePrefix))
	}
	return n, nil
}

// NetworkRm removes an agent-created stack network; idempotent when it is already gone.
func NetworkRm(ctx context.Context, args map[string]any) (any, error) {
	name, err := validateNetworkRm(args)
	if err != nil {
		return nil, err
	}
	lbl, err := CLI(ctx, "network", "inspect", "-f", `{{index .Labels "`+ManagedLabel+`"}}`, name)
	if err != nil {
		if strings.Contains(err.Error(), "No such network") || strings.Contains(err.Error(), "not found") {
			return map[string]any{"removed": name, "existed": false}, nil
		}
		return nil, err
	}
	if lbl != "1" {
		return nil, protocol.WithCode(protocol.CodeNotAllowed, fmt.Errorf("network %s is not managed by the agent", name))
	}
	if _, err := CLI(ctx, "network", "rm", name); err != nil {
		return nil, err
	}
	return map[string]any{"removed": name, "existed": true}, nil
}

// VolumeRm removes one stack volume (only on an explicit delete with removeVolumes); refuses while a container uses it.
func VolumeRm(ctx context.Context, args map[string]any) (any, error) {
	name, err := validateVolumeRm(args)
	if err != nil {
		return nil, err
	}
	if _, err := CLI(ctx, "volume", "inspect", "-f", "{{.Name}}", name); err != nil {
		if strings.Contains(err.Error(), "No such volume") || strings.Contains(err.Error(), "not found") {
			return map[string]any{"removed": name, "existed": false}, nil
		}
		return nil, err
	}
	users, err := CLI(ctx, "ps", "-a", "-q", "--filter", "volume="+name)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(users) != "" {
		return nil, protocol.WithCode(protocol.CodeConflict, fmt.Errorf("volume %s is in use by a container", name))
	}
	if _, err := CLI(ctx, "volume", "rm", name); err != nil {
		return nil, err
	}
	return map[string]any{"removed": name, "existed": true}, nil
}

// --- stats detail ----------------------------------------------------------------------------

type containerDetail struct {
	Health    string
	Restarts  int
	ExitCode  int
	StartedAt string
}

// parseInspectDetail reads `docker inspect -f '{{.Name}}\t<health>\t<restarts>\t<exit>\t<startedAt>'` lines.
func parseInspectDetail(out string) map[string]containerDetail {
	res := map[string]containerDetail{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(l), "\t")
		if len(f) != 5 {
			continue
		}
		name := strings.TrimPrefix(f[0], "/")
		r, _ := strconv.Atoi(f[2])
		x, _ := strconv.Atoi(f[3])
		res[name] = containerDetail{Health: f[1], Restarts: r, ExitCode: x, StartedAt: f[4]}
	}
	return res
}

// inspectDetail asks docker for health, restart count, exit code and start time of the named containers. Missing
// containers just have no entry (docker still prints the others before it fails).
func inspectDetail(ctx context.Context, names []string) map[string]containerDetail {
	if len(names) == 0 {
		return map[string]containerDetail{}
	}
	format := `{{.Name}}{{"\t"}}{{if .State.Health}}{{.State.Health.Status}}{{end}}{{"\t"}}{{.RestartCount}}{{"\t"}}{{.State.ExitCode}}{{"\t"}}{{.State.StartedAt}}`
	out, _ := exec.CommandContext(ctx, "docker", append([]string{"inspect", "-f", format}, names...)...).Output()
	return parseInspectDetail(string(out))
}
