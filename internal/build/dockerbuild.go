package build

// Dockerfile builds for customer apps (buildPack "dockerfile"). The engine sends buildPack, dockerfileLocation (relative to
// the build directory the context was packed from; default /Dockerfile), dockerTargetBuild and noCache with the `build`
// command; parseBuildSettings validates them (build_config.go). The agent re-validates the path
// against the unpacked context (no "..", no symlink escapes) and runs `docker build -f <file> [--target T] [--no-cache]`.
//
// Build-time env never goes on the command line or in the log: every variable is a BuildKit secret read from a 0600
// file outside the build context (`--secret id=NAME,src=FILE`, use it with RUN --mount=type=secret,id=NAME), and the
// variables the Dockerfile declares with ARG are also passed as `--build-arg NAME` (no value: docker reads it from its own
// process environment). Error messages start with a stable code ("dockerfile_not_found: ...").

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

const (
	DockerBuildCap     = 1 // heartbeat "dockerBuildV": the agent builds buildPack "dockerfile" (the engine refuses to send it to an agent without it)
	defaultDockerfile  = "/Dockerfile"
	maxDockerfileBytes = 1 << 20
)

var (
	dockerfileLocRe = regexp.MustCompile(`^[A-Za-z0-9._@+ /-]+$`)
	dockerTargetRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$`)
)

// buildCodeError is a build refusal with a stable machine-readable code; Error() is "code: message".
type buildCodeError struct{ Code, Msg string }

func (e *buildCodeError) Error() string { return e.Code + ": " + e.Msg }

func codeErr(code, format string, v ...any) error {
	return &buildCodeError{Code: code, Msg: fmt.Sprintf(format, v...)}
}

// errorCode returns the code of a buildCodeError ("" for any other error).
func errorCode(err error) string {
	var ce *buildCodeError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// validation marks a parse failure of a build or load request: the Dockerfile refusals keep their own code
// (dockerfile_invalid_path ...), everything else is bad_request.
func validation(err error) error {
	if c := errorCode(err); c != "" {
		return protocol.WithCode(c, err)
	}
	return protocol.BadRequest(err)
}

// cleanDockerfileLocation validates the engine-supplied value and returns the cleaned path relative to the build directory
// ("/Dockerfile" -> "Dockerfile", "/docker/prod.Dockerfile" -> "docker/prod.Dockerfile"). "" or whitespace = "/Dockerfile".
// Rejects "..", empty or "." segments, backslashes, control characters, odd characters and anything over 200 bytes.
func cleanDockerfileLocation(v string) (string, error) {
	t := strings.TrimSpace(v)
	if t == "" {
		t = defaultDockerfile
	}
	if len(t) > 200 || strings.ContainsAny(t, "\x00\r\n\\") || !dockerfileLocRe.MatchString(t) {
		return "", codeErr("dockerfile_invalid_path", "Dockerfile path %q is not valid (use a path like /Dockerfile, at most 200 characters)", truncate(t, 60))
	}
	rel := strings.TrimPrefix(t, "/")
	for _, p := range strings.Split(rel, "/") {
		if p == "" || p == "." || p == ".." {
			return "", codeErr("dockerfile_invalid_path", "Dockerfile path %q must stay inside the build directory (no .. or empty segments)", truncate(t, 60))
		}
	}
	return rel, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// cleanDockerTarget: "" = no --target; otherwise a BuildKit stage name.
func cleanDockerTarget(v string) (string, error) {
	t := strings.TrimSpace(v)
	if t == "" {
		return "", nil
	}
	if !dockerTargetRe.MatchString(t) {
		return "", codeErr("dockerfile_invalid_target", "build target %q is not valid (letters, digits, _ . - ; at most 120 characters)", truncate(t, 60))
	}
	return t, nil
}

// resolveDockerfile finds the Dockerfile inside the unpacked build directory src and returns its real absolute path.
// Symlinks are resolved and the result must still be inside src (a link to /etc/passwd or ../x is refused).
func resolveDockerfile(src, location string) (abs, rel string, err error) {
	rel, err = cleanDockerfileLocation(location)
	if err != nil {
		return "", "", err
	}
	root, err := filepath.EvalSymlinks(src)
	if err != nil {
		return "", "", fmt.Errorf("build dir: %w", err)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", "", codeErr("dockerfile_not_found", "Dockerfile not found at /%s in the build directory", rel)
		}
		return "", "", codeErr("dockerfile_invalid_path", "Dockerfile path /%s cannot be resolved", rel)
	}
	if !within(root, real) || real == root {
		return "", "", codeErr("dockerfile_invalid_path", "Dockerfile path /%s resolves outside the build directory", rel)
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return "", "", codeErr("dockerfile_not_found", "Dockerfile not found at /%s in the build directory (it is not a regular file)", rel)
	}
	if fi.Size() > maxDockerfileBytes {
		return "", "", codeErr("dockerfile_invalid_path", "Dockerfile at /%s is larger than %d bytes", rel, maxDockerfileBytes)
	}
	return real, rel, nil
}

// --- Dockerfile text: logical lines, stages, EXPOSE and ARG ----------------------------------------------------------

type dfInstruction struct {
	Name string // upper-cased
	Args string
}

// dockerfileInstructions joins backslash continuations and drops comments/blank lines.
func dockerfileInstructions(content string) []dfInstruction {
	var out []dfInstruction
	var cur strings.Builder
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") { // comment lines are removed even inside a continuation
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSpace(strings.TrimSuffix(line, "\\")) + " ")
			continue
		}
		cur.WriteString(line)
		text := strings.TrimSpace(cur.String())
		cur.Reset()
		name, args, _ := strings.Cut(text, " ")
		out = append(out, dfInstruction{Name: strings.ToUpper(name), Args: strings.TrimSpace(args)})
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		name, args, _ := strings.Cut(s, " ")
		out = append(out, dfInstruction{Name: strings.ToUpper(name), Args: strings.TrimSpace(args)})
	}
	return out
}

type dfStage struct {
	name    string // lower-cased AS name, "" when unnamed
	parent  int    // index of the stage this one is FROM, -1 for an external image
	exposes []int
}

// parseStages reads the FROM/EXPOSE structure of a Dockerfile: its stages in order and their lower-cased names.
func parseStages(content string) ([]dfStage, map[string]int) {
	var stages []dfStage
	byName := map[string]int{}
	for _, in := range dockerfileInstructions(content) {
		switch in.Name {
		case "FROM":
			fields := strings.Fields(in.Args)
			var rest []string
			for _, f := range fields {
				if strings.HasPrefix(f, "--") {
					continue
				}
				rest = append(rest, f)
			}
			st := dfStage{parent: -1}
			if len(rest) >= 1 {
				if i, ok := byName[strings.ToLower(rest[0])]; ok {
					st.parent = i
				}
			}
			if len(rest) >= 3 && strings.EqualFold(rest[1], "AS") {
				st.name = strings.ToLower(rest[2])
			}
			stages = append(stages, st)
			if st.name != "" {
				byName[st.name] = len(stages) - 1
			}
		case "EXPOSE":
			if len(stages) == 0 {
				continue
			}
			for _, tok := range strings.Fields(in.Args) {
				if p := exposeToken(tok); p > 0 {
					s := &stages[len(stages)-1]
					s.exposes = append(s.exposes, p)
				}
			}
		}
	}
	return stages, byName
}

// dockerTargetMissing reports whether target names no stage of the Dockerfile (by name, case-insensitive, or by index), and
// the named stages for the error message. An empty target is never missing.
func dockerTargetMissing(content, target string) (bool, []string) {
	stages, byName := parseStages(content)
	var names []string
	for _, st := range stages {
		if st.name != "" {
			names = append(names, st.name)
		}
	}
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return false, names
	}
	if _, ok := byName[t]; ok {
		return false, names
	}
	if n, err := strconv.Atoi(t); err == nil && n >= 0 && n < len(stages) {
		return false, names
	}
	return true, names
}

func targetNotFoundErr(target, rel string, names []string) error {
	have := "the Dockerfile has no named stages"
	if len(names) > 0 {
		have = "stages in the Dockerfile: " + strings.Join(names, ", ")
	}
	return codeErr("dockerfile_target_not_found", "build target %q was not found in /%s (%s)", target, rel, have)
}

// dockerTargetErrRe matches docker's own refusal: `target stage "x" could not be found`.
var dockerTargetErrRe = regexp.MustCompile(`target stage "?([^"\s]+)"? could not be found`)

// parseExposedPorts returns the ports EXPOSEd by the stage that is built (the --target stage, else the last stage), in
// order. An image inherits its parent stage's EXPOSE when it has none itself. Variables ($PORT), udp ports and
// non-numeric values are skipped; a range 3000-3005 gives its first port.
func parseExposedPorts(content, target string) []int {
	stages, byName := parseStages(content)
	if len(stages) == 0 {
		return nil
	}
	idx := len(stages) - 1
	if t := strings.ToLower(strings.TrimSpace(target)); t != "" {
		if i, ok := byName[t]; ok {
			idx = i
		} else if n, err := strconv.Atoi(t); err == nil && n >= 0 && n < len(stages) {
			idx = n
		} else {
			return nil
		}
	}
	for hops := 0; idx >= 0 && hops <= len(stages); hops++ {
		if len(stages[idx].exposes) > 0 {
			return stages[idx].exposes
		}
		idx = stages[idx].parent
	}
	return nil
}

// exposeToken: "8080", "8080/tcp", "3000-3005" -> 8080 / 8080 / 3000; "53/udp", "$PORT", "abc" -> 0.
func exposeToken(tok string) int {
	port, proto, hasProto := strings.Cut(tok, "/")
	if hasProto && !strings.EqualFold(proto, "tcp") {
		return 0
	}
	first, _, _ := strings.Cut(port, "-")
	n, err := strconv.Atoi(first)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// declaredArgs lists the ARG names the Dockerfile declares (any stage, including before the first FROM), sorted.
func declaredArgs(content string) []string {
	seen := map[string]bool{}
	for _, in := range dockerfileInstructions(content) {
		if in.Name != "ARG" {
			continue
		}
		for _, f := range strings.Fields(in.Args) {
			name, _, _ := strings.Cut(f, "=")
			if envNameRe.MatchString(name) {
				seen[name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// --- command construction ---------------------------------------------------------------------------------------------

// dockerBuildPlan is everything `docker build` needs: the argument list (no values), the extra process env (NAME=value, only
// read by docker from its own environment) and the secret files written.
type dockerBuildPlan struct {
	Args      []string
	ProcEnv   []string
	Secrets   []string // env names exposed as BuildKit secrets
	BuildArgs []string // env names also passed as --build-arg NAME
}

// planDockerBuild builds the `docker build` argument list. dfPath is the resolved Dockerfile, ctxDir the build directory,
// secretDir a private directory outside the context where one 0600 file per variable is written. Values are never part of
// Args; the file names are the variable names.
func planDockerBuild(set buildSettings, image, dfPath, ctxDir, secretDir string, argNames []string) (dockerBuildPlan, error) {
	p := dockerBuildPlan{Args: []string{"build", "--progress=plain", "-f", dfPath, "-t", image}}
	if set.DockerTarget != "" {
		p.Args = append(p.Args, "--target", set.DockerTarget)
	}
	if set.NoCache {
		p.Args = append(p.Args, "--no-cache")
	}
	names := make([]string, 0, len(set.Env))
	for k := range set.Env {
		names = append(names, k)
	}
	sort.Strings(names)
	declared := map[string]bool{}
	for _, n := range argNames {
		declared[n] = true
	}
	if len(names) > 0 {
		if err := os.MkdirAll(secretDir, 0o700); err != nil {
			return p, err
		}
	}
	for _, k := range names {
		f := filepath.Join(secretDir, k)
		if err := os.WriteFile(f, []byte(set.Env[k]), 0o600); err != nil {
			return p, err
		}
		p.Args = append(p.Args, "--secret", "id="+k+",src="+f)
		p.Secrets = append(p.Secrets, k)
		if declared[k] {
			p.Args = append(p.Args, "--build-arg", k)
			p.BuildArgs = append(p.BuildArgs, k)
			p.ProcEnv = append(p.ProcEnv, k+"="+set.Env[k])
		}
	}
	p.Args = append(p.Args, ctxDir)
	return p, nil
}

// redactDockerArgs renders a docker command line for the log. It never contains values by construction; this also masks
// any NAME=value after --build-arg and any secret source path, as a second line of defense.
func redactDockerArgs(args []string) string {
	out := make([]string, 0, len(args))
	for i, a := range args {
		switch {
		case i > 0 && args[i-1] == "--build-arg":
			name, _, _ := strings.Cut(a, "=")
			out = append(out, name)
		case i > 0 && args[i-1] == "--secret":
			id, _, _ := strings.Cut(a, ",")
			out = append(out, id+",src=<file>")
		default:
			out = append(out, a)
		}
	}
	return "docker " + strings.Join(out, " ")
}

// buildDockerfile validates the Dockerfile path against the unpacked context, writes the build-time env as 0600 secret files in
// <dir>/secrets (outside the context), runs `docker build` in its own process group (cancel/timeout kill it) and returns the
// ports the built stage EXPOSEs. dir is the per-build directory (the parent of src).
func buildDockerfile(ctx context.Context, dir, src, image string, w io.Writer, set buildSettings, logf func(string, ...any)) ([]int, error) {
	dfPath, rel, err := resolveDockerfile(src, set.DockerfileLoc)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(dfPath)
	if err != nil {
		return nil, codeErr("dockerfile_not_found", "Dockerfile not found at /%s in the build directory", rel)
	}
	if missing, names := dockerTargetMissing(string(content), set.DockerTarget); missing {
		return nil, targetNotFoundErr(set.DockerTarget, rel, names)
	}
	plan, err := planDockerBuild(set, image, dfPath, src, filepath.Join(dir, "secrets"), declaredArgs(string(content)))
	if err != nil {
		return nil, err
	}
	exposed := parseExposedPorts(string(content), set.DockerTarget)
	logf("building /%s%s%s", rel, map[bool]string{true: " (target " + set.DockerTarget + ")", false: ""}[set.DockerTarget != ""], map[bool]string{true: ", no cache", false: ""}[set.NoCache])
	if n := len(plan.Secrets); n > 0 {
		logf("build-time env: %d variable%s as BuildKit secrets (RUN --mount=type=secret,id=NAME); %d also as --build-arg (declared with ARG); values hidden", n, map[bool]string{true: "", false: "s"}[n == 1], len(plan.BuildArgs))
	}
	logf("$ %s", redactDockerArgs(plan.Args))
	cmd := exec.CommandContext(ctx, "docker", plan.Args...)
	cmd.Env = append(append(os.Environ(), "DOCKER_BUILDKIT=1"), plan.ProcEnv...)
	cmd.Dir = src
	cmd.Stdout, cmd.Stderr = w, w
	err = runGroup(ctx, cmd)
	_ = os.RemoveAll(filepath.Join(dir, "secrets"))
	if err != nil && set.DockerTarget != "" {
		// CLI's own refusal (a stage the text parse did not see, e.g. built from an ARG-generated FROM): same code.
		if m := dockerTargetErrRe.FindStringSubmatch(tailer(w)); m != nil {
			return nil, targetNotFoundErr(set.DockerTarget, rel, nil)
		}
	}
	return exposed, err
}

// tailer returns the last lines of the build output when w keeps them (the build log), else "".
func tailer(w io.Writer) string {
	if t, ok := w.(interface{ Tail(int) string }); ok {
		return t.Tail(20)
	}
	return ""
}
