package build

// Build settings sent by the engine with a `build` command: the app's env at build time
// and the build overrides (build command, start command, publish/output dir). Empty or whitespace-only values
// mean "auto-detect" and are never passed to railpack. Env values never go on the command line: `--env NAME` makes
// railpack read NAME from its own environment and hand it to BuildKit as a secret.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vinodkumar937/f2c-agent/internal/util"
)

var (
	envNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	outputDirRe = regexp.MustCompile(`^[A-Za-z0-9._\-/ ]+$`)
)

const maxBuildCmd = 2000

type buildSettings struct {
	Env                        map[string]string
	BuildCmd, StartCmd, OutDir string
	// Dockerfile builds (dockerbuild.go): BuildPack "dockerfile" bypasses railpack and the static shortcut.
	BuildPack, DockerfileLoc, DockerTarget string
	NoCache                                bool
}

func (s buildSettings) isDockerfile() bool { return s.BuildPack == "dockerfile" }

// cleanCmd trims a command; "" for empty/whitespace. Multi-line or overlong commands are rejected.
func cleanCmd(v, field string) (string, error) {
	t := strings.TrimSpace(v)
	if t == "" {
		return "", nil
	}
	if len(t) > maxBuildCmd {
		return "", errors.New(field + " is too long")
	}
	if strings.ContainsAny(t, "\x00\r\n") {
		return "", errors.New(field + " must be a single line")
	}
	return t, nil
}

// cleanOutputDir: "/dist/" -> "dist"; "", "/", "." or whitespace -> "" (auto). Escapes are rejected.
func cleanOutputDir(v string) (string, error) {
	t := strings.TrimSpace(strings.ReplaceAll(v, `\`, "/"))
	t = strings.TrimLeft(strings.TrimPrefix(t, "./"), "/")
	t = strings.TrimRight(t, "/")
	if t == "" || t == "." {
		return "", nil
	}
	for _, p := range strings.Split(t, "/") {
		if p == ".." || p == "" {
			return "", errors.New("invalid outputDir")
		}
	}
	if len(t) > 200 || !outputDirRe.MatchString(t) {
		return "", errors.New("invalid outputDir")
	}
	return t, nil
}

func parseBuildSettings(args map[string]any) (buildSettings, error) {
	var s buildSettings
	var err error
	if s.BuildCmd, err = cleanCmd(util.Str(args, "buildCmd"), "buildCmd"); err != nil {
		return s, err
	}
	if s.StartCmd, err = cleanCmd(util.Str(args, "startCmd"), "startCmd"); err != nil {
		return s, err
	}
	if s.OutDir, err = cleanOutputDir(util.Str(args, "outputDir")); err != nil {
		return s, err
	}
	if bp := strings.TrimSpace(util.Str(args, "buildPack")); bp != "" && bp != "nixpacks" && bp != "static" && bp != "dockerfile" {
		return s, errors.New("buildPack must be nixpacks, static or dockerfile")
	} else if bp == "dockerfile" {
		s.BuildPack = bp
		rel, derr := cleanDockerfileLocation(util.Str(args, "dockerfileLocation"))
		if derr != nil {
			return s, derr
		}
		s.DockerfileLoc = "/" + rel
		if s.DockerTarget, derr = cleanDockerTarget(util.Str(args, "dockerTargetBuild")); derr != nil {
			return s, derr
		}
		// A Dockerfile build ignores the build/start/output overrides (they stay stored for switching back): a stale
		// startCmd must never replace the image's CMD.
		s.BuildCmd, s.StartCmd, s.OutDir = "", "", ""
	}
	s.NoCache, _ = args["noCache"].(bool)
	if m, ok := args["env"].(map[string]any); ok {
		s.Env = map[string]string{}
		for k, v := range m {
			if sv, ok := v.(string); ok && envNameRe.MatchString(k) && k != "PORT" {
				s.Env[k] = sv
			}
		}
	}
	return s, nil
}

// secretValues: env values to mask in the streamed build log.
func (s buildSettings) secretValues() []string {
	out := []string{}
	for _, v := range s.Env {
		if len(strings.TrimSpace(v)) >= 6 {
			out = append(out, v)
		}
	}
	return out
}

// railpackArgs returns the extra railpack flags and the process env (NAME=value) for them.
func (s buildSettings) railpackArgs() (args, procEnv []string) {
	names := make([]string, 0, len(s.Env))
	for k := range s.Env {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		args = append(args, "--env", k)
		procEnv = append(procEnv, k+"="+s.Env[k])
	}
	if s.BuildCmd != "" {
		args = append(args, "--build-cmd", s.BuildCmd)
	}
	if s.StartCmd != "" {
		args = append(args, "--start-cmd", s.StartCmd)
	}
	if s.OutDir != "" {
		args = append(args, "--env", "RAILPACK_STATIC_FILE_ROOT="+s.OutDir, "--env", "RAILPACK_SPA_OUTPUT_DIR="+s.OutDir)
	}
	return args, procEnv
}

// readDetected keeps the parts of railpack's --info-out the engine needs for the detected runtime label.
func readDetected(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var info map[string]any
	if json.Unmarshal(b, &info) != nil {
		return nil
	}
	out := map[string]any{}
	for _, k := range []string{"detectedProviders", "metadata", "resolvedPackages"} {
		if v, ok := info[k]; ok {
			out[k] = v
		}
	}
	return out
}

func staticRoot(src, out string) string {
	if out == "" {
		return src
	}
	return filepath.Join(src, out)
}
