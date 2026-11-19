package build

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDockerfileLocationValidation(t *testing.T) {
	ok := map[string]string{
		"":                        "Dockerfile",
		"   ":                     "Dockerfile",
		"/Dockerfile":             "Dockerfile",
		"/docker/prod.Dockerfile": "docker/prod.Dockerfile",
		"Dockerfile":              "Dockerfile",
		"/deploy/Dockerfile.web":  "deploy/Dockerfile.web",
		"/my dir/Dockerfile":      "my dir/Dockerfile",
	}
	for in, want := range ok {
		got, err := cleanDockerfileLocation(in)
		if err != nil || got != want {
			t.Errorf("cleanDockerfileLocation(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"/../Dockerfile", "/a/../../etc/passwd", "/a/./Dockerfile", "//x", "/a//Dockerfile", `/a\Dockerfile`, "/a/Docker\nfile", "/x;rm -rf", "/" + strings.Repeat("a", 250), "/.."} {
		_, err := cleanDockerfileLocation(in)
		if errorCode(err) != "dockerfile_invalid_path" {
			t.Errorf("cleanDockerfileLocation(%q): want dockerfile_invalid_path, got %v", in, err)
		}
	}
}

func TestDockerfileTargetValidation(t *testing.T) {
	for _, in := range []string{"", "prod", "build-stage_1.x", " runtime "} {
		if _, err := cleanDockerTarget(in); err != nil {
			t.Errorf("target %q should be valid: %v", in, err)
		}
	}
	for _, in := range []string{"-x", "a b", "a;b", "$(x)", strings.Repeat("a", 130), "a/b"} {
		if _, err := cleanDockerTarget(in); errorCode(err) != "dockerfile_invalid_target" {
			t.Errorf("target %q should be refused with dockerfile_invalid_target, got %v", in, err)
		}
	}
}

func TestResolveDockerfile(t *testing.T) {
	src := t.TempDir()
	outside := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM scratch\n"), 0o644))
	must(os.MkdirAll(filepath.Join(src, "docker"), 0o755))
	must(os.WriteFile(filepath.Join(src, "docker", "prod.Dockerfile"), []byte("FROM scratch\n"), 0o644))
	must(os.WriteFile(filepath.Join(outside, "Dockerfile"), []byte("FROM evil\n"), 0o644))
	must(os.Symlink(filepath.Join(outside, "Dockerfile"), filepath.Join(src, "escape.Dockerfile")))
	must(os.Symlink(outside, filepath.Join(src, "linkdir")))
	must(os.Symlink("Dockerfile", filepath.Join(src, "inner.Dockerfile")))
	must(os.MkdirAll(filepath.Join(src, "adir"), 0o755))

	for loc, wantRel := range map[string]string{"": "Dockerfile", "/Dockerfile": "Dockerfile", "/docker/prod.Dockerfile": "docker/prod.Dockerfile", "/inner.Dockerfile": "inner.Dockerfile"} {
		abs, rel, err := resolveDockerfile(src, loc)
		if err != nil || rel != wantRel || !within(mustEval(t, src), abs) {
			t.Errorf("resolveDockerfile(%q) = %q, %q, %v", loc, abs, rel, err)
		}
	}
	cases := map[string]string{
		"/missing.Dockerfile": "dockerfile_not_found",
		"/docker/nope":        "dockerfile_not_found",
		"/adir":               "dockerfile_not_found",
		"/escape.Dockerfile":  "dockerfile_invalid_path", // symlink to a file outside
		"/linkdir/Dockerfile": "dockerfile_invalid_path", // symlinked directory outside
		"/../Dockerfile":      "dockerfile_invalid_path",
		"/docker/../../x":     "dockerfile_invalid_path",
	}
	for loc, code := range cases {
		_, _, err := resolveDockerfile(src, loc)
		if errorCode(err) != code {
			t.Errorf("resolveDockerfile(%q): want %s, got %v", loc, code, err)
		}
	}
	// The not-found message carries the path.
	_, _, err := resolveDockerfile(src, "/missing.Dockerfile")
	if err == nil || !strings.Contains(err.Error(), "/missing.Dockerfile") || !strings.HasPrefix(err.Error(), "dockerfile_not_found: ") {
		t.Errorf("not-found error = %v", err)
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPlanDockerfileBuildCommand(t *testing.T) {
	dir := t.TempDir()
	set := buildSettings{BuildPack: "dockerfile", DockerfileLoc: "/Dockerfile", DockerTarget: "prod", NoCache: true,
		Env: map[string]string{"API_URL": "https://example.test/x", "DB_PASSWORD": "s3cr3t-value-123", "UNUSED": "zzzzzzzz"}}
	p, err := planDockerBuild(set, "f2c/app:abc", "/ctx/Dockerfile", "/ctx", filepath.Join(dir, "secrets"), []string{"API_URL", "NODE_ENV"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(p.Args, " ")
	for _, want := range []string{"build --progress=plain -f /ctx/Dockerfile -t f2c/app:abc", "--target prod", "--no-cache", "--secret id=API_URL,src=", "--secret id=DB_PASSWORD,src=", "--build-arg API_URL", "/ctx"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q lack %q", joined, want)
		}
	}
	if p.Args[len(p.Args)-1] != "/ctx" {
		t.Errorf("context must be the last argument: %v", p.Args)
	}
	// build args only for ARG names the Dockerfile declares, and never with a value
	if !reflect.DeepEqual(p.BuildArgs, []string{"API_URL"}) || !reflect.DeepEqual(p.ProcEnv, []string{"API_URL=https://example.test/x"}) {
		t.Errorf("build args = %v, procEnv = %v", p.BuildArgs, p.ProcEnv)
	}
	if !reflect.DeepEqual(p.Secrets, []string{"API_URL", "DB_PASSWORD", "UNUSED"}) {
		t.Errorf("secrets = %v", p.Secrets)
	}
	// no value anywhere on the command line
	for _, v := range set.Env {
		if strings.Contains(joined, v) {
			t.Errorf("command line contains a secret value %q: %s", v, joined)
		}
	}
	if strings.Contains(joined, "=https") || strings.Contains(joined, "s3cr3t") {
		t.Errorf("value leaked: %s", joined)
	}
}

func TestDockerfileSecretFilesArePrivate(t *testing.T) {
	dir := t.TempDir()
	sdir := filepath.Join(dir, "secrets")
	set := buildSettings{BuildPack: "dockerfile", Env: map[string]string{"TOKEN_A": "value-one-123"}}
	if _, err := planDockerBuild(set, "img", "/c/Dockerfile", "/c", sdir, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(sdir, "TOKEN_A"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file: %v, %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(sdir, "TOKEN_A")); string(b) != "value-one-123" {
		t.Errorf("secret file content = %q", b)
	}
	if di, _ := os.Stat(sdir); di.Mode().Perm() != 0o700 {
		t.Errorf("secrets dir mode = %v", di.Mode().Perm())
	}
	// defaults: no target, no cache, no env -> no secret flags, no secrets dir
	p, _ := planDockerBuild(buildSettings{BuildPack: "dockerfile"}, "img", "/c/Dockerfile", "/c", filepath.Join(dir, "none"), nil)
	if got := strings.Join(p.Args, " "); got != "build --progress=plain -f /c/Dockerfile -t img /c" {
		t.Errorf("default args = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "none")); err == nil {
		t.Errorf("no secrets dir expected without env")
	}
}

func TestRedactDockerArgsAndSecretLog(t *testing.T) {
	args := []string{"build", "--secret", "id=K,src=/tmp/x/K", "--build-arg", "K=hunter2hunter2", "--build-arg", "Z", "."}
	got := redactDockerArgs(args)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "/tmp/x") || !strings.Contains(got, "--build-arg K ") || !strings.Contains(got, "id=K,src=<file>") {
		t.Errorf("redactDockerArgs = %q", got)
	}
	// build log redaction of env values (buildLog.secrets) still applies to docker output
	var streamed []string
	bl := newBuildLog(func(s string) { streamed = append(streamed, s) }, "hunter2hunter2")
	bl.Line("RUN echo hunter2hunter2")
	bl.Close()
	if strings.Contains(strings.Join(streamed, ""), "hunter2hunter2") {
		t.Errorf("value leaked in the streamed log: %v", streamed)
	}
}

func TestParseBuildSettingsDockerfile(t *testing.T) {
	s, err := parseBuildSettings(map[string]any{"buildPack": "dockerfile", "dockerfileLocation": "/docker/Dockerfile", "dockerTargetBuild": " prod ", "noCache": true, "env": map[string]any{"A_B": "v"}})
	if err != nil || !s.isDockerfile() || s.DockerfileLoc != "/docker/Dockerfile" || s.DockerTarget != "prod" || !s.NoCache {
		t.Fatalf("settings = %+v, %v", s, err)
	}
	if s, err = parseBuildSettings(map[string]any{"buildPack": "dockerfile"}); err != nil || s.DockerfileLoc != "/Dockerfile" {
		t.Errorf("default location: %+v, %v", s, err)
	}
	if s, err = parseBuildSettings(map[string]any{"buildPack": "nixpacks", "dockerfileLocation": "/x"}); err != nil || s.isDockerfile() || s.DockerfileLoc != "" {
		t.Errorf("railpack stays the default: %+v, %v", s, err)
	}
	if s, err = parseBuildSettings(map[string]any{}); err != nil || s.isDockerfile() {
		t.Errorf("empty: %+v, %v", s, err)
	}
	if _, err = parseBuildSettings(map[string]any{"buildPack": "dockerfile", "dockerfileLocation": "/../x"}); errorCode(err) != "dockerfile_invalid_path" {
		t.Errorf("traversal: %v", err)
	}
	if _, err = parseBuildSettings(map[string]any{"buildPack": "dockerfile", "dockerTargetBuild": "a b"}); errorCode(err) != "dockerfile_invalid_target" {
		t.Errorf("target: %v", err)
	}
	if _, err = parseBuildSettings(map[string]any{"buildPack": "weird"}); err == nil {
		t.Errorf("unknown buildPack must be refused")
	}
}

func TestParseExposedPortsDockerfile(t *testing.T) {
	cases := []struct {
		name, content, target string
		want                  []int
	}{
		{"simple", "FROM node:22\nEXPOSE 8080\nCMD [\"node\"]\n", "", []int{8080}},
		{"multiple, first wins", "FROM x\nEXPOSE 3000 9229\n", "", []int{3000, 9229}},
		{"proto and case", "from x\nexpose 8080/tcp 53/udp\n", "", []int{8080}},
		{"range", "FROM x\nEXPOSE 3000-3005\n", "", []int{3000}},
		{"variable skipped", "FROM x\nARG PORT=80\nEXPOSE $PORT ${PORT}\n", "", nil},
		{"variable then number", "FROM x\nEXPOSE $PORT 7000\n", "", []int{7000}},
		{"comment and continuation", "FROM x\n# EXPOSE 1111\nEXPOSE 2222 \\\n  # note\n  3333\n", "", []int{2222, 3333}},
		{"no expose", "FROM x\nCMD run\n", "", nil},
		{"CRLF", "FROM x\r\nEXPOSE 4000\r\n", "", []int{4000}},
		{"multi-stage: last stage wins", "FROM node AS build\nEXPOSE 1234\nFROM nginx AS run\nEXPOSE 80\n", "", []int{80}},
		{"multi-stage: target", "FROM node AS build\nEXPOSE 1234\nFROM nginx AS run\nEXPOSE 80\n", "build", []int{1234}},
		{"multi-stage: unknown target", "FROM node AS build\nEXPOSE 1234\n", "nope", nil},
		{"stage inherits from its parent stage", "FROM node AS base\nEXPOSE 5000\nFROM base AS prod\nCMD x\n", "prod", []int{5000}},
		{"stage inherits (last)", "FROM node AS base\nEXPOSE 5000\nFROM base\nCMD x\n", "", []int{5000}},
		{"platform flag in FROM", "FROM --platform=$BUILDPLATFORM golang:1 AS b\nEXPOSE 6000\n", "b", []int{6000}},
		{"out of range", "FROM x\nEXPOSE 0 70000 99999999\n", "", nil},
		{"empty", "", "", nil},
	}
	for _, c := range cases {
		if got := parseExposedPorts(c.content, c.target); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: parseExposedPorts = %v, want %v", c.name, got, c.want)
		}
	}
	if p := firstExposedPort("FROM x\nEXPOSE 9000 9001\n", ""); p != 9000 {
		t.Errorf("firstExposedPort = %d", p)
	}
	if p := firstExposedPort("FROM x\n", ""); p != 0 {
		t.Errorf("firstExposedPort (none) = %d", p)
	}
}

func TestDeclaredArgsDockerfile(t *testing.T) {
	got := declaredArgs("ARG VERSION=1\nFROM node:${VERSION}\nARG API_URL\nARG A=1 B\n# ARG NOPE\nARG bad-name\n")
	if !reflect.DeepEqual(got, []string{"A", "API_URL", "B", "VERSION"}) {
		t.Errorf("declaredArgs = %v", got)
	}
}

func TestDockerfileTargetNotFound(t *testing.T) {
	df := "FROM node AS Build\nRUN x\nFROM nginx AS run\nEXPOSE 80\nFROM scratch\n"
	for _, tgt := range []string{"", "build", "RUN", "0", "2"} {
		if missing, _ := dockerTargetMissing(df, tgt); missing {
			t.Errorf("target %q should exist", tgt)
		}
	}
	missing, names := dockerTargetMissing(df, "prod")
	if !missing || !reflect.DeepEqual(names, []string{"build", "run"}) {
		t.Fatalf("missing=%v names=%v", missing, names)
	}
	if m, _ := dockerTargetMissing(df, "3"); !m {
		t.Errorf("index 3 is out of range")
	}
	err := targetNotFoundErr("prod", "Dockerfile", names)
	if errorCode(err) != "dockerfile_target_not_found" || err.Error() != `dockerfile_target_not_found: build target "prod" was not found in /Dockerfile (stages in the Dockerfile: build, run)` {
		t.Errorf("message = %v", err)
	}
	if e := targetNotFoundErr("x", "Dockerfile", nil); !strings.Contains(e.Error(), "has no named stages") {
		t.Errorf("no-stage message = %v", e)
	}
	for _, line := range []string{`ERROR: target stage "prod" could not be found`, `target stage prod could not be found`} {
		if m := dockerTargetErrRe.FindStringSubmatch(line); m == nil || m[1] != "prod" {
			t.Errorf("docker error not recognised: %q -> %v", line, m)
		}
	}
	// the exposed port follows an index target too
	if p := firstExposedPort("FROM a\nEXPOSE 1000\nFROM b\nEXPOSE 2000\n", "0"); p != 1000 {
		t.Errorf("index target port = %d", p)
	}
}

func TestParseBuildSettingsDockerfileIgnoresOverrides(t *testing.T) {
	args := map[string]any{"buildCmd": "npm run build", "startCmd": "node server.js", "outputDir": "dist"}
	s, err := parseBuildSettings(args)
	if err != nil || s.BuildCmd == "" || s.StartCmd == "" || s.OutDir == "" {
		t.Fatalf("railpack keeps its overrides: %+v, %v", s, err)
	}
	args["buildPack"] = "dockerfile"
	s, err = parseBuildSettings(args)
	if err != nil || s.BuildCmd != "" || s.StartCmd != "" || s.OutDir != "" || s.hasOverrides() {
		t.Fatalf("a Dockerfile build must ignore stored build/start/output overrides: %+v, %v", s, err)
	}
	if ra, _ := s.railpackArgs(); strings.Contains(strings.Join(ra, " "), "start-cmd") {
		t.Errorf("start command leaked into railpack args: %v", ra)
	}
}
