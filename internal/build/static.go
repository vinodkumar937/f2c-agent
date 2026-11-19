package build

// Pure static sites (index.html at the context root and no language/build markers) skip Railpack: its builder
// image is ~430 MB, which dominated first builds on fresh servers. They are built from a tiny pinned Caddy
// image instead, listening on $PORT (default 3000) like Railpack's staticfile provider so routing and health
// checks behave the same.

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// staticCaddyImage: keep in sync with STATIC_CADDY_IMAGE in deploy/install.sh (pre-pulled there).
const staticCaddyImage = "caddy:2.10.2-alpine"

// staticMarkers: any of these at the context root means the app has a real build or runtime (or an explicit
// Railpack/Docker config), so Railpack keeps handling it.
var staticMarkers = []string{
	"package.json", "Staticfile", "railpack.json", "Dockerfile", "Containerfile", "docker-compose.yml",
	"requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "go.mod", "Gemfile", "composer.json",
	"Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "mix.exs", "deno.json", "deno.jsonc",
	"gleam.toml", "CMakeLists.txt", "Makefile", "start.sh", "Procfile", "mise.toml", ".tool-versions",
}

// isPureStatic reports whether src is a plain static site: index.html at the root and no build markers
// (no *.csproj either).
func isPureStatic(src string) bool {
	if fi, err := os.Stat(filepath.Join(src, "index.html")); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	for _, m := range staticMarkers {
		if _, err := os.Lstat(filepath.Join(src, m)); err == nil {
			return false
		}
	}
	if m, _ := filepath.Glob(filepath.Join(src, "*.csproj")); len(m) > 0 {
		return false
	}
	return true
}

const staticCaddyfile = `{
	admin off
	auto_https off
	persist_config off
}
:{$PORT:3000} {
	root * /srv
	encode gzip
	try_files {path} {path}/ {path}.html
	file_server
}
`

// staticDockerfile renders the generated Dockerfile (written outside the context, so it is never served).
func staticDockerfile() string {
	// setcap -r: caddy ships with cap_net_bind_service, which exec refuses under --cap-drop ALL + no-new-privileges.
	// One-line RUN: a Dockerfile instruction can't span raw newlines, so newlines/tabs become printf escapes.
	esc := strings.NewReplacer(`\`, `\\`, "%", "%%", "'", `'\''`, "\n", `\n`, "\t", `\t`).Replace(staticCaddyfile)
	return fmt.Sprintf("FROM %s\nRUN setcap -r /usr/bin/caddy\nRUN printf '%s' > /etc/caddy/Caddyfile\nCOPY . /srv\nENV PORT=3000\nEXPOSE 3000\nCMD [\"caddy\", \"run\", \"--config\", \"/etc/caddy/Caddyfile\", \"--adapter\", \"caddyfile\"]\n",
		staticCaddyImage, esc)
}

// buildStatic builds src with the generated Caddy Dockerfile via the local Docker (BuildKit) daemon.
func buildStatic(ctx context.Context, src, image string, w io.Writer) error {
	df := filepath.Join(filepath.Dir(src), "Dockerfile.f2c-static")
	if err := os.WriteFile(df, []byte(staticDockerfile()), 0o600); err != nil {
		return err
	}
	defer os.Remove(df)
	fmt.Fprintf(w, "[f2c] static site: caddy image (%s), skipping railpack\n", staticCaddyImage)
	cmd := exec.CommandContext(ctx, "docker", "build", "--progress=plain", "-f", df, "-t", image, src)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	cmd.Dir = src
	cmd.Stdout, cmd.Stderr = w, w
	return runGroup(ctx, cmd)
}
