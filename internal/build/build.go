package build

// engine-multimode M2.1: the agent `build` command.
// Downloads the build context from the engine (one-time token in the Authorization header), verifies size and
// sha256, unpacks it safely (no absolute paths, no "..", no symlink escapes, no device files), makes sure a local
// BuildKit is available, runs railpack and tags the image f2c/<app>:<tag> in the local Docker. The build dir is
// always removed. M2.2: output streams to the engine as stream frames (build_log.go), cancel kills the whole
// process group, and a failed/cancelled build removes its partial image tag.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/docker"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

// Builder runs build and image-load commands: it needs the state dir (build contexts live under <state>/builds) and
// a way to send log frames.
type Builder struct {
	stateDir string
	send     func(any) bool
}

const (
	defaultBuildMaxBytes  = 500 << 20 // compressed context cap (plan: 500 MB)
	maxBuildUnpackedBytes = 4 << 30   // unpacked cap
	maxBuildEntries       = 200_000
	defaultBuildTimeout   = 30 * time.Minute
	buildkitContainer     = "f2c-buildkit"
	buildkitImage         = "moby/buildkit:v0.34.0" // keep in sync with BUILDKIT_IMAGE (engine pipeline/build.ts)
	buildkitStateVolume   = "f2c-buildkit-state"
)

var (
	buildTagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	sha256Re   = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type buildSpec struct {
	URL, Token, SHA256, App, Tag string
	MaxBytes                     int64
	Timeout                      time.Duration
	UploadURL, UploadToken       string // M2.5 relay: export the image to the engine after building
	UploadMaxBytes               int64
	Settings                     buildSettings // env at build time + dashboard overrides (build_config.go)
}

func parseBuildArgs(args map[string]any) (buildSpec, error) {
	s := buildSpec{
		URL: util.Str(args, "artifactUrl"), Token: util.Str(args, "token"), SHA256: strings.ToLower(util.Str(args, "sha256")),
		App: util.Str(args, "app"), Tag: util.Str(args, "tag"), MaxBytes: int64(util.Num(args, "maxBytes")),
		Timeout: time.Duration(util.Num(args, "timeoutS")) * time.Second,
	}
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return s, errors.New("artifactUrl must be an http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" {
		return s, errors.New("artifactUrl must not carry credentials or a query (the token goes in the header)")
	}
	if s.Token == "" {
		return s, errors.New("token is required")
	}
	s.UploadURL, s.UploadToken, s.UploadMaxBytes = util.Str(args, "uploadUrl"), util.Str(args, "uploadToken"), capBytes(int64(util.Num(args, "uploadMaxBytes")))
	if s.UploadURL != "" {
		if err := checkTransferURL(s.UploadURL); err != nil {
			return s, err
		}
		if s.UploadToken == "" {
			return s, errors.New("uploadToken is required with uploadUrl")
		}
	}
	var serr error
	if s.Settings, serr = parseBuildSettings(args); serr != nil {
		return s, serr
	}
	if !sha256Re.MatchString(s.SHA256) {
		return s, errors.New("sha256 must be 64 hex characters")
	}
	if !docker.NameRe.MatchString(s.App) {
		return s, errors.New("app must match [a-z0-9][a-z0-9_.-]{0,62}")
	}
	if !buildTagRe.MatchString(s.Tag) {
		return s, errors.New("tag must match [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
	}
	if s.MaxBytes <= 0 || s.MaxBytes > defaultBuildMaxBytes {
		s.MaxBytes = defaultBuildMaxBytes
	}
	if s.Timeout <= 0 || s.Timeout > 2*time.Hour {
		s.Timeout = defaultBuildTimeout
	}
	return s, nil
}

func (a *Builder) buildsRoot() string { return filepath.Join(a.stateDir, "builds") }

func (a *Builder) Build(ctx context.Context, id string, args map[string]any) (any, error) {
	spec, err := parseBuildArgs(args)
	if err != nil {
		return nil, validation(err)
	}
	bl := newBuildLog(func(data string) { a.send(map[string]any{"t": "stream", "id": id, "data": data}) }, append([]string{spec.Token, spec.UploadToken}, spec.Settings.secretValues()...)...)
	defer bl.Close()
	return runBuild(ctx, a.buildsRoot(), id, spec, bl)
}

// runBuild does the whole build in <root>/<id>-<rand> and always removes that directory.
func runBuild(ctx context.Context, root, id string, spec buildSpec, bl *buildLog) (res any, err error) {
	if bl == nil {
		bl = newBuildLog(nil, append([]string{spec.Token}, spec.Settings.secretValues()...)...)
		defer bl.Close()
	}
	ctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	start := time.Now()
	image := fmt.Sprintf("f2c/%s:%s", spec.App, spec.Tag)

	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("build dir: %w", err)
	}
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	dir := filepath.Join(root, safeID(id)+"-"+hex.EncodeToString(rnd))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("build dir: %w", err)
	}
	defer os.RemoveAll(dir)
	logf := func(format string, v ...any) {
		log.Printf("build %s: "+format, append([]any{image}, v...)...)
		bl.Line(fmt.Sprintf("[f2c] "+format, v...))
	}
	// A failed or cancelled build must not leave a (partial) f2c/<app>:<tag> behind; a tag that existed before
	// this build and still points at the same image is kept.
	preID, _ := docker.CLI(ctx, "image", "inspect", "-f", "{{.Id}}", image)
	defer func() {
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			code := protocol.CodeCancelled
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				code = protocol.CodeTimeout
			}
			err = protocol.WithCode(code, fmt.Errorf("build %s: %w", map[bool]string{true: "timed out", false: "cancelled"}[errors.Is(ctx.Err(), context.DeadlineExceeded)], err))
		}
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		if cur, ierr := docker.CLI(cctx, "image", "inspect", "-f", "{{.Id}}", image); ierr == nil && cur != preID {
			if _, rerr := docker.CLI(cctx, "rmi", image); rerr == nil {
				log.Printf("build %s: removed partial image after failure", image)
			}
		}
	}()

	archive := filepath.Join(dir, "context.archive")
	n, err := downloadArtifact(ctx, spec, archive)
	if err != nil {
		return nil, err
	}
	logf("context downloaded and verified (%d bytes)", n)

	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0o700); err != nil {
		return nil, err
	}
	files, err := unpackContext(ctx, archive, src)
	if err != nil {
		return nil, protocol.DefaultCode(protocol.CodeBuildFailed, fmt.Errorf("unpack: %w", err))
	}
	_ = os.Remove(archive)
	logf("context unpacked (%d entries)", files)

	var (
		host, tool string
		detected   map[string]any
		exposed    []int
	)
	if spec.Settings.isDockerfile() {
		// buildPack "dockerfile": plain `docker build` of the customer's Dockerfile (dockerbuild.go); no railpack, no static shortcut.
		tool = "docker"
		exposed, err = buildDockerfile(ctx, dir, src, image, bl, spec.Settings, logf)
		if err != nil {
			if errorCode(err) != "" {
				return nil, protocol.WithCode(errorCode(err), err) // dockerfile_not_found / dockerfile_invalid_path ...: the message is already the answer
			}
			return nil, protocol.DefaultCode(protocol.CodeBuildFailed, fmt.Errorf("docker build failed: %w\n%s", err, bl.Tail(40)))
		}
	} else {
		host, err = ensureBuildkit(ctx)
		if err != nil {
			return nil, protocol.DefaultCode(protocol.CodeBuildFailed, err)
		}
		logf("building with BuildKit %s", host)
		tool, detected, err = buildImage(ctx, src, image, host, bl, spec.Settings)
		if err != nil {
			return nil, protocol.DefaultCode(protocol.CodeBuildFailed, fmt.Errorf("%s build failed: %w\n%s", tool, err, bl.Tail(40)))
		}
	}
	imgID, err := docker.CLI(ctx, "image", "inspect", "-f", "{{.Id}}", image)
	if err != nil {
		return nil, protocol.WithCode(protocol.CodeBuildFailed, fmt.Errorf("built image %s not found in docker: %w", image, err))
	}
	dur := time.Since(start)
	logf("built with %s in %s", tool, dur.Round(time.Millisecond))
	out := map[string]any{"image": image, "id": imgID, "tool": tool, "buildkitHost": host, "durationMs": dur.Milliseconds(), "contextBytes": n}
	if detected != nil {
		out["detected"] = detected
	}
	if len(exposed) > 0 {
		out["exposedPorts"] = exposed
	}
	if spec.UploadURL != "" {
		exp := filepath.Join(dir, "image.tar.gz")
		size, sum, err := exportImage(ctx, image, exp, spec.UploadMaxBytes)
		if err != nil {
			return nil, err
		}
		logf("image exported: %d bytes, sha256 %s", size, sum)
		if err := uploadImage(ctx, spec.UploadURL, spec.UploadToken, exp, sum, size); err != nil {
			return nil, err
		}
		_ = os.Remove(exp)
		logf("image uploaded to the engine")
		out["exportBytes"], out["exportSha256"] = size, sum
	}
	out["logTail"] = bl.Tail(40)
	return out, nil
}

func safeID(id string) string {
	id = regexp.MustCompile(`[^A-Za-z0-9_-]`).ReplaceAllString(id, "")
	if id == "" {
		return "build"
	}
	if len(id) > 40 {
		id = id[:40]
	}
	return id
}

// downloadArtifact streams the context to path, enforcing the size cap and the sha256. The token is only ever
// sent in the Authorization header and never logged or returned.
func downloadArtifact(ctx context.Context, spec buildSpec, path string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+spec.Token)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return 0, protocol.DefaultCode(protocol.CodeTransferFailed, fmt.Errorf("download: %s", redactURL(err.Error(), spec.URL)))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 0, protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("download: the engine answered %d", res.StatusCode))
	}
	if res.ContentLength > spec.MaxBytes {
		return 0, protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("download: context is %d bytes, over the %d byte cap", res.ContentLength, spec.MaxBytes))
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, spec.MaxBytes+1))
	if err != nil {
		return n, protocol.DefaultCode(protocol.CodeTransferFailed, fmt.Errorf("download: %w", err))
	}
	if n > spec.MaxBytes {
		return n, protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("download: context is over the %d byte cap", spec.MaxBytes))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != spec.SHA256 {
		return n, protocol.WithCode(protocol.CodeIntegrityFailed, fmt.Errorf("download: sha256 mismatch (got %s)", got))
	}
	return n, f.Close()
}

func redactURL(msg, u string) string { return strings.ReplaceAll(msg, u, "<artifactUrl>") }

// openArchive returns a tar stream for a plain, gzip or zstd (via the zstd binary) archive.
func openArchive(ctx context.Context, path string) (io.Reader, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	magic := make([]byte, 4)
	_, _ = io.ReadFull(f, magic)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, err
	}
	switch {
	case magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return gz, func() error { gz.Close(); return f.Close() }, nil
	case magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
		zstdBin, err := exec.LookPath("zstd")
		if err != nil {
			f.Close()
			return nil, nil, errors.New("context is zstd-compressed but the zstd binary is not installed")
		}
		cmd := exec.CommandContext(ctx, zstdBin, "-dc")
		cmd.Stdin = f
		out, err := cmd.StdoutPipe()
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		if err := cmd.Start(); err != nil {
			f.Close()
			return nil, nil, err
		}
		return out, func() error { _ = cmd.Process.Kill(); _ = cmd.Wait(); return f.Close() }, nil
	}
	return f, f.Close, nil
}

// within reports whether p (absolute, cleaned) is dest or inside it.
func within(dest, p string) bool {
	rel, err := filepath.Rel(dest, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// noSymlinkParents refuses to write through a symlinked parent directory (a link created earlier in the archive).
func noSymlinkParents(dest, target string) error {
	rel, _ := filepath.Rel(dest, filepath.Dir(target))
	cur := dest
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink %s", part)
		}
	}
	return nil
}

// unpackContext extracts the archive into dest (an empty dir). Only directories, regular files and symlinks whose
// target stays inside dest are allowed; modes are reduced to 0755/0644; sizes and entry counts are capped.
func unpackContext(ctx context.Context, archive, dest string) (int, error) {
	r, closeFn, err := openArchive(ctx, archive)
	if err != nil {
		return 0, err
	}
	defer closeFn()
	dest, _ = filepath.Abs(dest)
	tr := tar.NewReader(r)
	var total int64
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if count++; count > maxBuildEntries {
			return count, fmt.Errorf("more than %d entries", maxBuildEntries)
		}
		name := hdr.Name
		if hdr.Typeflag == tar.TypeXGlobalHeader || hdr.Typeflag == tar.TypeXHeader {
			continue
		}
		if filepath.IsAbs(name) || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
			return count, fmt.Errorf("absolute or invalid path %q", name)
		}
		clean := filepath.Clean(filepath.FromSlash(name))
		if clean == "." {
			continue
		}
		target := filepath.Join(dest, clean)
		if !within(dest, target) || target == dest {
			return count, fmt.Errorf("path %q escapes the build directory", name)
		}
		if err := noSymlinkParents(dest, target); err != nil {
			return count, err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return count, err
			}
		case tar.TypeReg:
			total += hdr.Size
			if total > maxBuildUnpackedBytes {
				return count, fmt.Errorf("unpacked context is over %d bytes", int64(maxBuildUnpackedBytes))
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return count, err
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return count, err
			}
			_, err = io.Copy(f, io.LimitReader(tr, hdr.Size))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return count, err
			}
		case tar.TypeSymlink:
			link := hdr.Linkname
			if link == "" || filepath.IsAbs(link) || strings.HasPrefix(link, "/") {
				return count, fmt.Errorf("symlink %q -> %q: absolute targets are not allowed", name, link)
			}
			if !within(dest, filepath.Join(filepath.Dir(target), filepath.FromSlash(link))) {
				return count, fmt.Errorf("symlink %q -> %q escapes the build directory", name, link)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return count, err
			}
			if err := os.Symlink(link, target); err != nil {
				return count, err
			}
		default:
			return count, fmt.Errorf("entry %q has an unsupported type (only files, directories and symlinks)", name)
		}
	}
}

// ensureBuildkit returns a BUILDKIT_HOST: $BUILDKIT_HOST, the f2c-buildkit container (started or created with the
// engine's image and state volume, cache kept), or a local buildkitd socket.
func ensureBuildkit(ctx context.Context) (string, error) {
	if h := strings.TrimSpace(os.Getenv("BUILDKIT_HOST")); h != "" {
		return h, nil
	}
	host := "docker-container://" + buildkitContainer
	state, _ := docker.CLI(ctx, "inspect", "-f", "{{.State.Running}}", buildkitContainer)
	switch state {
	case "true":
		return host, nil
	case "false":
		if _, err := docker.CLI(ctx, "start", buildkitContainer); err != nil {
			return "", fmt.Errorf("buildkit: %w", err)
		}
		return host, nil
	}
	for _, sock := range []string{"/run/buildkit/buildkitd.sock", "/var/run/buildkit/buildkitd.sock"} {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return "unix://" + sock, nil
		}
	}
	if _, err := docker.CLI(ctx, "run", "-d", "--name", buildkitContainer, "--restart", "unless-stopped", "--privileged",
		"--label", docker.ManagedLabel+"=1", "--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
		"-v", buildkitStateVolume+":/var/lib/buildkit", buildkitImage); err != nil {
		return "", fmt.Errorf("buildkit: %w", err)
	}
	time.Sleep(2 * time.Second)
	return host, nil
}

// buildImage builds pure static sites with a tiny Caddy image (static.go), else runs railpack (or `docker build` when
// railpack is missing and the context has a Dockerfile). detected is railpack's provider info (nil when unknown).
func buildImage(ctx context.Context, src, image, buildkitHost string, w io.Writer, set buildSettings) (string, map[string]any, error) {
	rp, err := exec.LookPath("railpack")
	if err != nil {
		if _, statErr := os.Stat("/usr/local/bin/railpack"); statErr == nil {
			rp, err = "/usr/local/bin/railpack", nil
		}
	}
	if isPureStatic(src) && set.BuildCmd == "" && set.StartCmd == "" {
		root := staticRoot(src, set.OutDir)
		if fi, serr := os.Stat(root); serr != nil || !fi.IsDir() {
			return "caddy-static", nil, fmt.Errorf("output directory %q not found in the build directory", set.OutDir)
		}
		return "caddy-static", map[string]any{"detectedProviders": []string{"staticfile"}}, buildStatic(ctx, root, image, w)
	}
	var cmd *exec.Cmd
	var detected map[string]any
	tool := "railpack"
	if err == nil {
		extra, procEnv := set.railpackArgs()
		extra = append(extra, installEnvArgs(src)...)
		env := append(append(os.Environ(), "BUILDKIT_HOST="+buildkitHost), procEnv...)
		info := filepath.Join(filepath.Dir(src), "railpack-info.json")
		prep := exec.CommandContext(ctx, rp, append([]string{"prepare", src, "--info-out", info, "--hide-pretty-plan"}, extra...)...)
		prep.Env, prep.Dir = env, src
		if prep.Run() == nil {
			detected = readDetected(info)
		}
		cmd = exec.CommandContext(ctx, rp, append([]string{"build", src, "--name", image, "--progress", "plain"}, extra...)...)
		cmd.Env = env
	} else if _, statErr := os.Stat(filepath.Join(src, "Dockerfile")); statErr == nil {
		tool = "docker"
		cmd = exec.CommandContext(ctx, "docker", "build", "--progress=plain", "-t", image, src)
	} else {
		return tool, nil, errors.New("railpack is not installed and the context has no Dockerfile")
	}
	cmd.Dir = src
	cmd.Stdout, cmd.Stderr = w, w
	return tool, detected, runGroup(ctx, cmd)
}

// installEnvArgs: with an npm lockfile and no explicit railpack config/override, install with `npm ci` (reproducible,
// skips the lockfile resolve; railpack's npm cache mount in the persistent f2c-buildkit volume keeps it warm).
func installEnvArgs(src string) []string {
	if os.Getenv("F2C_AGENT_NPM_CI") == "0" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(src, "railpack.json")); err == nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(src, "package-lock.json")); err != nil {
		return nil
	}
	return []string{"--env", "RAILPACK_INSTALL_CMD=npm ci --no-audit --no-fund"}
}

// New builds the build/load runner from the agent's state dir and a frame sender.
func New(stateDir string, send func(any) bool) *Builder {
	return &Builder{stateDir: stateDir, send: send}
}
