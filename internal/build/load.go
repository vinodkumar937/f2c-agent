package build

// engine-multimode M2.6: the run side of a registry-free transfer. `load` downloads a staged transfer (one-time
// token), enforces size + sha256, `docker load`s it and verifies the loaded image ID against the builder's. A load
// whose image ID is already present skips the download (the token is simply never used). `image_present` lets the
// engine skip export/upload/download entirely. The sweeper removes old f2c/* images (keeps current + previous per
// app and anything a container uses) and stale load dirs.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/docker"
	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/sysinfo"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

var imageIDRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type loadSpec struct {
	URL, Token, SHA256, Image, ImageID string
	Size                               int64
}

func validF2cImage(s string) bool {
	return strings.HasPrefix(s, "f2c/") && !strings.ContainsAny(s, " \t\n") && !strings.HasPrefix(s, "-")
}

func parseLoadArgs(args map[string]any) (loadSpec, error) {
	s := loadSpec{URL: util.Str(args, "artifactUrl"), Token: util.Str(args, "token"), SHA256: strings.ToLower(util.Str(args, "sha256")),
		Image: util.Str(args, "image"), ImageID: strings.ToLower(util.Str(args, "imageId")), Size: int64(util.Num(args, "size"))}
	if err := checkTransferURL(s.URL); err != nil {
		return s, err
	}
	if s.Token == "" {
		return s, errors.New("token is required")
	}
	if !sha256Re.MatchString(s.SHA256) {
		return s, errors.New("sha256 must be 64 hex characters")
	}
	if !validF2cImage(s.Image) {
		return s, errors.New("image must be an f2c/<app>:<tag> name")
	}
	if s.ImageID != "" && !imageIDRe.MatchString(s.ImageID) {
		return s, errors.New("imageId must be sha256:<64 hex>")
	}
	if s.Size <= 0 || s.Size > defaultTransferMaxBytes {
		return s, fmt.Errorf("size must be 1..%d", int64(defaultTransferMaxBytes))
	}
	return s, nil
}

func (a *Builder) Load(ctx context.Context, id string, args map[string]any) (any, error) {
	spec, err := parseLoadArgs(args)
	if err != nil {
		return nil, protocol.BadRequest(err)
	}
	bl := newBuildLog(func(data string) { a.send(map[string]any{"t": "stream", "id": id, "data": data}) }, spec.Token)
	defer bl.Close()
	return runLoad(ctx, filepath.Join(a.stateDir, "loads"), id, spec, bl)
}

// imagePresent: is image ID `want` present locally? If so (and image is given), tag it as image. Without want,
// reports the ID image currently has.
func imagePresent(ctx context.Context, image, want string) (bool, string) {
	ref := want
	if ref == "" {
		ref = image
	}
	if ref == "" {
		return false, ""
	}
	got, err := docker.CLI(ctx, "image", "inspect", "-f", "{{.Id}}", ref)
	if err != nil || (want != "" && got != want) {
		return false, ""
	}
	if want != "" && image != "" {
		if cur, _ := docker.CLI(ctx, "image", "inspect", "-f", "{{.Id}}", image); cur != want {
			if _, err := docker.CLI(ctx, "tag", want, image); err != nil {
				return false, ""
			}
		}
	}
	return true, got
}

func ImagePresent(ctx context.Context, args map[string]any) (any, error) {
	image, want := util.Str(args, "image"), strings.ToLower(util.Str(args, "imageId"))
	if image != "" && !validF2cImage(image) {
		return nil, protocol.BadRequest(errors.New("image must be an f2c/<app>:<tag> name"))
	}
	if want != "" && !imageIDRe.MatchString(want) {
		return nil, protocol.BadRequest(errors.New("imageId must be sha256:<64 hex>"))
	}
	ok, id := imagePresent(ctx, image, want)
	return map[string]any{"present": ok, "id": id}, nil
}

// runLoad downloads into <root>/<id>-<rand> (always removed), verifies size + sha256, then docker load + image ID.
func runLoad(ctx context.Context, root, id string, spec loadSpec, bl *buildLog) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	start := time.Now()
	if spec.ImageID != "" {
		if ok, _ := imagePresent(ctx, spec.Image, spec.ImageID); ok {
			bl.Line(fmt.Sprintf("[f2c] transfer skipped: image present (%s %s)", spec.Image, spec.ImageID[:19]))
			return map[string]any{"image": spec.Image, "id": spec.ImageID, "skipped": true, "durationMs": time.Since(start).Milliseconds()}, nil
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	dir := filepath.Join(root, safeID(id)+"-"+hex.EncodeToString(rnd))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "image.tar.gz")
	n, err := downloadArtifact(ctx, buildSpec{URL: spec.URL, Token: spec.Token, SHA256: spec.SHA256, MaxBytes: spec.Size}, path)
	if err != nil {
		return nil, protocol.WithCode(protocol.V1Code(err), fmt.Errorf("image %s", err)) // keeps the download's code
	}
	if n != spec.Size {
		return nil, protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("image download: size %d, expected %d", n, spec.Size))
	}
	bl.Line(fmt.Sprintf("[f2c] image transfer received and verified: %d bytes, sha256 %s", n, spec.SHA256))
	if _, err := docker.CLI(ctx, "load", "-q", "-i", path); err != nil {
		return nil, protocol.DefaultCode(protocol.CodeBuildFailed, fmt.Errorf("docker load: %w", err))
	}
	imgID, err := docker.CLI(ctx, "image", "inspect", "-f", "{{.Id}}", spec.Image)
	if err != nil {
		return nil, protocol.WithCode(protocol.CodeBuildFailed, fmt.Errorf("loaded transfer does not contain %s", spec.Image))
	}
	if spec.ImageID != "" && imgID != spec.ImageID {
		return nil, protocol.WithCode(protocol.CodeBuildFailed, fmt.Errorf("loaded %s has image ID %s, expected %s", spec.Image, imgID, spec.ImageID))
	}
	// M2.12 safety net: an image for another CPU type would crash-loop ("exec format error"); refuse it here.
	if arch, _ := docker.CLI(ctx, "image", "inspect", "-f", "{{.Architecture}}", spec.Image); arch != "" && sysinfo.NormArch(arch) != sysinfo.HostArch() {
		_, _ = docker.CLI(ctx, "image", "rm", spec.Image)
		return nil, protocol.WithCode(protocol.CodeBuildArchMismatch, fmt.Errorf("build_arch_mismatch: %s is linux/%s but this server is linux/%s", spec.Image, sysinfo.NormArch(arch), sysinfo.HostArch()))
	}
	bl.Line(fmt.Sprintf("[f2c] loaded %s (%s)", spec.Image, imgID))
	return map[string]any{"image": spec.Image, "id": imgID, "bytes": n, "sha256": spec.SHA256, "durationMs": time.Since(start).Milliseconds()}, nil
}

// --- sweeper ---------------------------------------------------------------------------------

type imgRow struct {
	Repo, Tag, ID string
	Created       time.Time
}

// planSweep returns the repo:tag refs to remove: per f2c/* repo, keep the newest 2 image IDs (current + previous)
// and every ID a container uses; everything else goes. Non-f2c repos and <none> tags are never touched.
func planSweep(rows []imgRow, inUse map[string]bool, keep int) []string {
	byRepo := map[string][]imgRow{}
	for _, r := range rows {
		if strings.HasPrefix(r.Repo, "f2c/") && r.Tag != "" && r.Tag != "<none>" {
			byRepo[r.Repo] = append(byRepo[r.Repo], r)
		}
	}
	var out []string
	for _, rs := range byRepo {
		newest := map[string]time.Time{}
		for _, r := range rs {
			if r.Created.After(newest[r.ID]) {
				newest[r.ID] = r.Created
			}
		}
		ids := make([]string, 0, len(newest))
		for id := range newest {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return newest[ids[i]].After(newest[ids[j]]) })
		kept := map[string]bool{}
		for i, id := range ids {
			if i < keep {
				kept[id] = true
			}
		}
		for _, r := range rs {
			if !kept[r.ID] && !inUse[r.ID] {
				out = append(out, r.Repo+":"+r.Tag)
			}
		}
	}
	sort.Strings(out)
	return out
}

// staleLoadDirs lists entries under root older than maxAge (an interrupted load leaves its dir).
func staleLoadDirs(root string, maxAge time.Duration, now time.Time) []string {
	ents, _ := os.ReadDir(root)
	var out []string
	for _, e := range ents {
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > maxAge {
			out = append(out, filepath.Join(root, e.Name()))
		}
	}
	return out
}

func sweepOnce(ctx context.Context, stateDir string) (removed []string) {
	for _, d := range staleLoadDirs(filepath.Join(stateDir, "loads"), 2*time.Hour, time.Now()) {
		if os.RemoveAll(d) == nil {
			removed = append(removed, d)
		}
	}
	list, err := docker.CLI(ctx, "image", "ls", "--format", "{{.Repository}}\t{{.Tag}}\t{{.ID}}", "--no-trunc", "--filter", "reference=f2c/*")
	if err != nil {
		return
	}
	var rows []imgRow
	for _, l := range strings.Split(list, "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 3 {
			continue
		}
		c, _ := docker.CLI(ctx, "image", "inspect", "-f", "{{.Created}}", f[2])
		t, _ := time.Parse(time.RFC3339Nano, c)
		rows = append(rows, imgRow{Repo: f[0], Tag: f[1], ID: f[2], Created: t})
	}
	inUse := map[string]bool{}
	if ids, err := docker.CLI(ctx, "ps", "-aq"); err == nil && ids != "" {
		args := append([]string{"inspect", "-f", "{{.Image}}"}, strings.Fields(ids)...)
		if imgs, err := docker.CLI(ctx, args...); err == nil {
			for _, i := range strings.Fields(imgs) {
				inUse[i] = true
			}
		} else {
			return // unsure what is in use: remove nothing
		}
	}
	for _, ref := range planSweep(rows, inUse, 2) {
		if _, err := docker.CLI(ctx, "rmi", ref); err == nil {
			removed = append(removed, ref)
		}
	}
	return
}

// StartSweeper runs sweepOnce hourly; F2C_AGENT_SWEEP=0 disables it (local harnesses sharing the host's Docker).
func (a *Builder) StartSweeper(ctx context.Context) {
	if os.Getenv("F2C_AGENT_SWEEP") == "0" {
		return
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweepOnce(ctx, a.stateDir)
			}
		}
	}()
}
