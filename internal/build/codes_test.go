package build

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

func code(t *testing.T, what string, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: want an error with code %s", what, want)
	}
	if got := protocol.V1Code(err); got != want {
		t.Fatalf("%s: code %s, want %s (%v)", what, got, want, err)
	}
	if m := protocol.ResultMessage("b", nil, err); m["code"] != nil && !protocol.LegacyCodes[want] {
		t.Fatalf("%s: protocol 0 frame carries %v", what, m["code"])
	}
}

// noDocker puts a docker on PATH that always fails, so the tests never touch a real daemon.
func noDocker(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\necho 'Cannot connect to the Docker daemon' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestBuildParseErrorCodes(t *testing.T) {
	_, err := (&Builder{}).Build(context.Background(), "b1", map[string]any{})
	code(t, "missing artifactUrl", err, protocol.CodeBadRequest)
	_, err = (&Builder{}).Build(context.Background(), "b1", map[string]any{"artifactUrl": "https://e.example.com/a", "token": "t", "sha256": strings.Repeat("a", 64), "app": "x", "tag": "1",
		"buildPack": "dockerfile", "dockerfileLocation": "/../x"})
	code(t, "dockerfile path", err, protocol.CodeDockerfileInvalidPath)
	if !strings.HasPrefix(err.Error(), "dockerfile_invalid_path: ") {
		t.Fatalf("the text prefix must stay: %v", err)
	}
	_, err = (&Builder{}).Load(context.Background(), "l1", map[string]any{})
	code(t, "load args", err, protocol.CodeBadRequest)
	_, err = ImagePresent(context.Background(), map[string]any{"image": "x"})
	code(t, "image_present", err, protocol.CodeBadRequest)
}

func TestDownloadErrorCodes(t *testing.T) {
	body := []byte("context bytes")
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			http.Error(w, "no", status)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	spec := buildSpec{URL: srv.URL, Token: "t", SHA256: strings.Repeat("0", 64), MaxBytes: 1 << 20}
	dl := func(spec buildSpec) error {
		_, err := downloadArtifact(context.Background(), spec, filepath.Join(t.TempDir(), "a"))
		return err
	}
	code(t, "sha256 mismatch", dl(spec), protocol.CodeIntegrityFailed)
	small := spec
	small.MaxBytes = 3
	code(t, "over the cap", dl(small), protocol.CodeTransferFailed)
	status = 500
	code(t, "engine 500", dl(spec), protocol.CodeTransferFailed)
	status = 0
	spec.URL = "http://127.0.0.1:1/x"
	code(t, "engine unreachable", dl(spec), protocol.CodeTransferFailed)
}

// A build that runs out of time is "timeout", one the engine cancels is "cancelled", whatever step it was in.
func TestBuildTimeoutAndCancelCodes(t *testing.T) {
	noDocker(t)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	spec := buildSpec{URL: srv.URL, Token: "t", SHA256: strings.Repeat("0", 64), MaxBytes: 1 << 20, App: "x", Tag: "1", Timeout: 150 * time.Millisecond}
	_, err := runBuild(context.Background(), t.TempDir(), "b1", spec, nil)
	code(t, "deadline", err, protocol.CodeTimeout)
	if !strings.HasPrefix(err.Error(), "build timed out: ") {
		t.Fatalf("text: %v", err)
	}
	spec.Timeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	_, err = runBuild(ctx, t.TempDir(), "b2", spec, nil)
	code(t, "cancel", err, protocol.CodeCancelled)
	if !strings.HasPrefix(err.Error(), "build cancelled: ") {
		t.Fatalf("text: %v", err)
	}
}

func TestLoadAndTransferErrorCodes(t *testing.T) {
	code(t, "transfer url", checkTransferURL("ftp://x"), protocol.CodeBadRequest)
	if err := checkTransferURL("https://e.example.com/up"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 502) }))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "img.tar.gz")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code(t, "upload answered 502", uploadImage(context.Background(), srv.URL+"/up", "t", f, strings.Repeat("0", 64), 1), protocol.CodeTransferFailed)
}
