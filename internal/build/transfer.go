package build

// Image transfer without a registry. A relay `build` (uploadUrl + uploadToken) exports the
// built image (`docker save | gzip`) to a file in the build dir, hashes it and PUTs it to the engine with its sha256
// and size; the engine re-hashes and rejects a mismatch. `load` fetches a staged transfer with a one-time token,
// enforces the size cap, verifies the sha256 and only then `docker load`s it. Tokens only ever go in the
// Authorization header and are redacted from the stream.

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
	"github.com/vinodkumar937/f2c-agent/internal/util"
)

const defaultTransferMaxBytes = 4 << 30

func checkTransferURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return protocol.BadRequest(errors.New("transfer url must be an http(s) URL"))
	}
	if u.User != nil || u.RawQuery != "" {
		return protocol.BadRequest(errors.New("transfer url must not carry credentials or a query (the token goes in the header)"))
	}
	return nil
}

func capBytes(v int64) int64 {
	if v <= 0 || v > defaultTransferMaxBytes {
		return defaultTransferMaxBytes
	}
	return v
}

// exportImage streams `docker save image | gzip` into path, returning size and sha256.
func exportImage(ctx context.Context, image, path string, max int64) (int64, string, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h), max: max}
	gz, _ := gzip.NewWriterLevel(cw, gzip.BestSpeed)
	cmd := exec.CommandContext(ctx, "docker", "save", image)
	cmd.Stdout = gz
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := runGroup(ctx, cmd); err != nil {
		if cw.over {
			return cw.n, "", protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("image export is over the %d byte cap", max))
		}
		return cw.n, "", protocol.DefaultCode(protocol.CodeTransferFailed, fmt.Errorf("docker save: %w: %s", err, util.Tail(stderr.String(), 400)))
	}
	if err := gz.Close(); err != nil {
		return cw.n, "", protocol.DefaultCode(protocol.CodeTransferFailed, fmt.Errorf("image export: %w", err))
	}
	if cw.over {
		return cw.n, "", protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("image export is over the %d byte cap", max))
	}
	return cw.n, hex.EncodeToString(h.Sum(nil)), f.Close()
}

type countWriter struct {
	w    io.Writer
	n    int64
	max  int64
	over bool
}

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	if c.n > c.max {
		c.over = true
		return 0, errors.New("over cap")
	}
	return c.w.Write(p)
}

// uploadImage PUTs the export to the engine with its sha256 + size; the engine answers 422 on a mismatch.
func uploadImage(ctx context.Context, rawURL, token, path, sum string, size int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, f)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-F2c-Sha256", sum)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return protocol.DefaultCode(protocol.CodeTransferFailed, fmt.Errorf("image upload: %s", strings.ReplaceAll(err.Error(), rawURL, "<uploadUrl>")))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return protocol.WithCode(protocol.CodeTransferFailed, fmt.Errorf("image upload: the engine answered %d", res.StatusCode))
	}
	return nil
}
