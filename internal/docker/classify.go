package docker

import (
	"context"
	"errors"
	"strings"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

// classifyCLI maps a failed `docker <verb>` to a result code (protocol >= 1; docs/protocol.md section 5.1). msg is
// docker's stderr (or the exec error when stderr was empty). It is the only place that reads docker's wording.
// Anything unrecognised is "" (reported as internal), except a failed `docker pull`, which is image_pull_failed.
func classifyCLI(ctx context.Context, verb, msg string) string {
	if ctx != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return protocol.CodeTimeout
		case errors.Is(ctx.Err(), context.Canceled):
			return protocol.CodeCancelled
		}
	}
	m := strings.ToLower(msg)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(m, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("cannot connect to the docker daemon", "is the docker daemon running", "permission denied while trying to connect to the docker daemon",
		`"docker": executable file not found`, "docker.sock: connect"):
		return protocol.CodeDockerUnavail
	case has("no space left on device"):
		return protocol.CodeNoSpace
	case has("port is already allocated", "address already in use", "ports are not available"):
		return protocol.CodePortInUse
	}
	pulling := verb == "pull" || (verb == "run" && has("unable to find image"))
	if pulling {
		if has("manifest unknown", "manifest for", "repository does not exist", "pull access denied", "requested access to the resource is denied",
			"not found: manifest", "unauthorized", "denied:", "name unknown") {
			return protocol.CodeImageNotFound
		}
		return protocol.CodeImagePullFailed
	}
	if has("no such container", "no such object", "no such network", "no such volume", "no such image") {
		return protocol.CodeNotFound
	}
	return ""
}
