package docker

import (
	"context"
	"testing"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

func TestClassifyCLI(t *testing.T) {
	for _, tc := range []struct {
		verb, msg, want string
	}{
		// the cases the engine depends on
		{"run", "docker: Error response from daemon: driver failed programming external connectivity on endpoint web: Bind for 127.0.0.1:20001 failed: port is already allocated.", protocol.CodePortInUse},
		{"run", "listen tcp4 0.0.0.0:80: bind: address already in use", protocol.CodePortInUse},
		{"start", "Error response from daemon: Ports are not available: exposing port TCP 127.0.0.1:20001 -> 0.0.0.0:0: listen tcp 127.0.0.1:20001: bind: address already in use", protocol.CodePortInUse},
		{"inspect", "Error: No such object: web", protocol.CodeNotFound},
		{"stop", "Error response from daemon: No such container: web", protocol.CodeNotFound},
		{"network", "Error response from daemon: network web not found", ""}, // wording without "no such": left to the caller (internal)
		{"network", "Error response from daemon: No such network: web", protocol.CodeNotFound},
		{"volume", "Error response from daemon: get x: no such volume", protocol.CodeNotFound},
		// pulls: not found vs everything else
		{"pull", "Error response from daemon: pull access denied for nginx, repository does not exist or may require 'docker login'", protocol.CodeImageNotFound},
		{"pull", "Error response from daemon: manifest for nginx:nope not found: manifest unknown: manifest unknown", protocol.CodeImageNotFound},
		{"pull", "Error response from daemon: unauthorized: authentication required", protocol.CodeImageNotFound},
		{"pull", "Error response from daemon: Get \"https://registry-1.docker.io/v2/\": dial tcp: lookup registry-1.docker.io: no such host", protocol.CodeImagePullFailed},
		{"pull", "Error response from daemon: toomanyrequests: You have reached your pull rate limit", protocol.CodeImagePullFailed},
		{"pull", "something nobody has ever seen", protocol.CodeImagePullFailed}, // decision 4: a failed pull falls back to image_pull_failed
		{"run", "Unable to find image 'x:1' locally\ndocker: Error response from daemon: Get \"https://r/v2/\": dial tcp: i/o timeout.", protocol.CodeImagePullFailed},
		{"run", "Unable to find image 'x:1' locally\ndocker: Error response from daemon: pull access denied for x", protocol.CodeImageNotFound},
		{"run", "docker: Error response from daemon: OCI runtime create failed: exec: \"nope\": executable file not found in $PATH", ""}, // the container's own program is missing: not a docker outage
		// environment
		{"ps", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", protocol.CodeDockerUnavail},
		{"ps", "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock", protocol.CodeDockerUnavail},
		{"pull", "exec: \"docker\": executable file not found in $PATH", protocol.CodeDockerUnavail},
		{"pull", "write /var/lib/docker/tmp/GetImageBlob: no space left on device", protocol.CodeNoSpace},
		{"load", "write /var/lib/docker/x: no space left on device", protocol.CodeNoSpace},
		// unrecognised: no code here, reported as internal
		{"rm", "Error response from daemon: removal of container web is already in progress", ""},
		{"run", "docker: Error response from daemon: something odd.", ""},
	} {
		if got := classifyCLI(context.Background(), tc.verb, tc.msg); got != tc.want {
			t.Errorf("%s %q -> %q, want %q", tc.verb, tc.msg, got, tc.want)
		}
	}
}

func TestClassifyCLIContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classifyCLI(ctx, "pull", "signal: killed"); got != protocol.CodeCancelled {
		t.Fatalf("cancelled: %s", got)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 0)
	defer dcancel()
	<-dctx.Done()
	if got := classifyCLI(dctx, "build", "signal: killed"); got != protocol.CodeTimeout {
		t.Fatalf("deadline: %s", got)
	}
}

// CommandError keeps the text exactly "docker <verb>: <stderr>" and carries the code only as protocol data.
func TestCommandErrorText(t *testing.T) {
	err := CommandError(context.Background(), "pull", "pull access denied")
	if err.Error() != "docker pull: pull access denied" || protocol.ResultCode(err) != protocol.CodeImageNotFound {
		t.Fatalf("%v %q", err, protocol.ResultCode(err))
	}
	if m := protocol.ResultMessage("x", nil, err); m["code"] != nil {
		t.Fatalf("protocol 0 must not carry the code: %v", m)
	}
	if err := CommandError(context.Background(), "rm", "weird"); protocol.ResultCode(err) != "" || err.Error() != "docker rm: weird" {
		t.Fatalf("unclassified: %v", err)
	}
}
