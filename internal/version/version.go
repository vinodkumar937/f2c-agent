// Package version holds the agent's build version.
package version

// Version is the agent's version. Release builds set it at link time:
//
//	go build -ldflags "-X github.com/vinodkumar937/f2c-agent/internal/version.Version=0.4.0+202611191200" ./cmd/f2c-agent
var Version = "0.1.0-dev"
