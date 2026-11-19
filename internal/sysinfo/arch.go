package sysinfo

import (
	"runtime"
)

// HostArch is this server's CPU architecture as the engine records it (M2.12 arch check): "amd64" or "arm64";
// anything else is passed through as-is (the engine treats it as not matching either).
func HostArch() string { return NormArch(runtime.GOARCH) }

func NormArch(a string) string {
	switch a {
	case "amd64", "x86_64", "x64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	}
	return a
}
