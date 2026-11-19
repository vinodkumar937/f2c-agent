package harden

import (
	"os/exec"
	"testing"
)

// TestHardenScriptHelpers runs deploy/test/harden_test.sh: the pure bash helpers of deploy/harden.sh (SSH lockout
// checks, fail2ban merge), sourced with F2C_HARDEN_LIB=1 so nothing on the host is touched.
func TestHardenScriptHelpers(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	out, err := exec.Command(bash, "../../deploy/test/harden_test.sh").CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("../../deploy/test/harden_test.sh: %v", err)
	}
}

// TestInstallFirewallHelpers runs deploy/test/install_fw_test.sh: install.sh's firewall helpers (which public ports
// default-deny would block, which of our rules are missing) against fake ss/ufw output, sourced with
// F2C_INSTALL_LIB=1 so nothing on the host is touched. Runs under sh and, when installed, dash (Ubuntu's /bin/sh).
func TestInstallFirewallHelpers(t *testing.T) {
	ran := 0
	for _, name := range []string{"sh", "dash"} {
		sh, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		ran++
		out, err := exec.Command(sh, "../../deploy/test/install_fw_test.sh").CombinedOutput()
		t.Logf("%s: %s", name, out)
		if err != nil {
			t.Fatalf("%s deploy/test/install_fw_test.sh: %v", name, err)
		}
	}
	if ran == 0 {
		t.Skip("no POSIX sh installed")
	}
}

// TestInstallSigHelpers runs deploy/test/install_sig_test.sh: install.sh's SHA256SUMS signature check against a list of
// trusted keys (the embedded key verifies a real release; unknown keys fail; either key of a list passes).
// The script skips itself when openssl has no ed25519 support.
func TestInstallSigHelpers(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX sh installed")
	}
	out, err := exec.Command(sh, "../../deploy/test/install_sig_test.sh").CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("../../deploy/test/install_sig_test.sh: %v", err)
	}
}

// TestInstallReleaseHelpers runs deploy/test/install_release_test.sh: install.sh's generated key block, SHA256SUMS.sigs
// verification by key id, the signed-file gate and --print-keys. It generates no key (it reuses a real release's signature).
func TestInstallReleaseHelpers(t *testing.T) {
	ran := 0
	for _, name := range []string{"sh", "dash"} {
		sh, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		ran++
		out, err := exec.Command(sh, "../../deploy/test/install_release_test.sh").CombinedOutput()
		t.Logf("%s: %s", name, out)
		if err != nil {
			t.Fatalf("%s deploy/test/install_release_test.sh: %v", name, err)
		}
	}
	if ran == 0 {
		t.Skip("no POSIX sh installed")
	}
}

// TestInstallSourceHelpers runs deploy/test/install_source_test.sh: where install.sh downloads from (the public release, latest or a pinned
// tag), that a signed release on disk verifies and a tampered or unpublished one does not, and the support-file gate. Local files, a throwaway key.
func TestInstallSourceHelpers(t *testing.T) {
	ran := 0
	for _, name := range []string{"sh", "dash"} {
		sh, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		ran++
		out, err := exec.Command(sh, "../../deploy/test/install_source_test.sh").CombinedOutput()
		t.Logf("%s: %s", name, out)
		if err != nil {
			t.Fatalf("%s deploy/test/install_source_test.sh: %v", name, err)
		}
	}
	if ran == 0 {
		t.Skip("no POSIX sh installed")
	}
}

// TestReleaseScriptChecks runs deploy/test/release_test.sh: scripts/release.sh needs an explicit version and fails hard without a signing key
// unless --no-sign is given.
func TestReleaseScriptChecks(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash installed")
	}
	out, err := exec.Command(bash, "../../deploy/test/release_test.sh").CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("../../deploy/test/release_test.sh: %v", err)
	}
}
