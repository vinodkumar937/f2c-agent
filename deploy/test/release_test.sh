#!/usr/bin/env bash
# Tests scripts/release.sh's argument and signing-key checks (nothing is built, no key is read or generated):
# a version is required and must look like a version, and signing is on unless --no-sign, so a missing key is an error (non-zero),
# never a warning that still produces an unsigned release.
# Run: bash deploy/test/release_test.sh   (also run by `go test`)
here=$(cd "$(dirname "$0")" && pwd)
R="$here/../../scripts/release.sh"
T=$(mktemp -d) && trap 'rm -rf "$T"' EXIT
N=0 FAILS=0
eq() { N=$((N + 1)); if [ "$2" != "$3" ]; then FAILS=$((FAILS + 1)); echo "FAIL $1: got [$2] want [$3]"; fi; }
run() { env -u F2C_AGENT_VERSION -u F2C_RELEASE_SIGNING_KEY "$@" >"$T/out" 2>"$T/err"; echo $?; }

eq no-version-is-usage-error "$(run bash "$R")" 2
eq no-version-message "$(grep -c 'a version is required' "$T/err")" 1
eq stale-default-gone "$(grep -c '0\.2\.0' "$R")" 0
eq bad-version-is-usage-error "$(run bash "$R" latest)" 2
eq bad-version-two-parts "$(run bash "$R" 1.2)" 2
eq unknown-flag "$(run bash "$R" 0.4.0 --nope)" 2
# no key and no --no-sign: hard failure before anything is built
eq missing-key-fails "$(run env F2C_RELEASE_SIGNING_KEY="$T/none.pem" bash "$R" 0.4.0)" 1
eq missing-key-message "$(grep -c "no signing key at $T/none.pem" "$T/err")" 1
eq missing-key-still-names-no-sign "$(grep -c -- '--no-sign' "$T/err")" 1
eq missing-key-builds-nothing "$(grep -c 'building linux' "$T/out")" 0
# an unreadable key path (a directory) is the same error
mkdir "$T/dir.pem"
eq key-is-a-directory-fails "$(run env F2C_RELEASE_SIGNING_KEY="$T/dir.pem" bash "$R" 0.4.0)" 1
# the version may come from the environment
eq env-version-accepted-then-key-check "$(run env F2C_AGENT_VERSION=0.4.0 F2C_RELEASE_SIGNING_KEY="$T/none.pem" bash "$R")" 1

echo "release_test.sh: $N checks, $FAILS failed"
[ "$FAILS" = 0 ]
