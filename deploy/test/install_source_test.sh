#!/bin/sh
# Tests install.sh's download source: release_dir (default = latest GitHub release, --version/F2C_VERSION = tag v<semver>), dl (clear failure),
# fetch_signed_sums against a local file:// "release" signed with a throwaway key (the embedded key list is replaced by that key for the test),
# and the support-file gate (signed file ok, tampered file refused, local files only when install.sh sits beside them). No network, no root.
# Skipped when openssl lacks ed25519. POSIX sh.
# Run: sh deploy/test/install_source_test.sh   (also run by `go test`)
# shellcheck disable=SC2034 # the variables are read by the sourced install.sh functions
here=$(cd "$(dirname "$0")" && pwd)
export F2C_INSTALL_LIB=1
# shellcheck source=/dev/null
. "$here/../install.sh"
set +eu

if ! command -v openssl >/dev/null 2>&1 || ! openssl genpkey -algorithm ed25519 >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  echo "install_source_test.sh: SKIP (openssl with ed25519 or curl not available)"
  exit 0
fi

T=$(mktemp -d) && trap 'rm -rf "$T"' EXIT
N=0 FAILS=0
ok() { N=$((N + 1)); _n=$1; shift; if ! "$@" >/dev/null 2>&1; then FAILS=$((FAILS + 1)); echo "FAIL $_n (want success)"; fi; }
no() { N=$((N + 1)); _n=$1; shift; if "$@" >/dev/null 2>&1; then FAILS=$((FAILS + 1)); echo "FAIL $_n (want failure)"; fi; }
eq() { N=$((N + 1)); if [ "$2" != "$3" ]; then FAILS=$((FAILS + 1)); echo "FAIL $1: got [$2] want [$3]"; fi; }
rc() { "$@" >/dev/null 2>&1; echo $?; }

# 1. release_dir
GH=https://github.com/vinodkumar937/f2c-agent/releases/download
eq dir-latest "$(release_dir "$GH" "")" "https://github.com/vinodkumar937/f2c-agent/releases/latest/download"
eq dir-latest-trailing-slash "$(release_dir "$GH/" "")" "https://github.com/vinodkumar937/f2c-agent/releases/latest/download"
eq dir-version "$(release_dir "$GH" "0.4.0")" "$GH/v0.4.0"
eq dir-version-with-v "$(release_dir "$GH" "v0.4.0")" "$GH/v0.4.0"
eq dir-version-drops-build-stamp "$(release_dir "$GH" "0.4.0+202611191030")" "$GH/v0.4.0"
eq dir-mirror "$(release_dir "file:///srv/rel/download" "1.2.3")" "file:///srv/rel/download/v1.2.3"
eq default-base "$F2C_RELEASE_BASE" ""   # only set by the main part of install.sh, not by the helpers
eq caddy-default-is-this-repo "$(sed -n 's/^F2C_CADDY_URL="${F2C_CADDY_URL:-\(.*\)}"$/\1/p' "$here/../install.sh")" 'https://github.com/vinodkumar937/f2c-agent/releases/download/$F2C_CADDY_TAG'
eq release-base-default-is-this-repo "$(sed -n 's/^F2C_RELEASE_BASE="${F2C_RELEASE_BASE:-\(.*\)}"$/\1/p' "$here/../install.sh")" "$GH"

# 2. a signed release on disk, fetched over file://
openssl genpkey -algorithm ed25519 -out "$T/k.key" 2>/dev/null
openssl pkey -in "$T/k.key" -pubout -out "$T/k.pub" 2>/dev/null
SPKI=$(openssl pkey -pubin -in "$T/k.pub" -outform DER 2>/dev/null | openssl base64 -A)
KEYS_TEST="aaaaaaaaaaaaaaaa active $SPKI"
PEM_TEST=$(cat "$T/k.pub")
REL=$T/rel/download/v1.0.0
mkdir -p "$REL"
printf 'binary-amd64\n' > "$REL/f2c-agent-linux-amd64"
printf '[Unit]\nDescription=test\n' > "$REL/f2c-agent.service"
printf 'resume\n' > "$REL/caddy-resume.conf"
{
  echo "# f2c-release 1"; echo "# version 1.0.0+202611190000"
  for f in f2c-agent-linux-amd64 f2c-agent.service caddy-resume.conf; do echo "$(sha256_of "$REL/$f")  $f"; done
} > "$REL/SHA256SUMS"
openssl pkeyutl -sign -inkey "$T/k.key" -rawin -in "$REL/SHA256SUMS" -out "$REL/SHA256SUMS.sig" 2>/dev/null
printf '{"v":1,"signatures":[{"keyId":"aaaaaaaaaaaaaaaa","alg":"ed25519","sig":"%s"}]}\n' "$(openssl base64 -A -in "$REL/SHA256SUMS.sig")" > "$REL/SHA256SUMS.sigs"
URL=file://$REL
F2C_RELEASE_KEYS=$KEYS_TEST F2C_RELEASE_PUBKEYS_PEM=$PEM_TEST
WORK=$T/w1 && mkdir -p "$WORK"
eq fetch-signed-rc0 "$(rc fetch_signed_sums "$URL")" 0
ok sums-downloaded test -s "$WORK/SHA256SUMS"
# the legacy path alone (no .sigs published)
WORK=$T/w2 && mkdir -p "$WORK" && mv "$REL/SHA256SUMS.sigs" "$T/sigs.hold"
eq fetch-legacy-sig-only-rc0 "$(rc fetch_signed_sums "$URL")" 0
mv "$T/sigs.hold" "$REL/SHA256SUMS.sigs"
# the embedded keys do not match -> refused (1)
WORK=$T/w3 && mkdir -p "$WORK"
eq fetch-wrong-keys-rc1 "$(F2C_RELEASE_KEYS="bbbbbbbbbbbbbbbb active $(printf '%s' "$SPKI" | tr 'A-Za-z' 'N-ZA-Mn-za-m')" F2C_RELEASE_PUBKEYS_PEM="" rc fetch_signed_sums "$URL")" 1
# a revoked key id is refused too
WORK=$T/w4 && mkdir -p "$WORK"
eq fetch-revoked-key-rc1 "$(F2C_RELEASE_KEYS="aaaaaaaaaaaaaaaa revoked $SPKI" F2C_RELEASE_PUBKEYS_PEM="" rc fetch_signed_sums "$URL")" 1
# tampered SHA256SUMS -> refused (1)
WORK=$T/w5 && mkdir -p "$WORK"; cp -R "$T/rel" "$T/rel-bad"
printf '# tampered\n' >> "$T/rel-bad/download/v1.0.0/SHA256SUMS"
eq fetch-tampered-rc1 "$(rc fetch_signed_sums "file://$T/rel-bad/download/v1.0.0")" 1
# release not published -> 2, and the message names the URL
WORK=$T/w6 && mkdir -p "$WORK"
eq fetch-missing-rc2 "$(rc fetch_signed_sums "file://$T/rel/download/v9.9.9")" 2
ok dl-failure-names-url sh -c ". '$here/../install.sh'; dl file://$T/nope $T/out 2>&1 | grep -q 'download failed: file://$T/nope'"

# 3. ensure_sums + support gate, as the installer runs them (subshell: ensure_sums exits on failure)
F2C_RELEASE_BASE=file://$T/rel/download RELEASE_VERSION=1.0.0 RELEASE_DIR="" SUMS_FILE="" WORK=$T/w7 HERE=$T/nohere
mkdir -p "$WORK" "$HERE"
ensure_sums >/dev/null 2>&1
eq ensure-sums-sets-dir "$RELEASE_DIR" "file://$T/rel/download/v1.0.0"
eq ensure-sums-sets-file "$SUMS_FILE" "$T/w7/SHA256SUMS"
eq support-downloads-and-gates "$(support f2c-agent.service 2>/dev/null)" "$T/w7/f2c-agent.service"
ok binary-hash-matches-signed-sums verify_release_sums "$SUMS_FILE" amd64 "$REL/f2c-agent-linux-amd64"
printf 'evil\n' > "$T/evil"; no binary-tampered-refused verify_release_sums "$SUMS_FILE" amd64 "$T/evil"
# a file the release serves but the signed SHA256SUMS lists differently is refused
cp -R "$T/rel" "$T/rel-swap"; printf '[Unit]\nDescription=evil\n' > "$T/rel-swap/download/v1.0.0/f2c-agent.service"
RELEASE_DIR=file://$T/rel-swap/download/v1.0.0
no support-swapped-file-refused support f2c-agent.service
RELEASE_DIR=file://$T/rel/download/v1.0.0
# local files are used only when install.sh sits beside them
printf 'local\n' > "$T/nohere/f2c-agent.service"
eq local-file-ignored-without-install-sh "$(support f2c-agent.service 2>/dev/null)" "$T/w7/f2c-agent.service"
printf '#!/bin/sh\n' > "$T/nohere/install.sh"
eq local-file-used-beside-install-sh "$(support f2c-agent.service 2>/dev/null)" "$T/nohere/f2c-agent.service"
# a missing release fails ensure_sums (exit 1) instead of continuing unverified
no ensure-sums-missing-release-fatal sh -c ". '$here/../install.sh'; WORK=$T/w8; mkdir -p \$WORK; SUMS_FILE=''; F2C_RELEASE_BASE=file://$T/rel/download RELEASE_VERSION=9.9.9; ensure_sums; echo reached"
eq ensure-sums-missing-release-exit-code "$(sh -c ". '$here/../install.sh'; WORK=$T/w9; mkdir -p \$WORK; SUMS_FILE=''; F2C_RELEASE_BASE=file://$T/rel/download RELEASE_VERSION=9.9.9; ensure_sums >/dev/null 2>&1; echo reached" 2>/dev/null | grep -c reached)" 0

echo "install_source_test.sh: $N checks, $FAILS failed"
[ "$FAILS" = 0 ]
