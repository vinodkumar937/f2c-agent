#!/bin/sh
# Tests install.sh's SHA256SUMS signature check with a key list (verify_sums_sig): the embedded release key verifies the
# real signed sums of an existing release (internal/update/testdata/), an unknown key is refused, and a multi-key list accepts a signature
# from either key. Throwaway keys are generated with openssl in a temp dir. Skipped when openssl lacks ed25519.
# Run: sh deploy/test/install_sig_test.sh   (also run by `go test` via harden_script_test.go)
here=$(cd "$(dirname "$0")" && pwd)
export F2C_INSTALL_LIB=1
# shellcheck source=/dev/null
. "$here/../install.sh"
set +eu

if ! command -v openssl >/dev/null 2>&1 || ! openssl genpkey -algorithm ed25519 >/dev/null 2>&1; then
  echo "install_sig_test.sh: SKIP (openssl with ed25519 not available)"
  exit 0
fi

T=$(mktemp -d) && trap 'rm -rf "$T"' EXIT
N=0 FAILS=0
ok() { # name command...
  N=$((N + 1)); _n=$1; shift
  if ! "$@"; then FAILS=$((FAILS + 1)); echo "FAIL $_n (want success)"; fi
}
no() {
  N=$((N + 1)); _n=$1; shift
  if "$@"; then FAILS=$((FAILS + 1)); echo "FAIL $_n (want failure)"; fi
}
fresh() { rm -rf "$T/k" && mkdir -p "$T/k"; }

# 1. embedded key vs a real release signature
REL="$here/../../internal/update/testdata/release-0.2.1"
fresh; ok embedded-key-verifies-real-release verify_sums_sig "$REL/SHA256SUMS" "$REL/SHA256SUMS.sig" "$F2C_RELEASE_PUBKEYS_PEM" "$T/k"
printf 'x' > "$T/tampered"; cat "$REL/SHA256SUMS" >> "$T/tampered"
fresh; no tampered-sums-refused verify_sums_sig "$T/tampered" "$REL/SHA256SUMS.sig" "$F2C_RELEASE_PUBKEYS_PEM" "$T/k"

# 2. throwaway keys
for k in a b c; do openssl genpkey -algorithm ed25519 -out "$T/$k.key" 2>/dev/null; openssl pkey -in "$T/$k.key" -pubout -out "$T/$k.pub" 2>/dev/null; done
printf 'data  f2c-agent-linux-amd64\n' > "$T/sums"
openssl pkeyutl -sign -inkey "$T/a.key" -rawin -in "$T/sums" -out "$T/sig-a" 2>/dev/null
openssl pkeyutl -sign -inkey "$T/b.key" -rawin -in "$T/sums" -out "$T/sig-b" 2>/dev/null
PUB_A=$(cat "$T/a.pub") PUB_B=$(cat "$T/b.pub") PUB_C=$(cat "$T/c.pub")
BOTH=$(printf '%s\n%s' "$PUB_A" "$PUB_B")

fresh; ok single-key-own-sig verify_sums_sig "$T/sums" "$T/sig-a" "$PUB_A" "$T/k"
fresh; no unknown-key-refused verify_sums_sig "$T/sums" "$T/sig-a" "$PUB_C" "$T/k"
fresh; no empty-list-refused verify_sums_sig "$T/sums" "$T/sig-a" "" "$T/k"
fresh; ok multi-key-accepts-first verify_sums_sig "$T/sums" "$T/sig-a" "$BOTH" "$T/k"
fresh; ok multi-key-accepts-second verify_sums_sig "$T/sums" "$T/sig-b" "$BOTH" "$T/k"
fresh; no multi-key-wrong-signer verify_sums_sig "$T/sums" "$T/sig-a" "$(printf '%s\n%s' "$PUB_B" "$PUB_C")" "$T/k"

echo "install_sig_test.sh: $N checks, $FAILS failed"
[ "$FAILS" = 0 ]
