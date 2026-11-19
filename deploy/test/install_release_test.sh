#!/bin/sh
# Tests install.sh's release checks: the generated key block, SHA256SUMS.sigs verification by key id, the signed-file gate
# (mismatch, unlisted, legacy vs current format, F2C_REQUIRE_SIGNED) and --print-keys. No key is generated: signatures come
# from the real signed sums of an existing release (internal/update/testdata/), and the "other key" is arbitrary bytes.
# Skipped when openssl lacks ed25519. POSIX sh.
# Run: sh deploy/test/install_release_test.sh   (also run by `go test`)
here=$(cd "$(dirname "$0")" && pwd)
export F2C_INSTALL_LIB=1
# shellcheck source=/dev/null
. "$here/../install.sh"
set +eu

if ! command -v openssl >/dev/null 2>&1; then
  echo "install_release_test.sh: SKIP (openssl not available)"
  exit 0
fi

T=$(mktemp -d) && trap 'rm -rf "$T"' EXIT
N=0 FAILS=0
ok() { N=$((N + 1)); _n=$1; shift; if ! "$@" >/dev/null 2>&1; then FAILS=$((FAILS + 1)); echo "FAIL $_n (want success)"; fi; }
no() { N=$((N + 1)); _n=$1; shift; if "$@" >/dev/null 2>&1; then FAILS=$((FAILS + 1)); echo "FAIL $_n (want failure)"; fi; }
eq() { N=$((N + 1)); if [ "$2" != "$3" ]; then FAILS=$((FAILS + 1)); echo "FAIL $1: got [$2] want [$3]"; fi; }
fresh() { rm -rf "$T/k" && mkdir -p "$T/k"; }

REL="$here/../../internal/update/testdata/release-0.3.0"
RAW_B64=$(openssl base64 -A -in "$REL/SHA256SUMS.sig")
REAL_ID=d5be90e42c884807
KEYS_LIVE=$F2C_RELEASE_KEYS
SPKI=$(printf '%s\n' "$KEYS_LIVE" | awk -v id="$REAL_ID" '$1 == id { print $3 }')
sigs() { printf '{"v":1,"signatures":[{"keyId":"%s","alg":"ed25519","sig":"%s"}]}\n' "$1" "$2"; }

# 1. the generated block
eq key-block-has-the-live-key "$SPKI" "MCowBQYDK2VwAyEAtsixg7qlWB4qdKyXQHQcCaGqcKXF+OCSspPutkGQ8Ts="
eq pem-from-block "$(release_keys_pem)" "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAtsixg7qlWB4qdKyXQHQcCaGqcKXF+OCSspPutkGQ8Ts=
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADtT/M0nfuu5IPKPm5nxabmlmtRZQ9QKJ3R8HeF+GWsI=
-----END PUBLIC KEY-----"
eq revoked-key-not-in-pem "$(F2C_RELEASE_KEYS="$REAL_ID revoked $SPKI" release_keys_pem)" ""
fresh; ok legacy-raw-sig-verifies verify_sums_sig "$REL/SHA256SUMS" "$REL/SHA256SUMS.sig" "$F2C_RELEASE_PUBKEYS_PEM" "$T/k"

# 2. SHA256SUMS.sigs by key id
sigs "$REAL_ID" "$RAW_B64" > "$T/sigs.ok"
fresh; ok sigs-by-id-verifies verify_sums_sigs "$REL/SHA256SUMS" "$T/sigs.ok" "$KEYS_LIVE" "$T/k"
printf '{\n  "v": 1,\n  "signatures": [\n    {\n      "keyId": "%s",\n      "alg": "ed25519",\n      "sig": "%s"\n    }\n  ]\n}\n' "$REAL_ID" "$RAW_B64" > "$T/sigs.pretty"
fresh; ok sigs-pretty-printed-verifies verify_sums_sigs "$REL/SHA256SUMS" "$T/sigs.pretty" "$KEYS_LIVE" "$T/k"
printf 'x' > "$T/sums.tampered"; cat "$REL/SHA256SUMS" >> "$T/sums.tampered"
fresh; no sigs-tampered-sums-refused verify_sums_sigs "$T/sums.tampered" "$T/sigs.ok" "$KEYS_LIVE" "$T/k"
sigs 1111111111111111 "$RAW_B64" > "$T/sigs.unknown"
fresh; no sigs-unknown-id-refused verify_sums_sigs "$REL/SHA256SUMS" "$T/sigs.unknown" "$KEYS_LIVE" "$T/k"
fresh; no sigs-revoked-id-refused verify_sums_sigs "$REL/SHA256SUMS" "$T/sigs.ok" "$REAL_ID revoked $SPKI" "$T/k"
# the id only selects: the real signature filed under another (arbitrary-bytes) key must not verify
FAKE_SPKI=$(printf '\060\052\005\006\003\053\145\160\003\041\000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | openssl base64 -A)
sigs 2222222222222222 "$RAW_B64" > "$T/sigs.wrong"
fresh; no sigs-id-is-only-a-selector verify_sums_sigs "$REL/SHA256SUMS" "$T/sigs.wrong" "2222222222222222 active $FAKE_SPKI" "$T/k"
printf '{"v":1,"signatures":[{"keyId":"1111111111111111","alg":"ed25519","sig":"AAAA"},{"keyId":"%s","alg":"ed25519","sig":"%s"}]}\n' "$REAL_ID" "$RAW_B64" > "$T/sigs.two"
fresh; ok sigs-later-entry-counts verify_sums_sigs "$REL/SHA256SUMS" "$T/sigs.two" "$KEYS_LIVE" "$T/k"
printf 'junk' > "$T/sigs.junk"
fresh; no sigs-junk-refused verify_sums_sigs "$REL/SHA256SUMS" "$T/sigs.junk" "$KEYS_LIVE" "$T/k"

# 3. the signed-file gate
printf 'hello\n' > "$T/f.txt"
H=$(sha256_of "$T/f.txt")
printf '%s  f.txt\n' "$H" > "$T/sums.legacy"
printf '# f2c-release 1\n# version 1.0.0\n%s  f.txt\n' "$H" > "$T/sums.new"
printf '%s  f.txt\n' "0000000000000000000000000000000000000000000000000000000000000000" > "$T/sums.bad"
ok sums-header-detected sums_has_header "$T/sums.new"
no sums-header-absent-legacy sums_has_header "$T/sums.legacy"
ok gate-match signed_file_gate "$T/sums.legacy" f.txt "$T/f.txt"
no gate-mismatch-fatal signed_file_gate "$T/sums.bad" f.txt "$T/f.txt"
ok gate-legacy-unlisted-warns signed_file_gate "$T/sums.legacy" other.txt "$T/f.txt"
no gate-legacy-unlisted-fatal-when-required env F2C_REQUIRE_SIGNED=1 sh -c '. "$1"; signed_file_gate "$2" other.txt "$3"' sh "$here/../install.sh" "$T/sums.legacy" "$T/f.txt"
no gate-new-format-unlisted-fatal signed_file_gate "$T/sums.new" other.txt "$T/f.txt"
eq gate-legacy-unlisted-message "$(signed_file_gate "$T/sums.legacy" other.txt "$T/f.txt" 2>&1 | grep -c 'legacy')" "1"
printf '# floor 0.3.1\n# fake  %s  f.txt\n%s  f.txt\n' "$H" "$H" > "$T/sums.comment"
ok gate-comment-lines-ignored signed_file_gate "$T/sums.comment" f.txt "$T/f.txt"
eq sums-hash-skips-comments "$(sums_hash "$T/sums.comment" f.txt)" "$H"

# 4. --print-keys (not advertised, but must work and print no key material beyond ids)
out=$(F2C_INSTALL_LIB=0 sh "$here/../install.sh" --print-keys 2>&1)
eq print-keys-first-line "$(printf '%s\n' "$out" | sed -n 1p)" "release keys serial 2"
eq print-keys-lists-id "$(printf '%s\n' "$out" | sed -n 2p)" "$REAL_ID  active"
eq print-keys-lists-backup-id "$(printf '%s\n' "$out" | sed -n 3p)" "3d4fe084d4acbab8  active"

echo "install_release_test.sh: $N checks, $FAILS failed"
[ "$FAILS" = 0 ]
