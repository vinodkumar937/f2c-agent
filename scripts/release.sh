#!/usr/bin/env bash
# Cross-build signed f2c-agent release artifacts for linux/amd64 and linux/arm64.
#
# Usage (from the repo root; the version is required, there is no default):
#   bash scripts/release.sh 0.4.0
#   F2C_AGENT_VERSION=0.4.0 bash scripts/release.sh
#   F2C_RELEASE_SIGNING_KEY=/path/to/ed25519.pem bash scripts/release.sh 0.4.0
#   F2C_AGENT_BIN_DIR=/path/to/agent-bin bash scripts/release.sh 0.4.0 --install
#   bash scripts/release.sh 0.4.0 --no-sign   (build and check everything, sign nothing; never touches a key file; NOT publishable)
#
# Options and environment:
#   <version>                 X.Y.Z (a +YYYYMMDDHHMM build stamp is appended unless the argument already has one). The GitHub tag is v<X.Y.Z>.
#   --no-sign                 the only way to skip signing: SHA256SUMS.sig/.sigs are not written and the key path is not looked at. Without
#                             it a missing or unreadable signing key (F2C_RELEASE_SIGNING_KEY, or the built-in default path) is an error.
#   --caddy-dir DIR           (or F2C_CADDY_DIR) a directory with caddy-linux-amd64 and caddy-linux-arm64: their sha256 are listed in
#                             SHA256SUMS (hash only, the binaries are published by the caddy-binaries.yml workflow). Needed for
#                             --dns-provider installs: install.sh refuses a Caddy binary that the signed SHA256SUMS does not list.
#   F2C_CADDY_TAG             the Caddy release tag for the "# caddy-tag" header (default: the one in deploy/install.sh)
#   F2C_RELEASE_FLOOR         optional "# floor <semver>": no agent may be moved below it, even by rollback (see docs/protocol.md 8.4)
#
# Outputs under dist/release/<version>/:
#   f2c-agent-linux-amd64, f2c-agent-linux-arm64
#   the deploy files (install.sh, harden.sh, units, caddy-resume.conf) and release-keys.json (a copy of keys/release-keys.json)
#   version.json             (written FIRST, so that SHA256SUMS lists it)
#   SHA256SUMS               ("# " header lines: f2c-release, version, released, caddy-tag, keys-serial, optional floor; then hashes)
#   SHA256SUMS.sig           (raw 64-byte ed25519 signature, for verifiers older than key ids)
#   SHA256SUMS.sigs          (JSON list of signatures by key id)
#
# Before anything is built it checks that the key block of deploy/install.sh equals keys/release-keys.json, and after SHA256SUMS is
# written that every line of it is a '#' comment or a hash line. The signing key must be listed as active in keys/release-keys.json.
# --install copies those files into $F2C_AGENT_BIN_DIR, an agent-bin directory that an engine serves for self-update (off by default; the
# variable is required).
# Publishing: install.sh downloads everything from the GitHub release v<X.Y.Z> (or releases/latest), so every file in the Outputs list above
# must be attached to it. The script prints the exact file list and a gh command at the end; it never uploads, tags, commits or pushes.
# Never prints key material.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${F2C_AGENT_BIN_DIR:-}"
TOOL_PKG="./cmd/ed25519tool"

INSTALL=0
NO_SIGN=0
CADDY_DIR="${F2C_CADDY_DIR:-}"
VERSION_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --install) INSTALL=1; shift ;;
    --no-sign) NO_SIGN=1; shift ;;
    --caddy-dir) CADDY_DIR="${2:?--caddy-dir needs a directory}"; shift 2 ;;
    --help|-h)
      sed -n '2,40p' "$0"
      exit 0
      ;;
    -*)
      echo "release.sh: unknown flag $1" >&2
      exit 2
      ;;
    *)
      VERSION_OVERRIDE="$1"
      shift
      ;;
  esac
done

BASE_SEMVER="${F2C_AGENT_VERSION:-}"
if [ -n "$VERSION_OVERRIDE" ]; then
  BASE_SEMVER="$VERSION_OVERRIDE"
fi
if [ -z "$BASE_SEMVER" ]; then
  echo "release.sh: a version is required, for example: bash scripts/release.sh 0.4.0 (or F2C_AGENT_VERSION=0.4.0)" >&2
  exit 2
fi
case "$BASE_SEMVER" in
  [0-9]*.[0-9]*.[0-9]* | [0-9]*.[0-9]*.[0-9]*+*) ;;
  *) echo "release.sh: the version must look like 0.4.0 or 0.4.0+202611191030 (got $BASE_SEMVER)" >&2; exit 2 ;;
esac
TAG="v${BASE_SEMVER%%+*}"
# If the override already has a build stamp (contains +), use as-is; else append YYYYMMDDHHMM (UTC).
case "$BASE_SEMVER" in
  *+*) VERSION="$BASE_SEMVER" ;;
  *) VERSION="${BASE_SEMVER}+$(date -u +%Y%m%d%H%M)" ;;
esac

DEFAULT_KEY="${HOME}/.f2c-release/ed25519.pem"
SIGNING_KEY="${F2C_RELEASE_SIGNING_KEY:-$DEFAULT_KEY}"
FLOOR="${F2C_RELEASE_FLOOR:-}"

OUT_DIR="$AGENT_DIR/dist/release/$VERSION"

echo "release.sh: version=$VERSION"
echo "release.sh: out=$OUT_DIR"

# --- checks that need no build -------------------------------------------------------------------------------------------------
# One trusted-key list (keys/release-keys.json): the key block in install.sh is generated from it and must not drift.
(cd "$AGENT_DIR" && go run "$TOOL_PKG" check-install deploy/install.sh)
KEYS_SERIAL=$(cd "$AGENT_DIR" && go run "$TOOL_PKG" print-keys | awk 'NR == 1 { print $2 }')
case "$VERSION" in *+[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) echo "release.sh: warning: $VERSION has no 12-digit +YYYYMMDDHHMM build stamp: the update guard cannot order it against other builds" >&2 ;; esac
if [ -n "$FLOOR" ]; then
  case "$FLOOR" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "release.sh: F2C_RELEASE_FLOOR must be a semver like 0.3.1 (got $FLOOR)" >&2; exit 2 ;; esac
fi
# The Caddy tag the installer defaults to, unless overridden.
CADDY_TAG="${F2C_CADDY_TAG:-$(sed -n 's/^F2C_CADDY_TAG="${F2C_CADDY_TAG:-\([^}]*\)}"$/\1/p' "$AGENT_DIR/deploy/install.sh" | head -n 1)}"
[ -n "$CADDY_TAG" ] || { echo "release.sh: cannot find the Caddy tag (set F2C_CADDY_TAG)" >&2; exit 2; }
# Signing: skipped only with --no-sign (the key path is then never looked at); otherwise the key file must exist, or this is an error.
WILL_SIGN=0
if [ "$NO_SIGN" = 0 ]; then
  if [ ! -f "$SIGNING_KEY" ] || [ ! -r "$SIGNING_KEY" ]; then
    echo "release.sh: no signing key at $SIGNING_KEY (set F2C_RELEASE_SIGNING_KEY, or pass --no-sign for an unsigned build that must not be published)" >&2
    exit 1
  fi
  WILL_SIGN=1
fi
mkdir -p "$OUT_DIR"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

ARCHES=(amd64 arm64)
for arch in "${ARCHES[@]}"; do
  out="$OUT_DIR/f2c-agent-linux-$arch"
  echo "release.sh: building linux/$arch -> $(basename "$out")"
  (
    cd "$AGENT_DIR"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
      -ldflags "-s -w -X github.com/vinodkumar937/f2c-agent/internal/version.Version=${VERSION}" \
      -o "$out" ./cmd/f2c-agent
  )
done

# Install files that ship next to the binaries (install.sh, harden.sh, systemd units, Caddy drop-in). They are copied flat
# into the release and listed in the signed SHA256SUMS, so one signature covers the binaries and the install files.
DEPLOY_FILES=(install.sh harden.sh f2c-agent.service f2c-harden.path f2c-harden.service f2c-caddy-dns-env.path f2c-caddy-dns-env.service caddy-resume.conf)
for f in "${DEPLOY_FILES[@]}"; do
  cp "$AGENT_DIR/deploy/$f" "$OUT_DIR/$f"
done
# The trusted-key list ships with the release (an engine's trust file is updated from it, see docs/protocol.md 8.3).
cp "$AGENT_DIR/keys/release-keys.json" "$OUT_DIR/release-keys.json"

# Caddy: hash only (the binaries are built elsewhere and are not part of this release). Needs --caddy-dir or F2C_CADDY_DIR.
CADDY_HASHES=()
if [ -n "$CADDY_DIR" ]; then
  for arch in "${ARCHES[@]}"; do
    [ -f "$CADDY_DIR/caddy-linux-$arch" ] || { echo "release.sh: $CADDY_DIR/caddy-linux-$arch not found" >&2; exit 2; }
    CADDY_HASHES+=("$(sha256_of "$CADDY_DIR/caddy-linux-$arch")  caddy-linux-$arch")
  done
else
  echo "release.sh: warning: no --caddy-dir: SHA256SUMS will not list the Caddy hashes (installs then rely on the Caddy download's own checksum)" >&2
fi

BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# version.json is written BEFORE SHA256SUMS so that SHA256SUMS can list it (and so the signature covers it). It therefore cannot
# hold the hash of SHA256SUMS or of the signatures; it only names those files.
VJ_CADDY=""
if [ "${#CADDY_HASHES[@]}" -gt 0 ]; then VJ_CADDY="${CADDY_HASHES[*]}"; fi
OUT_DIR="$OUT_DIR" VERSION="$VERSION" BUILT_AT="$BUILT_AT" WILL_SIGN="$WILL_SIGN" CADDY_TAG="$CADDY_TAG" KEYS_SERIAL="$KEYS_SERIAL" \
  FLOOR="$FLOOR" VJ_CADDY="$VJ_CADDY" DEPLOY_NAMES="${DEPLOY_FILES[*]}" python3 - <<'PY'
import hashlib, json, os, pathlib
env = os.environ
out = pathlib.Path(env["OUT_DIR"])
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
artifacts = []
for arch in ("amd64", "arm64"):
    name = f"f2c-agent-linux-{arch}"
    p = out / name
    artifacts.append({"name": name, "goos": "linux", "goarch": arch, "sha256": sha(p), "size": p.stat().st_size})
files = []
for name in env["DEPLOY_NAMES"].split() + ["release-keys.json"]:
    p = out / name
    files.append({"name": name, "sha256": sha(p), "size": p.stat().st_size})
manifest = {
    "name": "f2c-agent",
    "version": env["VERSION"],
    "builtAt": env["BUILT_AT"],
    "artifacts": artifacts,
    "files": files,
    "sumsFile": "SHA256SUMS",
    "signatureFile": "SHA256SUMS.sig" if env["WILL_SIGN"] == "1" else None,
    "signaturesFile": "SHA256SUMS.sigs" if env["WILL_SIGN"] == "1" else None,
    "keysSerial": int(env["KEYS_SERIAL"]),
}
if env["FLOOR"]:
    manifest["floor"] = env["FLOOR"]
if env["VJ_CADDY"]:
    hashes = {}
    parts = env["VJ_CADDY"].split()
    for i in range(0, len(parts), 2):
        hashes[parts[i + 1].removeprefix("caddy-linux-")] = parts[i]
    manifest["caddy"] = {"tag": env["CADDY_TAG"], "sha256": hashes}
(out / "version.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("release.sh: wrote version.json")
PY

# SHA256SUMS in coreutils format (two spaces), filenames only (no paths). Every line is either a '#' comment (the signed header: old
# parsers skip them) or '<sha256>  <name>'; the header comes first.
SUMS="$OUT_DIR/SHA256SUMS"
{
  echo "# f2c-release 1"
  echo "# version $VERSION"
  echo "# released $BUILT_AT"
  echo "# caddy-tag $CADDY_TAG"
  echo "# keys-serial $KEYS_SERIAL"
  if [ -n "$FLOOR" ]; then echo "# floor $FLOOR"; fi
  for name in "${DEPLOY_FILES[@]}"; do echo "$(sha256_of "$OUT_DIR/$name")  $name"; done
  for arch in "${ARCHES[@]}"; do echo "$(sha256_of "$OUT_DIR/f2c-agent-linux-$arch")  f2c-agent-linux-$arch"; done
  echo "$(sha256_of "$OUT_DIR/version.json")  version.json"
  echo "$(sha256_of "$OUT_DIR/release-keys.json")  release-keys.json"
  if [ "${#CADDY_HASHES[@]}" -gt 0 ]; then printf '%s\n' "${CADDY_HASHES[@]}"; fi
} > "$SUMS"
(cd "$AGENT_DIR" && go run "$TOOL_PKG" lint-sums "$SUMS")
echo "release.sh: wrote SHA256SUMS ($(grep -c '^#' "$SUMS") header lines, $(grep -vc '^#' "$SUMS") files)"

SIG="$OUT_DIR/SHA256SUMS.sig"
SIGS="$OUT_DIR/SHA256SUMS.sigs"
rm -f "$SIG" "$SIGS"
if [ "$WILL_SIGN" = 1 ]; then
  echo "release.sh: signing SHA256SUMS with $SIGNING_KEY"
  # sign-release refuses a key that keys/release-keys.json does not list as active; it writes .sig (raw) and .sigs (by key id).
  (cd "$AGENT_DIR" && go run "$TOOL_PKG" sign-release "$SIGNING_KEY" "$SUMS")
  # Verify immediately with the sibling public key when present
  PUB_PEM="${SIGNING_KEY%.pem}.pub"
  if [ -f "$PUB_PEM" ]; then
    (cd "$AGENT_DIR" && go run "$TOOL_PKG" verify-pem "$PUB_PEM" "$SUMS" "$SIG")
    echo "release.sh: signature verified against $PUB_PEM"
  fi
else
  echo "release.sh: --no-sign: SHA256SUMS.sig and SHA256SUMS.sigs not written (this release must not be published)" >&2
fi

echo "release.sh: artifacts:"
ls -la "$OUT_DIR"

if [ "$INSTALL" = 1 ]; then
  if [ -z "$BIN_DIR" ]; then
    echo "release.sh: --install needs F2C_AGENT_BIN_DIR (the engine agent-bin directory)" >&2
    exit 2
  fi
  mkdir -p "$BIN_DIR"
  echo "release.sh: installing into $BIN_DIR"
  for arch in "${ARCHES[@]}"; do
    install -m 0755 "$OUT_DIR/f2c-agent-linux-$arch" "$BIN_DIR/f2c-agent-linux-$arch"
  done
  install -m 0644 "$SUMS" "$BIN_DIR/SHA256SUMS"
  for f in "$SIG" "$SIGS"; do
    if [ -f "$f" ]; then
      install -m 0644 "$f" "$BIN_DIR/$(basename "$f")"
    fi
  done
  install -m 0644 "$OUT_DIR/version.json" "$BIN_DIR/version.json"
  install -m 0644 "$OUT_DIR/release-keys.json" "$BIN_DIR/release-keys.json"
  echo "release.sh: installed"
else
  echo "release.sh: skipping install to agent-bin (pass --install to copy)"
fi

# What install.sh fetches from the GitHub release: the binaries, install.sh and the support files, version.json, release-keys.json, SHA256SUMS and
# its signatures. Printed (not executed) so that nothing is published by accident.
UPLOAD=()
for f in "${ARCHES[@]/#/f2c-agent-linux-}" "${DEPLOY_FILES[@]}" version.json release-keys.json SHA256SUMS; do UPLOAD+=("$OUT_DIR/$f"); done
if [ "$WILL_SIGN" = 1 ]; then UPLOAD+=("$SIG" "$SIGS"); fi
for f in "${UPLOAD[@]}"; do [ -f "$f" ] || { echo "release.sh: internal error: $f is missing" >&2; exit 1; }; done
echo "release.sh: files to attach to the GitHub release $TAG (${#UPLOAD[@]}):"
for f in "${UPLOAD[@]}"; do echo "  $f"; done
if [ "$WILL_SIGN" = 1 ]; then
  echo "release.sh: publish (not run): gh release create $TAG --repo vinodkumar937/f2c-agent --title \"f2c-agent $TAG\" --notes-file <notes> <the files above>"
else
  echo "release.sh: unsigned build: do not publish"
fi
echo "release.sh: done $VERSION"
