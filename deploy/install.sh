#!/bin/sh
# f2c-agent installer. Run as root on a fresh app server (Ubuntu/Debian, systemd). No engine is needed:
#   curl -fsSL https://github.com/vinodkumar937/f2c-agent/releases/latest/download/install.sh | sudo sh -s -- --roles build,run
# It downloads the linux agent for this arch, its install files and the signed SHA256SUMS from the public GitHub release
# (F2C_RELEASE_BASE, default https://github.com/vinodkumar937/f2c-agent/releases/download), verifies SHA256SUMS against the
# release keys embedded below, then checks every download against it. A bad or missing signature is fatal. The agent is
# installed and its systemd unit left DISABLED until the server has joined an engine; join later with:
#   sudo runuser -u f2c-agent -- /var/lib/f2c-agent/bin/f2c-agent join --state-dir /var/lib/f2c-agent --engine https://ENGINE --token f2cj_...
#   sudo systemctl enable --now f2c-agent
# or join at install time with --engine <url> --token <join token> (the token is used once; the unit is then enabled).
# Version: latest release by default; --version 0.4.0 or F2C_VERSION=0.4.0 pins one (tag v0.4.0).
# F2C_AGENT_BIN=./f2c-agent installs a local binary instead (NOT verified against a release; support files then come from
# next to this script). DRY_RUN=1 prints the steps instead of changing the host (the signed release is still downloaded and checked).
# Recovery: sudo sh install.sh --reattach [--engine URL] — keeps agent.json, submits orphan inventory.
# Optional host hardening: --harden (OFF by default). Runs the same harden.sh used by the dashboard, after the
# agent joins and is connected: always a --dry-run preview first, printed here, then --apply only with
# F2C_HARDEN_CONFIRM=1 or a typed "yes" (terminal or /dev/tty). F2C_HARDEN_ALLOW_IPS="IP …" adds admin IPs to the
# SSH/fail2ban allow-list; the installing SSH peer is also always in fail2ban ignoreip (the engine's IPs never are:
# the agent link is outbound, and the engine sits behind a Cloudflare tunnel).
# Installs Docker and Caddy from their official apt repos when missing (Ubuntu/Debian; SKIP_DEPS=1 to only check).
# F2C_ROLES=build,run (default; same roles as the join) or --roles run: build tooling (railpack + the
# f2c-buildkit image, disk check) is installed only when the roles include build. Idempotent.
# --wildcard-domain <apps.example.com> --dns-provider cloudflare|digitalocean|other (other = on-demand HTTP-01, no DNS module): replaces the apt Caddy binary
# with the f2c build (DNS modules, built by the caddy-binaries.yml workflow and published as the GitHub release tag
# $F2C_CADDY_TAG of this repository, F2C_CADDY_URL overrides; its hash must match the signed SHA256SUMS) and adds a caddy EnvironmentFile
# drop-in pointing at /etc/f2c-agent/caddy-dns.env (0640 root:caddy; agent writes DO_AUTH_TOKEN/CF_API_TOKEN later via dns_token).
# Host firewall (ufw): default-deny incoming ON by default, non-destructive (never resets or deletes rules; only adds
# the detected SSH port(s), 80/tcp, 443/tcp, 443/udp). Public listening ports that would be blocked are listed first;
# an interactive install asks before blocking them (declined = firewall step skipped), a non-interactive one warns
# and proceeds. --no-firewall or F2C_FIREWALL=0 skips the step; F2C_FIREWALL=1 applies without asking.
# Does not touch DNS, does not print or store any token.
set -eu

# Trusted Ed25519 release public keys, generated from keys/release-keys.json (never edit the block by hand: release.sh and
# `go test ./keys/` fail when it drifts). One "<key id> <status> <SPKI base64>" line per key: active and retired keys verify,
# revoked ones stay listed so a signature by them is refused by name. A SHA256SUMS signature is accepted if ONE trusted key
# verifies it: SHA256SUMS.sigs picks the key by id, the legacy raw SHA256SUMS.sig tries every trusted key.
# BEGIN F2C_RELEASE_KEYS (generated from keys/release-keys.json by `go run ./cmd/ed25519tool sync-install`; do not edit)
F2C_RELEASE_KEYS_SERIAL=2
F2C_RELEASE_KEYS="d5be90e42c884807 active MCowBQYDK2VwAyEAtsixg7qlWB4qdKyXQHQcCaGqcKXF+OCSspPutkGQ8Ts=
3d4fe084d4acbab8 active MCowBQYDK2VwAyEADtT/M0nfuu5IPKPm5nxabmlmtRZQ9QKJ3R8HeF+GWsI="
# END F2C_RELEASE_KEYS

# release_keys_pem: SPKI PEM blocks, one after another, of every trusted (not revoked) key in F2C_RELEASE_KEYS
release_keys_pem() {
  printf '%s\n' "$F2C_RELEASE_KEYS" | awk 'NF == 3 && $2 != "revoked" { print "-----BEGIN PUBLIC KEY-----"; print $3; print "-----END PUBLIC KEY-----" }'
}
F2C_RELEASE_PUBKEYS_PEM=$(release_keys_pem)

# print_keys: the trusted key list (serial, then id and status per key)
print_keys() {
  echo "release keys serial $F2C_RELEASE_KEYS_SERIAL"
  printf '%s\n' "$F2C_RELEASE_KEYS" | awk 'NF == 3 { print $1 "  " $2 }'
}

# verify_sums_sig SUMS SIG KEYS_PEM DIR — 0 if SIG is a valid raw ed25519 signature of SUMS under any PEM block in KEYS_PEM
# (DIR is a scratch directory for the split key files). Needs OpenSSL 3 with ed25519 (Ubuntu 22.04+).
verify_sums_sig() {
  _vs_sums=$1 _vs_sig=$2 _vs_keys=$3 _vs_dir=$4
  command -v openssl >/dev/null 2>&1 || return 1
  printf '%s\n' "$_vs_keys" | awk -v d="$_vs_dir" '/-----BEGIN PUBLIC KEY-----/ { n++ } n { print > (d "/f2c-release-key-" n ".pub") }'
  for _vs_k in "$_vs_dir"/f2c-release-key-*.pub; do
    [ -f "$_vs_k" ] || continue
    if openssl pkeyutl -verify -pubin -inkey "$_vs_k" -rawin -in "$_vs_sums" -sigfile "$_vs_sig" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

# verify_sums_sigs SUMS SIGS KEYS DIR — 0 if one signature in the SHA256SUMS.sigs JSON file SIGS verifies SUMS under the
# key its keyId names in the KEYS list ("<id> <status> <SPKI base64>" lines). Unknown ids are skipped, a revoked id is
# refused with a message. The id only selects the key: the signature is always checked.
verify_sums_sigs() {
  _vg_sums=$1 _vg_sigs=$2 _vg_keys=$3 _vg_dir=$4
  command -v openssl >/dev/null 2>&1 || return 1
  _vg_flat=$(tr -d '\n\r' < "$_vg_sigs")
  printf '%s' "$_vg_flat" | grep -o '"keyId" *: *"[0-9a-f]*"' | sed 's/.*: *"\(.*\)"/\1/' > "$_vg_dir/sigs.ids"
  printf '%s' "$_vg_flat" | grep -o '"sig" *: *"[A-Za-z0-9+/=]*"' | sed 's/.*: *"\(.*\)"/\1/' > "$_vg_dir/sigs.b64"
  [ "$(wc -l < "$_vg_dir/sigs.ids")" -eq "$(wc -l < "$_vg_dir/sigs.b64")" ] || return 1
  paste -d ' ' "$_vg_dir/sigs.ids" "$_vg_dir/sigs.b64" > "$_vg_dir/sigs.pairs"
  while read -r _vg_id _vg_b64; do
    _vg_line=$(printf '%s\n' "$_vg_keys" | awk -v id="$_vg_id" 'NF == 3 && $1 == id { print; exit }')
    [ -n "$_vg_line" ] || continue
    case "$_vg_line" in
      *" revoked "*) echo "install.sh: SHA256SUMS signed by revoked key $_vg_id" >&2; continue ;;
    esac
    printf '%s\n' "$_vg_line" | awk '{ print "-----BEGIN PUBLIC KEY-----"; print $3; print "-----END PUBLIC KEY-----" }' > "$_vg_dir/sigs.key.pub"
    printf '%s' "$_vg_b64" | openssl base64 -d -A > "$_vg_dir/sigs.raw" 2>/dev/null || continue
    if openssl pkeyutl -verify -pubin -inkey "$_vg_dir/sigs.key.pub" -rawin -in "$_vg_sums" -sigfile "$_vg_dir/sigs.raw" >/dev/null 2>&1; then
      return 0
    fi
  done < "$_vg_dir/sigs.pairs"
  return 1
}

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# sums_hash SUMS NAME — the hash SUMS lists for NAME (empty when not listed)
sums_hash() { awk -v n="$2" '$1 !~ /^#/ && ($2 == n || $2 == ("*" n)) { print $1; exit }' "$1"; }

# check_signed_file SUMS NAME PATH — 0 PATH matches the hash SUMS lists for NAME, 1 it differs, 2 NAME is not listed
check_signed_file() {
  _cf_want=$(sums_hash "$1" "$2")
  [ -n "$_cf_want" ] || return 2
  [ "$_cf_want" = "$(sha256_of "$3")" ]
}

# sums_has_header SUMS — 0 when the signed SHA256SUMS carries the "# f2c-release" header (a current-format release)
sums_has_header() { grep -q '^# f2c-release ' "$1"; }

# signed_file_gate SUMS NAME PATH — enforce check_signed_file: a mismatch is fatal; a file the SUMS do not list is fatal for a
# current-format release or with F2C_REQUIRE_SIGNED=1, else (a legacy release) a warning.
signed_file_gate() {
  _sg=0; check_signed_file "$1" "$2" "$3" || _sg=$?
  case $_sg in
    0) return 0 ;;
    1) echo "install.sh: $2 does not match the signed SHA256SUMS" >&2; return 1 ;;
  esac
  if [ "${F2C_REQUIRE_SIGNED:-0}" = 1 ] || sums_has_header "$1"; then
    echo "install.sh: $2 is not listed in the signed SHA256SUMS" >&2
    return 1
  fi
  echo "install.sh: warning: $2 is not listed in the signed SHA256SUMS of this (legacy) release; not verified" >&2
  return 0
}

# release_dir BASE VERSION — the URL of a release's files: BASE/v<VERSION> (a +build stamp is dropped: the tag is v<semver>),
# or, with no VERSION, the latest release (GitHub: <releases>/latest/download, resolved by a redirect).
release_dir() {
  _rd_base=${1%/}
  if [ -n "$2" ]; then
    _rd_v=${2#v}
    printf '%s/v%s' "$_rd_base" "${_rd_v%%+*}"
  else
    printf '%s/latest/download' "${_rd_base%/download}"
  fi
}

# dl URL OUT — download URL to OUT; on failure print the URL and curl's own reason (a 404 shows as "returned error: 404")
dl() {
  _dl_err=$(curl -fsSL -o "$2" "$1" 2>&1) || {
    echo "install.sh: download failed: $1" >&2
    [ -z "$_dl_err" ] || echo "install.sh:   $_dl_err" >&2
    return 1
  }
}

# fetch_signed_sums DIR_URL — download SHA256SUMS and its signature from the release at DIR_URL into $WORK and verify them:
# SHA256SUMS.sigs by key id when the release has it, else (or when it does not verify) the legacy raw SHA256SUMS.sig under every trusted key.
# 0 verified, 1 the signature does not verify (fatal), 2 the files could not be downloaded.
fetch_signed_sums() {
  _fs_base="$1" _fs_sums="$WORK/SHA256SUMS"
  dl "$_fs_base/SHA256SUMS" "$_fs_sums" || return 2
  if curl -fsSL -o "$WORK/SHA256SUMS.sigs" "$_fs_base/SHA256SUMS.sigs" 2>/dev/null; then
    if verify_sums_sigs "$_fs_sums" "$WORK/SHA256SUMS.sigs" "$F2C_RELEASE_KEYS" "$WORK"; then return 0; fi
  fi
  dl "$_fs_base/SHA256SUMS.sig" "$WORK/SHA256SUMS.sig" || return 2
  if verify_sums_sig "$_fs_sums" "$WORK/SHA256SUMS.sig" "$F2C_RELEASE_PUBKEYS_PEM" "$WORK"; then return 0; fi
  echo "install.sh: SHA256SUMS signature verification failed (need OpenSSL 3 with ed25519 support)" >&2
  return 1
}

# verify_release_sums SUMS ARCH BIN_PATH — check BIN_PATH against the hash the verified SHA256SUMS lists for the agent binary.
verify_release_sums() {
  _arch=$2
  _want=$(sums_hash "$1" "f2c-agent-linux-$_arch")
  [ -n "$_want" ] || { echo "install.sh: SHA256SUMS has no f2c-agent-linux-$_arch" >&2; return 1; }
  _got=$(sha256_of "$3")
  [ "$_want" = "$_got" ] || { echo "install.sh: binary sha256 does not match signed SHA256SUMS" >&2; return 1; }
}

# ---------- release download helpers (they read SUMS_FILE, RELEASE_DIR, F2C_RELEASE_BASE, RELEASE_VERSION, HERE and WORK, set by the main part below;
# deploy/test/install_source_test.sh sources this file with F2C_INSTALL_LIB=1 and sets them itself).
SUMS_FILE=""
ensure_sums() {
  [ -z "$SUMS_FILE" ] || return 0
  RELEASE_DIR=$(release_dir "$F2C_RELEASE_BASE" "$RELEASE_VERSION")
  echo "install.sh: verifying the release at $RELEASE_DIR"
  _fs=0; fetch_signed_sums "$RELEASE_DIR" || _fs=$?
  case $_fs in
    0) SUMS_FILE="$WORK/SHA256SUMS"; sums_has_header "$SUMS_FILE" || echo "install.sh: warning: legacy release (no signed header): files missing from its signed SHA256SUMS are not verified" >&2 ;;
    1) exit 1 ;;
    *) echo "install.sh: could not download the signed SHA256SUMS from $RELEASE_DIR (is that release published? pin one with --version X.Y.Z)" >&2; exit 1 ;;
  esac
}
# local_support NAME — 0 when NAME sits next to this script AND install.sh does too (a repo checkout or an unpacked release; a `curl | sh` run has no install.sh beside it)
local_support() { [ -f "$HERE/install.sh" ] && [ -f "$HERE/$1" ]; }
support() {
  if local_support "$1"; then echo "$HERE/$1"; return; fi
  [ -n "$SUMS_FILE" ] || { echo "install.sh: no verified release to fetch $1 from" >&2; return 1; }
  dl "$RELEASE_DIR/$1" "$WORK/$1" || return 1
  signed_file_gate "$SUMS_FILE" "$1" "$WORK/$1" || return 1
  echo "$WORK/$1"
}
# ---------- pure helpers (no side effects). deploy/test/install_fw_test.sh sources this file with F2C_INSTALL_LIB=1,
# which stops right after them, before argument parsing or any host change. POSIX sh + awk. ----------

# ask_yes PROMPT: 0 only when the operator types "yes": on stdin when it is a terminal, else on /dev/tty
# (curl … | sh from an SSH session). No terminal at all (cloud-init, CI): never asks, answers no.
ask_yes() {
  _ay=""
  if [ -t 0 ]; then
    printf '%s' "$1" >&2
    read -r _ay || _ay=""
  elif (: < /dev/tty) 2>/dev/null; then
    printf '%s' "$1" > /dev/tty
    read -r _ay < /dev/tty || _ay=""
  fi
  [ "$_ay" = yes ]
}
# is_interactive: the same detection ask_yes uses. The /dev/tty probe runs in a subshell: in dash (Ubuntu's sh) a
# failed redirection on a special builtin such as ':' would otherwise exit the whole installer.
is_interactive() { [ -t 0 ] || (: < /dev/tty) 2>/dev/null; }

# fw_listen < `ss -Htuln`: "PORT/PROTO" (unique) for every TCP/UDP socket listening on a non-loopback address.
# Skipped: 127.0.0.0/8, ::1, ::ffff:127.x, IPv6 link-local fe80::/10, and the DHCP/mDNS client ports ufw's own
# before-rules always accept (68/udp, 546/udp, 5353/udp).
fw_listen() {
  awk '
    $1 != "tcp" && $1 != "udp" { next }
    {
      a = $5; n = split(a, x, ":"); port = x[n]
      addr = substr(a, 1, length(a) - length(port) - 1)
      gsub(/^\[|\]$/, "", addr); sub(/%.*/, "", addr); addr = tolower(addr)
      if (port !~ /^[0-9]+$/) next
      if (addr ~ /^127\./ || addr == "::1" || addr ~ /^::ffff:127\./ || addr ~ /^fe[89ab][0-9a-f]:/) next
      if ($1 == "udp" && (port == 68 || port == 546 || port == 5353)) next
      if (!seen[port "/" $1]++) print port "/" $1
    }'
}

# fw_rules < `ufw show added`: one "LO HI PROTO SRC" line per allow/limit rule (incoming).
#   PROTO: tcp | udp | any.  SRC: any (from anywhere, any interface, any destination) | restricted (from/to an
#   address or on an interface: still the operator's chosen access for that port) | hostonly (no port: a whole
#   source/interface, so it opens no port to everyone). deny/reject/out/route rules are ignored. Known app profiles:
#   OpenSSH, Nginx/Apache/WWW Full|HTTP(S)|Secure; unknown profiles are ignored (their ports then count as blocked).
fw_rules() {
  awk '
    function emit(spec, proto, src,   n, i, parts, r, pp) {
      n = split(spec, parts, ",")
      for (i = 1; i <= n; i++) {
        r = parts[i]
        if (r ~ /^[0-9]+:[0-9]+$/) { split(r, pp, ":"); print pp[1] + 0, pp[2] + 0, proto, src }
        else if (r ~ /^[0-9]+$/) print r + 0, r + 0, proto, src
      }
    }
    $1 != "ufw" { next }
    {
      if ($2 != "allow" && $2 != "limit") next
      src = "any"; proto = "any"; port = ""; simple = ""; side = ""
      for (j = 3; j <= NF; j++) {
        t = $j
        if (t == "comment") break
        if (t == "out") next
        if (t == "in") continue
        if (t == "on") { src = "restricted"; j++; continue }
        if (t == "from") { side = "from"; if ($(j + 1) != "any") src = "restricted"; j++; continue }
        if (t == "to") { side = "to"; if ($(j + 1) != "any") src = "restricted"; j++; continue }
        if (t == "port") { if (side == "from") src = "restricted"; else port = $(j + 1); j++; continue }
        if (t == "proto") { proto = $(j + 1); j++; continue }
        if (t == "app") { j++; continue }
        if (j == 3) simple = t
      }
      if (port == "" && simple ~ /^[0-9][0-9,:]*(\/(tcp|udp))?$/) {
        port = simple; if (port ~ /\//) { proto = substr(port, index(port, "/") + 1); port = substr(port, 1, index(port, "/") - 1) }
      }
      if (port == "") {
        if ($0 ~ /OpenSSH/) { port = "22"; proto = "tcp" }
        else if ($0 ~ /(Nginx|Apache|WWW) Full/) { port = "80,443"; proto = "tcp" }
        else if ($0 ~ /Nginx HTTPS|Apache Secure|WWW Secure/) { port = "443"; proto = "tcp" }
        else if ($0 ~ /Nginx HTTP|Apache|WWW/) { port = "80"; proto = "tcp" }
      }
      if (port == "") { if (simple == "" || simple == "from" || simple == "in") print 1, 65535, "any", "hostonly"; next }
      emit(port, proto, src)
    }'
}

# fw_uncovered "RULES" "SPECS" MODE: the SPECS (space-separated PORT/PROTO) that no rule (fw_rules output) covers,
# one per line. MODE any = only rules open to everyone count (is OUR rule already there?); MODE port = any rule that
# opens the port counts, also an address/interface-restricted one (would the port be blocked outright?).
fw_uncovered() {
  FW_RULES=$1 awk -v specs="$2" -v mode="$3" '
    BEGIN {
      n = split(ENVIRON["FW_RULES"], L, "\n"); m = split(specs, S, " ")
      for (i = 1; i <= m; i++) {
        split(S[i], s, "/"); p = s[1] + 0; pr = s[2]; hit = 0
        for (j = 1; j <= n; j++) {
          if (split(L[j], r, " ") < 4) continue
          if (r[4] == "hostonly" || (mode == "any" && r[4] != "any")) continue
          if (r[1] + 0 <= p && p <= r[2] + 0 && (r[3] == "any" || r[3] == pr)) { hit = 1; break }
        }
        if (!hit) print S[i]
      }
    }'
}
# fw_blocked "LISTEN" "RULES" "OURS": listening PORT/PROTO that neither our rules nor existing allow rules cover
fw_blocked() {
  _fb_rules=$2
  for _fb in $3; do _fb_rules="$_fb_rules
${_fb%/*} ${_fb%/*} ${_fb#*/} any"; done
  fw_uncovered "$_fb_rules" "$(printf '%s\n' "$1" | tr '\n' ' ')" port
}
# fw_policy KEY < /etc/default/ufw: deny | allow for DEFAULT_INPUT_POLICY / DEFAULT_OUTPUT_POLICY ("" if unset)
fw_policy() {
  awk -F= -v k="DEFAULT_$1_POLICY" '$1 == k { v = $2; gsub(/["'"'"' \t]/, "", v); print (v == "ACCEPT" ? "allow" : "deny"); exit }'
}
# words: newline/space list -> one space-separated line
words() { printf '%s\n' "$1" | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//'; }

# shellcheck disable=SC2317 # exit is reached only when the file is executed instead of sourced
if [ "${F2C_INSTALL_LIB:-}" = 1 ]; then return 0 2>/dev/null || exit 0; fi

BIN_SRC="${F2C_AGENT_BIN:-}"
# The engine is only needed to join (--engine/--token); nothing is downloaded from it.
ENGINE="${F2C_ENGINE:-}"
F2C_RELEASE_BASE="${F2C_RELEASE_BASE:-https://github.com/vinodkumar937/f2c-agent/releases/download}"
RELEASE_VERSION="${F2C_VERSION:-}"
RELEASE_DIR=""
JOIN_TOKEN="${F2C_JOIN_TOKEN:-}"
REATTACH=0
HARDEN=0
FIREWALL="${F2C_FIREWALL:-}" # 0 = skip the ufw step, 1 = apply without asking, unset = ask only if ports would be blocked
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE=/var/lib/f2c-agent
AGENT_BIN="$STATE/bin/f2c-agent"
ROLES="${F2C_ROLES:-build,run}"
WILDCARD_DOMAIN="${F2C_WILDCARD_DOMAIN:-}"
DNS_PROVIDER="${F2C_DNS_PROVIDER:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --roles) ROLES="${2:?--roles needs build,run|build|run}"; shift 2 ;;
    --roles=*) ROLES="${1#--roles=}"; shift ;;
    --wildcard-domain) WILDCARD_DOMAIN="${2:?--wildcard-domain needs a domain}"; shift 2 ;;
    --wildcard-domain=*) WILDCARD_DOMAIN="${1#--wildcard-domain=}"; shift ;;
    --dns-provider) DNS_PROVIDER="${2:?--dns-provider needs cloudflare|digitalocean|other}"; shift 2 ;;
    --dns-provider=*) DNS_PROVIDER="${1#--dns-provider=}"; shift ;;
    --version) RELEASE_VERSION="${2:?--version needs a release version like 0.4.0}"; shift 2 ;;
    --version=*) RELEASE_VERSION="${1#--version=}"; shift ;;
    --engine) ENGINE="${2:?--engine needs a URL}"; shift 2 ;;
    --engine=*) ENGINE="${1#--engine=}"; shift ;;
    --token) JOIN_TOKEN="${2:?--token needs a join token}"; shift 2 ;;
    --token=*) JOIN_TOKEN="${1#--token=}"; shift ;;
    --reattach) REATTACH=1; shift ;;
    --harden) HARDEN=1; shift ;;
    --no-firewall) FIREWALL=0; shift ;;
    --print-keys) print_keys; exit 0 ;;
    *) echo "install.sh: unknown argument $1" >&2; exit 1 ;;
  esac
done
WILDCARD_DOMAIN="${WILDCARD_DOMAIN#\*.}" # accept '*.apps.example.com'
ENGINE="${ENGINE%/}"
if [ -n "$JOIN_TOKEN" ] && [ -z "$ENGINE" ]; then echo "install.sh: --token needs --engine" >&2; exit 1; fi
if [ "$REATTACH" = 1 ] && [ -n "$JOIN_TOKEN" ]; then echo "install.sh: --reattach cannot be combined with --token" >&2; exit 1; fi
if [ "$REATTACH" = 1 ] && [ ! -f "$STATE/agent.json" ]; then echo "install.sh: --reattach needs an existing $STATE/agent.json" >&2; exit 1; fi
case "$(uname -m)" in x86_64 | amd64) AGENT_ARCH=amd64 ;; aarch64 | arm64) AGENT_ARCH=arm64 ;; *) echo "install.sh: unsupported CPU $(uname -m)" >&2; exit 1 ;; esac
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The release's SHA256SUMS, signature-checked against the embedded keys: it vouches for the agent binary, the install and support
# files and the Caddy binary. Downloaded once, when something has to be downloaded. A bad signature is fatal, and so is a release
# whose SHA256SUMS cannot be downloaded (nothing is installed unverified, except an explicit local F2C_AGENT_BIN).
# (SUMS_FILE, ensure_sums, local_support and support are defined with the helpers above)
# Agent binary: F2C_AGENT_BIN (a local build, not verified), else downloaded from the release and checked against the signed SHA256SUMS.
if [ -z "$BIN_SRC" ]; then
  ensure_sums
  echo "install.sh: downloading f2c-agent ($AGENT_ARCH) from $RELEASE_DIR"
  dl "$RELEASE_DIR/f2c-agent-linux-$AGENT_ARCH" "$WORK/f2c-agent" || exit 1
  verify_release_sums "$SUMS_FILE" "$AGENT_ARCH" "$WORK/f2c-agent" || exit 1
  BIN_SRC="$WORK/f2c-agent"
else
  echo "install.sh: installing the local binary $BIN_SRC (not verified against a release)" >&2
fi
# Unit files: next to this script when it is a repo checkout or an unpacked release (install.sh sits beside them), else downloaded from the
# release and checked against the signed SHA256SUMS (signed_file_gate; a file next to the script is not checked).
for _sf in f2c-agent.service caddy-resume.conf harden.sh f2c-harden.path f2c-harden.service f2c-caddy-dns-env.path f2c-caddy-dns-env.service; do
  local_support "$_sf" || { ensure_sums; break; }
done
SERVICE_FILE=$(support f2c-agent.service)
RESUME_FILE=$(support caddy-resume.conf)
case ",$ROLES," in *,build,* | *,run,*) ;; *) echo "install.sh: roles must include build and/or run (got $ROLES)" >&2; exit 1 ;; esac
case "$DNS_PROVIDER" in "" | cloudflare | digitalocean | other) ;; *) echo "install.sh: --dns-provider must be cloudflare, digitalocean or other (got $DNS_PROVIDER)" >&2; exit 1 ;; esac
if [ -n "$DNS_PROVIDER" ] && [ -z "$WILDCARD_DOMAIN" ]; then echo "install.sh: --dns-provider needs --wildcard-domain" >&2; exit 1; fi
if [ -n "$WILDCARD_DOMAIN" ]; then
  printf '%s' "$WILDCARD_DOMAIN" | grep -Eq '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$' || { echo "install.sh: bad --wildcard-domain $WILDCARD_DOMAIN" >&2; exit 1; }
fi
# f2c Caddy release: the caddy-binaries.yml workflow of THIS repository publishes caddy-linux-amd64, caddy-linux-arm64 and SHA256SUMS under the
# tag $F2C_CADDY_TAG (push that tag, or run the workflow); keep the versions in sync with deploy/caddy/Dockerfile. The release SHA256SUMS
# lists the Caddy hashes too (release.sh --caddy-dir). Only used with --dns-provider cloudflare|digitalocean.
F2C_CADDY_TAG="${F2C_CADDY_TAG:-caddy-v2.11.7-do1-cf1-ad1}"
F2C_CADDY_URL="${F2C_CADDY_URL:-https://github.com/vinodkumar937/f2c-agent/releases/download/$F2C_CADDY_TAG}"
# Keep in sync with build.go buildkitImage and the engine's railpack.
RAILPACK_VERSION="${RAILPACK_VERSION:-0.41.0}"
BUILDKIT_IMAGE="${BUILDKIT_IMAGE:-moby/buildkit:v0.34.0}"
# Railpack $RAILPACK_VERSION's base images (bump together with RAILPACK_VERSION) and the static-site image
# (keep in sync with static.go staticCaddyImage). Pre-pulled best-effort after BuildKit is up.
RAILPACK_MISE_TAG="${RAILPACK_MISE_TAG:-mise-2026.10.8}"
STATIC_CADDY_IMAGE="${STATIC_CADDY_IMAGE:-caddy:2.10.2-alpine}"
MIN_BUILD_DISK_GB="${MIN_BUILD_DISK_GB:-20}"

run() {
  if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ $*"; else "$@"; fi
}

[ "${DRY_RUN:-0}" = 1 ] || [ "$(id -u)" = 0 ] || { echo "install.sh: run as root (or DRY_RUN=1)" >&2; exit 1; }
# Docker (official apt repo) and Caddy (official Cloudsmith apt repo): installed only when missing, Ubuntu/Debian only.
# Idempotent: a second run finds both and skips this. SKIP_DEPS=1 keeps the old behaviour (fail if missing).
apt_repo_install() { # $1 name, $2 key URL, $3 keyring path, $4 sources.list line, $5 list file, $6.. packages
  name=$1 key=$2 ring=$3 line=$4 list=$5
  shift 5
  echo "install.sh: installing $name from its official apt repo"
  run install -d -m 0755 /etc/apt/keyrings
  if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ curl -fsSL $key | gpg --dearmor -o $ring"; echo "+ write $list: $line"; else
    curl -fsSL "$key" | gpg --dearmor --yes -o "$ring" && chmod a+r "$ring"
    echo "$line" > "$list"
  fi
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}
need_docker=0; need_caddy=0
command -v docker >/dev/null || need_docker=1
command -v caddy >/dev/null || need_caddy=1
if [ $need_docker = 1 ] || [ $need_caddy = 1 ]; then
  [ "${SKIP_DEPS:-0}" = 1 ] && { echo "install.sh: docker and/or caddy missing (SKIP_DEPS=1)" >&2; exit 1; }
  ID=""
  # shellcheck disable=SC1091
  [ -r /etc/os-release ] && . /etc/os-release
  # DRY_RUN on a non-Debian host (e.g. the Mac): preview as if Ubuntu instead of stopping.
  [ "${DRY_RUN:-0}" = 1 ] && [ -z "${ID:-}" ] && { ID=ubuntu; VERSION_CODENAME=noble; echo "install.sh: DRY_RUN on non-Debian host: previewing as ubuntu/noble"; }
  case "${ID:-}" in ubuntu | debian) ;; *) echo "install.sh: auto-install supports Ubuntu/Debian only (found ${ID:-unknown}); install Docker and Caddy yourself" >&2; exit 1 ;; esac
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg
  arch=$(dpkg --print-architecture 2>/dev/null || echo amd64)
  [ $need_docker = 1 ] && apt_repo_install Docker "https://download.docker.com/linux/$ID/gpg" /etc/apt/keyrings/docker.gpg \
    "deb [arch=$arch signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID ${VERSION_CODENAME:-} stable" \
    /etc/apt/sources.list.d/docker.list docker-ce docker-ce-cli containerd.io docker-buildx-plugin
  [ $need_caddy = 1 ] && apt_repo_install Caddy "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" /etc/apt/keyrings/caddy-stable.gpg \
    "deb [signed-by=/etc/apt/keyrings/caddy-stable.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" \
    /etc/apt/sources.list.d/caddy-stable.list caddy
  run systemctl enable --now docker
fi
[ -f "$BIN_SRC" ] || { echo "install.sh: agent binary not found at $BIN_SRC (set F2C_AGENT_BIN)" >&2; exit 1; }

# user + state dir (0700)
id f2c-agent >/dev/null 2>&1 || run useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin f2c-agent
run usermod -aG docker f2c-agent
run install -d -m 0700 -o f2c-agent -g f2c-agent "$STATE"

# build tooling (M2.7): only for build-role servers
case ",$ROLES," in
  *,build,*)
    avail_kb=$(df -Pk /var/lib/docker 2>/dev/null | awk 'NR==2{print $4}' || true)
    [ -n "$avail_kb" ] || avail_kb=$(df -Pk / | awk 'NR==2{print $4}')
    if [ "$avail_kb" -lt $((MIN_BUILD_DISK_GB * 1024 * 1024)) ]; then
      echo "install.sh: warning: $((avail_kb / 1024 / 1024)) GB free for Docker, builds want >= ${MIN_BUILD_DISK_GB} GB (BuildKit cache + images)" >&2
    fi
    have_rp=$(railpack --version 2>/dev/null | awk '{print $NF}' || true)
    if [ "$have_rp" = "$RAILPACK_VERSION" ]; then
      echo "install.sh: railpack $RAILPACK_VERSION present"
    else
      case "$(uname -m)" in x86_64 | amd64) rp_arch=x86_64 ;; aarch64 | arm64) rp_arch=arm64 ;; *) echo "install.sh: no railpack build for $(uname -m)" >&2; exit 1 ;; esac
      rp_tar="railpack-v$RAILPACK_VERSION-$rp_arch-unknown-linux-musl.tar.gz"
      rp_url="https://github.com/railwayapp/railpack/releases/download/v$RAILPACK_VERSION"
      echo "install.sh: installing railpack $RAILPACK_VERSION ($rp_arch)"
      if [ "${DRY_RUN:-0}" = 1 ]; then
        echo "+ curl -fsSL $rp_url/$rp_tar + checksums.txt; sha256 check; tar -xzf -> /usr/local/bin/railpack (0755)"
      else
        tmp=$(mktemp -d)
        curl -fsSL -o "$tmp/$rp_tar" "$rp_url/$rp_tar"
        curl -fsSL -o "$tmp/checksums.txt" "$rp_url/checksums.txt"
        (cd "$tmp" && grep " $rp_tar\$" checksums.txt | sha256sum -c -) || { rm -rf "$tmp"; echo "install.sh: railpack checksum mismatch" >&2; exit 1; }
        tar -xzf "$tmp/$rp_tar" -C "$tmp" railpack
        install -m 0755 "$tmp/railpack" /usr/local/bin/railpack
        rm -rf "$tmp"
      fi
    fi
    # The agent creates/starts the f2c-buildkit container (state volume f2c-buildkit-state) on the first build;
    # pre-pulling here keeps that first build fast. The image runs rootful under Docker (same as the engine host).
    if docker image inspect "$BUILDKIT_IMAGE" >/dev/null 2>&1; then echo "install.sh: $BUILDKIT_IMAGE present"; else run docker pull "$BUILDKIT_IMAGE"; fi
    # Warm the f2c-buildkit cache with Railpack's builder/runtime images (~430 MB on a fresh server) and the
    # static Caddy image. Same container/volume as build.go ensureBuildkit. Best-effort: never fails the install.
    # B3: buildctl has no "cacheonly" exporter (that is buildx); a build with no --output just fills the cache.
    prewarm_buildkit() {
      if [ "$(docker inspect -f '{{.State.Running}}' f2c-buildkit 2>/dev/null)" != true ]; then
        docker start f2c-buildkit >/dev/null 2>&1 || docker run -d --name f2c-buildkit --restart unless-stopped --privileged \
          --label f2c.agent=1 --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
          -v f2c-buildkit-state:/var/lib/buildkit "$BUILDKIT_IMAGE" >/dev/null || return 1
        sleep 3
      fi
      for img in "ghcr.io/railwayapp/railpack-builder:$RAILPACK_MISE_TAG" "ghcr.io/railwayapp/railpack-runtime:$RAILPACK_MISE_TAG"; do
        echo "install.sh: pre-pulling $img into BuildKit"
        printf 'FROM %s\nRUN true\n' "$img" | docker exec -i f2c-buildkit sh -c \
          'd=$(mktemp -d) && cat > "$d/Dockerfile" && buildctl build --frontend dockerfile.v0 --local context="$d" --local dockerfile="$d"; r=$?; rm -rf "$d"; exit $r' \
          || echo "install.sh: warning: could not pre-pull $img (first build will pull it)" >&2
      done
      echo "install.sh: pre-pulling $STATIC_CADDY_IMAGE"
      docker pull -q "$STATIC_CADDY_IMAGE" >/dev/null || echo "install.sh: warning: could not pre-pull $STATIC_CADDY_IMAGE" >&2
    }
    if [ "${DRY_RUN:-0}" = 1 ]; then
      echo "+ pre-pull railpack-builder/runtime:$RAILPACK_MISE_TAG into f2c-buildkit, docker pull $STATIC_CADDY_IMAGE (best-effort)"
    else
      prewarm_buildkit || echo "install.sh: warning: BuildKit pre-warm skipped" >&2
    fi
    ;;
  *) echo "install.sh: roles=$ROLES (no build): skipping railpack and BuildKit" ;;
esac

# Caddy resume configuration. Agent executable/unit migration is transactional at the end.
run install -d -m 0755 /etc/systemd/system/caddy.service.d
run install -m 0644 "$RESUME_FILE" /etc/systemd/system/caddy.service.d/f2c-resume.conf

# M2.8: f2c Caddy (DNS-01 modules) + EnvironmentFile drop-in, only with --dns-provider
if [ -n "$DNS_PROVIDER" ] && [ "$DNS_PROVIDER" != other ]; then # other: stock Caddy, on-demand HTTP-01
  case "$(uname -m)" in x86_64 | amd64) cd_arch=amd64 ;; aarch64 | arm64) cd_arch=arm64 ;; *) echo "install.sh: no f2c Caddy build for $(uname -m)" >&2; exit 1 ;; esac
  if caddy list-modules 2>/dev/null | grep -q "^dns.providers.$DNS_PROVIDER\$"; then
    echo "install.sh: caddy already has dns.providers.$DNS_PROVIDER"
  else
    echo "install.sh: installing f2c Caddy $F2C_CADDY_TAG ($cd_arch) for $DNS_PROVIDER, wildcard *.$WILDCARD_DOMAIN"
    if [ "${DRY_RUN:-0}" = 1 ]; then
      echo "+ curl -fsSL $F2C_CADDY_URL/caddy-linux-$cd_arch + SHA256SUMS; sha256 check; install -> /usr/bin/caddy (0755); restart caddy"
    else
      tmp=$(mktemp -d)
      if ! dl "$F2C_CADDY_URL/caddy-linux-$cd_arch" "$tmp/caddy-linux-$cd_arch" || ! dl "$F2C_CADDY_URL/SHA256SUMS" "$tmp/SHA256SUMS"; then
        rm -rf "$tmp"
        echo "install.sh: the f2c Caddy build ($F2C_CADDY_TAG) could not be downloaded from $F2C_CADDY_URL" >&2
        echo "install.sh:   a 404 means that Caddy release has not been published yet. Options: --dns-provider other (stock Caddy, on-demand HTTP-01)," >&2
        echo "install.sh:   F2C_CADDY_URL=<dir with caddy-linux-$cd_arch and SHA256SUMS> (and F2C_CADDY_TAG), or install a Caddy with the DNS module yourself." >&2
        exit 1
      fi
      (cd "$tmp" && grep " caddy-linux-$cd_arch\$" SHA256SUMS | sha256sum -c -) || { rm -rf "$tmp"; echo "install.sh: caddy checksum mismatch" >&2; exit 1; }
      # The signed SHA256SUMS list the Caddy hash too (hash only, the binary is not bundled): it must match.
      if [ -n "$SUMS_FILE" ]; then
        signed_file_gate "$SUMS_FILE" "caddy-linux-$cd_arch" "$tmp/caddy-linux-$cd_arch" || { rm -rf "$tmp"; exit 1; }
      else
        echo "install.sh: warning: local F2C_AGENT_BIN install: the Caddy binary is only checked against the Caddy release's own SHA256SUMS, not a signed release" >&2
      fi
      install -m 0755 "$tmp/caddy-linux-$cd_arch" /usr/bin/caddy
      rm -rf "$tmp"
      CADDY_SWAPPED=1
      # keep apt from overwriting the f2c build
      apt-mark hold caddy >/dev/null 2>&1 || true
    fi
  fi
  run install -d -m 0770 /etc/f2c-agent
  run chgrp caddy /etc/f2c-agent 2>/dev/null || true
  if [ -f /etc/f2c-agent/caddy-dns.env ]; then echo "install.sh: /etc/f2c-agent/caddy-dns.env exists, left alone"; else
    if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ write /etc/f2c-agent/caddy-dns.env (0640 root:caddy, F2C_WILDCARD_DOMAIN/F2C_DNS_PROVIDER, no token yet)"; else
      printf 'F2C_WILDCARD_DOMAIN=%s\nF2C_DNS_PROVIDER=%s\n' "$WILDCARD_DOMAIN" "$DNS_PROVIDER" > /etc/f2c-agent/caddy-dns.env
      chown root:caddy /etc/f2c-agent/caddy-dns.env
      chmod 0640 /etc/f2c-agent/caddy-dns.env
    fi
  fi
  # Agent syncs DO_AUTH_TOKEN/CF_API_TOKEN into this file on dns_token; Caddy config uses {env.DO_AUTH_TOKEN}.
  if [ "${DRY_RUN:-0}" != 1 ] && [ -f /etc/f2c-agent/caddy-dns.env ]; then
    chown root:caddy /etc/f2c-agent/caddy-dns.env 2>/dev/null || true
    chmod 0640 /etc/f2c-agent/caddy-dns.env 2>/dev/null || true
    command -v setfacl >/dev/null 2>&1 || run apt-get install -y -qq acl
    run setfacl -m u:f2c-agent:rw /etc/f2c-agent/caddy-dns.env || true
    run setfacl -m u:f2c-agent:x /etc/f2c-agent || true
  fi
  if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ write /etc/systemd/system/caddy.service.d/f2c-dns.conf: [Service] EnvironmentFile=-/etc/f2c-agent/caddy-dns.env"; else
    printf '# M2.8: DNS provider env for DNS-01 ({env.DO_AUTH_TOKEN}/{env.CF_API_TOKEN})\n[Service]\nEnvironmentFile=-/etc/f2c-agent/caddy-dns.env\n' > /etc/systemd/system/caddy.service.d/f2c-dns.conf
  fi
fi

# Provider "other": per-host on-demand certificates via HTTP-01 (no acme-dns). Clean up the old per-server acme-dns
# (removed design) idempotently: its container and creds file.
# (Any provider: these only ever came from that design. The agent also removes them at start.)
if docker inspect f2c-acme-dns >/dev/null 2>&1; then run docker rm -f f2c-acme-dns; fi
if [ -e "$STATE/acme-dns-creds.json" ]; then run rm -f "$STATE/acme-dns-creds.json"; fi
if [ -d "$STATE/acme-dns" ]; then run rm -rf "$STATE/acme-dns"; fi
if command -v ufw >/dev/null 2>&1; then # only the two allow rules that install added (no other 53 rules touched)
  for r in 53/udp 53/tcp; do if ufw show added 2>/dev/null | grep -qx "ufw allow $r"; then run ufw delete allow "$r"; fi; done
fi

# Step 4: certwatch prefers TLS SNI (no file access). Filesystem scan is a supplement for all providers:
# f2c-agent in group caddy, group-traversable cert dirs, default ACLs (Caddy renewals rewrite 0600/0700),
# and ReadOnlyPaths in f2c-agent.service under ProtectSystem=strict.
if id f2c-agent >/dev/null 2>&1 && getent group caddy >/dev/null 2>&1; then
  CADDY_DATA=/var/lib/caddy/.local/share/caddy
  command -v setfacl >/dev/null 2>&1 || run apt-get install -y -qq acl
  run mkdir -p "$CADDY_DATA/certificates"
  run chown -R caddy:caddy /var/lib/caddy/.local
  run usermod -aG caddy f2c-agent || true
  for d in /var/lib/caddy /var/lib/caddy/.local /var/lib/caddy/.local/share "$CADDY_DATA" "$CADDY_DATA/certificates"; do
    run chmod g+rx "$d" || true
    run setfacl -m u:f2c-agent:x "$d" || true
    run setfacl -m g:caddy:rx "$d" || true
  done
  run setfacl -R -m u:f2c-agent:rX "$CADDY_DATA/certificates"
  run setfacl -R -d -m u:f2c-agent:rX "$CADDY_DATA/certificates"
  run setfacl -R -d -m g:caddy:rx "$CADDY_DATA/certificates" || true
fi

# When the agent writes DO_AUTH_TOKEN/CF_API_TOKEN into caddy-dns.env, restart Caddy so EnvironmentFile
# is re-read for {env.*} placeholders. Path unit keeps f2c-agent NoNewPrivileges=yes (no sudo from agent).
PATH_UNIT=$(support f2c-caddy-dns-env.path)
PATH_SVC=$(support f2c-caddy-dns-env.service)
if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ install f2c-caddy-dns-env.path/.service and enable path"; else
  install -m 0644 "$PATH_UNIT" /etc/systemd/system/f2c-caddy-dns-env.path
  install -m 0644 "$PATH_SVC" /etc/systemd/system/f2c-caddy-dns-env.service
  systemctl daemon-reload
  systemctl enable --now f2c-caddy-dns-env.path
fi

# Host firewall: default-deny incoming is the baseline, applied NON-DESTRUCTIVELY. Never `ufw reset`, never deletes or
# replaces a rule: only ADDS the missing ones of ours, in this order: the detected SSH port(s) (no guess of 22: a
# non-default port would be locked out; none detected = step skipped with a warning), then 80/tcp, 443/tcp, 443/udp
# (host Caddy; apps publish on 127.0.0.1 only, commands.go). An existing rule counts as ours only if it is open to
# everyone (an admin-IP-only SSH rule does not stop us adding SSH for all). Outgoing policy is never touched.
#   - ufw inactive (fresh host): add rules, set default deny incoming if it is not deny, enable.
#   - ufw active, default incoming deny: only add the missing rules (nothing gets blocked; no prompt).
#   - ufw active, default incoming allow: add rules, then switch incoming to deny (the operator's rules are kept).
# Before enabling or switching to deny it lists the public listening ports (ss -Htuln, non-loopback, TCP+UDP) that
# no rule covers, i.e. that would be blocked. If there are any: interactive install -> asks (declined = the whole
# firewall step is skipped, nothing changed, install continues); non-interactive -> warns and proceeds;
# F2C_FIREWALL=1 -> proceeds without asking. --no-firewall / F2C_FIREWALL=0 skips the step. DRY_RUN=1 prints the plan.
# The optional harden.sh later adds rate limiting on the same SSH ports.
SSH_PORTS=$({ sshd -T 2>/dev/null | awk '$1=="port"{print $2}';
  ss -Htlnp 2>/dev/null | awk '/"sshd"/ {n=split($4,a,":"); print a[n]}';
  systemctl show ssh.socket -p Listen --value 2>/dev/null | grep -oE ':[0-9]+ \(Stream\)' | grep -oE '[0-9]+';
} | awk '$1 ~ /^[0-9]+$/ && $1 > 0 && $1 < 65536' | sort -un | tr '\n' ' ')
if [ "$FIREWALL" = 0 ]; then
  echo "install.sh: firewall step skipped (--no-firewall / F2C_FIREWALL=0); ufw left exactly as it is" >&2
elif [ -z "$SSH_PORTS" ]; then
  echo "install.sh: WARNING: cannot detect the SSH port(s); firewall step skipped, ufw left alone (review it manually)" >&2
else
  if ! command -v ufw >/dev/null 2>&1; then run apt-get install -y -qq ufw; fi
  fw_ours=""
  for p in $SSH_PORTS; do fw_ours="$fw_ours $p/tcp"; done
  fw_ours="${fw_ours# } 80/tcp 443/tcp 443/udp"
  fw_active=0 fw_rules_txt="" fw_note=""
  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q '^Status: active'; then fw_active=1; fi
    if fw_added=$(ufw show added 2>/dev/null); then fw_rules_txt=$(printf '%s\n' "$fw_added" | fw_rules)
    else fw_note="could not read the existing ufw rules (not root?); the plan assumes none"; fi
  fi
  fw_in=deny fw_out=allow
  if [ -r /etc/default/ufw ]; then
    fw_in=$(fw_policy INPUT < /etc/default/ufw); fw_in=${fw_in:-deny}
    fw_out=$(fw_policy OUTPUT < /etc/default/ufw); fw_out=${fw_out:-allow}
  fi # no file yet = ufw not installed; its package default is deny incoming, allow outgoing
  fw_add=$(words "$(fw_uncovered "$fw_rules_txt" "$fw_ours" any)")
  fw_set_deny=0; [ "$fw_in" = deny ] || fw_set_deny=1
  fw_enable=0; [ "$fw_active" = 1 ] || fw_enable=1
  fw_blocked_list=""
  if [ "$fw_enable" = 1 ] || [ "$fw_set_deny" = 1 ]; then
    if command -v ss >/dev/null 2>&1; then
      fw_blocked_list=$(words "$(fw_blocked "$(ss -Htuln 2>/dev/null | fw_listen)" "$fw_rules_txt" "$fw_ours")")
    else fw_note="${fw_note:+$fw_note; }ss not found: cannot list listening ports that would be blocked"; fi
  fi
  echo "install.sh: firewall plan: ufw $( [ "$fw_active" = 1 ] && echo active || echo inactive ); add rules: ${fw_add:-none (all present)}; existing rules kept; default incoming: $( [ "$fw_set_deny" = 1 ] && echo "deny (was $fw_in)" || echo "deny (unchanged)" ); $( [ "$fw_enable" = 1 ] && echo "then enable ufw" || echo "already enabled" )"
  [ -z "$fw_note" ] || echo "install.sh: note: $fw_note" >&2
  [ "$fw_out" = allow ] || echo "install.sh: WARNING: ufw default outgoing is $fw_out (left as is); the agent needs outbound 443 to the engine" >&2
  if [ -n "$fw_blocked_list" ]; then
    echo "install.sh: WARNING: these public listening ports have no ufw allow rule and would be BLOCKED by default-deny: $fw_blocked_list" >&2
    echo "install.sh:   allow them first (ufw allow PORT/PROTO), or skip this step with --no-firewall / F2C_FIREWALL=0" >&2
  fi
  fw_go=1
  if [ "${DRY_RUN:-0}" != 1 ] && [ -n "$fw_blocked_list" ] && [ "$FIREWALL" != 1 ]; then
    if is_interactive; then
      ask_yes "install.sh: block those ports and apply the firewall? Type yes to apply: " || fw_go=0
    else
      echo "install.sh: non-interactive install: applying the firewall; the ports listed above will be blocked" >&2
    fi
  fi
  if [ "$fw_go" = 0 ]; then
    echo "install.sh: WARNING: firewall step skipped (not confirmed); ufw unchanged. Re-run with F2C_FIREWALL=1 to apply, or configure ufw yourself" >&2
  else
    for r in $fw_add; do run ufw allow "$r"; done # SSH first: always allowed before any policy change or enable
    if [ "$fw_set_deny" = 1 ]; then run ufw default deny incoming; fi
    if [ "$fw_enable" = 1 ]; then run ufw --force enable; fi
  fi
fi

# Optional hardening support (installed now; OFF until --harden or an explicit dashboard action). Path unit is the
# minimal root bridge: agent can only write a validated harden request. No sudoers/polkit, NNP stays on. Only the
# watcher is enabled; the root oneshot has no [Install] section and is never enabled at boot.
HARDEN_SCRIPT=$(support harden.sh)
HARDEN_PATH=$(support f2c-harden.path)
HARDEN_SERVICE=$(support f2c-harden.service)
run install -d -m 0755 -o root -g root /usr/local/lib/f2c /var/lib/f2c-harden
run install -d -m 0700 -o f2c-agent -g f2c-agent "$STATE/harden"
run install -d -m 0750 -o root -g f2c-agent /var/lib/f2c-harden/results
run install -m 0755 -o root -g root "$HARDEN_SCRIPT" /usr/local/lib/f2c/harden.sh
run install -m 0644 -o root -g root "$HARDEN_PATH" /etc/systemd/system/f2c-harden.path
run install -m 0644 -o root -g root "$HARDEN_SERVICE" /etc/systemd/system/f2c-harden.service
run systemctl daemon-reload
run systemctl enable --now f2c-harden.path

# docker log caps (only when there is no daemon.json yet; never overwrite one)
if [ ! -f /etc/docker/daemon.json ]; then
  if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ write /etc/docker/daemon.json (json-file, 10m x 3)"; else
    printf '{\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "10m", "max-file": "3" }\n}\n' > /etc/docker/daemon.json
  fi
  echo "install.sh: wrote /etc/docker/daemon.json: restart docker when convenient (systemctl restart docker)"
else
  echo "install.sh: /etc/docker/daemon.json exists, left alone (add log-opts max-size/max-file yourself)"
fi

# The executable and its .new/.prev siblings must live inside the existing writable
# StateDirectory. selfupdate.go resolves its running executable, then verifies,
# smoke-tests and atomically renames beside it; no Go protocol change is needed.
install_agent() (
  set -eu
  if [ "${DRY_RUN:-0}" = 1 ]; then
    echo "+ backup existing agent unit, drop-ins and executable; preserve existing ExecStart arguments"
    echo "+ stage/check version/atomic install -> $AGENT_BIN (f2c-agent:f2c-agent 0755)"
    echo "+ migrate old executable paths in unit/drop-ins; keep ProtectSystem=strict; daemon-reload"
    echo "+ restart previously active service, or join/start only for a new identity; rollback on failure"
    return
  fi
  UNIT=/etc/systemd/system/f2c-agent.service
  DROP=/etc/systemd/system/f2c-agent.service.d
  SAVE="/var/backups/f2c-agent-install-$(date +%Y%m%d-%H%M%S)-$$"
  install -d -m 0700 "$SAVE"
  HAD_UNIT=0; HAD_BIN=0; HAD_PREV=0; WAS_ACTIVE=0; SUCCESS=0
  [ ! -L "$STATE/bin" ] && [ ! -L "$AGENT_BIN" ] || { echo "install.sh: refusing symlinked executable directory" >&2; exit 1; }
  if [ -f "$UNIT" ]; then cp -p "$UNIT" "$SAVE/unit"; HAD_UNIT=1; fi
  if [ -d "$DROP" ]; then cp -a "$DROP" "$SAVE/drop-ins"; fi
  if [ -f "$AGENT_BIN" ]; then cp -p "$AGENT_BIN" "$SAVE/binary"; HAD_BIN=1; fi
  if [ -f "$AGENT_BIN.prev" ]; then cp -p "$AGENT_BIN.prev" "$SAVE/binary.prev"; HAD_PREV=1; fi
  if [ -f /usr/local/bin/f2c-agent ]; then cp -p /usr/local/bin/f2c-agent "$SAVE/legacy-binary"; fi
  if systemctl is-active --quiet f2c-agent.service; then WAS_ACTIVE=1; fi
  agent_install_finish() {
    code=$1
    trap - 0
    set +e
    if [ "$SUCCESS" != 1 ]; then
      echo "install.sh: agent migration failed; restoring executable and unit from $SAVE" >&2
      systemctl stop f2c-agent.service >/dev/null 2>&1
      if [ "$HAD_BIN" = 1 ]; then install -m 0755 -o f2c-agent -g f2c-agent "$SAVE/binary" "$AGENT_BIN.rollback" && mv -f "$AGENT_BIN.rollback" "$AGENT_BIN"; else rm -f "$AGENT_BIN"; fi
      if [ "$HAD_PREV" = 1 ]; then install -m 0755 -o f2c-agent -g f2c-agent "$SAVE/binary.prev" "$AGENT_BIN.prev"; else rm -f "$AGENT_BIN.prev"; fi
      if [ "$HAD_UNIT" = 1 ]; then cp -p "$SAVE/unit" "$UNIT"; else rm -f "$UNIT"; fi
      if [ -d "$SAVE/drop-ins" ]; then install -d -m 0755 "$DROP"; cp -a "$SAVE/drop-ins/." "$DROP/"; fi
      systemctl daemon-reload || echo "install.sh: rollback daemon-reload needs operator attention" >&2
      if [ "$WAS_ACTIVE" = 1 ]; then systemctl start f2c-agent.service || echo "install.sh: rollback restart needs operator attention" >&2; fi
    fi
    rm -f "$AGENT_BIN.install-new"
    exit "$code"
  }
  trap 'agent_install_finish "$?"' 0
  if [ ! -d /etc/f2c-agent ]; then
    install -d -m 700 -o root -g root /etc/f2c-agent
  fi
  install -d -m 0700 -o f2c-agent -g f2c-agent "$STATE/bin"
  install -m 0755 -o f2c-agent -g f2c-agent "$BIN_SRC" "$AGENT_BIN.install-new"
  runuser -u f2c-agent -- "$AGENT_BIN.install-new" version >/dev/null
  if [ "$WAS_ACTIVE" = 1 ]; then systemctl stop f2c-agent.service; fi
  if [ "$HAD_BIN" = 1 ]; then install -m 0755 -o f2c-agent -g f2c-agent "$SAVE/binary" "$AGENT_BIN.prev";
  elif [ -f "$SAVE/legacy-binary" ]; then install -m 0755 -o f2c-agent -g f2c-agent "$SAVE/legacy-binary" "$AGENT_BIN.prev"; fi
  mv -f "$AGENT_BIN.install-new" "$AGENT_BIN"
  # Preserve existing arguments and hardening rather than overwrite customized units.
  if [ "$HAD_UNIT" = 1 ]; then
    sed "s@^ExecStart=/usr/local/bin/f2c-agent\([[:space:]]\|$\)@ExecStart=$AGENT_BIN\1@" "$SAVE/unit" > "$WORK/agent-unit"
    install -m 0644 "$WORK/agent-unit" "$UNIT"
  else install -m 0644 "$SERVICE_FILE" "$UNIT"; fi
  # Prefix possibly-missing sandbox paths so a preserved older unit does not fail 226/NAMESPACE.
  if [ -f "$UNIT" ]; then
    sed -i -e 's|^ReadWritePaths=/etc/f2c-agent$|ReadWritePaths=-/etc/f2c-agent|' \
           -e 's|^ReadOnlyPaths=/var/lib/caddy/.local/share/caddy/certificates$|ReadOnlyPaths=-/var/lib/caddy/.local/share/caddy/certificates|' \
           "$UNIT"
  fi
  # Ensure certwatch can read Caddy certs under ProtectSystem=strict (idempotent drop-in).
  install -d -m 0755 "$DROP"
  if [ ! -f "$DROP/10-caddy-certs.conf" ]; then
    printf '# certwatch + caddy-dns.env sync under ProtectSystem=strict\n[Service]\nSupplementaryGroups=caddy\nReadOnlyPaths=-/var/lib/caddy/.local/share/caddy/certificates\nReadWritePaths=-/etc/f2c-agent\n' > "$DROP/10-caddy-certs.conf"
    chmod 0644 "$DROP/10-caddy-certs.conf"
  else
    # Existing drop-ins (and a failed first install) may lack the '-' ignore prefix.
    sed -i -e 's|^ReadWritePaths=/etc/f2c-agent$|ReadWritePaths=-/etc/f2c-agent|' \
           -e 's|^ReadOnlyPaths=/var/lib/caddy/.local/share/caddy/certificates$|ReadOnlyPaths=-/var/lib/caddy/.local/share/caddy/certificates|' \
           "$DROP/10-caddy-certs.conf"
  fi
  for conf in "$DROP"/*.conf; do
    [ -f "$conf" ] || continue
    if grep -q '^ExecStart=/usr/local/bin/f2c-agent\([[:space:]]\|$\)' "$conf"; then
      sed "s@^ExecStart=/usr/local/bin/f2c-agent\([[:space:]]\|$\)@ExecStart=$AGENT_BIN\1@" "$conf" > "$WORK/agent-drop-in"
      install -m 0644 "$WORK/agent-drop-in" "$conf"
    fi
  done
  systemctl daemon-reload
  [ "$(systemctl show f2c-agent.service -p ProtectSystem --value)" = strict ] || { echo "install.sh: ProtectSystem must remain strict" >&2; exit 1; }
  systemctl show f2c-agent.service -p ExecStart --value | grep -Fq "path=$AGENT_BIN ;" || { echo "install.sh: unsupported executable override; refusing migration" >&2; exit 1; }
  if [ "$REATTACH" = 1 ]; then
    # Submit identity + inventory as an orphan; do not start serving until admin approves.
    # --engine optional: f2c-agent reattach falls back to agent.json engine URL.
    if [ -n "$ENGINE" ]; then
      runuser -u f2c-agent -- "$AGENT_BIN" reattach --state-dir "$STATE" --engine "$ENGINE"
    else
      runuser -u f2c-agent -- "$AGENT_BIN" reattach --state-dir "$STATE"
    fi
    echo "install.sh: reattach submitted; agent not started until an admin approves the orphan."
  elif [ -f "$STATE/agent.json" ]; then
    # Do not consume another join token or replace a server identity on re-install.
    if [ "$WAS_ACTIVE" = 1 ]; then systemctl start f2c-agent.service; fi
    echo "install.sh: existing server identity preserved; executable migration complete."
  elif [ -n "$JOIN_TOKEN" ]; then
    runuser -u f2c-agent -- "$AGENT_BIN" join --state-dir "$STATE" --engine "$ENGINE" --token "$JOIN_TOKEN"
    systemctl enable --now f2c-agent.service
  fi
  if [ "$WAS_ACTIVE" = 1 ]; then systemctl is-active --quiet f2c-agent.service; fi
  SUCCESS=1
  echo "install.sh: agent backups retained in $SAVE"
)
if [ "${CADDY_SWAPPED:-0}" = 1 ]; then run systemctl daemon-reload; run systemctl restart caddy; fi
# The unit and 10-caddy-certs.conf bind-mount /etc/f2c-agent (ProtectSystem=strict). systemd
# exits 226/NAMESPACE if that path is missing. The --dns-provider branch already created it;
# BYO installs (no wildcard) never did. Create only when absent so we don't reset 0770 root:caddy.
if [ ! -d /etc/f2c-agent ]; then
  run install -d -m 700 -o root -g root /etc/f2c-agent
fi
install_agent
if [ "${DRY_RUN:-0}" != 1 ] && [ "$REATTACH" != 1 ] && [ -z "$JOIN_TOKEN" ] && [ ! -f "$STATE/agent.json" ]; then
  echo "install.sh: installed; the agent has not joined an engine, so f2c-agent.service is not enabled. To join (token from the engine's Add server):"
  echo "  sudo runuser -u f2c-agent -- $AGENT_BIN join --state-dir $STATE --engine https://ENGINE --token f2cj_..."
  echo "  sudo systemctl enable --now f2c-agent"
fi
# harden_preview FILE: a readable summary of a harden.sh --dry-run JSON result (python3 when present, else the JSON)
harden_preview() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" <<'PY' || cat "$1"
import json, sys
r = json.load(open(sys.argv[1]))
print("harden dry run: %s: %s" % (r.get("status"), r.get("message")))
for c in r.get("prechecks") or []:
    print("  check %s: %s (%s)" % (c.get("name"), "ok" if c.get("ok") else "FAILED", c.get("detail")))
for s in r.get("steps") or []:
    reason = " (%s)" % s["reason"] if s.get("reason") else ""
    print("  %s: %s%s: %s" % (s.get("id"), s.get("status"), reason, s.get("detail")))
    for ch in s.get("changes") or []:
        print("      %s %s %s" % (ch.get("action"), ch.get("kind"), ch.get("target")))
    for n in s.get("notes") or []:
        print("      note: %s" % n)
PY
  else
    cat "$1"
  fi
}
# harden_confirmed: F2C_HARDEN_CONFIRM=1, or "yes" typed on the terminal (stdin, or /dev/tty for curl | sh)
harden_confirmed() {
  [ "${F2C_HARDEN_CONFIRM:-}" = 1 ] && return 0
  ask_yes "install.sh: apply the hardening above? Type yes to apply: "
}
if [ "$HARDEN" = 1 ]; then
  # Never run a root harden automatically on reinstall or reboot (explicit --harden only). It requires a joined,
  # active, connected agent plus engine reachability; a manual install without --engine stops safely at pre-check.
  # Always a dry run first, shown here; applied only after F2C_HARDEN_CONFIRM=1 or a typed "yes".
  set --
  [ -z "$ENGINE" ] || set -- "$@" --engine "$ENGINE"
  for ip in ${F2C_HARDEN_ALLOW_IPS:-}; do set -- "$@" --allow-ip "$ip"; done
  if [ "${DRY_RUN:-0}" = 1 ]; then
    echo "+ /usr/local/lib/f2c/harden.sh --dry-run (after the agent is joined), shown as a preview"
    echo "+ /usr/local/lib/f2c/harden.sh --apply only with F2C_HARDEN_CONFIRM=1 or a typed yes (nothing applied in DRY_RUN)"
  else
    _hp="" _hl=""
    if ! { _hp=$(mktemp) && _hl=$(mktemp); }; then
      echo "install.sh: warning: mktemp failed; hardening skipped" >&2; rm -f "$_hp"; _hp=""
    fi
    if [ -n "$_hp" ]; then
      if /usr/local/lib/f2c/harden.sh --dry-run "$@" > "$_hp" 2> "$_hl"; then
        harden_preview "$_hp"
        if harden_confirmed; then
          # Non-fatal: the agent is installed and connected either way; harden.sh rolls itself back on failure.
          /usr/local/lib/f2c/harden.sh --apply "$@" || echo "install.sh: warning: optional hardening did not finish; see the JSON above (rolled back on failure)" >&2
        else
          echo "install.sh: hardening NOT applied (preview only). To apply, re-run with --harden and type yes, or set F2C_HARDEN_CONFIRM=1." >&2
        fi
      else
        if [ -s "$_hp" ]; then harden_preview "$_hp"; fi
        tail -n 5 "$_hl" >&2
        echo "install.sh: warning: the harden dry run failed (see above); nothing applied" >&2
      fi
      rm -f "$_hp" "$_hl"
    fi
  fi
fi
echo "install.sh: done; executable $AGENT_BIN (self-update writable, strict protection retained)."
echo "Egress: outbound 443 to the engine URL, the registry and github.com (releases); no inbound agent port."
