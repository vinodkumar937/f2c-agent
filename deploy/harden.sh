#!/usr/bin/env bash
# f2c harden: OPTIONAL security hardening for an f2c app server (run as root). Off by default.
#
#   harden.sh --dry-run  [options]        plan only: prints the planned changes (with file diffs) as JSON, changes nothing
#   harden.sh --apply    [options]        apply, with pre/post checks and automatic rollback on failure
#   harden.sh --rollback [BACKUP_ID|last] restore everything from /var/lib/f2c-harden/backups/<BACKUP_ID>
#   harden.sh --request FILE [--result-dir DIR]   agent path (f2c-harden.service): mode/options come from FILE
#   harden.sh --stop-post                 ExecStopPost safety net: rolls back an apply that died before finishing
#
# Options: --allow-ip IP|CIDR (repeatable, max 16: SSH allow above the rate limit + fail2ban ignoreip)
#          --engine URL (engine reachability pre/post-check only)   --swap-gb N (0-16, default 2)
#          --no-ssh-keys-only (keep SSH password login)   --skip-agent-check (manual use before the agent joins)
#          --id RUN_ID   --result-dir DIR (also write <RUN_ID>.json + last.json there)
#
# Steps (JSON ids): unattended_upgrades, fail2ban, ssh_keys_only, ssh_rate_limit, sysctl, swap, time_sync, journald.
# Safety rules:
#   - SSH port(s) detected with `sshd -T`, `ss` and ssh.socket; allowed in ufw BEFORE any other ufw change; unknown
#     port = the ufw step is skipped. Admin IPs go above the `ufw limit` rule.
#   - Password login is disabled ONLY when at least one candidate (root, or a sudo/admin/wheel member) can still log
#     in with a key under the EFFECTIVE per-user config (`sshd -T -C user=…,host=…,addr=…` for the open SSH sessions'
#     and admin IPs): PubkeyAuthentication, PermitRootLogin (root only with yes/prohibit-password), AllowUsers,
#     AllowGroups, DenyUsers, DenyGroups, AuthenticationMethods, AuthorizedKeysFile (%h/%u/%U), StrictModes
#     permissions and a login shell. Keys with command=, "please log in as" messages, no-pty/restrict,
#     cert-authority or expiry-time do not count; AuthorizedKeysCommand-only users are "unknown" and do not count.
#     If `sshd -T` or `-C` does not work (old OpenSSH), passwords stay on: no guessing. PermitRootLogin is only
#     tightened from "yes"; any other value is kept. Drop-in /etc/ssh/sshd_config.d/00-f2c-harden.conf (00 = read
#     before 50-cloud-init.conf); `sshd -t`, then the same per-user check on the new config, before
#     `systemctl reload` (never restart); drop-in rolled back on any failure.
#   - fail2ban: one drop-in, /etc/fail2ban/jail.d/zz-f2c-harden.local ([sshd], read last). ignoreip is ADDED to the
#     operator's list (`%(known/ignoreip)s …`, else an explicit merged list). Ours: loopback, --allow-ip and the SSH
#     sessions open during harden; never the engine's IPs (outbound-only agent link; the engine sits behind a
#     Cloudflare tunnel, so its resolved IPs are shared Cloudflare addresses). Verified with `fail2ban-client -d` on a
#     copy of the config before writing and with `fail2ban-client get sshd ignoreip` after; backend, port,
#     maxretry, findtime and bantime are only set when the operator left them unset.
#   - Pre-checks (agent active + connected, engine reachable, sshd valid, ssh listening) gate --apply; the same
#     post-checks run after it and a failure rolls everything back automatically.
#   - Every changed file is backed up first (/var/lib/f2c-harden/backups/<ts>, 0700) with a manifest; --rollback
#     replays it in reverse. Idempotent: drop-in files, existing-rule checks; a second run reports "unchanged".
#   - Rollback is verified (every file and the ufw on/off state match the backup, sshd -t, SSH listening) and runs
#     on any failure, on SIGTERM (children run in the background so the trap fires at once), at the 15 min time
#     budget between steps, on an unexpected exit (EXIT trap) and, if this script is killed outright, from
#     ExecStopPost (--stop-post, via the in-flight marker /var/lib/f2c-harden/inflight).
#   - Every run ends with a result file when --result-dir is set, also on early errors (bad request) once the run id
#     is known. A run id that already has a result is never run again.
#   - Audit: one JSON line per event (start, checks, every step, rollback, outcome) on stderr (journal), appended to
#     /var/lib/f2c-harden/audit.log (0640) and included in the result as "audit".
#   - Never touches app containers, Docker or Caddy. Never reboots. Reads no secrets (authorized_keys lines are only
#     classified by key type and options; nothing from them is printed).
set -uo pipefail
umask 022
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

STATE_DIR=/var/lib/f2c-harden
BACKUPS="$STATE_DIR/backups"
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-f2c-harden.conf
F2B_ETC=/etc/fail2ban
F2B_DROPIN=$F2B_ETC/jail.d/zz-f2c-harden.local
F2B_OLD_FILES=("$F2B_ETC/jail.d/00-f2c-harden-ignoreip.local" "$F2B_ETC/jail.d/f2c-harden-sshd.local") # earlier drafts
INFLIGHT=$STATE_DIR/inflight   # "<run id> <backup dir> <result dir>" while an apply is changing the host
AUDIT_LOG=$STATE_DIR/audit.log
HARDEN_BUDGET_S=900            # 15 min of steps; f2c-harden.service TimeoutStartSec is 20 min
APT_AUTO=/etc/apt/apt.conf.d/20auto-upgrades
APT_NOREBOOT=/etc/apt/apt.conf.d/52f2c-harden
SYSCTL_FILE=/etc/sysctl.d/99-f2c-harden.conf
JOURNALD_FILE=/etc/systemd/journald.conf.d/00-f2c-harden.conf
SWAPFILE=/swapfile
STEP_IDS=(unattended_upgrades fail2ban ssh_keys_only ssh_rate_limit sysctl swap time_sync journald)

MODE="" RUN_ID="" ENGINE="" SWAP_GB=2 SSH_KEYS_ONLY=1 AGENT_CHECK=1 BACKUP_ID="" REQUEST="" RESULT_DIR=""
ALLOW_IPS=()

die_usage() { echo "harden.sh: $*" >&2; EARLY_MSG="harden_bad_request: $*"; exit 2; }

# ---------- validation ----------
valid_ip() { # IPv4/IPv6 address or CIDR
  local v=$1 ip mask
  ip=${v%/*}; mask=""; [[ $v == */* ]] && mask=${v#*/}
  if [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    local o; for o in "${BASH_REMATCH[@]:1}"; do ((10#$o <= 255)) || return 1; done
    [[ -z $mask ]] || { [[ $mask =~ ^[0-9]{1,2}$ ]] && ((10#$mask <= 32)); } || return 1
    return 0
  fi
  if [[ $ip =~ ^[0-9A-Fa-f:]{2,39}$ && $ip == *:*:* ]]; then
    [[ -z $mask ]] || { [[ $mask =~ ^[0-9]{1,3}$ ]] && ((10#$mask <= 128)); } || return 1
    return 0
  fi
  return 1
}
valid_engine() { [[ $1 =~ ^https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$ ]]; }
valid_backup_id() { [[ $1 == last || $1 =~ ^[0-9]{8}-[0-9]{6}$ ]]; }
valid_swap() { [[ $1 =~ ^[0-9]{1,2}$ ]] && ((10#$1 <= 16)); }
valid_run_id() { [[ $1 =~ ^[A-Za-z0-9_.:-]{1,80}$ ]]; }
add_allow_ip() {
  valid_ip "$1" || die_usage "bad --allow-ip value (want an IPv4/IPv6 address or CIDR)"
  ((${#ALLOW_IPS[@]} < 16)) || die_usage "at most 16 --allow-ip values"
  ALLOW_IPS+=("$1")
}

# Agent request file: key=value lines written by f2c-agent (harden.go). Never sourced; every value validated.
read_request() {
  local f=$1 k v
  [[ -L $f ]] && die_usage "request is a symlink; refused"
  [[ -f $f ]] || exit 0 # path-unit retrigger after the request was consumed
  (($(stat -c %s "$f") <= 4096)) || die_usage "request too large"
  while IFS='=' read -r k v; do
    case "$k" in
      id) valid_run_id "$v" || die_usage "bad id"; RUN_ID=$v ;;
      mode) case "$v" in dry_run) MODE=dry-run ;; apply) MODE=apply ;; rollback) MODE=rollback ;; *) die_usage "bad mode" ;; esac ;;
      allow_ip) add_allow_ip "$v" ;;
      swap_gb) valid_swap "$v" || die_usage "bad swap_gb"; SWAP_GB=$((10#$v)) ;;
      ssh_keys_only) case "$v" in 0 | 1) SSH_KEYS_ONLY=$v ;; *) die_usage "bad ssh_keys_only" ;; esac ;;
      engine) valid_engine "$v" || die_usage "bad engine"; ENGINE=$v ;;
      backup_id) [[ -z $v ]] || { valid_backup_id "$v" || die_usage "bad backup_id"; BACKUP_ID=$v; } ;;
      "" | \#*) ;;
      *) die_usage "unknown request key" ;;
    esac
  done < "$f"
  rm -f -- "$f" # consumed (unlink never follows a symlink)
  [[ -n $MODE && -n $RUN_ID ]] || die_usage "request needs id and mode"
}

# ---------- pure helpers (no side effects; deploy/test/harden_test.sh sources them with F2C_HARDEN_LIB=1) ----------
# Bash 3.2 compatible on purpose (the tests also run on macOS); everything stateful comes after the guard below.
json_str() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')
  printf '"%s"' "$s"
}
json_join() { local IFS=,; printf '[%s]' "$*"; }
lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
words_uniq() { tr -s ' \t\n' '\n' <<< "$1" | awk 'NF && !s[$0]++' | tr '\n' ' ' | sed 's/ $//'; } # order kept
words_missing() { # "WANT" "HAVE": the words of WANT that are not in HAVE
  local w out=""
  local -a want
  read -r -a want <<< "$1"
  for w in "${want[@]+"${want[@]}"}"; do [[ " $2 " == *" $w "* ]] || out+="$w "; done
  printf '%s' "${out% }"
}

# --- SSH (H1): who can still log in with a key once passwords are off ---
KEY_TYPES='ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com'
# key_line_class LINE -> usable | restricted:<why> | none (blank, comment, not a key line)
key_line_class() {
  local line=$1 opts low re
  line=${line#"${line%%[![:space:]]*}"}
  case $line in '' | \#*) echo none; return 0 ;; esac
  re="^(.*[[:space:]])?($KEY_TYPES)[[:space:]]+AAAA[A-Za-z0-9+/]+=*([[:space:]]|\$)"
  [[ $line =~ $re ]] || { echo none; return 0; }
  opts=$(lc ",${BASH_REMATCH[1]}"); low=$(lc "$line")
  case $low in *"login as"* | *"log in as"*) echo restricted:login_message; return 0 ;; esac
  case $opts in *,command=*) echo restricted:forced_command; return 0 ;; esac
  case $opts in *,cert-authority*) echo restricted:cert_authority; return 0 ;; esac
  case $opts in *,expiry-time=*) echo restricted:expiry_time; return 0 ;; esac
  case $opts in *,no-pty*) echo restricted:no_pty; return 0 ;; esac
  case $opts in
    *,restrict,* | *,restrict[[:space:]]*)
      case $opts in *,pty,* | *,pty[[:space:]]*) ;; *) echo restricted:no_pty; return 0 ;; esac ;;
  esac
  echo usable
}
# key_file_class FILE -> prints usable / the first restricted:<why> / none; 0 only when a usable key is in it
key_file_class() {
  local f=$1 l c first=""
  [[ -f $f && ! -L $f && -r $f ]] || { echo none; return 1; }
  while IFS= read -r l || [[ -n $l ]]; do
    c=$(key_line_class "$l")
    case $c in usable) echo usable; return 0 ;; restricted:*) [[ -n $first ]] || first=$c ;; esac
  done < "$f"
  echo "${first:-none}"
  return 1
}
owner_mode() { stat -c '%U %a' "$1" 2>/dev/null || stat -f '%Su %Lp' "$1" 2>/dev/null; } # GNU, else BSD
# strict_path_ok USER HOME FILE: sshd StrictModes: the file and each directory up to HOME (or /) are owned by USER or
# root and are not group/world-writable
strict_path_ok() {
  local u=$1 home=$2 p=$3 o m
  while :; do
    read -r o m <<< "$(owner_mode "$p")"
    [[ -n $o && $m =~ ^[0-7]+$ ]] || return 1
    [[ $o == "$u" || $o == root ]] || return 1
    (((8#$m & 8#022) == 0)) || return 1
    [[ $p == "$home" || $p == / || $p == . ]] && return 0
    p=$(dirname "$p")
  done
}
# akf_paths "AuthorizedKeysFile value" USER HOME UID -> one path per line (%% %h %u %U expanded, relative = HOME/…)
akf_paths() {
  local t u=$2 home=$3 uid=$4 pp='%%' ph='%h' pu='%u' pU='%U'
  local -a toks
  read -r -a toks <<< "$1"
  for t in "${toks[@]+"${toks[@]}"}"; do
    [[ $(lc "$t") == none ]] && continue
    t=${t//"$pp"/$'\001'}; t=${t//"$ph"/$home}; t=${t//"$pu"/$u}; t=${t//"$pU"/$uid}; t=${t//$'\001'/%}
    [[ $t == /* ]] || t="$home/$t"
    printf '%s\n' "$t"
  done
}
eff_val() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' <<< "$2"; } # sshd -T: value of KEY
eff_all() { awk -v k="$1" '$1 == k { for (i = 2; i <= NF; i++) print $i }' <<< "$2"; }  # every word of KEY lines
# shellcheck disable=SC2053 # unquoted on purpose: sshd patterns use * and ? like shell globs
sshd_pat_match() { [[ $1 == $2 ]]; }
# authmethods_ok "sshd -T": a key alone still satisfies AuthenticationMethods
authmethods_ok() {
  local v l part ok
  local -a lists parts
  v=$(eff_val authenticationmethods "$1")
  [[ -z $v || $v == any ]] && return 0
  read -r -a lists <<< "$v"
  for l in "${lists[@]}"; do
    ok=1
    IFS=, read -r -a parts <<< "$l"
    for part in "${parts[@]}"; do [[ $part == publickey ]] || ok=0; done
    ((ok)) && return 0
  done
  return 1
}
# user_list_verdict USER "GROUPS" "sshd -T" ADDR -> "" when AllowUsers/AllowGroups/DenyUsers/DenyGroups let USER in,
# else the reason. Conservative: a Deny pattern's @host part is assumed to match; an Allow pattern only counts when
# its @host part is * or matches ADDR literally (no CIDR); !negations never count as allowing.
user_list_verdict() {
  local u=$1 groups=$2 eff=$3 addr=${4:-} p up hp g hit allow
  local -a gl
  read -r -a gl <<< "$groups"
  while read -r p; do
    [[ -n $p ]] || continue
    up=${p%%@*}
    sshd_pat_match "$u" "$up" && { echo "denied by DenyUsers $p"; return 0; }
  done < <(eff_all denyusers "$eff")
  allow=$(eff_all allowusers "$eff")
  if [[ -n $allow ]]; then
    hit=0
    while read -r p; do
      [[ -n $p ]] || continue
      case $p in *@*) up=${p%%@*}; hp=${p#*@}; [[ $hp == '*' ]] || sshd_pat_match "$addr" "$hp" || continue ;; *) up=$p ;; esac
      case $up in '!'*) continue ;; esac
      sshd_pat_match "$u" "$up" && { hit=1; break; }
    done <<< "$allow"
    ((hit)) || { echo "not in AllowUsers"; return 0; }
  fi
  while read -r p; do
    [[ -n $p ]] || continue
    for g in "${gl[@]+"${gl[@]}"}"; do sshd_pat_match "$g" "$p" && { echo "denied by DenyGroups $p"; return 0; }; done
  done < <(eff_all denygroups "$eff")
  allow=$(eff_all allowgroups "$eff")
  if [[ -n $allow ]]; then
    hit=0
    while read -r p; do
      [[ -n $p && $p != '!'* ]] || continue
      for g in "${gl[@]+"${gl[@]}"}"; do sshd_pat_match "$g" "$p" && hit=1; done
    done <<< "$allow"
    ((hit)) || { echo "no group in AllowGroups"; return 0; }
  fi
  return 0
}
# user_key_verdict "passwd line" "GROUPS" "sshd -T -C output for this user" ADDR
#   -> usable | unusable:<why> | unknown:<why>   (only "usable" lets ssh_keys_only turn passwords off)
user_key_verdict() {
  local pw=$1 groups=$2 eff=$3 addr=${4:-} u uid home shell why f c first="" akc strict prl _x
  IFS=: read -r u _x uid _x _x home shell <<< "$pw"
  [[ -n $u && -n $home ]] || { echo unusable:no_account; return 0; }
  case $shell in */nologin | */false) echo unusable:no_login_shell; return 0 ;; esac
  case $(eff_val pubkeyauthentication "$eff") in '' | yes) ;; *) echo unusable:pubkey_disabled; return 0 ;; esac
  if [[ $u == root ]]; then
    prl=$(eff_val permitrootlogin "$eff")
    case $prl in yes | prohibit-password | without-password) ;; *) echo "unusable:root_login_${prl:-unknown}"; return 0 ;; esac
  fi
  why=$(user_list_verdict "$u" "$groups" "$eff" "$addr")
  [[ -z $why ]] || { echo "unusable:$why"; return 0; }
  authmethods_ok "$eff" || { echo "unusable:AuthenticationMethods $(eff_val authenticationmethods "$eff") needs more than a key"; return 0; }
  strict=$(eff_val strictmodes "$eff")
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    if c=$(key_file_class "$f"); then
      if [[ $strict == no ]] || strict_path_ok "$u" "$home" "$f"; then echo usable; return 0; fi
      [[ -n $first ]] || first="restricted:unsafe_permissions"
    elif [[ $c == restricted:* && -z $first ]]; then first=$c; fi
  done < <(akf_paths "$(eff_val authorizedkeysfile "$eff")" "$u" "$home" "$uid")
  akc=$(eff_val authorizedkeyscommand "$eff")
  if [[ -n $akc && $(lc "$akc") != none ]]; then echo "unknown:keys only via AuthorizedKeysCommand (not checked)"; return 0; fi
  if [[ -n $first ]]; then echo "unusable:only restricted keys (${first#restricted:})"; else echo "unusable:no authorized key"; fi
}

# --- fail2ban (H3): add to the operator's settings, never replace them ---
# f2b_user_keys FILE...: "<section> <key>" for every option set in these INI files (lowercase)
f2b_user_keys() {
  awk '
    /^[ \t]*[#;]/ { next }
    /^[ \t]*\[[^]]+\]/ { s = $0; sub(/^[ \t]*\[/, "", s); sub(/\].*/, "", s); sec = tolower(s); next }
    /^[A-Za-z_][A-Za-z0-9_.-]*[ \t]*[=:]/ { k = $0; sub(/[ \t]*[=:].*/, "", k); print sec, tolower(k) }
  ' "$@" 2>/dev/null
}
# f2b_operator_sets DIR KEY: KEY is set for the sshd jail ([DEFAULT] or [sshd]) by the operator or the distro, i.e.
# anywhere but jail.conf (fail2ban's own defaults) and our files
f2b_operator_sets() {
  local d=$1 k=$2 f
  local -a files=()
  for f in "$d/jail.local" "$d"/jail.d/*.conf "$d"/jail.d/*.local; do
    [[ -f $f ]] || continue
    case ${f##*/} in zz-f2c-harden.local | 00-f2c-harden-ignoreip.local | f2c-harden-sshd.local) continue ;; esac
    files+=("$f")
  done
  ((${#files[@]})) || return 1
  f2b_user_keys "${files[@]}" | grep -qx -e "default $k" -e "sshd $k"
}
# parse_f2b_dump_ignoreip < `fail2ban-client -d`: the sshd jail's ignoreip entries, one per line
parse_f2b_dump_ignoreip() {
  awk -v q="'" '
    index($0, q "sshd" q) && index($0, "addignoreip" q) {
      s = substr($0, index($0, "addignoreip" q) + 12)
      while ((i = index(s, q)) > 0) { s = substr(s, i + 1); j = index(s, q); if (j == 0) break; print substr(s, 1, j - 1); s = substr(s, j + 1) }
    }'
}
# parse_f2b_get_ignoreip < `fail2ban-client get sshd ignoreip`
parse_f2b_get_ignoreip() { awk '/^[|`]- / { print $2 }'; }
# f2b_our_ignoreip "PEER_IPS" [ALLOW_IP…]: the entries we add to ignoreip: loopback, the admin --allow-ip values and
# the SSH sessions open during harden (sorted, unique). Never the engine's IPs (see the header).
f2b_our_ignoreip() {
  local peers=$1
  shift
  # shellcheck disable=SC2086 # PEER_IPS is a space-separated list: split on purpose (IPs, no glob characters)
  printf '%s\n' 127.0.0.1/8 ::1 "$@" $peers | awk 'NF' | sort -u | tr '\n' ' ' | sed 's/ $//'
}
# f2b_dropin_content known|explicit "IGNOREIP" "PORTS" "UNSET KEYS"
f2b_dropin_content() {
  local mode=$1 ign=$2 ports=$3 unset=" $4 "
  printf '%s\n' "# f2c harden: sshd jail additions, read last (zz-). ignoreip is ADDED to the operator's list; the other" \
    "# options are set here only because the operator left them unset. Remove this file and reload fail2ban to undo." \
    "[sshd]"
  [[ $unset != *" enabled "* ]] || echo "enabled = true"
  if [[ $mode == known ]]; then printf 'ignoreip = %%(known/ignoreip)s %s\n' "$ign"; else printf 'ignoreip = %s\n' "$ign"; fi
  [[ $unset != *" backend "* ]] || echo "backend = systemd"
  [[ $unset != *" port "* ]] || echo "port = $ports"
  [[ $unset != *" maxretry "* ]] || echo "maxretry = 5"
  [[ $unset != *" findtime "* ]] || echo "findtime = 10m"
  [[ $unset != *" bantime "* ]] || echo "bantime = 1h"
}

# shellcheck disable=SC2317 # exit is reached when the file is executed instead of sourced
[[ ${F2C_HARDEN_LIB:-} == 1 ]] && { return 0 2>/dev/null || exit 0; }

# ---------- run state: audit trail, result files, interruptible children, exit safety ----------
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DONE=0 EARLY_MSG="" CHILD="" BK="" MANIFEST=""
AUDIT=()
# audit EVENT [STEP] [STATUS] [DETAIL]: one JSON line on stderr (journal), in audit.log and in the result's "audit"
audit() {
  local o
  o="{\"ts\":$(json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"),\"run\":$(json_str "${RUN_ID:-}"),\"mode\":$(json_str "${MODE:-}"),\"event\":$(json_str "$1")"
  [[ -z ${2:-} ]] || o+=",\"step\":$(json_str "$2")"
  [[ -z ${3:-} ]] || o+=",\"status\":$(json_str "$3")"
  [[ -z ${4:-} ]] || o+=",\"detail\":$(json_str "${4:0:500}")"
  o+="}"
  AUDIT+=("$o")
  printf 'f2c-harden audit %s\n' "$o" >&2
  if [[ -d $STATE_DIR && ! -L $STATE_DIR && $(id -u) == 0 ]]; then
    if [[ -f $AUDIT_LOG ]] && (($(stat -c %s "$AUDIT_LOG" 2>/dev/null || echo 0) > 1048576)); then mv -f -- "$AUDIT_LOG" "$AUDIT_LOG.1"; fi
    { printf '%s\n' "$o" >> "$AUDIT_LOG" && chmod 0640 "$AUDIT_LOG"; } 2>/dev/null || true
  fi
}
# write_result_json JSON: RESULT_DIR/<RUN_ID>.json + last.json (root-owned 0750 root:f2c-agent dir, files 0640)
write_result_json() {
  local tmp
  [[ -n $RESULT_DIR && -n $RUN_ID ]] && valid_run_id "$RUN_ID" || return 0
  install -d -m 0750 "$RESULT_DIR" || return 1
  getent group f2c-agent >/dev/null 2>&1 && chgrp f2c-agent "$RESULT_DIR"
  tmp=$(mktemp "$RESULT_DIR/.result.XXXXXX") && printf '%s\n' "$1" > "$tmp" && chmod 0640 "$tmp" &&
    { getent group f2c-agent >/dev/null 2>&1 && chgrp f2c-agent "$tmp"; cp -f "$tmp" "$RESULT_DIR/last.json.tmp" && mv -f "$RESULT_DIR/last.json.tmp" "$RESULT_DIR/last.json"; mv -f "$tmp" "$RESULT_DIR/$RUN_ID.json"; }
  find "$RESULT_DIR" -maxdepth 1 -name 'harden-*.json' -mtime +30 -delete 2>/dev/null
  return 0
}
min_result_json() { # STATUS MESSAGE [BACKUP_ID]: the result shape with no steps (early errors, safety net)
  printf '{"version":1,"id":%s,"mode":%s,"status":%s,"message":%s,"startedAt":%s,"finishedAt":%s,"backupId":%s,"sshKeysPresent":null,"sshPorts":[],"warnings":[],"prechecks":[],"postchecks":[],"steps":[],"audit":%s}' \
    "$(json_str "$RUN_ID")" "$(json_str "${MODE//-/_}")" "$(json_str "$1")" "$(json_str "$2")" "$(json_str "$STARTED")" \
    "$(json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" "$([[ -n ${3:-} ]] && json_str "$3" || echo null)" "$(json_join "${AUDIT[@]+"${AUDIT[@]}"}")"
}
# run_bg CMD…: bash runs a trap only after a foreground child exits; `wait` is interrupted at once, so SIGTERM
# (systemd timeout / stop) reaches on_term immediately even during apt-get. on_term stops $CHILD itself.
run_bg() {
  local r
  "$@" &
  CHILD=$!
  wait "$CHILD"
  r=$?
  CHILD=""
  return $r
}
# EXIT trap: a run that ends without its final result (bad request, unbound variable, a bug) still gets one, and an
# apply that had started changing the host is rolled back first.
on_exit() {
  local rc=$? st=failed msg bk=""
  trap - EXIT
  ((DONE)) && return 0
  [[ $MODE == stop-post ]] && return 0
  msg=${EARLY_MSG:-"harden_script_failed: harden.sh exited (code $rc) before it finished"}
  if [[ $MODE == apply && -n $BK && -s $MANIFEST && ! -e $BK/rolled_back ]]; then
    bk=$(basename "$BK")
    audit rollback_start "" "" "unexpected exit; backup $bk"
    if do_rollback "$BK" && rollback_checks "$BK"; then st=rolled_back msg+="; all changes rolled back"; else msg+="; rollback finished with errors (backup $bk)"; fi
    audit rollback "" "$st" "$msg"
  fi
  [[ -n $BK ]] && rm -f -- "$INFLIGHT"
  [[ -n $RUN_ID ]] || return 0
  audit outcome "" "$st" "$msg"
  write_result_json "$(min_result_json "$st" "$msg" "$bk")"
}
trap on_exit EXIT

while (($#)); do
  case "$1" in
    --dry-run) MODE=dry-run; shift ;;
    --apply) MODE=apply; shift ;;
    --rollback) MODE=rollback; shift; if (($#)) && [[ $1 != --* ]]; then BACKUP_ID=$1; shift; fi ;;
    --stop-post) MODE=stop-post; shift ;;
    --allow-ip) add_allow_ip "${2:-}"; shift 2 ;;
    --engine) valid_engine "${2:-}" || die_usage "bad --engine"; ENGINE=$2; shift 2 ;;
    --swap-gb) valid_swap "${2:-}" || die_usage "--swap-gb must be 0-16"; SWAP_GB=$((10#$2)); shift 2 ;;
    --no-ssh-keys-only) SSH_KEYS_ONLY=0; shift ;;
    --skip-agent-check) AGENT_CHECK=0; shift ;;
    --id) valid_run_id "${2:-}" || die_usage "bad --id"; RUN_ID=$2; shift 2 ;;
    --request) REQUEST=${2:-}; shift 2 ;;
    --result-dir) RESULT_DIR=${2:-}; shift 2 ;;
    -h | --help) DONE=1; sed -n '2,13p' "$0"; exit 0 ;;
    *) die_usage "unknown argument $1" ;;
  esac
done
[[ -n $REQUEST ]] && read_request "$REQUEST"
[[ -n $MODE ]] || die_usage "pick one of --dry-run, --apply, --rollback (nothing runs by default)"
[[ $MODE == rollback ]] && BACKUP_ID=${BACKUP_ID:-last}
[[ -n $BACKUP_ID ]] && { valid_backup_id "$BACKUP_ID" || die_usage "bad backup id"; }
[[ -n $RUN_ID || $MODE == stop-post ]] || RUN_ID="harden-cli-$(date -u +%Y%m%d%H%M%S)"
[[ $(id -u) == 0 ]] || die_usage "run as root"
# H2 (root side): a run id that already has a result was handled; never run it twice and never overwrite its result.
if [[ -n $REQUEST && -n $RESULT_DIR && -f $RESULT_DIR/$RUN_ID.json ]]; then
  echo "harden.sh: run $RUN_ID already has a result; not running it again" >&2
  audit duplicate "" "" "result already present; not run again"
  DONE=1
  exit 0
fi
DRY=0; [[ $MODE == dry-run ]] && DRY=1

# ---------- JSON result model ----------
declare -A STEP_STATUS STEP_REASON STEP_DETAIL STEP_CHANGES STEP_NOTES
CUR_CHANGES=()
ch_add() { # kind target action [diff]
  local o; o="{\"kind\":$(json_str "$1"),\"target\":$(json_str "$2"),\"action\":$(json_str "$3")"
  [[ -n ${4:-} ]] && o+=",\"diff\":$(json_str "$4")"
  CUR_CHANGES+=("$o}")
}
step_done() { # id status reason detail
  STEP_STATUS[$1]=$2; STEP_REASON[$1]=$3; STEP_DETAIL[$1]=$4
  STEP_CHANGES[$1]=$(json_join "${CUR_CHANGES[@]+"${CUR_CHANGES[@]}"}")
  CUR_CHANGES=()
  audit step "$1" "$2" "${3:+$3: }${4:-}"
}
# step_note id text: a caveat for the UI (per step "notes"; also collected into the run's "warnings")
step_note() { STEP_NOTES[$1]+="${STEP_NOTES[$1]:+$'\n'}$2"; }
notes_json() {
  local -a out=() n
  [[ -n ${STEP_NOTES[$1]:-} ]] || { printf '[]'; return; }
  while IFS= read -r n; do out+=("$(json_str "$n")"); done <<< "${STEP_NOTES[$1]}"
  json_join "${out[@]}"
}
warnings_json() {
  local -a out=() s n
  for s in "${STEP_IDS[@]}"; do
    [[ -n ${STEP_NOTES[$s]:-} ]] || continue
    while IFS= read -r n; do out+=("$(json_str "$s: $n")"); done <<< "${STEP_NOTES[$s]}"
  done
  json_join "${out[@]+"${out[@]}"}"
}
step_json() {
  local id=$1 r=${STEP_REASON[$1]:-}
  printf '{"id":%s,"status":%s,"reason":%s,"detail":%s,"notes":%s,"changes":%s}' "$(json_str "$id")" "$(json_str "${STEP_STATUS[$id]:-skipped}")" \
    "$([[ -n $r ]] && json_str "$r" || echo null)" "$(json_str "${STEP_DETAIL[$id]:-}")" "$(notes_json "$id")" "${STEP_CHANGES[$id]:-[]}"
}
CHECKS_PRE=() CHECKS_POST=()
check_add() { # pre|post name ok detail
  local o; o="{\"name\":$(json_str "$2"),\"ok\":$3,\"detail\":$(json_str "$4")}"
  if [[ $1 == pre ]]; then CHECKS_PRE+=("$o"); else CHECKS_POST+=("$o"); fi
}

# ---------- facts ----------
OS_ID=""; [[ -r /etc/os-release ]] && OS_ID=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2}' /etc/os-release)
ssh_ports() {
  {
    sshd -T 2>/dev/null | awk '$1=="port"{print $2}'
    ss -Htlnp 2>/dev/null | awk '/"sshd"/ {n=split($4,a,":"); print a[n]}'
    systemctl show ssh.socket -p Listen --value 2>/dev/null | grep -oE ':[0-9]+ \(Stream\)' | grep -oE '[0-9]+'
  } | awk '$1 ~ /^[0-9]+$/ && $1 > 0 && $1 < 65536' | sort -un | tr '\n' ' '
}
SSH_PORTS=$(ssh_ports); read -r -a SSH_PORT_ARR <<< "$SSH_PORTS"
PEER_IPS=""
for p in "${SSH_PORT_ARR[@]+"${SSH_PORT_ARR[@]}"}"; do
  PEER_IPS+=$(ss -Htn state established "( sport = :$p )" 2>/dev/null | awk '{print $4}' | sed -E 's/^\[?([^]]*)\]?:[0-9]+$/\1/' | sed 's/^::ffff://' | tr '\n' ' ')
done
PEER_IPS=$(tr ' ' '\n' <<< "$PEER_IPS" | awk 'NF' | sort -u | tr '\n' ' ')

# H1: who can still log in with a key, from the EFFECTIVE per-connection sshd config (Match blocks included).
# Probe addresses: the open SSH sessions' and the --allow-ip (single address) ones; a candidate counts only when it is
# usable from every probe address. `sshd -T -C` must work; otherwise nothing is guessed and passwords stay on.
KEY_USERS=() KEY_SKIPS=() KEYS_NOTE="" PROBE_NOTE="" PROBE_ADDRS=""
# probe_user USER: prints the verdict (usable / unusable:… / unknown:…); 0 only when usable from every probe address
probe_user() {
  local u=$1 pw groups a eff v=""
  pw=$(getent passwd "$u") || { echo unusable:no_account; return 1; }
  groups=$(id -Gn "$u" 2>/dev/null) || groups=""
  for a in $PROBE_ADDRS; do
    eff=$(sshd -T -C "user=$u,host=$a,addr=$a" 2>/dev/null) || { echo "unknown:sshd -T -C failed for $a"; return 1; }
    v=$(user_key_verdict "$pw" "$groups" "$eff" "$a")
    [[ $v == usable ]] || { echo "$v (from $a)"; return 1; }
  done
  [[ $v == usable ]] || { echo unknown:no_probe; return 1; }
  echo usable
}
detect_keys() {
  local u v g gid ip
  local -a cands=(root)
  command -v sshd >/dev/null 2>&1 || { KEYS_NOTE="sshd not found: cannot check SSH keys"; return; }
  sshd -T >/dev/null 2>&1 || { KEYS_NOTE="sshd -T failed (old OpenSSH or invalid config): effective SSH settings unknown"; return; }
  sshd -T -C user=root,host=192.0.2.1,addr=192.0.2.1 >/dev/null 2>&1 ||
    { KEYS_NOTE="this sshd does not support per-user checks (sshd -T -C): not guessing"; return; }
  PROBE_ADDRS=$PEER_IPS
  for ip in "${ALLOW_IPS[@]+"${ALLOW_IPS[@]}"}"; do [[ $ip == */* ]] || PROBE_ADDRS+=" $ip"; done
  PROBE_ADDRS=$(words_uniq "$PROBE_ADDRS")
  if [[ -z $PROBE_ADDRS ]]; then
    PROBE_ADDRS=192.0.2.1
    PROBE_NOTE="no open SSH session and no single --allow-ip address: Match Address/Host blocks checked for a generic address only"
  fi
  for g in sudo admin wheel; do
    gid=$(getent group "$g" | awk -F: '{print $3}')
    [[ -n $gid ]] || continue
    for u in $(getent group "$g" | awk -F: '{print $4}' | tr ',' ' ') $(getent passwd | awk -F: -v g="$gid" '$4 == g {print $1}'); do
      [[ " ${cands[*]} " == *" $u "* ]] || cands+=("$u")
    done
  done
  for u in "${cands[@]}"; do
    if v=$(probe_user "$u"); then KEY_USERS+=("$u"); else KEY_SKIPS+=("$u: ${v#*:}"); fi
  done
}
[[ $MODE == stop-post ]] || detect_keys
KEYS_PRESENT=false; ((${#KEY_USERS[@]})) && KEYS_PRESENT=true

# ---------- lock, backups ----------
install -d -m 0755 "$STATE_DIR"
install -d -m 0700 "$BACKUPS"
exec 9> "$STATE_DIR/lock"
LOCKED=1; flock -n 9 || LOCKED=0
declare -A BACKED
new_backup() {
  BK="$BACKUPS/$(date -u +%Y%m%d-%H%M%S)"; install -d -m 0700 "$BK/files"; MANIFEST="$BK/manifest"; : > "$MANIFEST"
  # in-flight marker: if this process dies without finishing (SIGKILL, OOM, power loss), --stop-post or the next run
  # rolls this backup back and writes this run's result
  printf '%s %s %s\n' "$RUN_ID" "$BK" "${RESULT_DIR:--}" > "$INFLIGHT.tmp" && chmod 0600 "$INFLIGHT.tmp" && mv -f "$INFLIGHT.tmp" "$INFLIGHT"
}
note() { echo "$*" >> "$MANIFEST"; } # step kind a b
backup_file() { # step path
  [[ -n ${BACKED[$2]:-} ]] && return 0
  BACKED[$2]=1
  if [[ -e $2 ]]; then install -d -m 0700 "$BK/files$(dirname "$2")"; cp -a -- "$2" "$BK/files$2" && note "$1" file existed "$2"
  else note "$1" file absent "$2"; fi
}
# file_change step path mode content: 0 = changed (or planned), 1 = unchanged, 2 = error
file_change() {
  local step=$1 path=$2 mode=$3 content=$4 tmp action d
  tmp=$(mktemp) || return 2
  printf '%s' "$content" > "$tmp"
  if [[ -f $path ]] && cmp -s "$tmp" "$path"; then rm -f "$tmp"; return 1; fi
  if [[ -e $path ]]; then action=replace; d=$(diff -u --label "$path" --label "$path" "$path" "$tmp")
  else action=create; d=$(diff -u --label /dev/null --label "$path" /dev/null "$tmp"); fi
  ((${#d} > 8192)) && d="${d:0:8192}…truncated"
  ch_add file "$path" "$action" "$d"
  if ((DRY == 0)); then
    backup_file "$step" "$path" || { rm -f "$tmp"; return 2; }
    install -D -m "$mode" -o root -g root "$tmp" "$path" || { rm -f "$tmp"; return 2; }
  fi
  rm -f "$tmp"; return 0
}
APT_UPDATED=0
apt_install() {
  # in the background (run_bg) so SIGTERM is handled at once; 120 s + 300 s keeps the whole run inside the budget
  ((APT_UPDATED)) || { run_bg timeout 120 apt-get -q -o DPkg::Lock::Timeout=60 update >/dev/null 2>&1 || true; APT_UPDATED=1; }
  run_bg env DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -q -o DPkg::Lock::Timeout=60 --no-install-recommends "$@" >/dev/null 2>&1
}
note_svc() { # step unit: remember enabled/active state once so rollback restores it exactly
  [[ -n ${BACKED["svc:$2"]:-} ]] && return 0
  BACKED["svc:$2"]=1
  note "$1" svc "$2" "$(systemctl is-enabled "$2" 2>/dev/null || echo disabled),$(systemctl is-active "$2" 2>/dev/null || echo inactive)"
}
have_pkg() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

# ---------- checks ----------
run_checks() { # pre|post
  local w=$1 tries=1 i ok detail
  [[ $w == post ]] && tries=6
  if [[ $OS_ID == ubuntu || $OS_ID == debian ]]; then check_add "$w" os_supported true "$OS_ID"; else check_add "$w" os_supported false "unsupported OS ${OS_ID:-unknown} (Ubuntu/Debian only)"; fi
  if ((AGENT_CHECK)); then
    if systemctl is-active --quiet f2c-agent.service; then check_add "$w" agent_active true "f2c-agent.service active"; else check_add "$w" agent_active false "f2c-agent.service not active"; fi
    ok=false; detail="no fresh authenticated wss proof from f2c-agent"
    for ((i = 0; i < tries + 2; i++)); do
      if link_proof_fresh; then ok=true; detail="authenticated wss session answered a ping in the last 30 s"; break; fi
      run_bg sleep 5
    done
    check_add "$w" agent_connected "$ok" "$detail"
  fi
  if [[ -n $ENGINE ]]; then
    ok=false; detail="engine unreachable"
    for ((i = 0; i < tries; i++)); do
      code=$(curl -sS -o /dev/null --max-time 10 -w '%{http_code}' "$ENGINE/agent/install.sh" 2>/dev/null || true)
      if [[ -n $code && $code != 000 ]]; then ok=true; detail="engine answered HTTP $code"; break; fi
      ((i + 1 < tries)) && run_bg sleep 5
    done
    check_add "$w" engine_reachable "$ok" "$detail"
  fi
  if sshd -t 2>/dev/null; then check_add "$w" sshd_config_valid true "sshd -t ok"; else check_add "$w" sshd_config_valid false "sshd -t failed"; fi
  if ((${#SSH_PORT_ARR[@]} == 0)); then check_add "$w" ssh_listening true "ssh port unknown; ufw step will be skipped"
  else
    local p missing=""
    for p in "${SSH_PORT_ARR[@]}"; do ss -Htln 2>/dev/null | awk '{print $4}' | grep -Eq ":$p\$" || missing+="$p "; done
    if [[ -z $missing ]]; then check_add "$w" ssh_listening true "listening on ${SSH_PORTS% }"; else check_add "$w" ssh_listening false "not listening on ${missing% }"; fi
    # after an apply: ufw (if active) must still let SSH in
    if [[ $w == post && $MODE == apply ]] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
      missing=""
      for p in "${SSH_PORT_ARR[@]}"; do ufw_port_open "$p" || missing+="$p "; done
      if [[ -z $missing ]]; then check_add "$w" ssh_allowed_by_ufw true "ufw allows SSH on ${SSH_PORTS% }"; else check_add "$w" ssh_allowed_by_ufw false "ufw does not allow SSH on ${missing% }"; fi
    fi
  fi
}
# ufw_port_open PORT: an active ufw lets new connections to PORT/tcp in (default allow, a port rule or OpenSSH)
ufw_port_open() {
  local st
  st=$(ufw status verbose 2>/dev/null) || return 1
  grep -Eq '^Default: allow \(incoming\)' <<< "$st" && return 0
  grep -Eq "^$1(/tcp)?( \(v6\))? +(ALLOW|LIMIT)( IN)? +Anywhere" <<< "$st" && return 0
  [[ $1 == 22 ]] && grep -Eq '^OpenSSH( \(v6\))? +(ALLOW|LIMIT)( IN)? +Anywhere' <<< "$st"
}
# Written by f2c-agent (harden.go) after hello_ok + a websocket Ping/Pong; checked strictly, nothing else read.
link_proof_fresh() {
  local f=/var/lib/f2c-agent/harden/link-proof uid ts kind rest
  [[ -f $f && ! -L $f ]] || return 1
  uid=$(id -u f2c-agent 2>/dev/null) || return 1
  [[ $(stat -c %u "$f") == "$uid" ]] && (($(stat -c %s "$f") <= 64)) || return 1
  read -r ts kind rest < "$f" || return 1
  [[ $ts =~ ^[0-9]{9,11}$ && $kind == wss && -z $rest ]] || return 1
  (($(date +%s) - ts <= 30))
}
checks_ok() { local c; for c in "$@"; do [[ $c == *'"ok":false'* ]] && return 1; done; return 0; }

reload_ssh() {
  sshd -t 2>/dev/null || return 1
  if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service
  elif systemctl is-active --quiet sshd.service; then systemctl reload sshd.service
  else return 0; fi # socket-activated and idle: the next start reads the new config
}

# ---------- steps ----------
step_unattended_upgrades() {
  local id=unattended_upgrades r1 r2 changed=0
  if ! have_pkg unattended-upgrades; then
    ch_add package unattended-upgrades install; changed=1
    ((DRY)) || { note $id pkg unattended-upgrades; apt_install unattended-upgrades || { step_done $id failed apt_failed "apt-get install unattended-upgrades failed"; return 1; }; }
  fi
  file_change $id "$APT_AUTO" 0644 $'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::AutocleanInterval "7";\n'; r1=$?
  file_change $id "$APT_NOREBOOT" 0644 $'// f2c harden: security updates only (distro default origins), never reboot automatically\nUnattended-Upgrade::Automatic-Reboot "false";\n'; r2=$?
  ((r1 == 2 || r2 == 2)) && { step_done $id failed write_failed "could not write apt config"; return 1; }
  ((r1 == 0 || r2 == 0)) && changed=1
  if ((DRY == 0)); then note_svc $id unattended-upgrades.service; systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true; fi
  if ((changed)); then step_done $id "$( ((DRY)) && echo planned || echo applied)" "" "daily security updates, no automatic reboot"
  else step_done $id unchanged "" "already on"; fi
}

# H3: the operator's fail2ban settings win. One drop-in, read last, that ADDS our ignoreip entries to whatever the
# operator configured and sets the other sshd options only where nothing but fail2ban's own jail.conf sets them.
f2b_dump_ignoreip() { # DIR: the sshd jail's ignoreip as fail2ban itself resolves it (fails if the config does not parse)
  local out
  out=$(timeout 30 fail2ban-client -c "$1" -d 2>/dev/null) || return 1
  parse_f2b_dump_ignoreip <<< "$out"
}
# f2b_copy_with CONTENT: a temp copy of /etc/fail2ban without our files, plus CONTENT as our drop-in ("" = none)
f2b_copy_with() {
  local tmp f
  tmp=$(mktemp -d) || return 1
  cp -a "$F2B_ETC/." "$tmp/" 2>/dev/null || { rm -rf "$tmp"; return 1; }
  for f in "${F2B_OLD_FILES[@]}" "$F2B_DROPIN"; do rm -f -- "$tmp/jail.d/${f##*/}"; done
  [[ -z $1 ]] || { install -d "$tmp/jail.d" && printf '%s\n' "$1" > "$tmp/jail.d/${F2B_DROPIN##*/}"; } || { rm -rf "$tmp"; return 1; }
  echo "$tmp"
}
# f2b_validate CONTENT "WANT": fail2ban parses the config with CONTENT and the sshd jail ignores every WANT entry
f2b_validate() {
  local tmp got
  tmp=$(f2b_copy_with "$1") || return 1
  got=$(f2b_dump_ignoreip "$tmp" | tr '\n' ' ') || got=""
  rm -rf -- "$tmp"
  [[ -n $got && -z $(words_missing "$2" "$got") ]]
}
f2b_norm() { tr ' ' '\n' <<< "$1" | sed -E 's#/(32|128)$##' | awk 'NF' | sort -u | tr '\n' ' '; }
step_fail2ban() {
  local id=fail2ban ours ports before="" want content mode unset="" k f r changed=0 was_active=0 installed=0 tmp live miss kept
  ours=$(f2b_our_ignoreip "$PEER_IPS" "${ALLOW_IPS[@]+"${ALLOW_IPS[@]}"}")
  ports=$(IFS=,; echo "${SSH_PORT_ARR[*]+"${SSH_PORT_ARR[*]}"}"); [[ -n $ports ]] || ports=ssh
  have_pkg fail2ban && [[ -d $F2B_ETC ]] && installed=1
  for k in enabled backend port maxretry findtime bantime; do
    ((installed)) && f2b_operator_sets "$F2B_ETC" "$k" && continue
    unset+="$k "
  done
  if ((installed)); then
    tmp=$(f2b_copy_with "") && before=$(f2b_dump_ignoreip "$tmp") || before=__fail
    [[ -n $tmp ]] && rm -rf -- "$tmp"
    if [[ $before == __fail ]]; then
      step_done $id skipped f2b_config_unreadable "fail2ban-client -d cannot read the current fail2ban config; fail2ban left alone"; return 0
    fi
    before=$(words_uniq "$before")
    want=$(words_uniq "$before $ours")
    mode=known content=$(f2b_dropin_content known "$ours" "$ports" "$unset")
    if ! f2b_validate "$content" "$want"; then
      mode=explicit content=$(f2b_dropin_content explicit "$want" "$ports" "$unset")
      f2b_validate "$content" "$want" ||
        { step_done $id skipped f2b_merge_unverified "could not verify that the operator's ignoreip is kept; fail2ban left alone"; return 0; }
    fi
  else
    before="" want=$ours mode=new content=$(f2b_dropin_content explicit "$ours" "$ports" "$unset")
  fi
  for f in "${F2B_OLD_FILES[@]}"; do # earlier f2c drafts (replaced [DEFAULT] ignoreip): ours to remove
    [[ -e $f ]] || continue
    ch_add file "$f" remove; changed=1
    ((DRY)) || { backup_file $id "$f" && rm -f -- "$f"; } || { step_done $id failed write_failed "could not remove $f"; return 1; }
  done
  file_change $id "$F2B_DROPIN" 0644 "$content"$'\n'; r=$?
  ((r == 2)) && { step_done $id failed write_failed "could not write $F2B_DROPIN"; return 1; }
  ((r == 0)) && changed=1
  systemctl is-active --quiet fail2ban.service && was_active=1
  if ! have_pkg fail2ban; then
    ch_add package fail2ban install; changed=1
    if ((DRY == 0)); then
      note $id pkg fail2ban
      apt_install fail2ban python3-systemd || { step_done $id failed apt_failed "apt-get install fail2ban failed"; return 1; }
    fi
  elif [[ " $unset " == *" backend "* ]] && ! have_pkg python3-systemd; then
    ch_add package python3-systemd install; changed=1
    ((DRY)) || apt_install python3-systemd || { step_done $id failed apt_failed "apt-get install python3-systemd failed"; return 1; }
  fi
  if ((DRY == 0)); then
    note_svc $id fail2ban.service
    systemctl enable fail2ban.service >/dev/null 2>&1 || true
    if ((was_active)); then fail2ban-client reload >/dev/null 2>&1 || { step_done $id failed reload_failed "fail2ban-client reload failed"; return 1; }
    else systemctl start fail2ban.service >/dev/null 2>&1 || { step_done $id failed start_failed "fail2ban did not start"; return 1; }; fi
    run_bg sleep 2
    fail2ban-client status sshd >/dev/null 2>&1 || { step_done $id failed jail_inactive "sshd jail not active"; return 1; }
    live=$(fail2ban-client get sshd ignoreip 2>/dev/null | parse_f2b_get_ignoreip | tr '\n' ' ')
    miss=$(words_missing "$(f2b_norm "$want")" "$(f2b_norm "$live")")
    [[ -z $miss ]] || step_note $id "fail2ban shows a different ignoreip than configured (not found as written: $miss)"
  fi
  kept=$(words_missing "$before" "$ours"); kept=$(wc -w <<< "$kept" | tr -d ' ')
  if ((changed)); then step_done $id "$( ((DRY)) && echo planned || echo applied)" "" "sshd jail on; ignoreip: $kept operator entr$( ((kept == 1)) && echo y || echo ies) kept + $ours ($mode); set by f2c: ${unset:-nothing (operator values kept)}"
  else step_done $id unchanged "" "sshd jail already on; ignoreip: $kept operator entries kept + $ours"; fi
}

# Keyboard-interactive / challenge-response login switch, per OpenSSH version. 8.7 renamed ChallengeResponseAuthentication
# to KbdInteractiveAuthentication (the old name stays as an alias). Before 8.7 (e.g. Ubuntu 20.04's 8.2) the switch is
# ChallengeResponseAuthentication and KbdInteractiveAuthentication defaults to it; both keywords are accepted there, so
# "is the keyword known" (sshd -t -o KbdInteractiveAuthentication=no) cannot tell old from new. What does: `sshd -T`
# still prints a challengeresponseauthentication line only before 8.7. Fallback: the version from `sshd -V` (old sshd
# prints it in its usage text) or `ssh -V`. Unknown: the old name, which every OpenSSH accepts.
sshd_version() { # prints "major minor" (e.g. "8 2"), or fails
  local v
  v=$( { sshd -V 2>&1; ssh -V 2>&1; } | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | sed -n 1p) || v=""
  [[ -n $v ]] || return 1
  v=${v#OpenSSH_}
  echo "${v%%.*} ${v#*.}"
}
kbd_mode() { # prints kbd (>= 8.7: KbdInteractiveAuthentication) or cr (< 8.7: ChallengeResponseAuthentication)
  local eff maj min
  eff=$(sshd -T 2>/dev/null) || eff=""
  if [[ -n $eff ]]; then
    if grep -qi '^challengeresponseauthentication ' <<<"$eff"; then echo cr; return 0; fi
    if grep -qi '^kbdinteractiveauthentication ' <<<"$eff"; then echo kbd; return 0; fi
  fi
  if read -r maj min < <(sshd_version) && [[ $maj =~ ^[0-9]+$ && $min =~ ^[0-9]+$ ]]; then
    if ((maj > 8 || (maj == 8 && min >= 7))); then echo kbd; else echo cr; fi
    return 0
  fi
  echo cr
}
kbd_keyword() { [[ $1 == kbd ]] && echo KbdInteractiveAuthentication || echo ChallengeResponseAuthentication; }
# kbd_effective_ok MODE "<sshd -T output>": the mode's key must be printed as "no" (cr mode on an sshd that only prints
# the new key: that one), and whichever of the two keys is printed must be "no" (catches an override elsewhere).
kbd_effective_ok() {
  local mode=$1 eff=$2 k
  if [[ $mode == cr ]] && grep -qi '^challengeresponseauthentication ' <<<"$eff"; then
    grep -qix 'challengeresponseauthentication no' <<<"$eff" || return 1
  else
    grep -qix 'kbdinteractiveauthentication no' <<<"$eff" || return 1
  fi
  for k in challengeresponseauthentication kbdinteractiveauthentication; do
    if grep -qi "^$k " <<<"$eff"; then grep -qix "$k no" <<<"$eff" || return 1; fi
  done
}
step_ssh_keys_only() {
  local id=ssh_keys_only prl content r kmode kkey eff u still=""
  if ((SSH_KEYS_ONLY == 0)); then step_done $id skipped not_requested "password login kept (sshKeysOnly=false)"; return 0; fi
  [[ -z $PROBE_NOTE ]] || step_note $id "$PROBE_NOTE"
  for u in "${KEY_SKIPS[@]+"${KEY_SKIPS[@]}"}"; do step_note $id "not counted: $u"; done
  if [[ -n $KEYS_NOTE ]]; then step_done $id skipped no_ssh_key "$KEYS_NOTE; password login kept"; return 0; fi
  if [[ $KEYS_PRESENT != true ]]; then step_done $id skipped no_ssh_key "nobody (root or a sudo/admin/wheel user) can log in with an unrestricted SSH key under the effective sshd config; password login kept (add a key first; see notes)"; return 0; fi
  grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null ||
    { step_done $id skipped sshd_no_include "/etc/ssh/sshd_config does not include sshd_config.d; not changed"; return 0; }
  prl=$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')
  kmode=$(kbd_mode); kkey=$(kbd_keyword "$kmode")
  content=$'# f2c harden: SSH keys only (remove this file and `systemctl reload ssh` to undo)\nPasswordAuthentication no\n'"$kkey"$' no\n'
  # only ever tightened: "yes" -> prohibit-password; no / forced-commands-only / prohibit-password are kept as they are
  [[ $prl == yes ]] && content+=$'PermitRootLogin prohibit-password\n'
  file_change $id "$SSHD_DROPIN" 0644 "$content"; r=$?
  ((r == 2)) && { step_done $id failed write_failed "could not write $SSHD_DROPIN"; return 1; }
  if ((r == 1)); then step_done $id unchanged "" "already keys only (keys for: ${KEY_USERS[*]})"; return 0; fi
  if ((DRY)); then step_done $id planned "" "PasswordAuthentication no, $kkey no$([[ $prl == yes ]] && echo ', PermitRootLogin prohibit-password') (keys found for: ${KEY_USERS[*]})"; return 0; fi
  if ! sshd -t 2>/dev/null; then restore_one "$SSHD_DROPIN"; step_done $id failed sshd_test_failed "sshd -t failed; drop-in rolled back, ssh not reloaded"; return 1; fi
  eff=$(sshd -T 2>/dev/null) || eff=""
  if ! grep -qx 'passwordauthentication no' <<<"$eff" || ! kbd_effective_ok "$kmode" "$eff"; then
    restore_one "$SSHD_DROPIN"; step_done $id failed sshd_effective_mismatch "sshd -T does not show passwordauthentication no and ${kkey,,} no (another setting wins); rolled back"; return 1
  fi
  # the same per-user key check, on the NEW config, before ssh is reloaded
  for u in "${KEY_USERS[@]}"; do probe_user "$u" >/dev/null && still+="$u "; done
  if [[ -z $still ]]; then
    restore_one "$SSHD_DROPIN"; step_done $id failed sshd_effective_mismatch "with the new config nobody could log in with a key any more; drop-in rolled back, ssh not reloaded"; return 1
  fi
  if ! reload_ssh; then restore_one "$SSHD_DROPIN"; reload_ssh || true; step_done $id failed reload_failed "ssh reload failed; drop-in rolled back"; return 1; fi
  step_done $id applied "" "keys only via PasswordAuthentication no, $kkey no (keys found for: ${KEY_USERS[*]}); ssh reloaded, not restarted"
}

ufw_has() { ufw show added 2>/dev/null | grep -qF -- "$1"; }
step_ssh_rate_limit() {
  local id=ssh_rate_limit p ip f active=0 n_rules plan=() cmd pos return_fail=0 parts=()
  command -v ufw >/dev/null 2>&1 || { step_done $id skipped ufw_missing "ufw not installed (install.sh installs it)"; return 0; }
  ((${#SSH_PORT_ARR[@]})) || { step_done $id skipped ssh_port_unknown "could not detect the SSH port; ufw left alone"; return 0; }
  ufw status 2>/dev/null | grep -q '^Status: active' && active=1
  n_rules=$(ufw show added 2>/dev/null | grep -c '^ufw ' || true)
  # 1) SSH port(s) allowed before anything else; 2) admin IPs above the limit rule; 3) limit; 4) web ports; 5) enable
  for p in "${SSH_PORT_ARR[@]}"; do ufw_has "ufw allow $p/tcp" || ufw_has "ufw limit $p/tcp" || plan+=("allow $p/tcp"); done
  for ip in "${ALLOW_IPS[@]+"${ALLOW_IPS[@]}"}"; do for p in "${SSH_PORT_ARR[@]}"; do
    ufw_has "from $ip to any port $p proto tcp" || plan+=("allowfrom $ip $p")
  done; done
  for p in "${SSH_PORT_ARR[@]}"; do ufw_has "ufw limit $p/tcp" || plan+=("limit $p/tcp"); done
  if ((active == 0)); then plan+=("allow 80/tcp" "allow 443/tcp" "allow 443/udp" "enable"); fi
  if ((${#plan[@]} == 0)); then step_done $id unchanged "" "ufw active; limit on ${SSH_PORTS% }/tcp"; return 0; fi
  for cmd in "${plan[@]}"; do
    case "$cmd" in allowfrom*) read -r -a parts <<< "$cmd"; ch_add ufw "allow from ${parts[1]} to port ${parts[2]}/tcp (above limit)" add_rule ;;
      enable) ch_add ufw "default deny incoming, allow outgoing; enable" enable ;; *) ch_add ufw "$cmd" add_rule ;; esac
  done
  if ((DRY)); then step_done $id planned "" "ufw limit on SSH port(s) ${SSH_PORTS% }; ${#ALLOW_IPS[@]} admin IP(s) allowed above it"; return 0; fi
  note $id ufw_was "$( ((active)) && echo active || echo inactive)"
  for f in /etc/ufw/user.rules /etc/ufw/user6.rules /etc/default/ufw /etc/ufw/ufw.conf; do backup_file $id "$f"; done
  for cmd in "${plan[@]}"; do
    case "$cmd" in
      allowfrom*) read -r -a parts <<< "$cmd"
        # above the limit rule: position 1 for IPv4; first (v6) rule for IPv6 (ufw keeps v4 rules before v6 ones)
        pos=""; if ((n_rules > 0)); then
          if [[ ${parts[1]} == *:* ]]; then pos=$(ufw status numbered 2>/dev/null | awk -F'[][]' '/\(v6\)/{gsub(/ /,"",$2); print $2; exit}'); else pos=1; fi
        fi
        if [[ -n $pos ]]; then ufw insert "$pos" allow from "${parts[1]}" to any port "${parts[2]}" proto tcp comment f2c-harden-admin >/dev/null || return_fail=1
        else ufw allow from "${parts[1]}" to any port "${parts[2]}" proto tcp comment f2c-harden-admin >/dev/null || return_fail=1; fi
        n_rules=$((n_rules + 1)) ;;
      enable) { ufw default deny incoming && ufw default allow outgoing && ufw --force enable; } >/dev/null || return_fail=1 ;;
      *) read -r -a parts <<< "$cmd"; ufw "${parts[@]}" >/dev/null || return_fail=1; n_rules=$((n_rules + 1)) ;;
    esac
    ((return_fail)) && { step_done $id failed ufw_failed "ufw $cmd failed"; return 1; }
  done
  for p in "${SSH_PORT_ARR[@]}"; do ufw status 2>/dev/null | grep -Eq "^$p/tcp +LIMIT" || { step_done $id failed ufw_verify_failed "ufw shows no LIMIT rule for $p/tcp"; return 1; }; done
  step_done $id applied "" "ufw limit on SSH port(s) ${SSH_PORTS% }; ${#ALLOW_IPS[@]} admin IP(s) allowed above it"
}

SYSCTL_CONTENT='# f2c harden: network hardening (Docker-safe: ip_forward untouched, rp_filter loose)
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
vm.swappiness = 10
'
step_sysctl() {
  local id=sysctl r key cur
  if [[ -f $SYSCTL_FILE ]] && cmp -s "$SYSCTL_FILE" <(printf '%s' "$SYSCTL_CONTENT"); then step_done $id unchanged "" "already set"; return 0; fi
  if ((DRY == 0)); then
    # remember runtime values so a rollback can put them back
    while read -r key _ _; do [[ $key == [a-z]* ]] || continue; cur=$(sysctl -n "$key" 2>/dev/null) && [[ -z ${BACKED["sysctl:$key"]:-} ]] && { BACKED["sysctl:$key"]=1; note $id sysctl "$key" "$cur"; }; done <<< "$SYSCTL_CONTENT"
  fi
  file_change $id "$SYSCTL_FILE" 0644 "$SYSCTL_CONTENT"; r=$?
  ((r == 2)) && { step_done $id failed write_failed "could not write $SYSCTL_FILE"; return 1; }
  if ((r == 1)); then step_done $id unchanged "" "already set"; return 0; fi
  if ((DRY)); then step_done $id planned "" "syncookies, no redirects, no source routing, rp_filter=2, swappiness=10"; return 0; fi
  sysctl -q -e -p "$SYSCTL_FILE" >/dev/null 2>&1 || { step_done $id failed sysctl_failed "sysctl -p failed"; return 1; }
  step_done $id applied "" "syncookies, no redirects, no source routing, rp_filter=2, swappiness=10"
}

step_swap() {
  local id=swap avail_kb need_kb
  if [[ -n $(swapon --show --noheadings 2>/dev/null) ]]; then step_done $id unchanged swap_present "swap already active"; return 0; fi
  ((SWAP_GB > 0)) || { step_done $id skipped not_requested "swapGb=0"; return 0; }
  [[ -e $SWAPFILE ]] && { step_done $id skipped swapfile_exists "$SWAPFILE exists but is not active; left alone"; return 0; }
  avail_kb=$(df -Pk / | awk 'NR==2{print $4}'); need_kb=$(((SWAP_GB + 5) * 1024 * 1024))
  ((avail_kb >= need_kb)) || { step_done $id skipped swap_no_disk "needs ${SWAP_GB} GB + 5 GB free on /"; return 0; }
  ch_add swap "$SWAPFILE (${SWAP_GB}G)" create
  grep -q "^$SWAPFILE " /etc/fstab 2>/dev/null || ch_add file /etc/fstab replace "+$SWAPFILE none swap sw 0 0"
  if ((DRY)); then step_done $id planned "" "${SWAP_GB} GB swap file"; return 0; fi
  note $id swap "$SWAPFILE" created
  if ! { { run_bg fallocate -l "${SWAP_GB}G" "$SWAPFILE" || run_bg dd if=/dev/zero of="$SWAPFILE" bs=1M count=$((SWAP_GB * 1024)) status=none; } &&
    chmod 600 "$SWAPFILE" && mkswap "$SWAPFILE" >/dev/null && swapon "$SWAPFILE"; }; then
    step_done $id failed swap_failed "could not create swap"; return 1
  fi
  if ! grep -q "^$SWAPFILE " /etc/fstab; then backup_file $id /etc/fstab; echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab; fi
  step_done $id applied "" "${SWAP_GB} GB swap file"
}

step_time_sync() {
  local id=time_sync synced d
  synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  [[ $synced == yes ]] && { step_done $id unchanged "" "clock synchronized"; return 0; }
  for d in chrony chronyd ntp ntpd ntpsec openntpd systemd-timesyncd; do
    systemctl is-active --quiet "$d.service" && { step_done $id unchanged ntp_other_daemon "$d active, not synchronized yet"; return 0; }
  done
  systemctl cat systemd-timesyncd.service >/dev/null 2>&1 || { step_done $id skipped ntp_unavailable "no time-sync daemon installed"; return 0; }
  ch_add service systemd-timesyncd enable
  ((DRY)) && { step_done $id planned "" "timedatectl set-ntp true"; return 0; }
  note $id ntp "$(timedatectl show -p NTP --value 2>/dev/null || echo no)" x
  timedatectl set-ntp true || { step_done $id failed ntp_failed "timedatectl set-ntp true failed"; return 1; }
  step_done $id applied "" "systemd-timesyncd enabled"
}

step_journald() {
  local id=journald r
  file_change $id "$JOURNALD_FILE" 0644 $'# f2c harden: cap the systemd journal\n[Journal]\nSystemMaxUse=500M\nSystemKeepFree=1G\n'; r=$?
  ((r == 2)) && { step_done $id failed write_failed "could not write $JOURNALD_FILE"; return 1; }
  ((r == 1)) && { step_done $id unchanged "" "journal capped at 500M"; return 0; }
  step_note $id "The journald size cap applies fully after the next journald restart or reboot (harden.sh never restarts journald); the journal is vacuumed to 500M now."
  ((DRY)) && { step_done $id planned "" "journal capped at 500M, keeps 1G free"; return 0; }
  journalctl --vacuum-size=500M >/dev/null 2>&1 || true
  step_done $id applied "" "journal capped at 500M, keeps 1G free"
}

# ---------- rollback ----------
restore_one() { # path: restore from this run's backup (single-file undo inside a step)
  local line
  line=$(grep -E " file (existed|absent) $1\$" "$MANIFEST" | tail -1)
  case "$line" in *" file existed "*) cp -a -- "$BK/files$1" "$1" ;; *" file absent "*) rm -f -- "$1" ;; esac
}
ROLLED=""
do_rollback() { # backup dir; replays the manifest in reverse
  local dir=$1 step kind a b line ok=0
  local -a lines
  mapfile -t lines < <(tac "$dir/manifest")
  for line in "${lines[@]}"; do
    read -r step kind a b <<< "$line"
    case "$kind" in
      file) if [[ $a == existed ]]; then cp -a -- "$dir/files$b" "$b" || ok=1; else rm -f -- "$b"; fi ;;
      sysctl) sysctl -q -w "$a=$b" >/dev/null 2>&1 || true ;;
      swap) swapoff "$a" 2>/dev/null; rm -f -- "$a" ;;
      ntp) [[ $a == no ]] && timedatectl set-ntp false 2>/dev/null ;;
      ufw_was) [[ $a == inactive ]] && ufw --force disable >/dev/null 2>&1 ;;
      pkg) [[ $a == fail2ban ]] && systemctl disable --now fail2ban.service >/dev/null 2>&1 ;;
      svc) case "${b%%,*}" in enabled) systemctl enable "$a" >/dev/null 2>&1 ;; *) systemctl disable "$a" >/dev/null 2>&1 ;; esac
           case "${b##*,}" in active) systemctl start "$a" >/dev/null 2>&1 ;; *) systemctl stop "$a" >/dev/null 2>&1 ;; esac ;;
    esac
    [[ " $ROLLED " == *" $step "* ]] || ROLLED+="$step "
  done
  ufw status 2>/dev/null | grep -q '^Status: active' && { ufw reload >/dev/null 2>&1 || ok=1; }
  reload_ssh || ok=1
  systemctl is-active --quiet fail2ban.service && { fail2ban-client reload >/dev/null 2>&1 || true; }
  touch "$dir/rolled_back"
  return $ok
}

# rollback_checks DIR: after do_rollback, prove it worked; adds a rollback_verified post-check, 0 = verified
rollback_checks() {
  local dir=$1 step kind a b bad="" ufw_want="" cur p
  while read -r step kind a b; do
    case $kind in
      file) if [[ $a == existed ]]; then cmp -s -- "$dir/files$b" "$b" || bad+="$b differs from backup; "
            else [[ ! -e $b ]] || bad+="$b still present; "; fi ;;
      ufw_was) ufw_want=$a ;;
    esac
  done < "$dir/manifest"
  if [[ -n $ufw_want ]]; then
    cur=inactive; ufw status 2>/dev/null | grep -q '^Status: active' && cur=active
    [[ $cur == "$ufw_want" ]] || bad+="ufw is $cur, was $ufw_want; "
  fi
  if ! sshd -t 2>/dev/null; then
    # emergency: our drop-in is the one thing we may always remove (it never existed before f2c)
    if [[ -f $SSHD_DROPIN ]]; then rm -f -- "$SSHD_DROPIN"; reload_ssh || true; fi
    sshd -t 2>/dev/null || bad+="sshd -t fails; "
  fi
  for p in "${SSH_PORT_ARR[@]+"${SSH_PORT_ARR[@]}"}"; do
    ss -Htln 2>/dev/null | awk '{print $4}' | grep -Eq ":$p\$" || bad+="ssh not listening on $p; "
  done
  if [[ -z $bad ]]; then check_add post rollback_verified true "every file and the ufw state match the backup; sshd -t ok; ssh listening"; return 0; fi
  check_add post rollback_verified false "${bad%; }"
  return 1
}
checks_summary() { local c n=0 bad=0; for c in "$@"; do n=$((n + 1)); [[ $c == *'"ok":false'* ]] && bad=$((bad + 1)); done; echo "$n checks, $bad failed"; }
# recover_inflight WHY: an apply died without finishing (marker left): roll its backup back, verify, write its result
recover_inflight() {
  local why=$1 rid bk rdir extra
  read -r rid bk rdir extra < "$INFLIGHT" || { rm -f -- "$INFLIGHT"; return 0; }
  if ! valid_run_id "$rid" || [[ $bk != "$BACKUPS"/* || $bk == *..* || ! -f $bk/manifest || -n $extra ]]; then
    audit recover "" skipped "in-flight marker unusable; removed"; rm -f -- "$INFLIGHT"; return 0
  fi
  (recover_run "$rid" "$bk" "$rdir" "$why")
  rm -f -- "$INFLIGHT"
}
recover_run() { # only ever called in a subshell: it takes over the run globals of the dead run
  local why=$4 st msg r bk=$2
  RUN_ID=$1 MODE=apply BK=$2 MANIFEST=$2/manifest DONE=1 AUDIT=() CHECKS_POST=() ROLLED=""
  if [[ $3 == - ]]; then RESULT_DIR=""; else RESULT_DIR=$3; fi
  {
    st=rolled_back msg="harden_interrupted: harden.sh stopped before it finished ($why)"
    audit rollback_start "" "" "$msg; backup ${bk##*/}"
    if [[ -e $bk/rolled_back ]]; then msg+="; already rolled back"
    elif do_rollback "$bk" && rollback_checks "$bk"; then msg+="; all changes rolled back"
    else st=failed msg+="; rollback finished with errors (backup ${bk##*/})"; fi
    audit rollback "" "$st" "$msg"
    audit outcome "" "$st" "$msg"
    if [[ -n $RESULT_DIR && ! -f $RESULT_DIR/$RUN_ID.json ]]; then
      r=$(min_result_json "$st" "$msg" "${bk##*/}")
      r=${r/'"postchecks":[]'/"\"postchecks\":$(json_join "${CHECKS_POST[@]+"${CHECKS_POST[@]}"}")"}
      write_result_json "$r"
    fi
  }
}

# ---------- result ----------
emit_result() {
  local s steps_json=() ports_json mode_json RESULT
  audit outcome "" "$STATUS" "$MESSAGE${BACKUP_OUT:+ (backup $BACKUP_OUT)}"
  for s in "${STEP_IDS[@]}"; do steps_json+=("$(step_json "$s")"); done
  ports_json=$(json_join "${SSH_PORT_ARR[@]+"${SSH_PORT_ARR[@]}"}")
  mode_json=${MODE/-/_}
  RESULT=$(printf '{"version":1,"id":%s,"mode":%s,"status":%s,"message":%s,"startedAt":%s,"finishedAt":%s,"backupId":%s,"sshKeysPresent":%s,"sshPorts":%s,"warnings":%s,"prechecks":%s,"postchecks":%s,"steps":%s,"audit":%s}' \
    "$(json_str "$RUN_ID")" "$(json_str "$mode_json")" "$(json_str "$STATUS")" "$(json_str "$MESSAGE")" "$(json_str "$STARTED")" \
    "$(json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" "$([[ -n $BACKUP_OUT ]] && json_str "$BACKUP_OUT" || echo null)" \
    "$([[ -n $KEYS_NOTE ]] && echo null || echo "$KEYS_PRESENT")" "$ports_json" "$(warnings_json)" \
    "$(json_join "${CHECKS_PRE[@]+"${CHECKS_PRE[@]}"}")" "$(json_join "${CHECKS_POST[@]+"${CHECKS_POST[@]}"}")" "$(json_join "${steps_json[@]}")" \
    "$(json_join "${AUDIT[@]+"${AUDIT[@]}"}")")
  DONE=1
  printf '%s\n' "$RESULT"
  # root-owned results dir (installer: 0750 root:f2c-agent); never written into an agent-controlled path
  write_result_json "$RESULT"
}
# systemd timeout / stop / Ctrl-C: stop the running child, undo what this run changed, verify, report.
# Children run in the background (run_bg), so this runs at once, not after apt-get finishes.
on_term() {
  local i
  trap - TERM INT
  audit signal "" "" "SIGTERM/SIGINT"
  if [[ -n $CHILD ]]; then
    kill -TERM "$CHILD" 2>/dev/null
    for ((i = 0; i < 30; i++)); do kill -0 "$CHILD" 2>/dev/null || break; sleep 1; done
    kill -KILL "$CHILD" 2>/dev/null; CHILD=""
  fi
  if [[ $MODE == apply && -n $BK && -s $MANIFEST && ! -e $BK/rolled_back ]]; then
    audit rollback_start "" "" "interrupted; backup $(basename "$BK")"
    if do_rollback "$BK" && rollback_checks "$BK"; then STATUS=rolled_back; else STATUS=failed; fi
    MESSAGE="harden_interrupted: interrupted (timeout or signal); rollback ${STATUS/rolled_back/done}"; BACKUP_OUT=$(basename "$BK")
    MESSAGE=${MESSAGE/rollback failed/rollback finished with errors}
    audit rollback "" "$STATUS" "$MESSAGE"
  else STATUS=failed MESSAGE="harden_interrupted: interrupted (timeout or signal)"; fi
  [[ -n $BK ]] && rm -f -- "$INFLIGHT"
  emit_result; exit 4
}
trap on_term TERM INT

# ---------- main ----------
STATUS=succeeded MESSAGE="" BACKUP_OUT=""
if [[ $MODE == stop-post ]]; then
  # ExecStopPost: runs after every stop of f2c-harden.service. Normally nothing is in flight; after a kill (timeout
  # SIGKILL, OOM, crash) the marker is still there: roll back, verify, write that run's result.
  if ((LOCKED)) && [[ -f $INFLIGHT ]]; then recover_inflight "systemd result ${SERVICE_RESULT:-unknown}"; fi
  DONE=1
  exit 0
fi
audit start "" "" "dry_run=$DRY ssh_keys_only=$SSH_KEYS_ONLY swap_gb=$SWAP_GB allow_ips=${#ALLOW_IPS[@]}${BACKUP_ID:+ backup=$BACKUP_ID}"
if ((LOCKED)) && [[ -f $INFLIGHT ]]; then recover_inflight "found at the start of run $RUN_ID"; fi
if ((LOCKED == 0)); then
  STATUS=failed MESSAGE="harden_running: another harden run holds the lock; nothing changed"
  for s in "${STEP_IDS[@]}"; do step_done "$s" skipped harden_running "another run in progress"; done
elif [[ $MODE == rollback ]]; then
  if [[ $BACKUP_ID == last ]]; then BACKUP_ID=$(find "$BACKUPS" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*-[0-9]*' -printf '%f\n' 2>/dev/null | sort | tail -1); fi
  dir="$BACKUPS/$BACKUP_ID"
  if [[ -z $BACKUP_ID || ! -f $dir/manifest ]]; then STATUS=failed MESSAGE="harden_nothing_to_rollback: no backup ${BACKUP_ID:-found}"
  elif [[ -e $dir/rolled_back ]]; then MESSAGE="backup $BACKUP_ID was already rolled back"; BACKUP_OUT=$BACKUP_ID
  else
    run_checks pre
    audit rollback_start "" "" "backup $BACKUP_ID"
    if do_rollback "$dir" && rollback_checks "$dir"; then MESSAGE="restored from backup $BACKUP_ID"; else STATUS=failed MESSAGE="rollback of $BACKUP_ID finished with errors"; fi
    audit rollback "" "$STATUS" "$MESSAGE"
    BACKUP_OUT=$BACKUP_ID
    run_checks post
    checks_ok "${CHECKS_POST[@]}" || { STATUS=failed; MESSAGE+="; post-check failed"; }
  fi
  for s in "${STEP_IDS[@]}"; do
    if [[ " $ROLLED " == *" $s "* ]]; then step_done "$s" rolled_back "" "restored"; else step_done "$s" unchanged "" "nothing to restore"; fi
  done
else
  run_checks pre
  audit precheck "" "$(checks_ok "${CHECKS_PRE[@]}" && echo ok || echo failed)" "$(checks_summary "${CHECKS_PRE[@]}")"
  if ! checks_ok "${CHECKS_PRE[@]}"; then
    STATUS=failed MESSAGE="pre-check failed; nothing changed"
    for s in "${STEP_IDS[@]}"; do step_done "$s" skipped precheck_failed "pre-check failed"; done
  else
    ((DRY)) || new_backup
    failed_step="" START_S=$(date +%s)
    for s in "${STEP_IDS[@]}"; do
      if [[ -n $failed_step ]]; then step_done "$s" skipped earlier_step_failed "not run: $failed_step failed"; continue; fi
      if ((DRY == 0 && $(date +%s) - START_S > HARDEN_BUDGET_S)); then
        step_done "$s" skipped time_budget "not run: the ${HARDEN_BUDGET_S}s time budget is used up"; failed_step=time_budget; continue
      fi
      "step_$s" || failed_step=$s
    done
    if ((DRY)); then MESSAGE="dry run: nothing changed"
    else
      if [[ $failed_step == time_budget ]]; then MESSAGE="harden_timeout: the steps took longer than ${HARDEN_BUDGET_S}s"
      elif [[ -n $failed_step ]]; then MESSAGE="$failed_step failed"
      else
        run_checks post
        audit postcheck "" "$(checks_ok "${CHECKS_POST[@]}" && echo ok || echo failed)" "$(checks_summary "${CHECKS_POST[@]}")"
        checks_ok "${CHECKS_POST[@]}" || MESSAGE="post-check failed"
      fi
      if [[ -n $MESSAGE ]]; then
        audit rollback_start "" "" "$MESSAGE; backup $(basename "$BK")"
        if do_rollback "$BK" && rollback_checks "$BK"; then STATUS=rolled_back MESSAGE+="; all changes rolled back"
        else STATUS=failed MESSAGE+="; rollback finished with errors (backup $(basename "$BK"))"; fi
        audit rollback "" "$STATUS" "$MESSAGE"
        for s in "${STEP_IDS[@]}"; do [[ " $ROLLED " == *" $s "* && ${STEP_STATUS[$s]} == applied ]] && STEP_STATUS[$s]=rolled_back; done
        BACKUP_OUT=$(basename "$BK")
      elif [[ -s $MANIFEST ]]; then BACKUP_OUT=$(basename "$BK"); MESSAGE="hardened; backup $BACKUP_OUT"
      else rm -rf -- "$BK"; MESSAGE="already hardened; nothing changed"; fi
      rm -f -- "$INFLIGHT"
    fi
  fi
fi

emit_result
[[ $STATUS == succeeded ]]
