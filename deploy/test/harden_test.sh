#!/usr/bin/env bash
# Unit tests for the pure helpers in deploy/harden.sh (SSH key/lockout checks, fail2ban merge). Changes nothing on the
# host: harden.sh is sourced with F2C_HARDEN_LIB=1, which stops before anything stateful. Bash 3.2+ (macOS works).
# Run: bash deploy/test/harden_test.sh   (also run by `go test` via harden_script_test.go)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
F2C_HARDEN_LIB=1 source "$here/../harden.sh"
set +e

FAILS=0 N=0
eq() { # name want got
  N=$((N + 1))
  if [[ $2 != "$3" ]]; then FAILS=$((FAILS + 1)); printf 'FAIL %s\n  want: %s\n  got:  %s\n' "$1" "$2" "$3"; fi
}
ok() { N=$((N + 1)); if ! "${@:2}"; then FAILS=$((FAILS + 1)); echo "FAIL $1 (expected success)"; fi; }
no() { N=$((N + 1)); if "${@:2}"; then FAILS=$((FAILS + 1)); echo "FAIL $1 (expected failure)"; fi; }

K='AAAAC3NzaC1lZDI1NTE5AAAAIOnlyAFakeTestKeyNotARealOne0000000000000'
# --- authorized_keys line classification ---
eq plain usable "$(key_line_class "ssh-ed25519 $K me@laptop")"
eq rsa usable "$(key_line_class "ssh-rsa $K")"
eq leading-space usable "$(key_line_class "   ecdsa-sha2-nistp256 $K x")"
eq sk usable "$(key_line_class "sk-ssh-ed25519@openssh.com $K")"
eq from-ok usable "$(key_line_class "from=\"10.0.0.0/8\" ssh-ed25519 $K")"
eq restrict-pty usable "$(key_line_class "restrict,pty ssh-ed25519 $K")"
eq comment none "$(key_line_class "# ssh-ed25519 $K")"
eq blank none "$(key_line_class "")"
eq garbage none "$(key_line_class "hello world")"
eq no-base64 none "$(key_line_class "ssh-ed25519 notakey")"
eq forced restricted:forced_command "$(key_line_class "command=\"/usr/bin/backup\" ssh-ed25519 $K")"
eq forced-upper restricted:forced_command "$(key_line_class "no-port-forwarding,Command=\"x\" ssh-ed25519 $K")"
eq cloud-root restricted:login_message "$(key_line_class "no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command=\"echo 'Please login as the user \\\"ubuntu\\\" rather than the user \\\"root\\\".';echo;sleep 10;exit 142\" ssh-rsa $K")"
eq log-in-as restricted:login_message "$(key_line_class "command=\"echo Please log in as admin\" ssh-rsa $K")"
eq no-pty restricted:no_pty "$(key_line_class "no-pty ssh-ed25519 $K")"
eq restrict restricted:no_pty "$(key_line_class "restrict ssh-ed25519 $K")"
eq cert-authority restricted:cert_authority "$(key_line_class "cert-authority ssh-ed25519 $K")"
eq expiry restricted:expiry_time "$(key_line_class "expiry-time=\"20300101\" ssh-ed25519 $K")"

# --- AuthenticationMethods ---
ok am-empty authmethods_ok "port 22"
ok am-any authmethods_ok "authenticationmethods any"
ok am-pubkey authmethods_ok "authenticationmethods publickey"
ok am-alt authmethods_ok "authenticationmethods publickey,password publickey"
no am-2fa authmethods_ok "authenticationmethods publickey,keyboard-interactive"
no am-pw authmethods_ok "authenticationmethods password"

# --- Allow/Deny lists ---
eq list-none "" "$(user_list_verdict alice "alice sudo" "port 22")"
eq allow-user "" "$(user_list_verdict alice "alice" $'allowusers bob alice')"
eq allow-glob "" "$(user_list_verdict alice "alice" $'allowusers a*')"
eq allow-miss "not in AllowUsers" "$(user_list_verdict alice "alice" $'allowusers bob')"
eq allow-host-star "" "$(user_list_verdict alice "alice" $'allowusers alice@*')"
eq allow-host-addr "" "$(user_list_verdict alice "alice" $'allowusers alice@10.1.2.3' 10.1.2.3)"
eq allow-host-other "not in AllowUsers" "$(user_list_verdict alice "alice" $'allowusers alice@10.9.9.9' 10.1.2.3)"
eq allow-neg "not in AllowUsers" "$(user_list_verdict alice "alice" $'allowusers !alice')"
eq deny-user "denied by DenyUsers alice" "$(user_list_verdict alice "alice" $'denyusers alice')"
eq deny-host "denied by DenyUsers alice@10.0.0.1" "$(user_list_verdict alice "alice" $'denyusers alice@10.0.0.1' 192.0.2.1)"
eq deny-group "denied by DenyGroups sudo" "$(user_list_verdict alice "alice sudo" $'denygroups sudo')"
eq allow-group "" "$(user_list_verdict alice "alice sudo" $'allowgroups sudo')"
eq allow-group-miss "no group in AllowGroups" "$(user_list_verdict alice "alice" $'allowgroups sshusers')"

# --- AuthorizedKeysFile expansion ---
eq akf-default "/h/a/.ssh/authorized_keys
/h/a/.ssh/authorized_keys2" "$(akf_paths ".ssh/authorized_keys .ssh/authorized_keys2" alice /h/a 1000)"
eq akf-tokens "/etc/ssh/keys/alice
/etc/ssh/1000/k
/h/a/%h" "$(akf_paths "/etc/ssh/keys/%u /etc/ssh/%U/k %%h" alice /h/a 1000)"
eq akf-home "/h/a/k" "$(akf_paths "%h/k none" alice /h/a 1000)"
eq akf-none "" "$(akf_paths "none" alice /h/a 1000)"

# --- user_key_verdict with a real (temporary) home ---
me=$(id -un); tmp=$(mktemp -d); home="$tmp/home"
mkdir -m 0700 "$home" "$home/.ssh"
pw="$me:x:1000:1000::$home:/bin/bash"
EFF=$'pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nstrictmodes yes\nauthenticationmethods any'
eq ukv-nokey "unusable:no authorized key" "$(user_key_verdict "$pw" "$me" "$EFF")"
printf 'command="echo Please login as ubuntu" ssh-rsa %s\n' "$K" > "$home/.ssh/authorized_keys"; chmod 0600 "$home/.ssh/authorized_keys"
eq ukv-restricted "unusable:only restricted keys (login_message)" "$(user_key_verdict "$pw" "$me" "$EFF")"
printf 'ssh-ed25519 %s me\n' "$K" >> "$home/.ssh/authorized_keys"
eq ukv-usable usable "$(user_key_verdict "$pw" "$me" "$EFF")"
eq ukv-nologin unusable:no_login_shell "$(user_key_verdict "$me:x:1000:1000::$home:/usr/sbin/nologin" "$me" "$EFF")"
eq ukv-pubkey-off unusable:pubkey_disabled "$(user_key_verdict "$pw" "$me" "${EFF/pubkeyauthentication yes/pubkeyauthentication no}")"
eq ukv-2fa "unusable:AuthenticationMethods publickey,password needs more than a key" "$(user_key_verdict "$pw" "$me" "${EFF/authenticationmethods any/authenticationmethods publickey,password}")"
eq ukv-allow "unusable:not in AllowUsers" "$(user_key_verdict "$pw" "$me" "$EFF"$'\nallowusers someoneelse')"
eq ukv-akf-other "unusable:no authorized key" "$(user_key_verdict "$pw" "$me" "${EFF/.ssh\/authorized_keys .ssh\/authorized_keys2/\/nonexistent\/%u}")"
eq ukv-akc "unknown:keys only via AuthorizedKeysCommand (not checked)" "$(user_key_verdict "$pw" "$me" "${EFF/.ssh\/authorized_keys .ssh\/authorized_keys2/none}"$'\nauthorizedkeyscommand /usr/bin/fetch-keys %u')"
chmod 0775 "$home/.ssh"
eq ukv-strict "unusable:only restricted keys (unsafe_permissions)" "$(user_key_verdict "$pw" "$me" "$EFF")"
eq ukv-nostrict usable "$(user_key_verdict "$pw" "$me" "${EFF/strictmodes yes/strictmodes no}")"
chmod 0700 "$home/.ssh"
ln -s "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; mv "$home/.ssh/authorized_keys" "$tmp/real_keys"; ln -sf "$tmp/real_keys" "$home/.ssh/authorized_keys"
eq ukv-symlink "unusable:no authorized key" "$(user_key_verdict "$pw" "$me" "$EFF")"
rm -f "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"
printf 'ssh-ed25519 %s me\n' "$K" > "$home/.ssh/authorized_keys"; chmod 0600 "$home/.ssh/authorized_keys"
# root: PermitRootLogin
rpw="root:x:0:0::$home:/bin/bash"
if [[ $me == root ]]; then RE=$EFF; else RE=${EFF/strictmodes yes/strictmodes no}; fi
eq root-no unusable:root_login_no "$(user_key_verdict "$rpw" "root" "$RE"$'\npermitrootlogin no')"
eq root-fco unusable:root_login_forced-commands-only "$(user_key_verdict "$rpw" "root" "$RE"$'\npermitrootlogin forced-commands-only')"
eq root-pp usable "$(user_key_verdict "$rpw" "root" "$RE"$'\npermitrootlogin prohibit-password')"
eq root-yes usable "$(user_key_verdict "$rpw" "root" "$RE"$'\npermitrootlogin yes')"

# --- fail2ban: operator settings and merge ---
f="$tmp/f2b"; mkdir -p "$f/jail.d"
printf '[DEFAULT]\nbantime = 10m\nmaxretry = 5\n[sshd]\nport = ssh\n' > "$f/jail.conf"
no f2b-only-jailconf f2b_operator_sets "$f" bantime
printf '[sshd]\nenabled = true\n' > "$f/jail.d/defaults-debian.conf"
ok f2b-distro-enabled f2b_operator_sets "$f" enabled
no f2b-distro-bantime f2b_operator_sets "$f" bantime
printf '[DEFAULT]\n# bantime = 1d\nBanTime = 1d\n[nginx]\nmaxretry = 2\n' > "$f/jail.local"
ok f2b-local-bantime f2b_operator_sets "$f" bantime
no f2b-other-jail f2b_operator_sets "$f" maxretry
printf '[sshd]\nfindtime: 1h\n' > "$f/jail.d/ops.local"
ok f2b-colon f2b_operator_sets "$f" findtime
printf '[sshd]\nbackend = systemd\n' > "$f/jail.d/zz-f2c-harden.local"
no f2b-ours-ignored f2b_operator_sets "$f" backend
eq dropin-known "# f2c harden: sshd jail additions, read last (zz-). ignoreip is ADDED to the operator's list; the other
# options are set here only because the operator left them unset. Remove this file and reload fail2ban to undo.
[sshd]
ignoreip = %(known/ignoreip)s 127.0.0.1/8 ::1 203.0.113.5
backend = systemd
maxretry = 5" "$(f2b_dropin_content known "127.0.0.1/8 ::1 203.0.113.5" 22 "backend maxretry")"
eq dropin-explicit-all "[sshd]
enabled = true
ignoreip = 10.0.0.1 203.0.113.5
backend = systemd
port = 22,2222
maxretry = 5
findtime = 10m
bantime = 1h" "$(f2b_dropin_content explicit "10.0.0.1 203.0.113.5" 22,2222 "enabled backend port maxretry findtime bantime" | sed 1,2d)"
DUMP="['set', 'sshd', 'addlogpath', '/var/log/auth.log', 'head']
['set', 'sshd', 'addignoreip', '127.0.0.1/8', '::1', '10.0.0.0/8']
['set', 'nginx', 'addignoreip', '198.51.100.99']"
eq dump-parse "127.0.0.1/8 ::1 10.0.0.0/8" "$(parse_f2b_dump_ignoreip <<< "$DUMP" | tr '\n' ' ' | sed 's/ $//')"
GET="These IP addresses/networks are ignored:
|- 127.0.0.0/8
|- ::1
\`- 203.0.113.5"
eq get-parse "127.0.0.0/8 ::1 203.0.113.5" "$(parse_f2b_get_ignoreip <<< "$GET" | tr '\n' ' ' | sed 's/ $//')"
eq words-uniq "a b c" "$(words_uniq $'a  b\na c')"
eq words-missing "c" "$(words_missing "a b c" "b a")"
eq words-missing-none "" "$(words_missing "a" "a b")"
# 9.1: our ignoreip = loopback + --allow-ip + open SSH sessions; nothing else (no engine IPs)
eq ours-ignoreip "10.0.0.0/8 127.0.0.1/8 198.51.100.4 203.0.113.9 ::1" "$(f2b_our_ignoreip "203.0.113.9 198.51.100.4" 10.0.0.0/8 203.0.113.9)"
eq ours-ignoreip-min "127.0.0.1/8 ::1" "$(f2b_our_ignoreip "")"
# --- agent checks per mode: a rollback skips agent_active/agent_connected unless --rollback-agent-check ---
eq agentcheck-apply 1 "$(effective_agent_check apply 1 0)"
eq agentcheck-dryrun 1 "$(effective_agent_check dry-run 1 0)"
eq agentcheck-apply-skip 0 "$(effective_agent_check apply 0 0)"
eq agentcheck-apply-flag-ignored 1 "$(effective_agent_check apply 1 1)"
eq agentcheck-rollback-default 0 "$(effective_agent_check rollback 1 0)"
eq agentcheck-rollback-flag 1 "$(effective_agent_check rollback 1 1)"
eq agentcheck-rollback-flag-skip 0 "$(effective_agent_check rollback 0 1)"
# the CLI wiring, without root: harden.sh stops at "run as root" after the mode and the agent check are settled
if [[ $(id -u) != 0 ]]; then
  agentcheck_cli() { bash -x "$here/../harden.sh" "$@" 2>&1 | sed -n 's/^+ AGENT_CHECK=//p' | tail -1; }
  eq agentcheck-cli-rollback 0 "$(agentcheck_cli --rollback last)"
  eq agentcheck-cli-rollback-flag 1 "$(agentcheck_cli --rollback last --rollback-agent-check)"
  eq agentcheck-cli-apply 1 "$(agentcheck_cli --apply)"
  eq agentcheck-cli-apply-skip 0 "$(agentcheck_cli --apply --skip-agent-check)"
fi
# --- fail2ban ignoreip: compared by network, not text (fail2ban shows 127.0.0.1/8 as 127.0.0.0/8) ---
eq norm-v4-hostbits "127.0.0.0/8" "$(f2b_norm "127.0.0.1/8" | sed 's/ $//')"
eq norm-v4-same "127.0.0.0/8" "$(f2b_norm "127.0.0.0/8" | sed 's/ $//')"
eq norm-v4-host32 "203.0.113.5" "$(f2b_norm "203.0.113.5/32" | sed 's/ $//')"
eq norm-v4-bare "203.0.113.5" "$(f2b_norm "203.0.113.5" | sed 's/ $//')"
eq norm-v4-odd-prefix "10.1.0.0/20" "$(f2b_norm "10.1.15.200/20" | sed 's/ $//')"
eq norm-v4-zero "0.0.0.0/0" "$(f2b_norm "192.0.2.1/0" | sed 's/ $//')"
eq norm-v6-loop128 "::1" "$(f2b_norm "::1/128" | sed 's/ $//')"
eq norm-v6-loop "::1" "$(f2b_norm "::1" | sed 's/ $//')"
eq norm-v6-long "::1" "$(f2b_norm "0:0:0:0:0:0:0:1" | sed 's/ $//')"
eq norm-v6-case "2001:db8::/32" "$(f2b_norm "2001:DB8:0:0:0:0:0:1/32" | sed 's/ $//')"
eq norm-v6-hostbits "2001:db8:abcd:1200::/56" "$(f2b_norm "2001:db8:abcd:12ff::1/56" | sed 's/ $//')"
eq norm-v6-leading0 "2001:db8::1:0:0:1" "$(f2b_norm "2001:0db8:0000:0000:0001:0000:0000:0001" | sed 's/ $//')"
eq norm-v6-mapped "::ffff:c000:201" "$(f2b_norm "::ffff:192.0.2.1" | sed 's/ $//')"
eq norm-host "example.com" "$(f2b_norm "example.com" | sed 's/ $//')"
eq norm-bad-kept "300.1.1.1 fe80::1%eth0" "$(f2b_norm "300.1.1.1 fe80::1%eth0" | sed 's/ $//')"
eq norm-list "127.0.0.0/8 203.0.113.5 ::1" "$(f2b_norm "::1/128 127.0.0.1/8 203.0.113.5/32 127.0.0.0/8" | sed 's/ $//')"
# the harden check: what we configured vs what fail2ban-client shows (the false warning seen on Ubuntu 24.04)
eq norm-live-match "" "$(words_missing "$(f2b_norm "198.51.100.4 127.0.0.1/8 ::1")" "$(f2b_norm "$(parse_f2b_get_ignoreip <<< "$GET" | tr '\n' ' ') 198.51.100.4")")"
eq norm-live-miss "198.51.100.7" "$(words_missing "$(f2b_norm "198.51.100.7 127.0.0.1/8")" "$(f2b_norm "127.0.0.0/8 ::1")")"
eq json-str '"a\"b\\c\n"' "$(json_str $'a"b\\c\n')"

rm -rf -- "$tmp"
echo "harden_test.sh: $N checks, $FAILS failed"
((FAILS == 0))
