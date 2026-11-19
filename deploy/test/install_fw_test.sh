#!/bin/sh
# Unit tests for install.sh's firewall helpers (which ports default-deny would block, which of our rules are missing).
# Uses fake `ss -Htuln` and `ufw show added` output; changes nothing: install.sh is sourced with F2C_INSTALL_LIB=1,
# which stops before argument parsing or any host change. POSIX sh.
# Run: sh deploy/test/install_fw_test.sh   (also run by `go test` via harden_script_test.go)
here=$(cd "$(dirname "$0")" && pwd)
export F2C_INSTALL_LIB=1
# shellcheck source=/dev/null
. "$here/../install.sh"
set +eu

N=0 FAILS=0
eq() { # name want got
  N=$((N + 1))
  if [ "$2" != "$3" ]; then FAILS=$((FAILS + 1)); printf 'FAIL %s\n  want: %s\n  got:  %s\n' "$1" "$2" "$3"; fi
}

SS='tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      4096            [::]:22            [::]:*
tcp   LISTEN 0      4096       127.0.0.1:2019       0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      511                *:80               *:*
tcp   LISTEN 0      511                *:443              *:*
udp   UNCONN 0      0                  *:443              *:*
tcp   LISTEN 0      244          0.0.0.0:5432       0.0.0.0:*
tcp   LISTEN 0      244            [::1]:6379          [::]:*
tcp   LISTEN 0      4096   [::ffff:127.0.0.1]:9000     *:*
tcp   LISTEN 0      128         10.0.0.5:8080       0.0.0.0:*
udp   UNCONN 0      0       10.0.0.5%eth0:68        0.0.0.0:*
udp   UNCONN 0      0     [fe80::1%eth0]:546           [::]:*
udp   UNCONN 0      0            0.0.0.0:51820      0.0.0.0:*
udp   UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*'
eq listen "22/tcp 80/tcp 443/tcp 443/udp 5432/tcp 8080/tcp 51820/udp" "$(words "$(printf '%s\n' "$SS" | fw_listen)")"
LISTEN=$(printf '%s\n' "$SS" | fw_listen)
OURS="22/tcp 80/tcp 443/tcp 443/udp"

# fresh host: no rules -> everything not ours would be blocked; all our rules are missing
eq fresh-blocked "5432/tcp 8080/tcp 51820/udp" "$(words "$(fw_blocked "$LISTEN" "" "$OURS")")"
eq fresh-add "22/tcp 80/tcp 443/tcp 443/udp" "$(words "$(fw_uncovered "" "$OURS" any)")"

ADDED="Added user rules (see 'ufw status' for running firewall):
ufw allow 22/tcp
ufw allow from 10.0.0.0/8 to any port 5432 proto tcp
ufw allow 51820/udp comment 'wireguard'
ufw allow 'Nginx Full'
ufw deny 8080/tcp
ufw allow out 25/tcp"
RULES=$(printf '%s\n' "$ADDED" | fw_rules)
eq rules "22 22 tcp any|5432 5432 tcp restricted|51820 51820 udp any|80 80 tcp any|443 443 tcp any" "$(printf '%s\n' "$RULES" | tr '\n' '|' | sed 's/|$//')"
# restricted 5432 still counts as the operator's choice; deny 8080 does not open it -> 8080 listed
eq existing-blocked "8080/tcp" "$(words "$(fw_blocked "$LISTEN" "$RULES" "$OURS")")"
eq existing-add "443/udp" "$(words "$(fw_uncovered "$RULES" "$OURS" any)")"

# an admin-IP-only SSH rule (harden.sh) must NOT stop us adding SSH for everyone; a limit rule does
R2=$(printf '%s\n' "ufw allow from 203.0.113.7 to any port 22 proto tcp comment 'f2c-harden-admin'" | fw_rules)
eq ssh-admin-only "22/tcp" "$(words "$(fw_uncovered "$R2" "22/tcp" any)")"
eq ssh-admin-only-not-blocked "" "$(words "$(fw_blocked "22/tcp" "$R2" "")")"
R3=$(printf '%s\n' "ufw limit 22/tcp" | fw_rules)
eq ssh-limit "" "$(words "$(fw_uncovered "$R3" "22/tcp" any)")"

# forms: ranges, lists, no-proto, OpenSSH profile, source port, interface, source-only, dest address
R4=$(printf '%s\n' "ufw allow 3000:3010/tcp" "ufw allow 53" "ufw allow 60000,60001/udp" "ufw allow OpenSSH" \
  "ufw allow from any port 53 to any port 1000 proto udp" "ufw allow in on wg0 to any port 9100" \
  "ufw allow from 198.51.100.9" "ufw allow proto tcp from any to 10.0.0.5 port 8443" "ufw reject 23" | fw_rules)
eq forms "3000 3010 tcp any|53 53 any any|60000 60000 udp any|60001 60001 udp any|22 22 tcp any|1000 1000 udp restricted|9100 9100 any restricted|1 65535 any hostonly|8443 8443 tcp restricted" "$(printf '%s\n' "$R4" | tr '\n' '|' | sed 's/|$//')"
eq range-covers "" "$(words "$(fw_blocked "3005/tcp 53/udp 53/tcp 60001/udp" "$R4" "")")"
eq source-only-not-cover "7000/tcp" "$(words "$(fw_blocked "7000/tcp 8443/tcp 9100/udp" "$R4" "")")"
eq proto-mismatch "3005/udp" "$(words "$(fw_blocked "3005/udp" "$R4" "")")"
eq no-ports "" "$(words "$(fw_blocked "" "$R4" "$OURS")")"
eq none-rules "" "$(printf '%s\n' "Added user rules (see 'ufw status' for running firewall):" "(None)" | fw_rules)"

# /etc/default/ufw
eq pol-drop deny "$(printf 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n' | fw_policy INPUT)"
eq pol-out allow "$(printf 'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n' | fw_policy OUTPUT)"
eq pol-accept allow "$(printf 'DEFAULT_INPUT_POLICY="ACCEPT"\n' | fw_policy INPUT)"
eq pol-reject deny "$(printf "DEFAULT_INPUT_POLICY='REJECT'\n" | fw_policy INPUT)"
eq pol-unset "" "$(printf 'IPV6=yes\n' | fw_policy INPUT)"

# ask_yes never reads a "yes" from a non-terminal stdin (piped script). Skipped when a /dev/tty exists, where it
# would (correctly) wait for the operator.
if ! (: < /dev/tty) 2>/dev/null; then
  if echo yes | ask_yes "" 2>/dev/null; then eq ask-no-tty no yes; else eq ask-no-tty no no; fi
  if is_interactive; then eq interactive no yes; else eq interactive no no; fi
fi

echo "install_fw_test.sh: $N checks, $FAILS failed"
[ "$FAILS" = 0 ]
