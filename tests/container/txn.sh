#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2001  # ok/bad always return 0; sed indents multi-line output
# Self-test for the SSH/firewall rollback transaction (shell implementation).
# Usage: tests/container/txn.sh [base-image]   (default debian:12)
# Scenarios (each moves sshd to 2222, so a rollback is observable):
#   1. ssh rollback has fired (marker) -> --confirm must roll back firewall too
#   2. timers fire unconfirmed -> both rolled back, timers gone, next run not blocked
#   3. --yes, firewall fails after activation -> ssh rolled back as well
#   4. --yes refuses a port change without HARDEN_UNATTENDED_FORCE
set -euo pipefail

base=${1:-debian:12}
root=$(cd "$(dirname "$0")/../.." && pwd)
tag="lh-test:$(echo "$base" | tr '/:' '--')"
name="lh-txn-$(echo "$base" | tr '/:.' '---')"
H=/opt/linux-hardening/scripts/harden.sh
fails=0

docker build -q --build-arg BASE="$base" -t "$tag" "$root/tests/container" >/dev/null
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "$root":/opt/linux-hardening:ro \
  "$tag" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 60); do
  state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
  [[ $state == running || $state == degraded ]] && break
  sleep 1
done

x() { docker exec "$name" bash -c "$1"; }
ok() { echo "  ok:   $1"; }
bad() { echo "  FAIL: $1"; fails=$((fails + 1)); }
expect() { # description command
  if x "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi
}
sshd_port() { x "ss -Htln | awk '{print \$4}' | grep -Eo '[0-9]+\$' | sort -un | paste -sd' ' -"; }
fw_loaded() { x 'nft list table inet hardening >/dev/null 2>&1'; }
timers() { x "systemctl list-units --all --plain --no-legend 'hardening-rollback-*.timer' | awk '{print \$1}' | paste -sd' ' -"; }
# Interactive run (pty via script(1)), left waiting for --confirm.
start_interactive() {
  x "rm -f /root/inter.log; (script -qfc 'HARDEN_ROLLBACK_SECONDS=30 HARDEN_SSH_PORT=2222 $H --only ssh,firewall' /dev/null <<<y >/root/inter.log 2>&1 &)"
  for _ in $(seq 60); do
    [[ $(timers) == *ssh* && $(timers) == *firewall* ]] && return 0
    sleep 1
  done
  x 'cat /root/inter.log'; bad "rollback timers were not scheduled"; return 1
}
wait_interactive() { for _ in $(seq 90); do x 'pgrep -f "harden.sh --only" >/dev/null' || return 0; sleep 1; done; }
reset_state() {
  x "systemctl stop 'hardening-rollback-*.timer' >/dev/null 2>&1 || true; rm -rf /run/linux-hardening"
  x "rm -f /etc/ssh/sshd_config.d/00-hardening.conf /etc/nftables.d/hardening.nft; nft delete table inet hardening 2>/dev/null || true; systemctl restart ssh"
}

echo "== setup: install packages (nftables)"
x "$H --yes --only packages >/root/setup.log 2>&1" || { x 'tail -20 /root/setup.log'; exit 1; }
reset_state

echo "== 1. ssh rollback fired before --confirm -> firewall rolled back too"
start_interactive
[[ $(sshd_port) == *2222* ]] && fw_loaded && ok "changes active (sshd on 2222, nft table loaded)" || bad "changes active"
# Simulate the ssh timer having fired: marker present, timer gone.
x 'systemctl stop hardening-rollback-ssh.timer; touch /run/linux-hardening/rolledback-ssh'
out=$(x "$H --confirm" 2>&1) && bad "--confirm should exit 1" || ok "--confirm exited non-zero"
echo "$out" | sed 's/^/      /'
[[ $out == *"TOO LATE"*ssh* ]] && ok "reports ssh too late" || bad "reports ssh too late"
fw_loaded && bad "firewall table still loaded" || ok "firewall rolled back (table removed)"
[[ -z $(timers) ]] && ok "no rollback timers left" || bad "timers left: $(timers)"
expect "firewall confirmed marker absent" '! test -e /run/linux-hardening/confirmed-firewall'
wait_interactive
x 'grep -q "rolling back ALL pending" /root/inter.log' && ok "interactive run reported the transaction rollback" || { bad "interactive run report"; x 'tail -15 /root/inter.log'; }
reset_state

echo "== 2. no confirmation: timers fire -> both rolled back; next run not blocked"
start_interactive
for _ in $(seq 90); do
  x 'test -e /run/linux-hardening/rolledback-ssh && test -e /run/linux-hardening/rolledback-firewall' && break
  sleep 1
done
sleep 3
[[ $(sshd_port) == 22 ]] && ok "sshd back on 22" || bad "sshd ports: $(sshd_port)"
fw_loaded && bad "firewall table still loaded" || ok "firewall rolled back"
[[ -z $(timers) ]] && ok "fired timers are gone (RemainAfterElapse=no)" || bad "timers left: $(timers)"
expect "both rolledback markers" 'test -e /run/linux-hardening/rolledback-ssh && test -e /run/linux-hardening/rolledback-firewall'
wait_interactive
out=$(x "$H --check --only ssh 2>&1; $H --yes --only banner 2>&1" || true)
[[ $out == *"still pending"* ]] && bad "later run blocked by 'rollback still pending'" || ok "later run not blocked"
out=$(x "$H --confirm" 2>&1 || true)
[[ $out == *"TOO LATE"* ]] && ok "--confirm after firing says TOO LATE" || bad "--confirm after firing: $out"
reset_state

echo "== 3. --yes, firewall fails after activation -> ssh rolled back too"
x 'systemctl disable nftables >/dev/null 2>&1; systemctl mask nftables >/dev/null 2>&1'
out=$(x "HARDEN_UNATTENDED_FORCE=true HARDEN_SSH_PORT=2222 HARDEN_ROLLBACK_SECONDS=60 $H --yes --only ssh,firewall" 2>&1 || true)
echo "$out" | grep -E 'rolling back|verification failed|confirm|^ssh |^firewall ' | sed 's/^/      /'
[[ $(sshd_port) == 22 ]] && ok "sshd back on 22" || bad "sshd ports: $(sshd_port)"
fw_loaded && bad "firewall table still loaded" || ok "firewall rolled back"
[[ -z $(timers) ]] && ok "no rollback timers left" || bad "timers left: $(timers)"
x 'systemctl unmask nftables >/dev/null 2>&1'
reset_state

echo "== 4. --yes refuses a port change without HARDEN_UNATTENDED_FORCE"
out=$(x "HARDEN_SSH_PORT=2222 $H --yes --only ssh" 2>&1 || true)
[[ $out == *"refusing because the SSH port changes"* ]] && ok "refused" || bad "not refused"
[[ $(sshd_port) == 22 ]] && ok "sshd still on 22" || bad "sshd ports: $(sshd_port)"
expect "no drop-in written" '! test -e /etc/ssh/sshd_config.d/00-hardening.conf'

if (( fails )); then echo "FAIL: $fails check(s) failed ($base)"; exit 1; fi
echo "PASS: rollback transaction ($base)"
