#!/usr/bin/env bash
# Smoke test: harden a systemd container, re-run for idempotence, then audit.
# Usage: tests/container/run.sh <base-image> [shell|ansible]
# Containers can't exercise everything (kernel sysctls, modules, auditd,
# SELinux); exit code 2 (warnings) is accepted, 1 (error) is not.
set -euo pipefail

base=${1:?base image}
mode=${2:-shell}
root=$(cd "$(dirname "$0")/../.." && pwd)
tag="lh-test:$(echo "$base" | tr '/:' '--')"
name="lh-$(echo "$base" | tr '/:.' '---')-$mode"

docker build -q --build-arg BASE="$base" -t "$tag" "$root/tests/container" >/dev/null
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "$root":/opt/linux-hardening:ro \
  "$tag" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

# Wait for systemd to come up.
for _ in $(seq 60); do
  state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
  [[ $state == running || $state == degraded ]] && break
  sleep 1
done

run() {
  local rc=0
  docker exec "$name" "$@" || rc=$?
  if (( rc != 0 && rc != 2 )); then
    echo "FAIL ($rc): $*" >&2
    exit 1
  fi
  return 0
}

# Containers can't load audit rules, kernel modules or most sysctls, so audit
# failures are printed for review but not fatal here; VM tests gate on them.
audit() {
  docker exec "$name" /opt/linux-hardening/scripts/harden.sh --audit 2>&1 \
    | sed -n '/^GROUP/,$p' || true
}

if [[ $mode == shell ]]; then
  run /opt/linux-hardening/scripts/harden.sh --yes
  out=$(docker exec "$name" /opt/linux-hardening/scripts/harden.sh --yes 2>&1 || true)
  echo "$out" | tail -25
  # sysctl/mac/auditd can't converge in a container (read-only /proc/sys,
  # no LSM, no audit netlink), so they're excluded from the idempotence check.
  if echo "$out" | grep -E '^[a-z0-9_]+ +changed \(' | grep -Evq '^(sysctl|mac|auditd) '; then
    echo "FAIL: second run was not idempotent" >&2
    exit 1
  fi
  audit
else
  # Leap 15.6 ships python 3.6; the image adds python3.11 for ansible-core.
  py=$(docker exec "$name" sh -c 'command -v python3.11 || command -v python3')
  docker exec "$name" sh -c "command -v ansible-playbook >/dev/null || $py -m pip install -q ansible-core 2>/dev/null || $py -m pip install -q --break-system-packages ansible-core"
  pb="ansible-playbook -i localhost, -c local -e ansible_python_interpreter=$py /opt/linux-hardening/ansible/site.yml"
  docker exec -e ANSIBLE_CONFIG=/opt/linux-hardening/ansible/ansible.cfg "$name" sh -c "$pb"
  out=$(docker exec -e ANSIBLE_CONFIG=/opt/linux-hardening/ansible/ansible.cfg "$name" sh -c "$pb" 2>&1)
  echo "$out" | grep -E '^(TASK|changed)' | grep -B1 '^changed' || true
  echo "$out" | tail -20
  echo "$out" | grep -Eq 'changed=0 ' || { echo "FAIL: ansible not idempotent" >&2; exit 1; }
  # Cross-check: shell audit against the Ansible-hardened host.
  audit
fi
echo "PASS: $base ($mode)"
