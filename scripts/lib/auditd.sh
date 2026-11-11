# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: auditd — /etc/audit/rules.d/99-hardening.rules from data/audit.rules.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

AUDIT_RULES_DIR=/etc/audit/rules.d
AUDIT_FILE="$AUDIT_RULES_DIR/99-hardening.rules"

auditd_render() {
  local line path parent arches=(b64)
  [[ $ARCH == x86_64 ]] && arches+=(b32)
  echo "## Managed by linux-hardening (from data/audit.rules)."
  while IFS= read -r line; do
    line=${line//auid!=unset/auid!=4294967295}
    if [[ $line =~ ^-w[[:space:]]+([^[:space:]]+) ]]; then
      path=${BASH_REMATCH[1]}
      if [[ $path == */ ]]; then
        # directory watch: auditctl needs the directory itself
        [[ -d $path ]] || continue
      else
        # file watch: the file or its parent directory must exist
        parent=$(dirname "$path")
        [[ -e $path || -d $parent ]] || continue
      fi
    fi
    if [[ $line == *ARCH* ]]; then
      local a
      for a in "${arches[@]}"; do printf '%s\n' "${line//ARCH/$a}"; done
    else
      printf '%s\n' "$line"
    fi
  done < <(data_lines audit.rules)
  if is_true "$HARDEN_AUDIT_IMMUTABLE"; then echo "-e 2"; fi
  return 0
}

# Other rules.d files with an uncommented "-a task,never".
auditd_task_never_files() {
  local f
  for f in "$AUDIT_RULES_DIR"/*.rules; do
    [[ -f $f && $f != "$AUDIT_FILE" ]] || continue
    grep -qE '^[[:space:]]*-a[[:space:]]+(task,never|never,task)' "$f" && echo "$f"
  done
  return 0
}

apply_auditd() {
  local f
  command -v augenrules >/dev/null 2>&1 || { mark_warn "auditd not installed"; mark_skip "auditd not installed"; return 0; }
  local changed=0
  while IFS= read -r f; do
    [[ -z $f ]] && continue
    if is_true "$HARDEN_AUDIT_FIX_TASK_NEVER"; then
      install_content "$f" "$(stat -c '%a' "$f")" root:root "$(sed -E 's/^([[:space:]]*-a[[:space:]]+(task,never|never,task))/# disabled by linux-hardening: \1/' "$f")"
      (( INSTALL_CHANGED )) && changed=1
    else
      mark_warn "$f contains '-a task,never': syscall audit rules are disabled (set HARDEN_AUDIT_FIX_TASK_NEVER=true to comment it out)"
    fi
  done < <(auditd_task_never_files)

  install_content "$AUDIT_FILE" 0640 root:root "$(auditd_render)"
  (( INSTALL_CHANGED )) && changed=1

  ensure_unit_enabled_now auditd
  if (( changed )) && [[ $LH_MODE == apply ]]; then
    local st; st=$(auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2}' || true)
    if [[ $st == 2 ]]; then
      mark_warn "audit rules are immutable (-e 2) in the running kernel: new rules load at next boot"
    elif ! augenrules --load >/dev/null 2>&1; then
      mark_warn "augenrules --load reported errors (check auditctl -l)"
    else
      mark_changed "loaded audit rules (augenrules --load)"
    fi
  fi
}

audit_auditd() {
  local f
  command -v auditctl >/dev/null 2>&1 || { audit_fail "auditd installed"; return 0; }
  audit_content "$AUDIT_FILE" "$(auditd_render)"
  audit_check "auditd enabled" systemctl is-enabled --quiet auditd
  audit_check "auditd active" systemctl is-active --quiet auditd
  local loaded; loaded=$(auditctl -l 2>/dev/null || true)
  if [[ $loaded == *"-k identity"* || $loaded == *"key=identity"* ]]; then audit_pass "hardening audit rules loaded"; else audit_fail "hardening audit rules loaded"; fi
  if is_true "$HARDEN_AUDIT_IMMUTABLE"; then
    if [[ $(auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2}') == 2 ]]; then audit_pass "audit config immutable"; else audit_fail "audit config immutable"; fi
  fi
  while IFS= read -r f; do
    [[ -n $f ]] && audit_fail "no '-a task,never' in $f"
  done < <(auditd_task_never_files)
}
