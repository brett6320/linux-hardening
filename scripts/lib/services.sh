# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: services — disable+mask idle units from data/services.list, mask
# ctrl-alt-del.target, enable chrony. Never stops a running service.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

svc_chrony_unit() { if [[ $OS_FAMILY == debian ]]; then echo chrony.service; else echo chronyd.service; fi; }

_svc_busy() { # active, or its socket twin is active (masking would break activation)
  local u=$1 twin=""
  unit_active "$u" && return 0
  [[ $u == *.service ]] && twin="${u%.service}.socket"
  [[ -n $twin ]] && unit_active "$twin"
}

svc_mask() {
  local u=$1
  mark_changed "disable + mask $u"
  if [[ $LH_MODE == apply ]]; then
    lh_ensure_backup_dir
    echo "masked $CURRENT_GROUP $u" >>"$LH_BACKUP_DIR/manifest"
  fi
  run systemctl disable --quiet "$u" 2>/dev/null || true
  run systemctl mask --quiet "$u"
}

apply_services() {
  local u st chrony
  while IFS= read -r u; do
    unit_exists "$u" || continue
    st=$(unit_state "$u")
    [[ $st == masked ]] && continue
    if _svc_busy "$u"; then
      mark_warn "$u is active; not stopping it (disable it yourself if unused)"
      continue
    fi
    svc_mask "$u"
  done < <(data_lines services.list)

  if [[ $(unit_state ctrl-alt-del.target) != masked ]]; then svc_mask ctrl-alt-del.target; fi

  chrony=$(svc_chrony_unit)
  if unit_exists "$chrony"; then
    ensure_unit_enabled_now "$chrony"
  else
    mark_warn "chrony not installed ($chrony missing)"
  fi
}

audit_services() {
  local u st chrony
  while IFS= read -r u; do
    unit_exists "$u" || continue
    st=$(unit_state "$u")
    if [[ $st == masked ]]; then audit_pass "$u masked"
    elif unit_active "$u"; then audit_fail "$u masked (active; left running by design)"
    else audit_fail "$u masked (is $st)"; fi
  done < <(data_lines services.list)
  if [[ $(unit_state ctrl-alt-del.target) == masked ]]; then audit_pass "ctrl-alt-del.target masked"; else audit_fail "ctrl-alt-del.target masked"; fi
  chrony=$(svc_chrony_unit)
  audit_check "$chrony enabled" systemctl is-enabled --quiet "$chrony"
  audit_check "$chrony active" systemctl is-active --quiet "$chrony"
}
