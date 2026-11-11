# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: mac — SELinux (rhel; suse where shipped) or AppArmor (debian; suse 15).
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

SELINUX_CONFIG=/etc/selinux/config

# selinux | apparmor
mac_kind() {
  case $OS_FAMILY in
    rhel) echo selinux ;;
    debian) echo apparmor ;;
    suse) if [[ -f $SELINUX_CONFIG ]] && command -v getenforce >/dev/null 2>&1; then echo selinux; else echo apparmor; fi ;;
  esac
}

mac_apparmor_pkgs() {
  if [[ $OS_FAMILY == suse ]]; then echo "apparmor-parser apparmor-utils"; else echo "apparmor apparmor-utils"; fi
}

selinux_mode() { getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo disabled; }

selinux_render_config() { # mode
  if [[ -f $SELINUX_CONFIG ]] && grep -qE '^[[:space:]]*SELINUX=' "$SELINUX_CONFIG"; then
    sed -E "s/^[[:space:]]*SELINUX=.*/SELINUX=$1/" "$SELINUX_CONFIG"
  else
    { [[ -f $SELINUX_CONFIG ]] && cat "$SELINUX_CONFIG"; true; }
    echo "SELINUX=$1"
  fi
}

selinux_recent_denials() {
  local out
  command -v ausearch >/dev/null 2>&1 || return 1
  out=$(ausearch -m avc -ts today 2>/dev/null || true)
  [[ $out == *"type=AVC"* ]]
}

apply_mac_selinux() {
  local mode
  command -v getenforce >/dev/null 2>&1 || { mark_warn "SELinux tools not installed"; mark_skip "no SELinux tooling"; return 0; }
  mode=$(selinux_mode)
  case $mode in
    disabled)
      install_content "$SELINUX_CONFIG" 0644 root:root "$(selinux_render_config permissive)"
      mark_warn "SELinux is disabled: set permissive for next boot (expect a full relabel; reboot, review AVCs, re-run)" ;;
    permissive)
      if selinux_recent_denials && ! is_true "$HARDEN_SELINUX_FORCE"; then
        mark_warn "SELinux permissive with AVC denials today: staying permissive (fix them or set HARDEN_SELINUX_FORCE=true)"
        return 0
      fi
      mark_changed "setenforce 1"
      run setenforce 1
      install_content "$SELINUX_CONFIG" 0644 root:root "$(selinux_render_config enforcing)" ;;
    enforcing)
      install_content "$SELINUX_CONFIG" 0644 root:root "$(selinux_render_config enforcing)" ;;
  esac
}

apply_mac_apparmor() {
  local -a pkgs
  read -r -a pkgs <<<"$(mac_apparmor_pkgs)"
  ensure_packages "${pkgs[@]}" || mark_warn "AppArmor package install failed"
  if [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo N) != Y ]]; then
    mark_warn "AppArmor is not enabled in the kernel (boot parameter apparmor=1 security=apparmor needed)"
  fi
  if unit_exists apparmor.service; then ensure_unit_enabled_now apparmor.service
  elif [[ $LH_MODE != check ]]; then mark_warn "apparmor.service not found"; fi
}

apply_mac() {
  if [[ $(mac_kind) == selinux ]]; then apply_mac_selinux; else apply_mac_apparmor; fi
}

audit_mac() {
  local mode cfg
  if [[ $(mac_kind) == selinux ]]; then
    command -v getenforce >/dev/null 2>&1 || { audit_fail "SELinux tooling installed"; return 0; }
    mode=$(selinux_mode)
    cfg=$(awk -F= '/^[[:space:]]*SELINUX=/{v=$2} END{print v}' "$SELINUX_CONFIG" 2>/dev/null || true)
    if [[ $mode == enforcing ]]; then audit_pass "SELinux enforcing"
    elif [[ $mode == permissive ]] && selinux_recent_denials && ! is_true "$HARDEN_SELINUX_FORCE"; then
      audit_fail "SELinux enforcing (permissive: AVC denials today)"
    else audit_fail "SELinux enforcing (is $mode)"; fi
    if [[ $cfg == enforcing ]]; then audit_pass "$SELINUX_CONFIG SELINUX=enforcing"; else audit_fail "$SELINUX_CONFIG SELINUX=enforcing (is ${cfg:-unset})"; fi
  else
    local p; for p in $(mac_apparmor_pkgs); do audit_check "package $p installed" pkg_installed "$p"; done
    if [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo N) == Y ]]; then audit_pass "AppArmor enabled in kernel"; else audit_fail "AppArmor enabled in kernel"; fi
    audit_check "apparmor.service enabled" systemctl is-enabled --quiet apparmor.service
  fi
}
