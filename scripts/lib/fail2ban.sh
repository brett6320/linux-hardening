# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: fail2ban — sshd jail.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

F2B_JAIL=/etc/fail2ban/jail.d/99-hardening.local

f2b_render() {
  local banaction=firewallcmd-rich-rules ignore
  [[ $OS_FAMILY == debian ]] && banaction=nftables-multiport
  # shellcheck disable=SC2086  # word-splitting the space-separated lists is intended
  ignore=$(printf '%s\n' 127.0.0.1/8 ::1 $HARDEN_ADMIN_SOURCES $HARDEN_FAIL2BAN_IGNOREIP | awk 'NF && !seen[$0]++' | paste -sd' ' -)
  cat <<EOF
# Managed by linux-hardening.
[DEFAULT]
bantime = $HARDEN_FAIL2BAN_BANTIME
bantime.increment = true
findtime = 10m
maxretry = $HARDEN_FAIL2BAN_MAXRETRY
ignoreip = $ignore
backend = systemd
banaction = $banaction

[sshd]
enabled = true
port = $HARDEN_SSH_PORT
EOF
}

apply_fail2ban() {
  local err
  command -v fail2ban-client >/dev/null 2>&1 || { mark_warn "fail2ban not installed (see packages group)"; mark_skip "fail2ban not installed"; return 0; }
  if [[ $OS_FAMILY != debian ]] && ! unit_active firewalld && [[ $LH_MODE != check ]]; then
    mark_warn "firewalld not active: banaction firewallcmd-rich-rules will not work"
  fi
  install_content "$F2B_JAIL" 0644 root:root "$(f2b_render)"
  if (( INSTALL_CHANGED )) && [[ $LH_MODE == apply ]]; then
    if ! err=$(fail2ban-client -t 2>&1); then
      log_error "fail2ban-client -t: $err"
      restore_group_files_now fail2ban
      die_group "fail2ban configuration test failed; restored previous file"
    fi
    if unit_active fail2ban; then
      systemctl reload-or-restart fail2ban
      mark_changed "reloaded fail2ban"
    fi
  fi
  ensure_unit_enabled_now fail2ban
}

audit_fail2ban() {
  command -v fail2ban-client >/dev/null 2>&1 || { audit_fail "fail2ban installed"; return 0; }
  audit_content "$F2B_JAIL" "$(f2b_render)"
  audit_check "fail2ban enabled" systemctl is-enabled --quiet fail2ban
  audit_check "fail2ban active" systemctl is-active --quiet fail2ban
  audit_check "sshd jail running" fail2ban-client status sshd
}
