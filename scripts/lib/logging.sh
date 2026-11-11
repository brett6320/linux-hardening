# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: logging — persistent journald, rsyslog file mode.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

LOG_JOURNALD=/etc/systemd/journald.conf.d/99-hardening.conf
LOG_RSYSLOG=/etc/rsyslog.d/99-hardening.conf

log_render_journald() { printf '%s\n' "# Managed by linux-hardening." "[Journal]" "Storage=persistent" "Compress=yes" "SystemMaxUse=1G"; }
log_render_rsyslog() { printf '%s\n' "# Managed by linux-hardening." "\$FileCreateMode 0640"; }
log_rsyslog_installed() { command -v rsyslogd >/dev/null 2>&1; }

apply_logging() {
  install_content "$LOG_JOURNALD" 0644 root:root "$(log_render_journald)"
  if (( INSTALL_CHANGED )); then
    run systemctl restart systemd-journald
    mark_changed "restarted systemd-journald"
  fi
  if log_rsyslog_installed; then
    install_content "$LOG_RSYSLOG" 0644 root:root "$(log_render_rsyslog)"
    if (( INSTALL_CHANGED )) && unit_active rsyslog; then
      run systemctl restart rsyslog
      mark_changed "restarted rsyslog"
    fi
  fi
}

audit_logging() {
  local st
  audit_content "$LOG_JOURNALD" "$(log_render_journald)"
  st=$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null | awk -F= '/^Storage=/{v=$2} END{print v}' || true)
  if [[ $st == persistent ]]; then audit_pass "journald Storage=persistent (effective)"; else audit_fail "journald Storage=persistent (effective: ${st:-auto})"; fi
  if log_rsyslog_installed; then
    audit_content "$LOG_RSYSLOG" "$(log_render_rsyslog)"
  else
    audit_na "rsyslog not installed"
  fi
}
