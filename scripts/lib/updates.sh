# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: updates — automatic security updates.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

UPD_APT_PERIODIC=/etc/apt/apt.conf.d/20auto-upgrades
UPD_APT_SETTINGS=/etc/apt/apt.conf.d/52hardening-unattended
UPD_DNF_CONF=/etc/dnf/automatic.conf
UPD_SUSE_SVC=/etc/systemd/system/hardening-autopatch.service
UPD_SUSE_TIMER=/etc/systemd/system/hardening-autopatch.timer
UPD_SUSE_RB_SVC=/etc/systemd/system/hardening-autoreboot.service
UPD_SUSE_RB_TIMER=/etc/systemd/system/hardening-autoreboot.timer

updates_render_apt_periodic() {
  cat <<'EOF'
// Managed by linux-hardening.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

updates_render_apt_settings() {
  local reboot=false
  is_true "$HARDEN_AUTO_REBOOT" && reboot=true
  echo '// Managed by linux-hardening: security origins only.'
  echo '#clear Unattended-Upgrade::Allowed-Origins;'
  echo '#clear Unattended-Upgrade::Origins-Pattern;'
  echo 'Unattended-Upgrade::Origins-Pattern {'
  if $IS_UBUNTU; then
    # shellcheck disable=SC2016
    printf '%s\n' \
      '        "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu";' \
      '        "origin=UbuntuESMApps,archive=${distro_codename}-apps-security";' \
      '        "origin=UbuntuESM,archive=${distro_codename}-infra-security";'
  else
    # shellcheck disable=SC2016
    printf '%s\n' \
      '        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";' \
      '        "origin=Debian,codename=${distro_codename},label=Debian-Security";'
  fi
  echo '};'
  echo "Unattended-Upgrade::Automatic-Reboot \"$reboot\";"
  echo "Unattended-Upgrade::Automatic-Reboot-Time \"$HARDEN_AUTO_REBOOT_TIME\";"
}

# ini_set_content FILE SECTION KEY VALUE... -> prints FILE with keys set.
# Replaces the first "key = ..." in [section], drops duplicates, appends
# missing keys/sections. Comments and other content are kept.
ini_render() {
  local file=$1 section=$2; shift 2
  local kv=("$@")
  { [[ -f $file ]] && cat "$file"; true; } | LH_KVS="$(printf '%s\n' "${kv[@]}")" awk -v sec="$section" '
    BEGIN { n = split(ENVIRON["LH_KVS"], arr, "\n"); m = 0
            for (i = 1; i <= n; i++) if (arr[i] != "") { p = index(arr[i], "="); k = substr(arr[i], 1, p-1); key[++m] = k; val[k] = substr(arr[i], p+1); done[k] = 0 } }
    function flush_missing(   j) { for (j = 1; j <= m; j++) if (!done[key[j]]) { print key[j] " = " val[key[j]]; done[key[j]] = 1 } }
    /^[[:space:]]*\[/ {
      if (insec) flush_missing()
      s = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", s)
      insec = (s == sec); if (insec) seen = 1
      print; next }
    insec && /^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*=/ {
      k = $0; sub(/[[:space:]]*=.*/, "", k); gsub(/^[[:space:]]+/, "", k)
      if (k in val) { if (!done[k]) { print k " = " val[k]; done[k] = 1 } ; next } }
    { print }
    END { if (insec) flush_missing()
          if (!seen) { print ""; print "[" sec "]"; flush_missing() } }'
}

updates_render_dnf_conf() {
  local type=security reboot=never
  $IS_FEDORA && type=default
  is_true "$HARDEN_AUTO_REBOOT" && reboot=when-needed
  ini_render "$UPD_DNF_CONF" commands "upgrade_type=$type" "apply_updates=yes" "reboot=$reboot"
}

updates_render_suse_service() {
  cat <<'EOF'
# Managed by linux-hardening.
[Unit]
Description=linux-hardening: install security patches
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper --non-interactive patch --category security --auto-agree-with-licenses
# 100-103: patches applied / reboot or zypper restart needed
SuccessExitStatus=100 101 102 103
EOF
}

updates_render_suse_timer() {
  cat <<'EOF'
# Managed by linux-hardening.
[Unit]
Description=linux-hardening: daily security patches

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

updates_render_suse_reboot_service() {
  cat <<'EOF'
# Managed by linux-hardening.
[Unit]
Description=linux-hardening: reboot if patches require it

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'zypper -q needs-rebooting >/dev/null 2>&1; [ $$? -eq 102 ] && systemctl reboot || true'
EOF
}

updates_render_suse_reboot_timer() {
  printf '%s\n' '# Managed by linux-hardening.' '[Unit]' 'Description=linux-hardening: reboot window' '' \
    '[Timer]' "OnCalendar=*-*-* ${HARDEN_AUTO_REBOOT_TIME}:00" '' '[Install]' 'WantedBy=timers.target'
}

updates_dnf_timer() { if $USE_DNF5; then echo dnf5-automatic.timer; else echo dnf-automatic.timer; fi; }

apply_updates() {
  local reload=0
  case $OS_FAMILY in
    debian)
      pkg_installed unattended-upgrades || { mark_skip "unattended-upgrades not installed"; return 0; }
      install_content "$UPD_APT_PERIODIC" 0644 root:root "$(updates_render_apt_periodic)"
      install_content "$UPD_APT_SETTINGS" 0644 root:root "$(updates_render_apt_settings)"
      ensure_unit_enabled_now apt-daily.timer
      ensure_unit_enabled_now apt-daily-upgrade.timer
      ;;
    rhel)
      local timer; timer=$(updates_dnf_timer)
      unit_exists "$timer" || { mark_skip "$timer not available (dnf-automatic not installed)"; return 0; }
      install_content "$UPD_DNF_CONF" 0644 root:root "$(updates_render_dnf_conf)"
      ensure_unit_enabled_now "$timer"
      ;;
    suse)
      install_content "$UPD_SUSE_SVC" 0644 root:root "$(updates_render_suse_service)"; (( INSTALL_CHANGED )) && reload=1
      install_content "$UPD_SUSE_TIMER" 0644 root:root "$(updates_render_suse_timer)"; (( INSTALL_CHANGED )) && reload=1
      if is_true "$HARDEN_AUTO_REBOOT"; then
        install_content "$UPD_SUSE_RB_SVC" 0644 root:root "$(updates_render_suse_reboot_service)"; (( INSTALL_CHANGED )) && reload=1
        install_content "$UPD_SUSE_RB_TIMER" 0644 root:root "$(updates_render_suse_reboot_timer)"; (( INSTALL_CHANGED )) && reload=1
      fi
      if (( reload )); then run systemctl daemon-reload; fi
      if [[ $LH_MODE == check ]] && (( reload )); then
        log_check "would enable hardening-autopatch.timer"
      else
        ensure_unit_enabled_now hardening-autopatch.timer
        if is_true "$HARDEN_AUTO_REBOOT"; then
          ensure_unit_enabled_now hardening-autoreboot.timer
        elif unit_exists hardening-autoreboot.timer && [[ $(unit_state hardening-autoreboot.timer) == enabled ]]; then
          mark_changed "disable hardening-autoreboot.timer (HARDEN_AUTO_REBOOT=false)"
          run systemctl disable --now --quiet hardening-autoreboot.timer
        fi
      fi
      ;;
  esac
  return 0
}

_audit_file() { # path expected desc
  audit_content "$1" "$2" "${3:-$1}"
}

audit_updates() {
  case $OS_FAMILY in
    debian)
      _audit_file "$UPD_APT_PERIODIC" "$(updates_render_apt_periodic)"
      _audit_file "$UPD_APT_SETTINGS" "$(updates_render_apt_settings)"
      audit_check "apt-daily-upgrade.timer enabled" systemctl is-enabled --quiet apt-daily-upgrade.timer ;;
    rhel)
      local timer; timer=$(updates_dnf_timer)
      if [[ -f $UPD_DNF_CONF && "$(cat "$UPD_DNF_CONF")" == "$(updates_render_dnf_conf)" ]]; then
        audit_pass "$UPD_DNF_CONF settings"; else audit_fail "$UPD_DNF_CONF settings"; fi
      audit_check "$timer enabled" systemctl is-enabled --quiet "$timer"
      audit_check "$timer active" systemctl is-active --quiet "$timer" ;;
    suse)
      _audit_file "$UPD_SUSE_SVC" "$(updates_render_suse_service)"
      _audit_file "$UPD_SUSE_TIMER" "$(updates_render_suse_timer)"
      audit_check "hardening-autopatch.timer enabled" systemctl is-enabled --quiet hardening-autopatch.timer
      if is_true "$HARDEN_AUTO_REBOOT"; then
        audit_check "hardening-autoreboot.timer enabled" systemctl is-enabled --quiet hardening-autoreboot.timer
      fi ;;
  esac
}
