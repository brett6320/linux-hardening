# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: accounts — login.defs, faillock (rhel), core dumps, sudo logging.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

ACC_LIMITS=/etc/security/limits.d/99-hardening.conf
ACC_COREDUMP=/etc/systemd/coredump.conf.d/99-hardening.conf
ACC_SUDOERS=/etc/sudoers.d/99-hardening
ACC_LOGROTATE=/etc/logrotate.d/hardening-sudo
ACC_FAILLOCK=/etc/security/faillock.conf
ACC_LOGINDEFS_DROPIN=/etc/login.defs.d/99-hardening.defs

# kv_render FILE SEP KEY=VALUE...  -> FILE content with each KEY set once.
# The first uncommented KEY line is replaced, later duplicates dropped,
# missing keys appended. SEP is the separator written (" " or " = ").
kv_render() {
  local file=$1 sep=$2; shift 2
  { [[ -f $file ]] && cat "$file"; true; } | LH_KVS="$(printf '%s\n' "$@")" awk -v sep="$sep" '
    BEGIN { n = split(ENVIRON["LH_KVS"], a, "\n"); m = 0
            for (i = 1; i <= n; i++) if (a[i] != "") { p = index(a[i], "="); k = substr(a[i], 1, p-1); keys[++m] = k; val[k] = substr(a[i], p+1) } }
    {
      line = $0; k = line; sub(/^[[:space:]]+/, "", k); sub(/[[:space:]=].*/, "", k)
      if (line !~ /^[[:space:]]*#/ && (k in val)) { if (!done[k]) { print k sep val[k]; done[k] = 1 }; next }
      print
    }
    END { add = 0
          for (j = 1; j <= m; j++) if (!done[keys[j]]) { if (!add) { print "# linux-hardening"; add = 1 }; print keys[j] sep val[keys[j]] } }'
}

# Value of KEY (last uncommented) in a login.defs-style file.
_defs_get() { [[ -f $2 ]] && awk -v k="$1" '$1 == k { v = $2 } END { print v }' "$2"; return 0; }

# Where login.defs settings go: "file <path>" (edit), or "dropin <path>".
acc_logindefs_target() {
  if [[ -f /etc/login.defs ]]; then
    echo "file /etc/login.defs"
  elif [[ $OS_FAMILY == suse && -f /usr/etc/login.defs ]]; then
    if [[ -d /etc/login.defs.d || -d /usr/etc/login.defs.d ]]; then echo "dropin $ACC_LOGINDEFS_DROPIN"
    else echo "copy /etc/login.defs"; fi
  else
    echo "file /etc/login.defs"
  fi
}

acc_logindefs_kvs() { # $1 = source file for current ENCRYPT_METHOD
  printf '%s\n' PASS_MAX_DAYS=365 PASS_MIN_DAYS=1 PASS_WARN_AGE=14 UMASK=027
  case $(_defs_get ENCRYPT_METHOD "$1") in
    YESCRYPT|SHA512) ;;
    *) echo ENCRYPT_METHOD=SHA512 ;;
  esac
}

acc_render_logindefs() { # prints "<path>\n<content>"
  local kind path src kvs
  read -r kind path <<<"$(acc_logindefs_target)"
  case $kind in
    file) src=/etc/login.defs ;;
    copy|dropin) src=/usr/etc/login.defs ;;
  esac
  mapfile -t kvs < <(acc_logindefs_kvs "$src")
  echo "$path"
  case $kind in
    file) kv_render "$src" " " "${kvs[@]}" ;;
    copy) kv_render "$src" " " "${kvs[@]}" ;;
    dropin) echo "# Managed by linux-hardening."; local kv; for kv in "${kvs[@]}"; do echo "${kv%%=*} ${kv#*=}"; done ;;
  esac
}

acc_render_faillock() { kv_render "$ACC_FAILLOCK" " = " deny=5 unlock_time=900 fail_interval=900; }
acc_render_limits() { printf '%s\n' "# Managed by linux-hardening." "* hard core 0"; }
acc_render_coredump() { printf '%s\n' "# Managed by linux-hardening." "[Coredump]" "Storage=none" "ProcessSizeMax=0"; }
acc_render_sudoers() {
  printf '%s\n' "# Managed by linux-hardening." "Defaults use_pty" 'Defaults logfile="/var/log/sudo.log"' "Defaults timestamp_timeout=5"
}
acc_render_logrotate() {
  printf '%s\n' "# Managed by linux-hardening." "/var/log/sudo.log {" "    weekly" "    rotate 12" "    compress" "    missingok" "}"
}

acc_authselect_in_use() { command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1; }
acc_authselect_has_faillock() { local o; o=$(authselect current 2>/dev/null || true); [[ $o == *with-faillock* ]]; }

acc_report() {
  local uid0 sysacc uid_min
  uid0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | paste -sd' ' -)
  if [[ -n $uid0 ]]; then mark_warn "UID 0 accounts other than root: $uid0"; fi
  uid_min=$(_defs_get UID_MIN /etc/login.defs); [[ $uid_min =~ ^[0-9]+$ ]] || uid_min=1000
  sysacc=$(awk -F: -v m="$uid_min" '$3 > 0 && $3 < m && $7 !~ /(nologin|false|sync|shutdown|halt)$/ && $7 != "" {print $1}' /etc/passwd | paste -sd' ' -)
  if [[ -n $sysacc ]]; then mark_info "system accounts with a login shell (report only): $sysacc"; fi
}

apply_accounts() {
  local out path content tmp err
  out=$(acc_render_logindefs); path=${out%%$'\n'*}; content=${out#*$'\n'}
  if [[ $path == "$ACC_LOGINDEFS_DROPIN" && ! -d /etc/login.defs.d ]]; then run mkdir -p -m 0755 /etc/login.defs.d; fi
  install_content "$path" 0644 root:root "$content"

  if [[ $OS_FAMILY == rhel ]]; then
    install_content "$ACC_FAILLOCK" 0644 root:root "$(acc_render_faillock)"
    if acc_authselect_in_use && ! acc_authselect_has_faillock; then
      mark_changed "authselect enable-feature with-faillock"
      run authselect enable-feature with-faillock >/dev/null
    fi
  fi

  install_content "$ACC_LIMITS" 0644 root:root "$(acc_render_limits)"
  install_content "$ACC_COREDUMP" 0644 root:root "$(acc_render_coredump)"

  if command -v visudo >/dev/null 2>&1; then
    tmp=$(mktemp "$LH_RUN_DIR/sudoers.XXXXXX")
    acc_render_sudoers >"$tmp"
    if ! err=$(visudo -cf "$tmp" 2>&1); then die_group "visudo rejected the sudoers drop-in: $err"; fi
    [[ -d /etc/sudoers.d ]] || die_group "/etc/sudoers.d missing"
    install_file "$tmp" "$ACC_SUDOERS" 0440 root:root
    rm -f "$tmp"
    install_content "$ACC_LOGROTATE" 0644 root:root "$(acc_render_logrotate)"
  else
    mark_warn "sudo not installed; sudoers drop-in skipped"
  fi
  acc_report
}

_acc_audit_file() { # path expected
  if [[ -f $1 && "$(cat "$1")" == "$2" ]]; then audit_pass "$1 up to date"; else audit_fail "$1 up to date"; fi
}

audit_accounts() {
  local out path content uid0 m
  out=$(acc_render_logindefs); path=${out%%$'\n'*}; content=${out#*$'\n'}
  _acc_audit_file "$path" "$content"
  if [[ $OS_FAMILY == rhel ]]; then
    _acc_audit_file "$ACC_FAILLOCK" "$(acc_render_faillock)"
    if acc_authselect_in_use; then audit_check "authselect with-faillock" acc_authselect_has_faillock
    else audit_na "authselect not in use"; fi
  else
    audit_na "faillock (PAM not wired on $OS_FAMILY)"
  fi
  _acc_audit_file "$ACC_LIMITS" "$(acc_render_limits)"
  _acc_audit_file "$ACC_COREDUMP" "$(acc_render_coredump)"
  if command -v visudo >/dev/null 2>&1; then
    _acc_audit_file "$ACC_SUDOERS" "$(acc_render_sudoers)"
    if [[ -f $ACC_SUDOERS ]]; then
      m=$(stat -c '%a' "$ACC_SUDOERS")
      if [[ $m == 440 ]]; then audit_pass "$ACC_SUDOERS mode 0440"; else audit_fail "$ACC_SUDOERS mode 0440 (is $m)"; fi
    fi
    _acc_audit_file "$ACC_LOGROTATE" "$(acc_render_logrotate)"
  else
    audit_na "sudo not installed"
  fi
  uid0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | paste -sd' ' -)
  if [[ -z $uid0 ]]; then audit_pass "no UID 0 account besides root"; else audit_fail "UID 0 accounts besides root: $uid0"; fi
}
