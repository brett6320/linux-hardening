# shellcheck shell=bash
# Globals defined here are consumed by harden.sh and the group libraries.
# shellcheck disable=SC2034
# linux-hardening: shared helpers for the shell implementation.
#
# Logging, OS detection, configuration, result tracking, backups/manifest,
# idempotent file installation (respects --check), package/service helpers and
# auto-rollback scheduling via systemd-run. Sourced by harden.sh and by every
# scripts/lib/<group>.sh.

if [[ -n ${LH_COMMON_LOADED:-} ]]; then return 0; fi
LH_COMMON_LOADED=1

# Execution order. banner runs before ssh so /etc/issue.net exists before
# sshd references it; fail2ban runs after firewall (its banaction needs it).
LH_GROUPS=(packages updates banner ssh firewall fail2ban sysctl modules auditd accounts fileperms services mac logging)

LH_BACKUP_ROOT=${LH_BACKUP_ROOT:-/var/backups/linux-hardening}
LH_STATE_DIR=/var/lib/linux-hardening   # rollback scripts
LH_MARK_DIR=/run/linux-hardening        # confirm / rolled-back markers
LH_MODE=apply                           # apply | check | audit
LH_ASSUME_YES=false
LH_TS=""                                # backup timestamp of this run
LH_BACKUP_DIR=""
LH_RUN_DIR=""                           # per-run scratch dir (results, pending rollbacks)
LH_RESULTS=""
LH_DATA_DIR=${LH_DATA_DIR:-}
CURRENT_GROUP=main
INSTALL_CHANGED=0

# OS facts (filled by lh_detect_os)
OS_ID="" OS_ID_LIKE="" OS_VERSION_ID="" OS_MAJOR=0 OS_FAMILY="" OS_PRETTY=""
IS_UBUNTU=false IS_FEDORA=false IS_RHEL=false IS_EL_CLONE=false IS_SLES=false
IS_TUMBLEWEED=false USE_DNF5=false ARCH=""

# ---------------------------------------------------------------------------
# Logging (stderr; stdout is reserved for the report and render functions)
# ---------------------------------------------------------------------------
if [[ -t 2 ]]; then
  _C_RED=$'\e[31m' _C_YEL=$'\e[33m' _C_GRN=$'\e[32m' _C_BLU=$'\e[36m' _C_OFF=$'\e[0m'
else
  _C_RED="" _C_YEL="" _C_GRN="" _C_BLU="" _C_OFF=""
fi

_log() { printf '%s[%-9s]%s %s\n' "$1" "$CURRENT_GROUP" "$_C_OFF" "$2" >&2; }
log_info()   { _log "" "$*"; }
log_change() { _log "$_C_GRN" "$*"; }
log_check()  { _log "$_C_BLU" "[check] $*"; }
log_warn()   { _log "$_C_YEL" "WARNING: $*"; }
log_error()  { _log "$_C_RED" "ERROR: $*"; }

die() { log_error "$*"; exit 1; }

is_true() {
  case ${1,,} in
    true|yes|1|on) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Result tracking. Groups run in subshells, so results go through a file:
#   <group>\t<kind>\t<message>
# kinds: changed warn skip error pass fail na info
# ---------------------------------------------------------------------------
_result() {
  local msg=${2:-}
  msg=${msg//$'\n'/ }
  msg=${msg//$'\t'/ }
  printf '%s\t%s\t%s\n' "$CURRENT_GROUP" "$1" "$msg" >>"$LH_RESULTS"
}

mark_changed() {
  _result changed "$1"
  if [[ $LH_MODE == check ]]; then log_check "would: $1"; else log_change "$1"; fi
}
mark_warn()  { _result warn "$1"; log_warn "$1"; }
mark_skip()  { _result skip "$1"; log_info "skipped: $1"; }
mark_info()  { _result info "$1"; log_info "$1"; }
mark_error() { _result error "$1"; log_error "$1"; }
# Abort the current group (we are inside the group subshell).
die_group()  { mark_error "$1"; exit 3; }

# Normalized directive set: drops comments (#, //) and blank lines, collapses
# whitespace, sorts. Lets --audit accept a file written by the Ansible role,
# which differs only in headers, ordering and spacing.
# With "ordered", order is kept (nft rules are evaluated top to bottom).
_directives() {
  local sorter=(env LC_ALL=C sort -u)
  [[ ${1:-} == ordered ]] && sorter=(cat)
  sed -E -e 's/^[[:space:]]+//' -e 's/[[:space:]]+/ /g' -e 's/ $//' | grep -Ev '^(#|//|$)' | "${sorter[@]}"
}

# audit_content FILE EXPECTED [DESC] [ordered] -> pass when FILE has the same directives.
audit_content() {
  local desc="${3:-$1} up to date"
  if [[ -f $1 && "$(_directives "${4:-}" <"$1")" == "$(_directives "${4:-}" <<<"$2")" ]]; then
    audit_pass "$desc"; else audit_fail "$desc"; fi
}

audit_pass() { _result pass "$1"; log_info "PASS  $1"; }
audit_fail() { _result fail "$1"; _log "$_C_RED" "FAIL  $1"; }
audit_na()   { _result na "$1"; log_info "N/A   $1"; }
# audit_check "description" command...  -> pass if command succeeds
audit_check() {
  local desc=$1; shift
  if "$@" >/dev/null 2>&1; then audit_pass "$desc"; else audit_fail "$desc"; fi
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
lh_apply_defaults() {
  : "${HARDEN_SSH_PORT:=22}"
  : "${HARDEN_SSH_ALLOW_USERS:=}"
  : "${HARDEN_FORCE_KEY_ONLY:=false}"
  : "${HARDEN_ADMIN_SOURCES:=}"
  : "${HARDEN_ALLOWED_TCP_PORTS:=}"
  : "${HARDEN_ALLOWED_UDP_PORTS:=}"
  : "${HARDEN_FIREWALL_FORCE:=false}"
  : "${HARDEN_FIREWALL_IGNORE_LISTENERS=udp/5353 tcp/5355 udp/5355}"
  : "${HARDEN_ROLLBACK_SECONDS:=120}"
  : "${HARDEN_UNATTENDED_FORCE:=false}"
  : "${HARDEN_DISABLE_IPV6:=false}"
  : "${HARDEN_IPV6_ACCEPT_RA_OFF:=false}"
  : "${HARDEN_KEXEC_DISABLE:=false}"
  : "${HARDEN_APPLY_UPDATES:=true}"
  : "${HARDEN_AUTO_REBOOT:=false}"
  : "${HARDEN_AUTO_REBOOT_TIME:=04:00}"
  : "${HARDEN_FAIL2BAN_BANTIME:=1h}"
  : "${HARDEN_FAIL2BAN_MAXRETRY:=5}"
  : "${HARDEN_FAIL2BAN_IGNOREIP:=}"
  : "${HARDEN_AUDIT_IMMUTABLE:=false}"
  : "${HARDEN_AUDIT_FIX_TASK_NEVER:=false}"
  : "${HARDEN_SELINUX_FORCE:=false}"
  local g v
  for g in "${LH_GROUPS[@]}"; do
    v="HARDEN_${g^^}"
    if [[ -z ${!v:-} ]]; then printf -v "$v" '%s' true; fi
  done
}

# Reject config files that a non-root user could have written: they are sourced.
_lh_check_conf_perms() {
  local f=$1 uid mode
  uid=$(stat -c '%u' "$f")
  mode=$(stat -c '%a' "$f")
  if [[ $uid != 0 ]] || (( (8#$mode & 8#022) != 0 )); then
    die "refusing to source $f: must be owned by root and not group/world-writable"
  fi
}

# Precedence: /etc/linux-hardening.conf < --config FILE < environment.
lh_load_config() {
  local cfg=${1:-} f n
  local -A envsave=()
  for n in $(compgen -v HARDEN_ || true); do envsave[$n]=${!n}; done
  if [[ -n $cfg && ! -f $cfg ]]; then die "config file not found: $cfg"; fi
  for f in /etc/linux-hardening.conf "$cfg"; do
    [[ -n $f && -f $f ]] || continue
    _lh_check_conf_perms "$f"
    # shellcheck source=/dev/null
    source "$f"
  done
  for n in "${!envsave[@]}"; do printf -v "$n" '%s' "${envsave[$n]}"; done
  lh_apply_defaults
  lh_validate_config
}

_valid_port() { [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
_valid_port_spec() {
  local a b
  if [[ $1 =~ ^([0-9]+)-([0-9]+)$ ]]; then
    a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]}
    _valid_port "$a" && _valid_port "$b" && (( a <= b ))
  else
    _valid_port "$1"
  fi
}
_valid_cidr() {
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] && return 0
  [[ $1 =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ && $1 == *:* ]]
}

lh_validate_config() {
  local v p b g
  _valid_port "$HARDEN_SSH_PORT" || die "HARDEN_SSH_PORT invalid: $HARDEN_SSH_PORT"
  if ! [[ $HARDEN_ROLLBACK_SECONDS =~ ^[0-9]+$ ]] || (( HARDEN_ROLLBACK_SECONDS < 30 )); then
    die "HARDEN_ROLLBACK_SECONDS must be an integer >= 30"
  fi
  [[ $HARDEN_FAIL2BAN_MAXRETRY =~ ^[0-9]+$ ]] || die "HARDEN_FAIL2BAN_MAXRETRY must be an integer"
  [[ $HARDEN_FAIL2BAN_BANTIME =~ ^[0-9]+[smhdw]?$ ]] || die "HARDEN_FAIL2BAN_BANTIME invalid (e.g. 600, 10m, 1h)"
  [[ $HARDEN_AUTO_REBOOT_TIME =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "HARDEN_AUTO_REBOOT_TIME must be HH:MM"
  for p in $HARDEN_ALLOWED_TCP_PORTS $HARDEN_ALLOWED_UDP_PORTS; do
    _valid_port_spec "$p" || die "invalid port in HARDEN_ALLOWED_*_PORTS: $p"
  done
  for v in $HARDEN_ADMIN_SOURCES $HARDEN_FAIL2BAN_IGNOREIP; do
    _valid_cidr "$v" || die "invalid address/CIDR: $v"
  done
  for v in $HARDEN_SSH_ALLOW_USERS; do
    [[ $v =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*\$?(@[A-Za-z0-9.:/*?-]+)?$ ]] || die "invalid user in HARDEN_SSH_ALLOW_USERS: $v"
  done
  for b in FORCE_KEY_ONLY FIREWALL_FORCE DISABLE_IPV6 IPV6_ACCEPT_RA_OFF KEXEC_DISABLE APPLY_UPDATES \
           AUTO_REBOOT AUDIT_IMMUTABLE AUDIT_FIX_TASK_NEVER SELINUX_FORCE UNATTENDED_FORCE; do
    v="HARDEN_$b"
    _lh_norm_bool "$v"
  done
  for g in "${LH_GROUPS[@]}"; do _lh_norm_bool "HARDEN_${g^^}"; done
}

_lh_norm_bool() {
  local name=$1 val=${!1}
  case ${val,,} in
    true|yes|1|on) printf -v "$name" true ;;
    false|no|0|off) printf -v "$name" false ;;
    *) die "$name must be true or false (got '$val')" ;;
  esac
}

lh_group_enabled() { local v="HARDEN_${1^^}"; is_true "${!v:-true}"; }

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
_osr_get() {
  local key=$1 line
  line=$(grep -E "^${key}=" /etc/os-release | head -n1 || true)
  line=${line#*=}
  line=${line#\"}; line=${line%\"}
  line=${line#\'}; line=${line%\'}
  printf '%s' "$line"
}

lh_detect_os() {
  [[ -r /etc/os-release ]] || die "/etc/os-release not found; unsupported OS"
  OS_ID=$(_osr_get ID)
  OS_ID_LIKE=$(_osr_get ID_LIKE)
  OS_VERSION_ID=$(_osr_get VERSION_ID)
  OS_PRETTY=$(_osr_get PRETTY_NAME)
  OS_MAJOR=${OS_VERSION_ID%%.*}
  [[ $OS_MAJOR =~ ^[0-9]+$ ]] || OS_MAJOR=0
  ARCH=$(uname -m)

  OS_FAMILY=$(_lh_family_of "$OS_ID")
  if [[ -z $OS_FAMILY ]]; then
    local w
    for w in $OS_ID_LIKE; do
      OS_FAMILY=$(_lh_family_of "$w")
      [[ -n $OS_FAMILY ]] && break
    done
  fi
  [[ -n $OS_FAMILY ]] || die "unsupported distribution: ID=$OS_ID ID_LIKE=$OS_ID_LIKE"

  case $OS_ID in
    ubuntu) IS_UBUNTU=true ;;
    fedora) IS_FEDORA=true ;;
    rhel) IS_RHEL=true ;;
    rocky|almalinux|centos) IS_EL_CLONE=true ;;
    sles|sled|sles_sap) IS_SLES=true ;;
    opensuse-tumbleweed|opensuse-slowroll) IS_TUMBLEWEED=true ;;
  esac
  if $IS_FEDORA && { (( OS_MAJOR >= 41 )) || command -v dnf5 >/dev/null 2>&1; }; then USE_DNF5=true; fi
}

_lh_family_of() {
  case $1 in
    debian|ubuntu) echo debian ;;
    rhel|rocky|almalinux|centos|fedora) echo rhel ;;
    sles|sled|sles_sap|suse|opensuse|opensuse-*) echo suse ;;
    *) echo "" ;;
  esac
}

fips_enabled() { [[ -r /proc/sys/crypto/fips_enabled && $(</proc/sys/crypto/fips_enabled) == 1 ]]; }
selinux_enabled() { command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; }

# ---------------------------------------------------------------------------
# Backups and manifest
#   manifest lines: <kind> <group> <path> [extra...]
#   kinds: modified created dir perms masked note
# ---------------------------------------------------------------------------
lh_ensure_backup_dir() {
  [[ -d $LH_BACKUP_DIR ]] && return 0
  mkdir -p "$LH_BACKUP_ROOT"
  chmod 0700 "$LH_BACKUP_ROOT"
  mkdir -p "$LH_BACKUP_DIR"
  printf '# linux-hardening backup %s host=%s os=%s\n' "$LH_TS" "$(hostname)" "$OS_PRETTY" >"$LH_BACKUP_DIR/manifest"
}

_manifest_has() { [[ -f $LH_BACKUP_DIR/manifest ]] && grep -qE "^(modified|created|dir) [^ ]+ $(_re_escape "$1")\$" "$LH_BACKUP_DIR/manifest"; }
_re_escape() { printf '%s' "$1" | sed -e 's/[]\/$*.^[]/\\&/g'; }

# Back up a file (or note its creation) once per run.
backup_file() {
  local p=$1
  lh_ensure_backup_dir
  _manifest_has "$p" && return 0
  if [[ -e $p || -L $p ]]; then
    mkdir -p "$LH_BACKUP_DIR$(dirname "$p")"
    cp -a "$p" "$LH_BACKUP_DIR$p"
    echo "modified $CURRENT_GROUP $p" >>"$LH_BACKUP_DIR/manifest"
  else
    echo "created $CURRENT_GROUP $p" >>"$LH_BACKUP_DIR/manifest"
  fi
}

# Back up a whole directory (used for /etc/firewalld).
backup_dir() {
  local d=$1
  lh_ensure_backup_dir
  _manifest_has "$d" && return 0
  mkdir -p "$LH_BACKUP_DIR$(dirname "$d")"
  cp -a "$d" "$LH_BACKUP_DIR$d"
  echo "dir $CURRENT_GROUP $d" >>"$LH_BACKUP_DIR/manifest"
}

manifest_note() { # key value
  lh_ensure_backup_dir
  echo "note $CURRENT_GROUP $1 $2" >>"$LH_BACKUP_DIR/manifest"
}

# ---------------------------------------------------------------------------
# Idempotent file installation
# ---------------------------------------------------------------------------
# same_content A B -> true when both files have identical bytes. Uses
# sha256sum (coreutils) because cmp/diffutils is absent on minimal images.
same_content() {
  [[ -f $1 && -f $2 ]] || return 1
  [[ $(sha256sum <"$1") == "$(sha256sum <"$2")" ]]
}

# install_file SRC DEST [MODE] [OWNER:GROUP]
# Sets INSTALL_CHANGED=1 when DEST was (or, in check mode, would be) written.
install_file() {
  local src=$1 dest=$2 mode=${3:-0644} owner=${4:-root:root} tmp dir
  INSTALL_CHANGED=0
  if [[ -f $dest && ! -L $dest ]] && same_content "$src" "$dest"; then
    ensure_perms "$dest" "$mode" "$owner"
    return 0
  fi
  INSTALL_CHANGED=1
  if [[ $LH_MODE == check ]]; then
    mark_changed "write $dest"
    if [[ -f $dest ]] && command -v diff >/dev/null 2>&1; then diff -u "$dest" "$src" | sed -n '3,60p' >&2 || true; fi
    return 0
  fi
  backup_file "$dest"
  dir=$(dirname "$dest")
  mkdir -p "$dir"
  tmp=$(mktemp "$dir/.linux-hardening.XXXXXX")
  cat "$src" >"$tmp"
  chmod "$mode" "$tmp"
  chown "$owner" "$tmp"
  mv -f "$tmp" "$dest"
  if selinux_enabled && command -v restorecon >/dev/null 2>&1; then restorecon -F "$dest" 2>/dev/null || true; fi
  mark_changed "wrote $dest"
}

# install_content DEST MODE OWNER CONTENT   (a trailing newline is added)
install_content() {
  local dest=$1 mode=$2 owner=$3 content=$4 tmp
  tmp=$(mktemp "$LH_RUN_DIR/content.XXXXXX")
  printf '%s\n' "$content" >"$tmp"
  install_file "$tmp" "$dest" "$mode" "$owner"
  rm -f "$tmp"
}

# ensure_perms PATH MODE [OWNER:GROUP]   (empty owner keeps owner)
ensure_perms() {
  local p=$1 mode=$2 owner=${3:-} cur_mode cur_owner
  [[ -e $p ]] || return 0
  cur_mode=$(stat -c '%a' "$p")
  cur_owner=$(stat -c '%U:%G' "$p")
  if (( 8#$cur_mode == 8#$mode )) && [[ -z $owner || $cur_owner == "$owner" ]]; then return 0; fi
  if [[ $LH_MODE == check ]]; then
    mark_changed "set $p to $mode${owner:+ $owner} (now $cur_mode $cur_owner)"
    return 0
  fi
  lh_ensure_backup_dir
  echo "perms $CURRENT_GROUP $p $cur_mode $cur_owner" >>"$LH_BACKUP_DIR/manifest"
  chmod "$mode" "$p" || return 1
  if [[ -n $owner ]]; then chown "$owner" "$p" || return 1; fi
  mark_changed "set $p to $mode${owner:+ $owner} (was $cur_mode $cur_owner)"
}

# Run a state-changing command (printed only in check mode).
run() {
  if [[ $LH_MODE == check ]]; then
    log_check "would run: $*"
    return 0
  fi
  "$@"
}

# Read a data/ list file: strip comments and blank lines.
data_lines() {
  local f="$LH_DATA_DIR/$1"
  [[ -r $f ]] || die "data file missing: $f"
  sed -e 's/#.*$//' -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' "$f" | grep -v '^$' || true
}
data_file() { printf '%s/%s' "$LH_DATA_DIR" "$1"; }

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
pkg_installed() {
  case $OS_FAMILY in
    debian) [[ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true) == "install ok installed" ]] ;;
    *) rpm -q --quiet "$1" 2>/dev/null ;;
  esac
}

pkg_available() {
  local out
  case $OS_FAMILY in
    debian)
      out=$(apt-cache policy "$1" 2>/dev/null || true)
      [[ $out =~ Candidate:\ [^\(] ]] ;;
    rhel) dnf -q list --available "$1" >/dev/null 2>&1 || pkg_installed "$1" ;;
    suse) zypper -n -q search -x -t package "$1" >/dev/null 2>&1 ;;
  esac
}

pkg_refresh() {
  case $OS_FAMILY in
    debian) run env DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get -q update ;;
    rhel) run dnf -q -y makecache ;;
    suse) run zypper -n -q refresh ;;
  esac
}

pkg_install() {
  (( $# )) || return 0
  case $OS_FAMILY in
    debian) run env DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get -q -y -o Dpkg::Options::=--force-confold install "$@" ;;
    rhel) run dnf -q -y install "$@" ;;
    suse) run zypper -n -q install --auto-agree-with-licenses "$@" ;;
  esac
}

pkg_remove() {
  (( $# )) || return 0
  case $OS_FAMILY in
    debian) run env DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get -q -y remove "$@" ;;
    rhel) run dnf -q -y remove "$@" ;;
    suse) run zypper -n -q remove "$@" ;;
  esac
}

# ensure_packages pkg... : install the missing ones. Returns nonzero on failure.
ensure_packages() {
  local p missing=()
  for p in "$@"; do pkg_installed "$p" || missing+=("$p"); done
  (( ${#missing[@]} )) || return 0
  mark_changed "install packages: ${missing[*]}"
  pkg_install "${missing[@]}"
}

# ---------------------------------------------------------------------------
# systemd helpers
# ---------------------------------------------------------------------------
unit_exists() {
  local out
  out=$(systemctl list-unit-files --no-legend --no-pager "$1" 2>/dev/null || true)
  [[ -n $out ]]
}
unit_state()  { systemctl is-enabled "$1" 2>/dev/null || true; }
unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

# enable + start a unit if needed.
ensure_unit_enabled_now() {
  local u=$1 st
  st=$(unit_state "$u")
  case $st in
    enabled|enabled-runtime|static|alias|indirect|generated) ;;
    masked) mark_warn "$u is masked; not enabling"; return 0 ;;
    *) mark_changed "enable $u"; run systemctl enable --quiet "$u" ;;
  esac
  if ! unit_active "$u"; then
    if [[ $LH_MODE == check ]]; then
      mark_changed "start $u"
    elif systemctl start "$u" 2>/dev/null; then
      mark_changed "start $u"
    else
      mark_warn "$u failed to start (see journalctl -u $u)"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Restore / rollback rendering (shared by --restore and auto-rollback)
# ---------------------------------------------------------------------------
# Print bash commands that restore every manifest entry of <dir> (optionally
# only those of group <grp>), newest first.
lh_render_restore_cmds() {
  local dir=$1 grp=${2:-} kind g path a b
  [[ -f $dir/manifest ]] || return 0
  while read -r kind g path a b; do
    [[ $kind == \#* || -z $kind ]] && continue
    [[ -n $grp && $g != "$grp" ]] && continue
    case $kind in
      modified)
        printf 'mkdir -p %q && cp -a %q %q && echo restored %q\n' "$(dirname "$path")" "$dir$path" "$path" "$path" ;;
      created)
        printf 'if [ -f %q ] || [ -L %q ]; then rm -f %q && echo removed %q; fi\n' "$path" "$path" "$path" "$path" ;;
      dir)
        printf 'rm -rf %q && cp -a %q %q && echo restored %q\n' "$path" "$dir$path" "$path" "$path" ;;
      perms)
        printf 'chmod %q %q; chown %q %q; echo reset perms %q\n' "$a" "$path" "$b" "$path" "$path" ;;
      masked)
        printf 'systemctl unmask %q && echo unmasked %q\n' "$path" "$path" ;;
    esac
  done < <(tac "$dir/manifest")
}

_manifest_note_get() { # dir group key
  awk -v g="$2" -v k="$3" '$1=="note" && $2==g && $3==k {v=$4} END {print v}' "$1/manifest"
}

# Print bash commands that make a restored group's config effective.
lh_render_reload_cmds() {
  local grp=$1 dir=${2:-}
  case $grp in
    ssh)
      local svc=sshd
      [[ $OS_FAMILY == debian ]] && svc=ssh
      [[ $OS_FAMILY == debian ]] && echo '[ -d /run/sshd ] || mkdir -m 0755 /run/sshd'
      echo 'if sshd -t 2>/dev/null || /usr/sbin/sshd -t; then'
      if [[ $OS_FAMILY == debian ]] && [[ $(unit_state ssh.socket) == enabled ]]; then
        echo '  systemctl daemon-reload; systemctl restart ssh.socket; systemctl try-reload-or-restart ssh.service'
      else
        echo "  systemctl reload-or-restart $svc"
      fi
      echo 'else echo "sshd -t failed after restore; sshd NOT reloaded" >&2; fi'
      ;;
    firewall)
      if [[ $OS_FAMILY == debian ]]; then
        if [[ -n $dir && $(_manifest_note_get "$dir" firewall nft_table_was_loaded) == no ]]; then
          echo 'nft delete table inet hardening 2>/dev/null || true'
        else
          echo 'if [ -f /etc/nftables.d/hardening.nft ]; then nft -f /etc/nftables.d/hardening.nft; else nft delete table inet hardening 2>/dev/null || true; fi'
        fi
        if [[ -n $dir && $(_manifest_note_get "$dir" firewall nftables_was_enabled) == no ]]; then
          echo 'systemctl disable --quiet nftables || true'
        fi
      else
        if [[ -n $dir && $(_manifest_note_get "$dir" firewall firewalld_was_active) == no ]]; then
          echo 'systemctl disable --now --quiet firewalld || true'
        else
          echo 'firewall-cmd --reload || systemctl restart firewalld'
          # Interface bindings live in NetworkManager profiles, outside
          # /etc/firewalld: rebind runtime + permanent (updates NM too).
          if [[ -n $dir ]]; then
            local kv
            while IFS= read -r kv; do
              [[ -n $kv ]] || continue
              printf 'firewall-cmd --zone=%q --change-interface=%q || true\n' "${kv#*=}" "${kv%%=*}"
              printf 'firewall-cmd --permanent --zone=%q --change-interface=%q || true\n' "${kv#*=}" "${kv%%=*}"
            done < <(awk '$1=="note" && $2=="firewall" && $3=="iface_prev_zone" {print $4}' "$dir/manifest")
          fi
        fi
      fi
      ;;
    fail2ban) echo 'systemctl try-reload-or-restart fail2ban || true' ;;
    sysctl)   echo 'sysctl --system >/dev/null || true' ;;
    auditd)   echo 'augenrules --load || true' ;;
    logging)  echo 'systemctl restart systemd-journald || true; systemctl try-restart rsyslog 2>/dev/null || true' ;;
    updates|services|fileperms) echo 'systemctl daemon-reload || true' ;;
  esac
}

# ---------------------------------------------------------------------------
# Auto-rollback (safety rule 3)
# ---------------------------------------------------------------------------
rollback_unit() { printf 'hardening-rollback-%s' "$1"; }

# SSH and firewall rollbacks form one transaction: $LH_MARK_DIR/txn lists the
# groups scheduled in the current run. If any of them rolls back (timer fired
# or verification failed), all of them roll back; they are cancelled only
# together. Markers: rolledback-<g> (written as the rollback starts),
# confirmed-<g>. rollback.lock serialises rollback scripts and --confirm.

# Write the rollback script for <grp> from this run's manifest.
# shellcheck disable=SC2016  # single-quoted lines are code for the generated script
_rollback_write_script() {
  local grp=$1 f="$LH_STATE_DIR/rollback-$1.sh"
  mkdir -p "$LH_STATE_DIR"
  chmod 0700 "$LH_STATE_DIR"
  {
    echo '#!/bin/bash'
    echo "# linux-hardening auto-rollback for group '$grp' (backup $LH_TS)"
    echo 'set -u'
    printf 'M=%q\nS=%q\n' "$LH_MARK_DIR" "$LH_STATE_DIR"
    echo 'mkdir -p "$M"'
    echo 'if [ -z "${LH_ROLLBACK_LOCKED:-}" ]; then exec 8>"$M/rollback.lock"; flock 8; export LH_ROLLBACK_LOCKED=1; fi'
    echo "if [ -e \"\$M/rolledback-$grp\" ]; then echo 'linux-hardening: $grp already rolled back'; exit 0; fi"
    echo "if [ -e \"\$M/confirmed-$grp\" ] && [ -z \"\${LH_ROLLBACK_FORCE:-}\" ]; then echo 'linux-hardening: $grp was confirmed; not rolling back'; exit 0; fi"
    echo "touch \"\$M/rolledback-$grp\""
    echo "echo 'linux-hardening: rolling back $grp changes from $LH_TS'"
    lh_render_restore_cmds "$LH_BACKUP_DIR" "$grp"
    lh_render_reload_cmds "$grp" "$LH_BACKUP_DIR"
    echo '# Roll back the rest of the transaction too.'
    echo 'for o in $(cat "$M/txn" 2>/dev/null); do'
    echo "  [ \"\$o\" = $grp ] && continue"
    echo '  [ -e "$M/rolledback-$o" ] && continue'
    echo '  [ -f "$S/rollback-$o.sh" ] || continue'
    echo "  echo \"linux-hardening: also rolling back \$o (rolled back together with $grp)\""
    echo '  systemctl stop "hardening-rollback-$o.timer" >/dev/null 2>&1 || true'
    echo '  LH_ROLLBACK_FORCE=1 bash "$S/rollback-$o.sh"'
    echo 'done'
  } >"$f"
  chmod 0700 "$f"
  printf '%s' "$f"
}

# Hold rollback.lock (fd 8) while deciding/cancelling; scripts run meanwhile skip locking.
lh_txn_lock() {
  mkdir -p "$LH_MARK_DIR"
  exec 8>"$LH_MARK_DIR/rollback.lock"
  flock 8
  export LH_ROLLBACK_LOCKED=1
}
lh_txn_unlock() { unset LH_ROLLBACK_LOCKED; exec 8>&-; }

# Schedule rollback of <grp> in HARDEN_ROLLBACK_SECONDS. Call immediately
# before activating the change (reload sshd / load firewall rules).
schedule_rollback() {
  local grp=$1 unit f
  unit=$(rollback_unit "$grp")
  [[ $LH_MODE == apply ]] || return 0
  f=$(_rollback_write_script "$grp") || f=""
  if [[ -z $f || ! -s $f ]] || ! bash -n "$f" 2>/dev/null; then
    restore_group_files_now "$grp"
    die_group "could not write a valid rollback script to $LH_STATE_DIR; restored files, $grp changes not activated"
  fi
  systemctl stop "$unit.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "$unit.service" "$unit.timer" >/dev/null 2>&1 || true
  mkdir -p "$LH_MARK_DIR"
  if [[ ! -e $LH_RUN_DIR/txn_started ]]; then
    # First rollback of this run: start a new transaction (no rollback can be
    # pending here; main refuses to run while one is).
    rm -f "$LH_MARK_DIR"/rolledback-* "$LH_MARK_DIR"/confirmed-* "$LH_MARK_DIR/txn"
    touch "$LH_RUN_DIR/txn_started"
  fi
  rm -f "$LH_MARK_DIR/rolledback-$grp" "$LH_MARK_DIR/confirmed-$grp"
  # RemainAfterElapse=no: a fired timer disappears instead of lingering as
  # "active (elapsed)"; firing is detected through the rolledback marker.
  # AccuracySec=1s: the default (1min) could stretch the window by a minute.
  systemd-run --quiet --on-active="${HARDEN_ROLLBACK_SECONDS}s" --unit="$unit" \
    --timer-property=RemainAfterElapse=no --timer-property=AccuracySec=1s \
    --description="linux-hardening auto-rollback ($grp)" /bin/bash "$f" || {
      restore_group_files_now "$grp"
      die_group "could not schedule rollback with systemd-run; restored files, $grp changes not activated"
    }
  echo "$grp" >>"$LH_MARK_DIR/txn"
  echo "$grp" >>"$LH_RUN_DIR/pending"
  log_info "auto-rollback scheduled: $unit fires in ${HARDEN_ROLLBACK_SECONDS}s unless confirmed"
}

cancel_rollback() {
  local grp=$1 unit
  unit=$(rollback_unit "$grp")
  systemctl stop "$unit.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "$unit.service" "$unit.timer" >/dev/null 2>&1 || true
  mkdir -p "$LH_MARK_DIR"
  touch "$LH_MARK_DIR/confirmed-$grp"
}

# Run the rollback for <grp> right now (verification failed). The script
# also rolls back the other groups of the transaction.
rollback_now() {
  local grp=$1
  systemctl stop "$(rollback_unit "$grp").timer" >/dev/null 2>&1 || true
  if [[ -f $LH_STATE_DIR/rollback-$grp.sh ]]; then LH_ROLLBACK_FORCE=1 bash "$LH_STATE_DIR/rollback-$grp.sh" >&2 || true; fi
}

# Is the rollback timer of <grp> still waiting to fire?
rollback_timer_waiting() {
  [[ $(systemctl show --property=SubState --value "$(rollback_unit "$1").timer" 2>/dev/null || true) == waiting ]]
}

# Restore this run's backup of <grp> immediately, without reload (validation failure).
restore_group_files_now() {
  local grp=$1
  [[ -f $LH_BACKUP_DIR/manifest ]] || return 0
  bash -c "$(lh_render_restore_cmds "$LH_BACKUP_DIR" "$grp")" >&2 || true
}

# Is sshd healthy: config valid, unit active, listening on HARDEN_SSH_PORT?
ssh_alive() {
  local i out sshd
  sshd=$(command -v sshd || echo /usr/sbin/sshd)
  if [[ $OS_FAMILY == debian && ! -d /run/sshd ]]; then mkdir -m 0755 /run/sshd; fi
  "$sshd" -t >/dev/null 2>&1 || return 1
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if { unit_active ssh.socket || unit_active ssh || unit_active sshd; }; then
      out=$(ss -Htln "sport = :$HARDEN_SSH_PORT" 2>/dev/null || true)
      [[ -n $out ]] && return 0
    fi
    sleep 1
    : "$i"
  done
  return 1
}

# ---------------------------------------------------------------------------
# Who is running us over SSH? (for --yes refusals, safety rule 3)
# sudo strips SSH_CONNECTION, so walk up the process tree: the topmost
# ancestor carrying SSH_CONNECTION is the login shell of the SSH session.
# Sets LH_SSH_CLIENT (client IP) and LH_SSH_USER (session owner); empty when
# not run from an SSH session.
# ---------------------------------------------------------------------------
LH_SSH_CLIENT="" LH_SSH_USER=""
lh_ssh_session() {
  local pid=$$ conn uid n=0
  LH_SSH_CLIENT="" LH_SSH_USER=""
  if [[ -n ${SSH_CONNECTION:-} ]]; then LH_SSH_CLIENT=${SSH_CONNECTION%% *}; fi
  while [[ $pid =~ ^[0-9]+$ ]] && (( pid > 1 && n++ < 64 )); do
    conn=$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -n1 || true)
    # Nearest ancestor wins: a tmux/screen server further up keeps the
    # SSH_CONNECTION of whichever session first started it.
    if [[ -n $conn ]]; then
      LH_SSH_CLIENT=${conn%% *}
      uid=$(awk '$1 == "Uid:" { print $2 }' "/proc/$pid/status" 2>/dev/null || true)
      [[ -n $uid ]] && LH_SSH_USER=$(getent passwd "$uid" | cut -d: -f1 || true)
      break
    fi
    pid=$(awk '$1 == "PPid:" { print $2 }' "/proc/$pid/status" 2>/dev/null || true)
  done
  return 0
}

# The account whose access must survive: SUDO_USER, else the SSH session owner.
lh_invoking_user() {
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then printf '%s' "$SUDO_USER"; return 0; fi
  lh_ssh_session
  printf '%s' "$LH_SSH_USER"
}

# Unattended (--yes) runs cancel the rollback after local checks only; the
# risky cases need HARDEN_UNATTENDED_FORCE=true.
lh_unattended_guarded() {
  [[ $LH_MODE == apply ]] && is_true "$LH_ASSUME_YES" && ! is_true "$HARDEN_UNATTENDED_FORCE"
}

# ---------------------------------------------------------------------------
# Address matching (pure bash)
# ---------------------------------------------------------------------------
_ip4_to_int() {
  local -a o; local x
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a o <<<"$1"
  for x in "${o[@]}"; do (( 10#$x <= 255 )) || return 1; done
  printf '%d' $(( (10#${o[0]} << 24) | (10#${o[1]} << 16) | (10#${o[2]} << 8) | 10#${o[3]} ))
}

# IPv6 address -> 32 lowercase hex digits (handles ::, zone ids, dotted tail).
_ip6_expand() {
  local a=${1,,} head tail v4 n out="" g i
  local -a hparts=() tparts=() all=()
  a=${a%%%*}
  [[ $a == *:* && $a =~ ^[0-9a-f:.]+$ ]] || return 1
  if [[ $a =~ ^(.*:)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    v4=$(_ip4_to_int "${BASH_REMATCH[2]}") || return 1
    a="${BASH_REMATCH[1]}$(printf '%x:%x' $(( v4 >> 16 )) $(( v4 & 0xffff )))"
  fi
  if [[ $a == *::* ]]; then
    head=${a%%::*}; tail=${a#*::}
    [[ $tail == *::* ]] && return 1
    [[ -n $head ]] && IFS=: read -r -a hparts <<<"$head"
    [[ -n $tail ]] && IFS=: read -r -a tparts <<<"$tail"
    n=$(( 8 - ${#hparts[@]} - ${#tparts[@]} ))
    (( n >= 1 )) || return 1
    all=("${hparts[@]}")
    for (( i = 0; i < n; i++ )); do all+=(0); done
    all+=("${tparts[@]}")
  else
    IFS=: read -r -a all <<<"$a"
  fi
  (( ${#all[@]} == 8 )) || return 1
  for g in "${all[@]}"; do
    [[ $g =~ ^[0-9a-f]{1,4}$ ]] || return 1
    out+=$(printf '%04x' "0x$g")
  done
  printf '%s' "$out"
}

# ip_in_cidr ADDR CIDR -> 0 if ADDR is inside CIDR (v4 or v6; a bare address
# is a /32 or /128). IPv4-mapped IPv6 clients are matched as IPv4.
ip_in_cidr() {
  local addr=$1 cidr=$2 net len a n mask full rem an nn
  net=${cidr%/*}
  [[ $cidr == */* ]] && len=${cidr#*/} || len=""
  if [[ $addr =~ ^::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then addr=${BASH_REMATCH[1]}; fi
  if [[ $net != *:* ]]; then
    [[ $addr != *:* ]] || return 1
    a=$(_ip4_to_int "$addr") || return 1
    n=$(_ip4_to_int "$net") || return 1
    len=${len:-32}; (( len <= 32 )) || return 1
    mask=$(( len == 0 ? 0 : (0xffffffff << (32 - len)) & 0xffffffff ))
    (( (a & mask) == (n & mask) ))
  else
    [[ $addr == *:* ]] || return 1
    a=$(_ip6_expand "$addr") || return 1
    n=$(_ip6_expand "$net") || return 1
    len=${len:-128}; (( len <= 128 )) || return 1
    full=$(( len / 4 )); rem=$(( len % 4 ))
    [[ ${a:0:full} == "${n:0:full}" ]] || return 1
    (( rem == 0 )) && return 0
    an=$(( 0x${a:full:1} )); nn=$(( 0x${n:full:1} ))
    mask=$(( (0xf << (4 - rem)) & 0xf ))
    (( (an & mask) == (nn & mask) ))
  fi
}
