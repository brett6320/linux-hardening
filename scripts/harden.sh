#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
#
# linux-hardening — shell implementation of docs/SPEC.md.
#
# Layouts:
#   repo:      <repo>/scripts/harden.sh  with data in <repo>/data
#   installed: cp -a <repo> /opt/linux-hardening
#              ln -s /opt/linux-hardening/scripts/harden.sh /usr/local/sbin/linux-harden
#              (data is then found at /opt/linux-hardening/data)
# LH_DATA_DIR=/path overrides the data directory.

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  echo "harden.sh requires bash >= 4.4" >&2
  exit 1
fi

LH_SELF=$(readlink -f "${BASH_SOURCE[0]}")
LH_SCRIPT_DIR=$(dirname "$LH_SELF")
LH_LIB_DIR="$LH_SCRIPT_DIR/lib"

# shellcheck source=lib/common.sh
source "$LH_LIB_DIR/common.sh"
# shellcheck source=lib/packages.sh
source "$LH_LIB_DIR/packages.sh"
# shellcheck source=lib/updates.sh
source "$LH_LIB_DIR/updates.sh"
# shellcheck source=lib/banner.sh
source "$LH_LIB_DIR/banner.sh"
# shellcheck source=lib/ssh.sh
source "$LH_LIB_DIR/ssh.sh"
# shellcheck source=lib/firewall.sh
source "$LH_LIB_DIR/firewall.sh"
# shellcheck source=lib/fail2ban.sh
source "$LH_LIB_DIR/fail2ban.sh"
# shellcheck source=lib/sysctl.sh
source "$LH_LIB_DIR/sysctl.sh"
# shellcheck source=lib/modules.sh
source "$LH_LIB_DIR/modules.sh"
# shellcheck source=lib/auditd.sh
source "$LH_LIB_DIR/auditd.sh"
# shellcheck source=lib/accounts.sh
source "$LH_LIB_DIR/accounts.sh"
# shellcheck source=lib/fileperms.sh
source "$LH_LIB_DIR/fileperms.sh"
# shellcheck source=lib/services.sh
source "$LH_LIB_DIR/services.sh"
# shellcheck source=lib/mac.sh
source "$LH_LIB_DIR/mac.sh"
# shellcheck source=lib/logging.sh
source "$LH_LIB_DIR/logging.sh"

usage() {
  cat <<EOF
Usage: harden.sh [options]

Applies the controls in docs/SPEC.md. Requires root (except -h).

Modes:
  (default)           apply hardening
  --check             dry run: print what would change, change nothing
  --audit             read-only verification; exit 1 if any check fails
  --confirm           cancel pending auto-rollback units (run from a NEW SSH session)
  --restore TS        revert the backup taken at timestamp TS
  --list-backups      list backups under $LH_BACKUP_ROOT

Options:
  --yes               non-interactive (no prompts; rollback auto-cancelled once sshd verified)
  --config FILE       extra config file (overrides /etc/linux-hardening.conf; env overrides both)
  --only g1,g2        run only these groups
  --skip g1,g2        skip these groups
  -h, --help          this help

Groups: ${LH_GROUPS[*]}
Exit: 0 ok, 1 error / failed audit, 2 warnings.

Installed layout: copy the repo to /opt/linux-hardening and run
/opt/linux-hardening/scripts/harden.sh (or a symlink to it). See
scripts/linux-hardening.conf.example for all variables.
EOF
}

# ---------------------------------------------------------------------------
lh_locate_data() {
  local c
  if [[ -z $LH_DATA_DIR ]]; then
    for c in "$LH_SCRIPT_DIR/../data" /opt/linux-hardening/data; do
      if [[ -f $c/sysctl.conf ]]; then LH_DATA_DIR=$(readlink -f "$c"); break; fi
    done
    [[ -n $LH_DATA_DIR ]] || die "cannot find data/ directory (looked next to $LH_SCRIPT_DIR and in /opt/linux-hardening)"
  fi
  [[ -d $LH_DATA_DIR ]] || die "data directory not found: $LH_DATA_DIR"
  for c in sysctl.conf modules.list services.list audit.rules remove-packages.list issue.net; do
    [[ -s $LH_DATA_DIR/$c ]] || die "data file missing or empty: $LH_DATA_DIR/$c"
  done
}

_csv_to_groups() { # validate a comma list of group names, print space-separated
  local item g ok out=()
  IFS=',' read -r -a items <<<"$1"
  for item in "${items[@]}"; do
    [[ -z $item ]] && continue
    ok=false
    for g in "${LH_GROUPS[@]}"; do [[ $g == "$item" ]] && ok=true; done
    $ok || die "unknown group: $item (valid: ${LH_GROUPS[*]})"
    out+=("$item")
  done
  printf '%s ' "${out[@]}"
}

_in_list() { local x=$1; shift; local y; for y in "$@"; do [[ $x == "$y" ]] && return 0; done; return 1; }

# ---------------------------------------------------------------------------
# Group execution: each group runs in a subshell so a failure aborts only that
# group. Results come back through $LH_RESULTS.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2329  # invoked from the EXIT trap in run_group
_group_exit_trap() {
  local rc=$1
  if (( rc != 0 && rc != 3 )); then
    _result error "aborted: '$BASH_COMMAND' exited $rc"
    log_error "aborted at '$BASH_COMMAND' (exit $rc)"
  fi
}

run_group() {
  local g=$1
  CURRENT_GROUP=$g
  log_info "---- $g ($LH_MODE)"
  set +e
  (
    set -e
    trap '_group_exit_trap $?' EXIT
    if [[ $LH_MODE == audit ]]; then "audit_$g"; else "apply_$g"; fi
  )
  set -e
  CURRENT_GROUP=main
}

# ---------------------------------------------------------------------------
# Confirmation of SSH/firewall changes (safety rule 3)
# ---------------------------------------------------------------------------
confirm_pending_rollbacks() {
  local pending=() g waited=0 limit all_done
  [[ -f $LH_RUN_DIR/pending ]] || return 0
  mapfile -t pending < <(sort -u "$LH_RUN_DIR/pending")
  rm -f "$LH_RUN_DIR/pending"
  (( ${#pending[@]} )) || return 0
  CURRENT_GROUP=confirm

  if [[ -t 0 ]] && ! is_true "$LH_ASSUME_YES"; then
    mkdir -p "$LH_MARK_DIR"
    printf '%s\n' "${SSH_CONNECTION:-}" >"$LH_MARK_DIR/session"
    cat >&2 <<EOF

  ============================================================================
  SSH/firewall changes are active (${pending[*]}). They will be ROLLED BACK in
  ${HARDEN_ROLLBACK_SECONDS}s unless you confirm from a NEW SSH session:

      ssh -p $HARDEN_SSH_PORT <user>@<this host>
      sudo $LH_SELF --confirm

  Keep this session open. Ctrl-C here does not cancel the rollback.
  ============================================================================
EOF
    limit=$(( HARDEN_ROLLBACK_SECONDS + 30 ))
    while (( waited < limit )); do
      all_done=true
      for g in "${pending[@]}"; do
        if [[ ! -e $LH_MARK_DIR/confirmed-$g && ! -e $LH_MARK_DIR/rolledback-$g ]]; then all_done=false; fi
      done
      $all_done && break
      sleep 2
      waited=$(( waited + 2 ))
    done
    for g in "${pending[@]}"; do
      CURRENT_GROUP=$g
      if [[ -e $LH_MARK_DIR/rolledback-$g ]]; then
        mark_error "not confirmed in time: changes were rolled back"
      elif [[ -e $LH_MARK_DIR/confirmed-$g ]]; then
        log_info "confirmed; rollback cancelled"
      else
        mark_warn "no confirmation seen; rollback unit $(rollback_unit "$g") may still be pending"
      fi
    done
  else
    for g in "${pending[@]}"; do
      CURRENT_GROUP=$g
      if [[ $g == ssh && -e $LH_RUN_DIR/ssh_port_changed && ! -e $LH_RUN_DIR/firewall_ok ]]; then
        rollback_now "$g"
        mark_error "SSH port changed but the firewall group did not open it in this run (skipped/failed/ufw): rolled back"
      elif ssh_alive && _group_still_active "$g"; then
        cancel_rollback "$g"
        log_info "sshd verified (config valid, active, listening on $HARDEN_SSH_PORT); rollback cancelled"
      else
        rollback_now "$g"
        mark_error "post-change verification failed: rolled back"
      fi
    done
  fi
  CURRENT_GROUP=main
}

_group_still_active() {
  case $1 in
    firewall)
      if [[ $OS_FAMILY == debian ]]; then nft list table inet hardening >/dev/null 2>&1
      else unit_active firewalld; fi ;;
    *) return 0 ;;
  esac
}

do_confirm() {
  local units u g found=false sess
  sess=$(cat "$LH_MARK_DIR/session" 2>/dev/null || true)
  if [[ -n $sess && $sess == "${SSH_CONNECTION:-}" ]]; then
    log_warn "this looks like the same SSH session that ran the hardening; a NEW session proves more"
  fi
  units=$(systemctl list-units --all --plain --no-legend --no-pager 'hardening-rollback-*.timer' 2>/dev/null | awk '{print $1}' || true)
  mkdir -p "$LH_MARK_DIR"
  for u in $units; do
    g=${u#hardening-rollback-}; g=${g%.timer}
    if [[ -e $LH_MARK_DIR/rolledback-$g ]] || ! systemctl is-active --quiet "$u" \
       || systemctl is-active --quiet "${u%.timer}.service"; then
      echo "TOO LATE: $u already fired; $g changes were (or are being) rolled back" >&2
      continue
    fi
    cancel_rollback "$g"
    echo "cancelled $u"
    found=true
  done
  $found || echo "no pending rollback units"
}

do_list_backups() {
  local d n
  [[ -d $LH_BACKUP_ROOT ]] || { echo "no backups in $LH_BACKUP_ROOT"; return 0; }
  for d in "$LH_BACKUP_ROOT"/*/; do
    [[ -f $d/manifest ]] || continue
    n=$(grep -cv '^#' "$d/manifest" || true)
    printf '%s  (%s entries; groups: %s)\n' "$(basename "$d")" "$n" \
      "$(awk '!/^#/ && $1!="note" {print $2}' "$d/manifest" | sort -u | paste -sd, -)"
  done
}

do_restore() {
  local ts=$1 dir groups g script
  [[ $ts =~ ^[0-9]{8}-[0-9]{6}(-[0-9]+)?$ ]] || die "invalid timestamp: $ts"
  dir="$LH_BACKUP_ROOT/$ts"
  [[ -f $dir/manifest ]] || die "no backup manifest at $dir"
  groups=$(awk '!/^#/ && $1!="note" {print $2}' "$dir/manifest" | sort -u)
  script=$(
    echo 'set -u'
    lh_render_restore_cmds "$dir"
    for g in $groups; do lh_render_reload_cmds "$g" "$dir"; done
  )
  if [[ $LH_MODE == check ]]; then
    echo "# restore plan for $ts:"
    printf '%s\n' "$script"
    return 0
  fi
  if ! is_true "$LH_ASSUME_YES"; then
    [[ -t 0 ]] || die "--restore needs --yes when not interactive"
    printf 'Restore backup %s (groups: %s)? [y/N] ' "$ts" "$(echo "$groups" | paste -sd, -)" >&2
    local ans; read -r ans
    [[ $ans == [yY]* ]] || die "aborted"
  fi
  for g in $groups; do systemctl stop "$(rollback_unit "$g").timer" >/dev/null 2>&1 || true; done
  bash -c "$script"
  echo "restored $ts"
}

# ---------------------------------------------------------------------------
print_report() {
  local g kinds msg status rc=0 any_warn=false any_err=false any_fail=false
  local -a ch wa sk er pa fa na
  echo
  if [[ $LH_MODE == audit ]]; then
    printf '%-10s %-6s %-6s %-6s %s\n' GROUP PASS FAIL N/A NOTES
  else
    printf '%-10s %s\n' GROUP RESULT
  fi
  for g in "${LH_GROUPS[@]}" confirm; do
    kinds=$(awk -F'\t' -v g="$g" '$1==g' "$LH_RESULTS")
    if [[ $g == confirm && -z $kinds ]]; then continue; fi
    mapfile -t ch < <(awk -F'\t' '$2=="changed"{print $3}' <<<"$kinds")
    mapfile -t wa < <(awk -F'\t' '$2=="warn"{print $3}' <<<"$kinds")
    mapfile -t sk < <(awk -F'\t' '$2=="skip"{print $3}' <<<"$kinds")
    mapfile -t er < <(awk -F'\t' '$2=="error"{print $3}' <<<"$kinds")
    mapfile -t pa < <(awk -F'\t' '$2=="pass"{print $3}' <<<"$kinds")
    mapfile -t fa < <(awk -F'\t' '$2=="fail"{print $3}' <<<"$kinds")
    mapfile -t na < <(awk -F'\t' '$2=="na"{print $3}' <<<"$kinds")
    (( ${#wa[@]} )) && any_warn=true
    (( ${#er[@]} )) && any_err=true
    (( ${#fa[@]} )) && any_fail=true
    if [[ $LH_MODE == audit ]]; then
      if (( ${#sk[@]} )); then
        printf '%-10s %-6s %-6s %-6s skipped (%s)\n' "$g" - - - "${sk[0]}"
        continue
      fi
      msg=""
      (( ${#fa[@]} )) && msg="failed: $(IFS=';'; echo "${fa[*]}")"
      (( ${#er[@]} )) && msg="error: ${er[*]} $msg"
      printf '%-10s %-6s %-6s %-6s %s\n' "$g" "${#pa[@]}" "${#fa[@]}" "${#na[@]}" "$msg"
      continue
    fi
    if (( ${#er[@]} )); then
      status="error ($(IFS=';'; echo "${er[*]}"))"
    elif (( ${#sk[@]} )); then
      status="skipped (${sk[0]})"
    elif (( ${#ch[@]} )); then
      if [[ $LH_MODE == check ]]; then status="would change (${#ch[@]})"; else status="changed (${#ch[@]})"; fi
    else
      status=ok
    fi
    if (( ${#wa[@]} )); then status+="; warning ($(IFS=';'; echo "${wa[*]}"))"; fi
    printf '%-10s %s\n' "$g" "$status"
  done
  if [[ $LH_MODE != audit ]]; then report_reboot_required; fi

  if $any_err || $any_fail; then rc=1
  elif $any_warn && [[ $LH_MODE != audit ]]; then rc=2
  fi
  return "$rc"
}

report_reboot_required() {
  local need="no"
  case $OS_FAMILY in
    debian) [[ -e /var/run/reboot-required ]] && need=yes ;;
    rhel)
      if command -v needs-restarting >/dev/null 2>&1; then
        needs-restarting -r >/dev/null 2>&1 || need=yes
      elif dnf needs-restarting --help >/dev/null 2>&1; then
        dnf -q needs-restarting -r >/dev/null 2>&1 || need=yes
      else need=unknown; fi ;;
    suse)
      local rc=0
      zypper -q needs-rebooting >/dev/null 2>&1 || rc=$?
      if (( rc == 102 )); then need=yes; elif (( rc != 0 )); then need=unknown; fi ;;
  esac
  printf '%-10s %s\n' reboot "required: $need"
}

# ---------------------------------------------------------------------------
main() {
  local action=run cfg="" only="" skip="" restore_ts="" g
  while (( $# )); do
    case $1 in
      -h|--help) usage; exit 0 ;;
      --check) LH_MODE=check ;;
      --audit) LH_MODE=audit ;;
      --yes|-y) LH_ASSUME_YES=true ;;
      --confirm) action=confirm ;;
      --restore) action=restore; restore_ts=${2:-}; [[ -n $restore_ts ]] || die "--restore needs a timestamp"; shift ;;
      --list-backups) action=list ;;
      --config) cfg=${2:-}; [[ -n $cfg ]] || die "--config needs a file"; shift ;;
      --only) only=${2:-}; shift ;;
      --skip) skip=${2:-}; shift ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
  done

  (( EUID == 0 )) || die "must be run as root (try: sudo $0 ...)"

  case $action in
    confirm) do_confirm; exit 0 ;;
    list) do_list_backups; exit 0 ;;
  esac

  lh_locate_data
  lh_load_config "$cfg"
  lh_detect_os

  LH_RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/linux-hardening.XXXXXX")
  LH_RESULTS="$LH_RUN_DIR/results"
  : >"$LH_RESULTS"
  trap 'rm -rf "$LH_RUN_DIR"' EXIT

  if [[ $action == restore ]]; then do_restore "$restore_ts"; exit 0; fi

  exec 9>/run/linux-hardening.lock
  flock -n 9 || die "another harden.sh run is in progress"

  if [[ $LH_MODE == apply ]]; then
    local pend
    pend=$(systemctl list-timers --all --plain --no-legend 'hardening-rollback-*.timer' 2>/dev/null | grep -o 'hardening-rollback-[a-z0-9]*\.timer' || true)
    [[ -z $pend ]] || die "auto-rollback still pending from an earlier run ($pend): run --confirm or wait for it"
  fi

  LH_TS=$(date +%Y%m%d-%H%M%S)
  [[ -e $LH_BACKUP_ROOT/$LH_TS ]] && LH_TS="$LH_TS-$$"
  LH_BACKUP_DIR="$LH_BACKUP_ROOT/$LH_TS"

  local -a sel_only=() sel_skip=()
  local glist
  if [[ -n $only ]]; then glist=$(_csv_to_groups "$only"); read -r -a sel_only <<<"$glist"; fi
  if [[ -n $skip ]]; then glist=$(_csv_to_groups "$skip"); read -r -a sel_skip <<<"$glist"; fi

  log_info "$OS_PRETTY (family $OS_FAMILY, $ARCH) — mode: $LH_MODE — data: $LH_DATA_DIR"

  if [[ $LH_MODE == apply ]] && ! is_true "$LH_ASSUME_YES"; then
    [[ -t 0 ]] || die "not interactive: pass --yes to apply without prompting"
    printf 'Apply hardening to %s (%s)? [y/N] ' "$(hostname)" "$OS_PRETTY" >&2
    local ans; read -r ans
    [[ $ans == [yY]* ]] || die "aborted by operator"
  fi

  for g in "${LH_GROUPS[@]}"; do
    # Confirm SSH/firewall right after they activate (firewall is followed by
    # fail2ban), before slower groups eat into the rollback window.
    if [[ $g == fail2ban ]]; then confirm_pending_rollbacks; fi
    CURRENT_GROUP=$g
    if (( ${#sel_only[@]} )) && ! _in_list "$g" "${sel_only[@]}"; then
      _result skip "not selected (--only)"; continue
    fi
    if (( ${#sel_skip[@]} )) && _in_list "$g" "${sel_skip[@]}"; then
      _result skip "excluded (--skip)"; continue
    fi
    if ! lh_group_enabled "$g"; then
      _result skip "disabled (HARDEN_${g^^}=false)"; continue
    fi
    run_group "$g"
  done
  confirm_pending_rollbacks
  CURRENT_GROUP=main

  if [[ -d $LH_BACKUP_DIR ]]; then log_info "backup: $LH_BACKUP_DIR (restore with --restore $LH_TS)"; fi
  local rc=0
  print_report || rc=$?
  exit "$rc"
}

main "$@"
