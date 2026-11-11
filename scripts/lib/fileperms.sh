# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: fileperms — permissions on sensitive files, /dev/shm and /tmp options.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

FP_TMP_DROPIN=/etc/systemd/system/tmp.mount.d/99-hardening.conf
FP_SHM_LINE="tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"

# Desired "path mode owner" (owner empty = keep).
fp_targets() {
  local f g m
  for f in /etc/ssh/ssh_host_*_key; do
    [[ -f $f ]] || continue
    g=$(stat -c '%G' "$f")
    if [[ $g == ssh_keys ]]; then echo "$f 0640 root:ssh_keys"; else echo "$f 0600 root:root"; fi
  done
  for f in /etc/ssh/ssh_host_*_key.pub; do [[ -f $f ]] && echo "$f 0644 root:root"; done
  for f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-; do
    [[ -f $f ]] || continue
    m=$(stat -c '%a' "$f")
    # strip world bits and group-write; keep distro owner/group
    printf '%s %04o \n' "$f" $(( 8#$m & ~8#027 & 8#7777 ))
  done
  for f in /etc/passwd /etc/group; do [[ -f $f ]] && echo "$f 0644 root:root"; done
  [[ -f /etc/crontab ]] && echo "/etc/crontab 0600 root:root"
  for f in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d $f ]] && echo "$f 0700 root:root"
  done
  for f in /boot/grub*/grub.cfg; do [[ -f $f ]] && echo "$f 0600 "; done
  return 0
}

fp_shm_fstab_entry() { awk '$1 !~ /^#/ && $2 == "/dev/shm"' /etc/fstab 2>/dev/null || true; }
# Last (topmost) mount at $1; /proc is used because findmnt isn't on every minimal image.
fp_mount_opts() { awk -v m="$1" '$2 == m { o = $4 } END { print o }' /proc/self/mounts 2>/dev/null || true; }
_has_opts() { local o; for o in "${@:2}"; do [[ ,$1, == *,$o,* ]] || return 1; done; }

fp_tmp_is_tmpmount() {
  [[ $(findmnt -no FSTYPE /tmp 2>/dev/null || true) == tmpfs ]] && unit_active tmp.mount
}
fp_render_tmp_dropin() { printf '%s\n' "# Managed by linux-hardening." "[Mount]" "Options=mode=1777,strictatime,nosuid,nodev"; }

apply_fileperms() {
  local p mode owner entry
  while read -r p mode owner; do
    ensure_perms "$p" "$mode" "${owner:-}" || mark_warn "could not set permissions on $p"
  done < <(fp_targets)

  # /dev/shm
  entry=$(fp_shm_fstab_entry)
  if [[ -z $entry ]]; then
    install_content /etc/fstab 0644 root:root "$(cat /etc/fstab 2>/dev/null; echo "$FP_SHM_LINE")"
  elif ! _has_opts "$(awk '{print $4}' <<<"$entry")" nodev nosuid noexec; then
    mark_warn "/etc/fstab has a /dev/shm entry without nodev,nosuid,noexec; not editing it"
  fi
  if ! _has_opts "$(fp_mount_opts /dev/shm)" nodev nosuid noexec; then
    mark_changed "remount /dev/shm nodev,nosuid,noexec"
    run mount -o remount,nodev,nosuid,noexec /dev/shm || mark_warn "remount of /dev/shm failed"
  fi

  # /tmp
  if fp_tmp_is_tmpmount; then
    install_content "$FP_TMP_DROPIN" 0644 root:root "$(fp_render_tmp_dropin)"
    if (( INSTALL_CHANGED )); then run systemctl daemon-reload; fi
    if ! _has_opts "$(fp_mount_opts /tmp)" nosuid nodev; then  # strictatime isn't shown in /proc/mounts
      mark_changed "remount /tmp nosuid,nodev,strictatime"
      run mount -o remount,nosuid,nodev,strictatime /tmp || mark_warn "remount of /tmp failed"
    fi
  else
    mark_info "/tmp is not a tmp.mount tmpfs: /tmp options skipped"
  fi
}

audit_fileperms() {
  local p mode owner cur cur_owner entry list
  while read -r p mode owner; do
    cur=$(stat -c '%a' "$p"); cur_owner=$(stat -c '%U:%G' "$p")
    if (( 8#$cur == 8#$mode )) && [[ -z ${owner:-} || $cur_owner == "$owner" ]]; then
      audit_pass "$p $mode${owner:+ $owner}"
    else
      audit_fail "$p $mode${owner:+ $owner} (is $cur $cur_owner)"
    fi
  done < <(fp_targets)

  entry=$(fp_shm_fstab_entry)
  if [[ -n $entry ]] && _has_opts "$(awk '{print $4}' <<<"$entry")" nodev nosuid noexec; then
    audit_pass "/etc/fstab /dev/shm nodev,nosuid,noexec"; else audit_fail "/etc/fstab /dev/shm nodev,nosuid,noexec"; fi
  if _has_opts "$(fp_mount_opts /dev/shm)" nodev nosuid noexec; then audit_pass "/dev/shm mounted nodev,nosuid,noexec"
  else audit_fail "/dev/shm mounted nodev,nosuid,noexec"; fi

  if fp_tmp_is_tmpmount; then
    audit_content "$FP_TMP_DROPIN" "$(fp_render_tmp_dropin)"
    if _has_opts "$(fp_mount_opts /tmp)" nosuid nodev; then audit_pass "/tmp mounted nosuid,nodev"; else audit_fail "/tmp mounted nosuid,nodev"; fi
  else
    audit_na "/tmp not a tmp.mount tmpfs"
  fi

  # Listing only (slow): not pass/fail, the spec only asks to list them.
  log_info "scanning local filesystems for world-writable and unowned files (slow)..."
  list=$(df --local -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR > 1 {print $6}' \
    | while IFS= read -r p; do
        find "$p" -xdev \( -type f -perm -0002 -printf 'world-writable %p\n' \) -o \( \( -nouser -o -nogroup \) -printf 'unowned %p\n' \) 2>/dev/null || true
      done | sort -u)
  if [[ -n $list ]]; then
    mark_info "world-writable/unowned files: $(wc -l <<<"$list") (listed below)"
    head -n 200 <<<"$list" | while IFS= read -r p; do printf '    %s\n' "$p"; done >&2
  else
    audit_pass "no world-writable or unowned files on local filesystems"
  fi
}
