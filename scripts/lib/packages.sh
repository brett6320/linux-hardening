# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: packages — refresh metadata, apply updates, install tooling, remove
# legacy packages from data/remove-packages.list.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

# Packages wanted on this host (respecting group toggles).
packages_wanted() {
  local -a p=(chrony)
  case $OS_FAMILY in
    debian)
      lh_group_enabled auditd && p+=(auditd)
      lh_group_enabled firewall && p+=(nftables)
      lh_group_enabled updates && p+=(unattended-upgrades)
      p+=(needrestart) ;;
    rhel)
      lh_group_enabled auditd && p+=(audit)
      lh_group_enabled firewall && p+=(firewalld)
      if lh_group_enabled updates; then
        if $USE_DNF5; then p+=(dnf5-plugin-automatic); else p+=(dnf-automatic); fi
      fi
      if $USE_DNF5; then p+=(dnf5-plugins)
      elif pkg_installed dnf-utils || pkg_available dnf-utils; then p+=(dnf-utils)
      else p+=(dnf-plugins-core); fi ;;
    suse)
      lh_group_enabled auditd && p+=(audit)
      lh_group_enabled firewall && p+=(firewalld) ;;
  esac
  printf '%s\n' "${p[@]}"
}

# Packages from data/remove-packages.list for this family.
packages_to_remove() {
  local line
  while IFS= read -r line; do
    [[ $line == "$OS_FAMILY":* ]] && printf '%s\n' "${line#*:}"
  done < <(data_lines remove-packages.list)
  return 0
}

pending_update_count() {
  local out
  case $OS_FAMILY in
    debian) out=$(apt-get -s -q upgrade --with-new-pkgs 2>/dev/null || true)
            grep -c '^Inst ' <<<"$out" || true ;;
    rhel)   out=$(dnf -q check-update 2>/dev/null || true)
            grep -cE '^[[:alnum:]_.+-]+\.[[:alnum:]_]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+' <<<"$out" || true ;;
    suse)   out=$(zypper -n -q list-updates 2>/dev/null || true)
            grep -c '^v ' <<<"$out" || true ;;
  esac
}

# EPEL is needed for fail2ban on RHEL and its rebuilds (not Fedora).
packages_ensure_epel() {
  [[ $OS_FAMILY == rhel ]] && ! $IS_FEDORA || return 0
  pkg_installed epel-release && return 0
  if $IS_RHEL; then
    local arch=$ARCH
    mark_changed "enable EPEL + CodeReady Builder (RHEL $OS_MAJOR)"
    run subscription-manager repos --enable "codeready-builder-for-rhel-${OS_MAJOR}-${arch}-rpms" || return 1
    run dnf -q -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_MAJOR}.noarch.rpm" || return 1
  else
    mark_changed "enable EPEL + CRB"
    run dnf -q -y install epel-release || return 1
    run dnf -q -y config-manager --set-enabled crb || run dnf -q -y config-manager setopt crb.enabled=1 || return 1
  fi
}

# SLES needs PackageHub for fail2ban; openSUSE ships it in the main repo.
packages_ensure_packagehub() {
  $IS_SLES || return 0
  pkg_available fail2ban && return 0
  mark_changed "activate SUSE PackageHub"
  run SUSEConnect -p "PackageHub/${OS_VERSION_ID}/${ARCH}" || return 1
  run zypper -n -q refresh || true
  [[ $LH_MODE == check ]] || pkg_available fail2ban
}

apply_packages() {
  local n p
  local -a wanted remove=()

  pkg_refresh || mark_warn "package metadata refresh failed"

  mapfile -t wanted < <(packages_wanted)
  ensure_packages "${wanted[@]}" || mark_warn "some packages failed to install: ${wanted[*]}"

  if lh_group_enabled fail2ban && ! pkg_installed fail2ban; then
    local f2b=(fail2ban) ok=true
    [[ $OS_FAMILY == debian ]] && f2b+=(python3-systemd)
    case $OS_FAMILY in
      rhel) packages_ensure_epel || { ok=false; mark_warn "EPEL unavailable; fail2ban not installed"; } ;;
      suse) packages_ensure_packagehub || { ok=false; mark_warn "PackageHub unavailable; fail2ban not installed"; } ;;
    esac
    if $ok; then ensure_packages "${f2b[@]}" || mark_warn "fail2ban install failed"; fi
  elif lh_group_enabled fail2ban && [[ $OS_FAMILY == debian ]]; then
    ensure_packages python3-systemd || mark_warn "python3-systemd install failed"
  fi

  while IFS= read -r p; do
    [[ -n $p ]] && pkg_installed "$p" && remove+=("$p")
  done < <(packages_to_remove)
  if (( ${#remove[@]} )); then
    mark_changed "remove packages: ${remove[*]}"
    pkg_remove "${remove[@]}" || mark_warn "package removal failed: ${remove[*]}"
  fi

  # Last, so updates from repos enabled above (EPEL, PackageHub) are included.
  # A second pass catches updates that only appear after the first one, e.g.
  # an updated epel-release repointing EPEL to a newer minor-version repo.
  if is_true "$HARDEN_APPLY_UPDATES"; then
    local pass
    for pass in 1 2; do
      if (( pass == 2 )); then
        [[ $LH_MODE == apply ]] || break
        pkg_refresh >/dev/null 2>&1 || true
      fi
      n=$(pending_update_count)
      (( n > 0 )) || break
      if (( pass == 1 )); then mark_changed "apply $n pending updates"
      else mark_changed "apply $n more updates that appeared after the first pass"; fi
      packages_upgrade || mark_warn "applying updates failed"
    done
  fi
}

packages_upgrade() {
  case $OS_FAMILY in
    debian) run env DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get -q -y -o Dpkg::Options::=--force-confold upgrade --with-new-pkgs ;;
    rhel) run dnf -q -y upgrade ;;
    suse) if $IS_TUMBLEWEED; then run zypper -n -q dup --auto-agree-with-licenses
          else run zypper -n -q update --auto-agree-with-licenses; fi ;;
  esac
}

audit_packages() {
  local p
  local -a wanted
  mapfile -t wanted < <(packages_wanted)
  for p in "${wanted[@]}"; do audit_check "package $p installed" pkg_installed "$p"; done
  if lh_group_enabled fail2ban; then audit_check "package fail2ban installed" pkg_installed fail2ban; fi
  while IFS= read -r p; do
    [[ -z $p ]] && continue
    if pkg_installed "$p"; then audit_fail "package $p removed"; else audit_pass "package $p removed"; fi
  done < <(packages_to_remove)
  if is_true "$HARDEN_APPLY_UPDATES"; then
    local n; n=$(pending_update_count)
    if (( n == 0 )); then audit_pass "no pending updates (cached metadata)"; else audit_fail "no pending updates ($n pending)"; fi
  fi
}
