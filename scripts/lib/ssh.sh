# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: ssh — sshd drop-in with lockout protection (safety rule 1) and
# auto-rollback (safety rule 3).
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

SSH_DROPIN_DIR=/etc/ssh/sshd_config.d
SSH_DROPIN="$SSH_DROPIN_DIR/00-hardening.conf"
SSH_KEX="sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org"
SSH_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
SSH_MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"

# Filled by ssh_compute_policy
SSHD_T=""
SSH_KEY_ONLY=false
SSH_ROOT_LOGIN=prohibit-password
SSH_CAPABLE_USERS=()
SSH_POLICY_WARNINGS=()

sshd_bin() { command -v sshd 2>/dev/null || echo /usr/sbin/sshd; }

# Main config: SUSE 16/Tumbleweed ship only the vendor file in /usr/etc.
ssh_main_config() {
  if [[ $OS_FAMILY == suse && ! -e /etc/ssh/sshd_config && -e /usr/etc/ssh/sshd_config ]]; then
    echo /usr/etc/ssh/sshd_config
  else
    echo /etc/ssh/sshd_config
  fi
}

ssh_service() { if [[ $OS_FAMILY == debian ]]; then echo ssh; else echo sshd; fi; }

# Ubuntu 22.10+ socket activation.
ssh_socket_mode() { [[ $OS_FAMILY == debian && $(unit_state ssh.socket) == enabled ]]; }

# Values of a keyword from cached `sshd -T` output (one per line).
sshd_t_get() { awk -v k="${1,,}" '$1 == k { $1 = ""; sub(/^ /, ""); print }' <<<"$SSHD_T"; }

# Debian/Ubuntu sshd -t/-T need /run/sshd, which only exists while ssh.service
# runs (idle socket activation). It is a runtime tmpfs dir; creating it is harmless.
ssh_prepare_runtime() {
  if [[ $OS_FAMILY == debian && ! -d /run/sshd ]]; then mkdir -m 0755 /run/sshd; fi
}

ssh_load_effective() {
  ssh_prepare_runtime
  SSHD_T=$("$(sshd_bin)" -T 2>/dev/null) || return 1
  [[ -n $SSHD_T ]]
}

# Expand sshd tokens in an AuthorizedKeysFile entry. Relative -> $home.
# Usage: ssh_expand_akf PATTERN USER HOME UID
ssh_expand_akf() {
  local p=$1 user=$2 home=$3 uid=$4 out="" i c n
  for (( i = 0; i < ${#p}; i++ )); do
    c=${p:i:1}
    if [[ $c == "%" ]]; then
      n=${p:i+1:1}
      i=$(( i + 1 ))
      case $n in
        %) out+="%" ;;
        h) out+=$home ;;
        u) out+=$user ;;
        U) out+=$uid ;;
        *) return 1 ;;  # unsupported token: treat as unusable
      esac
    else
      out+=$c
    fi
  done
  [[ $out == /* ]] || out="$home/$out"
  printf '%s' "$out"
}

_valid_login_shell() {
  case ${1##*/} in
    ''|nologin|false|sync|shutdown|halt) return 1 ;;
  esac
  [[ -x $1 ]]
}

# Non-root members (supplementary or primary) of sudo/wheel.
ssh_admin_candidates() {
  local grp line gid members u
  for grp in sudo wheel; do
    line=$(getent group "$grp" 2>/dev/null) || continue
    gid=$(cut -d: -f3 <<<"$line")
    members=$(cut -d: -f4 <<<"$line")
    tr ',' '\n' <<<"$members"
    getent passwd | awk -F: -v g="$gid" '$4 == g { print $1 }'
  done | while IFS= read -r u; do
    if [[ -n $u ]]; then echo "$u"; fi
  done | sort -u
  return 0
}

# Does <user> have at least one key line in an AuthorizedKeysFile?
ssh_user_has_keys() {
  local user=$1 home=$2 uid=$3 pat f
  local akf; akf=$(sshd_t_get authorizedkeysfile | head -n1)
  [[ -z $akf || $akf == none ]] && return 1
  for pat in $akf; do
    f=$(ssh_expand_akf "$pat" "$user" "$home" "$uid") || continue
    if [[ -s $f ]] && grep -qEv '^[[:space:]]*(#|$)' "$f" 2>/dev/null; then return 0; fi
  done
  return 1
}

_in_words() { local x=$1 w; for w in $2; do [[ ${w%%@*} == "$x" ]] && return 0; done; return 1; }

# Decide key-only / root login policy (safety rule 1). Needs SSHD_T loaded.
ssh_compute_policy() {
  local u ent uid home shell akc have_akc=false
  SSH_CAPABLE_USERS=()
  SSH_POLICY_WARNINGS=()
  akc=$(sshd_t_get authorizedkeyscommand | head -n1)
  [[ -n $akc && ${akc,,} != none ]] && have_akc=true

  while IFS= read -r u; do
    ent=$(getent passwd "$u") || continue                       # (a) exists
    uid=$(cut -d: -f3 <<<"$ent"); home=$(cut -d: -f6 <<<"$ent"); shell=$(cut -d: -f7 <<<"$ent")
    [[ $uid == 0 || $u == root ]] && continue                    # non-root
    _valid_login_shell "$shell" || continue                       # (b)
    # (c) sudo/wheel membership is given by ssh_admin_candidates
    if $have_akc || ssh_user_has_keys "$u" "$home" "$uid"; then  # (d)
      if [[ -z $HARDEN_SSH_ALLOW_USERS ]] || _in_words "$u" "$HARDEN_SSH_ALLOW_USERS"; then
        SSH_CAPABLE_USERS+=("$u")
      fi
    fi
  done < <(ssh_admin_candidates)

  if (( ${#SSH_CAPABLE_USERS[@]} )); then
    SSH_KEY_ONLY=true
    SSH_ROOT_LOGIN=no
  else
    local rhome; rhome=$(getent passwd root | cut -d: -f6)
    if $have_akc || ssh_user_has_keys root "${rhome:-/root}" 0; then
      SSH_ROOT_LOGIN=prohibit-password
      SSH_POLICY_WARNINGS+=("no key-capable sudo/wheel user${HARDEN_SSH_ALLOW_USERS:+ in HARDEN_SSH_ALLOW_USERS}: PermitRootLogin prohibit-password (root keys keep working)")
    else
      # Deviation from SPEC: prohibit-password would lock out a root-only,
      # password-only host. Leave PermitRootLogin unmanaged instead.
      SSH_ROOT_LOGIN=""
      SSH_POLICY_WARNINGS+=("no key-capable user and root has no authorized keys: PermitRootLogin left unmanaged to avoid lockout")
    fi
    if is_true "$HARDEN_FORCE_KEY_ONLY"; then
      SSH_KEY_ONLY=true
      SSH_POLICY_WARNINGS+=("HARDEN_FORCE_KEY_ONLY=true: disabling password auth without a verified key-capable user")
    else
      SSH_KEY_ONLY=false
      SSH_POLICY_WARNINGS+=("password authentication left enabled (no key-capable user; set HARDEN_FORCE_KEY_ONLY=true to override)")
    fi
  fi
}

# Comma list filtered to algorithms supported by the installed OpenSSH.
ssh_filter_algos() {
  local type=$1 list=$2 supported a out=()
  supported=$(ssh -Q "$type" 2>/dev/null || true)
  [[ -n $supported ]] || return 0
  IFS=',' read -r -a algos <<<"$list"
  for a in "${algos[@]}"; do
    grep -qxF "$a" <<<"$supported" && out+=("$a")
  done
  (( ${#out[@]} )) && (IFS=','; printf '%s' "${out[*]}")
  return 0
}

ssh_manage_crypto() { [[ $OS_FAMILY != rhel ]] && ! fips_enabled; }

# Desired "Keyword value" lines (policy must be computed).
ssh_desired_settings() {
  local v
  echo "Port $HARDEN_SSH_PORT"
  if [[ -n $SSH_ROOT_LOGIN ]]; then echo "PermitRootLogin $SSH_ROOT_LOGIN"; fi
  if $SSH_KEY_ONLY; then
    echo "PasswordAuthentication no"
    echo "KbdInteractiveAuthentication no"
  fi
  cat <<'EOF'
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no
UseDNS no
LogLevel VERBOSE
Banner /etc/issue.net
HostbasedAuthentication no
IgnoreRhosts yes
EOF
  if [[ -n $HARDEN_SSH_ALLOW_USERS ]]; then echo "AllowUsers $HARDEN_SSH_ALLOW_USERS"; fi
  if ssh_manage_crypto; then
    v=$(ssh_filter_algos kex "$SSH_KEX");        [[ -n $v ]] && echo "KexAlgorithms $v"
    v=$(ssh_filter_algos cipher "$SSH_CIPHERS"); [[ -n $v ]] && echo "Ciphers $v"
    v=$(ssh_filter_algos mac "$SSH_MACS");       [[ -n $v ]] && echo "MACs $v"
  fi
  return 0
}

ssh_render_dropin() {
  echo "# Managed by linux-hardening — do not edit; changes are overwritten."
  echo "# Must sort before 50-*.conf: sshd uses the first value it reads."
  ssh_desired_settings
}

ssh_include_present() {
  grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$1" 2>/dev/null
}

ssh_check_allow_users() {
  local u
  for u in $HARDEN_SSH_ALLOW_USERS; do
    getent passwd "${u%%@*}" >/dev/null || return 1
  done
}

ssh_rhel_crypto_policy_check() {
  local pol
  [[ $OS_FAMILY == rhel ]] || return 0
  fips_enabled && return 0
  command -v update-crypto-policies >/dev/null 2>&1 || return 0
  pol=$(update-crypto-policies --show 2>/dev/null || true)
  if [[ $pol == LEGACY* ]]; then
    mark_warn "system crypto policy is $pol; use at least DEFAULT (update-crypto-policies --set DEFAULT)"
  fi
}

ssh_selinux_port() {
  local port=$HARDEN_SSH_PORT out
  [[ $port == 22 ]] && return 0
  selinux_enabled || return 0
  if ! command -v semanage >/dev/null 2>&1; then
    ensure_packages policycoreutils-python-utils || die_group "semanage unavailable; cannot label port $port as ssh_port_t"
  fi
  if [[ $LH_MODE == check ]] && ! command -v semanage >/dev/null 2>&1; then
    mark_changed "label tcp/$port as ssh_port_t"; return 0
  fi
  out=$(semanage port -l 2>/dev/null | awk '$1 == "ssh_port_t" && $2 == "tcp"' || true)
  if [[ $out =~ (^|[ ,])$port(,|$) ]]; then return 0; fi
  mark_changed "label tcp/$port as ssh_port_t (SELinux)"
  run semanage port -a -t ssh_port_t -p tcp "$port" 2>/dev/null \
    || run semanage port -m -t ssh_port_t -p tcp "$port" \
    || die_group "semanage failed for port $port"
}

apply_ssh() {
  local sshd main old_ports changed=0 w eff exp key
  sshd=$(sshd_bin)
  [[ -x $sshd ]] || { mark_skip "sshd not installed"; return 0; }
  ssh_load_effective || die_group "sshd -T failed: current sshd configuration is invalid; not touching it"

  if ! ssh_check_allow_users; then
    die_group "HARDEN_SSH_ALLOW_USERS contains a user that does not exist: $HARDEN_SSH_ALLOW_USERS"
  fi
  if [[ -n $HARDEN_SSH_ALLOW_USERS && -n ${SUDO_USER:-} && $SUDO_USER != root ]] \
     && ! _in_words "$SUDO_USER" "$HARDEN_SSH_ALLOW_USERS"; then
    mark_warn "you ($SUDO_USER) are not in HARDEN_SSH_ALLOW_USERS"
  fi

  ssh_compute_policy
  for w in "${SSH_POLICY_WARNINGS[@]}"; do mark_warn "$w"; done
  if (( ${#SSH_CAPABLE_USERS[@]} )); then log_info "key-capable users: ${SSH_CAPABLE_USERS[*]}"; fi
  ssh_rhel_crypto_policy_check
  if fips_enabled; then log_info "FIPS mode: crypto settings left to the system"; fi

  old_ports=$(sshd_t_get port | sort -n | paste -sd' ' -)

  # Include must be in effect for the drop-in.
  main=$(ssh_main_config)
  if ! ssh_include_present "$main"; then
    if [[ $main == /etc/ssh/sshd_config && -f $main ]]; then
      install_content "$main" 0600 root:root "$(printf 'Include /etc/ssh/sshd_config.d/*.conf\n'; cat "$main")"
      (( INSTALL_CHANGED )) && changed=1
    else
      die_group "$main has no 'Include /etc/ssh/sshd_config.d/*.conf'; refusing to edit vendor config"
    fi
  fi

  ssh_selinux_port

  if [[ ! -d $SSH_DROPIN_DIR ]]; then run mkdir -p -m 0755 "$SSH_DROPIN_DIR"; fi
  install_content "$SSH_DROPIN" 0600 root:root "$(ssh_render_dropin)"
  (( INSTALL_CHANGED )) && changed=1

  (( changed )) || return 0
  [[ $LH_MODE == check ]] && return 0

  local err
  if ! err=$("$sshd" -t 2>&1); then
    log_error "sshd -t: $err"
    restore_group_files_now ssh
    die_group "sshd -t failed with the new config; restored previous files"
  fi

  # Effective values (another earlier-sorting file could win).
  ssh_load_effective || true
  for key in port permitrootlogin passwordauthentication; do
    case $key in
      port) exp=$HARDEN_SSH_PORT ;;
      permitrootlogin) [[ -n $SSH_ROOT_LOGIN ]] || continue; exp=$SSH_ROOT_LOGIN ;;
      passwordauthentication) $SSH_KEY_ONLY || continue; exp=no ;;
    esac
    eff=$(sshd_t_get "$key" | sort -un | paste -sd' ' -)
    [[ $exp == prohibit-password && $eff == without-password ]] && eff=$exp
    if [[ $key == port && $eff != "$exp" ]]; then
      # Port lines accumulate across files: another file keeps sshd on extra ports.
      restore_group_files_now ssh
      die_group "effective sshd ports would be '$eff', not '$exp' (another config file sets Port); restored previous files"
    fi
    if [[ ${eff,,} != "${exp,,}" ]]; then
      mark_warn "effective $key is '$eff', expected '$exp' (overridden by another sshd config file?)"
    fi
  done

  if [[ $old_ports != "$HARDEN_SSH_PORT" ]] && ! lh_group_enabled firewall; then
    mark_warn "SSH port changes ($old_ports -> $HARDEN_SSH_PORT) with the firewall group disabled; open the new port yourself"
  fi

  if [[ $old_ports != "$HARDEN_SSH_PORT" ]]; then touch "$LH_RUN_DIR/ssh_port_changed"; fi
  schedule_rollback ssh
  if ! ssh_activate "$old_ports"; then
    rollback_now ssh
    die_group "reloading sshd failed; rolled back"
  fi
  mark_changed "reloaded sshd"
}

# Make the new config effective. Ubuntu socket activation: a port change needs
# daemon-reload (the socket generator reads sshd -T) + ssh.socket restart.
ssh_activate() { # old_ports
  if ssh_socket_mode; then
    if [[ $1 != "$HARDEN_SSH_PORT" ]]; then
      systemctl daemon-reload || return 1
      systemctl restart ssh.socket || return 1
    fi
    systemctl try-reload-or-restart ssh.service || return 1
  else
    systemctl reload-or-restart "$(ssh_service)" || return 1
  fi
}

audit_ssh() {
  local sshd main line key exp eff a b
  sshd=$(sshd_bin)
  [[ -x $sshd ]] || { audit_na "sshd not installed"; return 0; }
  ssh_load_effective || { audit_fail "sshd -T succeeds"; return 0; }
  main=$(ssh_main_config)
  audit_check "$main includes sshd_config.d/*.conf" ssh_include_present "$main"
  ssh_compute_policy
  audit_content "$SSH_DROPIN" "$(ssh_render_dropin)"
  while IFS= read -r line; do
    key=${line%% *}; exp=${line#* }
    eff=$(sshd_t_get "$key" | paste -sd' ' -)
    if [[ $key == AllowUsers ]]; then
      a=$(tr ' ' '\n' <<<"$exp" | sort | paste -sd' ' -); b=$(tr ' ' '\n' <<<"$eff" | sort | paste -sd' ' -)
      if [[ $a == "$b" ]]; then audit_pass "sshd $key"; else audit_fail "sshd $key (is '$eff')"; fi
      continue
    fi
    [[ $exp == prohibit-password && $eff == without-password ]] && eff=$exp
    if [[ ${eff,,} == "${exp,,}" ]]; then audit_pass "sshd $key $exp"; else audit_fail "sshd $key $exp (is '$eff')"; fi
  done < <(ssh_desired_settings)
  if ! $SSH_KEY_ONLY; then audit_na "PasswordAuthentication no (no key-capable user; left enabled by safety rule 1)"; fi
  if [[ $OS_FAMILY == rhel ]] && ! fips_enabled && command -v update-crypto-policies >/dev/null 2>&1; then
    eff=$(update-crypto-policies --show 2>/dev/null || true)
    if [[ $eff == LEGACY* ]]; then audit_fail "crypto policy at least DEFAULT (is $eff)"; else audit_pass "crypto policy at least DEFAULT ($eff)"; fi
  fi
  audit_check "sshd listening on $HARDEN_SSH_PORT" ssh_alive
}
