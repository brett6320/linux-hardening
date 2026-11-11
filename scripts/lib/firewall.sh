# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: firewall — default-deny inbound. nftables (debian) or firewalld
# (rhel/suse). Listening-port precheck (safety rule 2), auto-rollback (rule 3).
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

FW_NFT_DIR=/etc/nftables.d
FW_NFT_FILE="$FW_NFT_DIR/hardening.nft"
FW_NFT_CONF=/etc/nftables.conf
FW_NFT_INCLUDE='include "/etc/nftables.d/*.nft"'
FW_ZONE=drop
FW_EXCLUDE_IF_RE='^(docker|cni|veth|wg|tailscale|virbr)'

fw_ufw_active() {
  command -v ufw >/dev/null 2>&1 || return 1
  local out; out=$(ufw status 2>/dev/null || true)
  [[ $out == *"Status: active"* ]]
}

# Is <port> covered by a list of port specs (N or N-M)?
fw_port_in() {
  local port=$1 s; shift
  for s in "$@"; do
    if [[ $s == *-* ]]; then
      (( port >= ${s%-*} && port <= ${s#*-} )) && return 0
    elif [[ $s == "$port" ]]; then
      return 0
    fi
  done
  return 1
}

# shellcheck disable=SC2086  # port lists are space-separated on purpose
fw_allowed() { # proto port
  case $1 in
    tcp) [[ $2 == "$HARDEN_SSH_PORT" ]] || fw_port_in "$2" $HARDEN_ALLOWED_TCP_PORTS ;;
    udp) [[ $2 == 68 || $2 == 546 ]] || fw_port_in "$2" $HARDEN_ALLOWED_UDP_PORTS ;;
    *) return 1 ;;
  esac
}

_fw_is_loopback() {
  case $1 in
    127.*|::1|::ffff:127.*|0:0:0:0:0:0:0:1) return 0 ;;
    *) return 1 ;;
  esac
}

# Print "proto/port addr process" for each non-loopback listening socket not
# covered by the allowlist. In --check mode the current sshd ports are also
# ignored when the ssh group (which would move sshd first) is enabled.
fw_listening_violations() {
  local netid state rq sq local_ peer proc addr port proto extra_ports="" ssout
  command -v ss >/dev/null 2>&1 || die_group "ss not found: cannot run the listening-port precheck"
  ssout=$(ss -Htulpn 2>/dev/null) || die_group "ss -Htulpn failed: cannot run the listening-port precheck"
  if [[ $LH_MODE == check ]] && lh_group_enabled ssh; then
    extra_ports=$("$(command -v sshd || echo /usr/sbin/sshd)" -T 2>/dev/null | awk '$1=="port"{print $2}' | paste -sd' ' - || true)
  fi
  while read -r netid state rq sq local_ peer proc; do
    : "$state" "$rq" "$sq" "$peer"
    [[ -n $local_ ]] || continue
    port=${local_##*:}
    addr=${local_%:*}
    addr=${addr#[}; addr=${addr%]}; addr=${addr%%%*}
    [[ $port =~ ^[0-9]+$ ]] || continue
    _fw_is_loopback "$addr" && continue
    case $netid in tcp*) proto=tcp ;; udp*) proto=udp ;; *) continue ;; esac
    fw_allowed "$proto" "$port" && continue
    [[ " $HARDEN_FIREWALL_IGNORE_LISTENERS " == *" $proto/$port "* ]] && continue
    # shellcheck disable=SC2086  # space-separated port list
    if [[ $proto == tcp && -n $extra_ports ]] && fw_port_in "$port" $extra_ports; then continue; fi
    printf '%s/%s %s %s\n' "$proto" "$port" "$addr" "${proc:-}"
  done <<<"$ssout"
}

# Default-route interfaces, minus container/VPN/virtual ones.
fw_default_ifaces() {
  { ip -o route show default 2>/dev/null; ip -o -6 route show default 2>/dev/null; } \
    | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i+1)}' \
    | sort -u | grep -Ev "$FW_EXCLUDE_IF_RE" || true
}

_fw_sources() { # v4|v6
  local s out=()
  for s in $HARDEN_ADMIN_SOURCES; do
    if [[ $1 == v6 && $s == *:* ]] || [[ $1 == v4 && $s != *:* ]]; then out+=("$s"); fi
  done
  (( ${#out[@]} )) && (IFS=','; printf '%s' "${out[*]// /}" | sed 's/,/, /g')
  return 0
}

_fw_portset() { # space list -> "a, b-c"
  local -a p; read -r -a p <<<"$1"
  (IFS=','; printf '%s' "${p[*]}" | sed 's/,/, /g')
}

fw_render_nft() {
  local v4 v6
  cat <<'EOF'
#!/usr/sbin/nft -f
# Managed by linux-hardening — do not edit.
# Own table, input chain only: no flush ruleset, no forward chain, so Docker,
# Kubernetes and libvirt rules are left alone. Ports published by Docker (-p)
# bypass this chain; use DOCKER-USER or bind them to 127.0.0.1.
table inet hardening {}
delete table inet hardening

table inet hardening {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iifname "lo" accept
		icmp type echo-request limit rate 10/second burst 20 packets accept
		icmp type echo-request drop
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		udp sport 67 udp dport 68 accept
		ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
EOF
  if [[ -n $HARDEN_ADMIN_SOURCES ]]; then
    v4=$(_fw_sources v4); v6=$(_fw_sources v6)
    [[ -n $v4 ]] && printf '\t\tip saddr { %s } tcp dport %s accept\n' "$v4" "$HARDEN_SSH_PORT"
    [[ -n $v6 ]] && printf '\t\tip6 saddr { %s } tcp dport %s accept\n' "$v6" "$HARDEN_SSH_PORT"
  else
    printf '\t\ttcp dport %s accept\n' "$HARDEN_SSH_PORT"
  fi
  [[ -n $HARDEN_ALLOWED_TCP_PORTS ]] && printf '\t\ttcp dport { %s } accept\n' "$(_fw_portset "$HARDEN_ALLOWED_TCP_PORTS")"
  [[ -n $HARDEN_ALLOWED_UDP_PORTS ]] && printf '\t\tudp dport { %s } accept\n' "$(_fw_portset "$HARDEN_ALLOWED_UDP_PORTS")"
  printf '\t}\n}\n'
}

fw_render_nft_conf() {
  if [[ -f $FW_NFT_CONF ]]; then
    cat "$FW_NFT_CONF"
    grep -qxF "$FW_NFT_INCLUDE" "$FW_NFT_CONF" || printf '\n# Added by linux-hardening\n%s\n' "$FW_NFT_INCLUDE"
  else
    printf '#!/usr/sbin/nft -f\n\n%s\n' "$FW_NFT_INCLUDE"
  fi
}

# --- firewalld ------------------------------------------------------------
fw_running() { unit_active firewalld; }
# Permanent-config command: firewall-cmd --permanent when running, else offline.
fwp() { if fw_running; then firewall-cmd --permanent "$@"; else firewall-offline-cmd "$@"; fi; }
fwq() { if fw_running; then firewall-cmd "$@"; else firewall-offline-cmd "$@"; fi; }

_fw_rich_ssh() { # source
  local fam=ipv4
  [[ $1 == *:* ]] && fam=ipv6
  printf 'rule family="%s" source address="%s" port port="%s" protocol="tcp" accept' "$fam" "$1" "$HARDEN_SSH_PORT"
}

# Desired firewalld items: "kind<TAB>value" (kind: port service protocol rich-rule interface)
fw_desired_items() {
  local p s i
  if [[ -n $HARDEN_ADMIN_SOURCES ]]; then
    for s in $HARDEN_ADMIN_SOURCES; do printf 'rich-rule\t%s\n' "$(_fw_rich_ssh "$s")"; done
  else
    printf 'port\t%s/tcp\n' "$HARDEN_SSH_PORT"
  fi
  for p in $HARDEN_ALLOWED_TCP_PORTS; do printf 'port\t%s/tcp\n' "$p"; done
  for p in $HARDEN_ALLOWED_UDP_PORTS; do printf 'port\t%s/udp\n' "$p"; done
  printf 'service\tdhcpv6-client\nprotocol\ticmp\nprotocol\tipv6-icmp\n'
  for i in $(fw_default_ifaces); do printf 'interface\t%s\n' "$i"; done
}

# Items not yet present in the permanent config.
fw_missing_items() {
  local kind val
  while IFS=$'\t' read -r kind val; do
    # NetworkManager-owned interfaces are bound via NM, not the zone file:
    # judge them by their effective zone when firewalld is running.
    if [[ $kind == interface ]] && fw_running; then
      [[ $(firewall-cmd --get-zone-of-interface="$val" 2>/dev/null || true) == "$FW_ZONE" ]] && continue
    elif fwp --zone="$FW_ZONE" "--query-$kind=$val" >/dev/null 2>&1; then
      continue
    fi
    printf '%s\t%s\n' "$kind" "$val"
  done < <(fw_desired_items)
  # SSH restricted to sources: the plain port must not also be open.
  if [[ -n $HARDEN_ADMIN_SOURCES ]] && fwp --zone="$FW_ZONE" "--query-port=$HARDEN_SSH_PORT/tcp" >/dev/null 2>&1; then
    printf 'remove-port\t%s/tcp\n' "$HARDEN_SSH_PORT"
  fi
}

apply_firewall_firewalld() {
  local -a missing
  local kind val dz running=false enabled=false i
  command -v firewall-cmd >/dev/null 2>&1 || { mark_skip "firewalld not installed"; return 0; }
  fw_running && running=true
  [[ $(unit_state firewalld) == enabled ]] && enabled=true
  dz=$(fwq --get-default-zone 2>/dev/null || true)
  mapfile -t missing < <(fw_missing_items)

  if [[ $dz == "$FW_ZONE" ]] && $running && $enabled && (( ${#missing[@]} == 0 )); then return 0; fi

  [[ $dz == "$FW_ZONE" ]] || mark_changed "firewalld default zone $dz -> $FW_ZONE"
  for i in "${missing[@]}"; do mark_changed "firewalld zone $FW_ZONE: ${i/$'\t'/ }"; done
  $running || mark_changed "start firewalld"
  $enabled || mark_changed "enable firewalld"
  [[ $LH_MODE == check ]] && return 0

  backup_dir /etc/firewalld
  manifest_note firewalld_was_active "$($running && echo yes || echo no)"
  for i in "${missing[@]}"; do
    [[ ${i%%$'\t'*} == interface ]] || continue
    val=${i#*$'\t'}
    kind=$(fwq --get-zone-of-interface="$val" 2>/dev/null || true)
    manifest_note iface_prev_zone "$val=${kind:-$dz}"
  done
  schedule_rollback firewall
  if ! fw_firewalld_activate "$dz" "$running" "$enabled" "${missing[@]}"; then
    rollback_now firewall
    die_group "configuring firewalld failed; rolled back"
  fi
}

fw_firewalld_activate() { # default_zone running enabled items...
  local dz=$1 running=$2 enabled=$3 i kind val; shift 3
  for i in "$@"; do
    kind=${i%%$'\t'*}; val=${i#*$'\t'}
    case $kind in
      interface) fwp --zone="$FW_ZONE" "--change-interface=$val" >/dev/null || return 1 ;;
      remove-port) fwp --zone="$FW_ZONE" "--remove-port=$val" >/dev/null || return 1 ;;
      *) fwp --zone="$FW_ZONE" "--add-$kind=$val" >/dev/null || return 1 ;;
    esac
  done
  if [[ $dz != "$FW_ZONE" ]]; then fwq --set-default-zone="$FW_ZONE" >/dev/null || return 1; fi
  if $running; then
    firewall-cmd --reload >/dev/null || return 1
    for i in $(fw_default_ifaces); do
      firewall-cmd --zone="$FW_ZONE" --change-interface="$i" >/dev/null 2>&1 || true
    done
  else
    systemctl enable --now --quiet firewalld || return 1
  fi
  if ! $enabled; then systemctl enable --quiet firewalld || return 1; fi
  mark_changed "firewalld configured and reloaded"
}

apply_firewall_nftables() {
  local tmp content loaded=false file_changed=0 conf_mode=0755 was_enabled
  command -v nft >/dev/null 2>&1 || { mark_skip "nftables not installed"; return 0; }
  content=$(fw_render_nft)
  tmp=$(mktemp "$LH_RUN_DIR/nft.XXXXXX")
  printf '%s\n' "$content" >"$tmp"
  nft -c -f "$tmp" >/dev/null || die_group "generated nftables ruleset failed validation (nft -c)"
  rm -f "$tmp"
  nft list table inet hardening >/dev/null 2>&1 && loaded=true
  was_enabled=$(unit_state nftables)

  if [[ ! -d $FW_NFT_DIR ]]; then run mkdir -p -m 0755 "$FW_NFT_DIR"; fi
  install_content "$FW_NFT_FILE" 0644 root:root "$content"; file_changed=$INSTALL_CHANGED
  [[ -f $FW_NFT_CONF ]] && conf_mode=$(stat -c '%a' "$FW_NFT_CONF")
  tmp=$(mktemp "$LH_RUN_DIR/nftconf.XXXXXX")
  fw_render_nft_conf >"$tmp"
  if [[ $LH_MODE == apply || -f $FW_NFT_FILE ]] && ! nft -c -f "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"
    [[ $LH_MODE == check ]] || restore_group_files_now firewall
    die_group "$FW_NFT_CONF (with include) fails nft -c; it would break the firewall at boot"
  fi
  if [[ $was_enabled != enabled ]] && grep -qE 'policy[[:space:]]+drop' "$FW_NFT_CONF" 2>/dev/null; then
    mark_warn "$FW_NFT_CONF has its own 'policy drop' chains and was never enabled; review it before the next boot"
  fi
  install_file "$tmp" "$FW_NFT_CONF" "$conf_mode" root:root
  rm -f "$tmp"

  if (( file_changed )) || ! $loaded; then
    if [[ $LH_MODE == check ]]; then
      mark_changed "load $FW_NFT_FILE"
    else
      manifest_note nft_table_was_loaded "$($loaded && echo yes || echo no)"
      [[ $was_enabled == enabled ]] || manifest_note nftables_was_enabled no
      schedule_rollback firewall
      if ! nft -f "$FW_NFT_FILE"; then
        rollback_now firewall
        die_group "loading $FW_NFT_FILE failed; rolled back"
      fi
      mark_changed "loaded table inet hardening"
    fi
  fi
  # Enable for boot only: starting nftables.service now would run the distro
  # nftables.conf (often 'flush ruleset') and wipe Docker/libvirt rules.
  if [[ $was_enabled != enabled ]]; then
    mark_changed "enable nftables.service (boot persistence)"
    run systemctl enable --quiet nftables
  fi
}

apply_firewall() {
  local v l
  if fw_ufw_active; then
    mark_warn "ufw is active; not managing the firewall"
    mark_skip "ufw active"
    return 0  # no firewall_ok marker: an SSH port change is not confirmed
  fi
  v=$(fw_listening_violations) || exit 3
  if [[ -n $v ]]; then
    if is_true "$HARDEN_FIREWALL_FORCE"; then
      mark_warn "HARDEN_FIREWALL_FORCE=true: blocking listening ports $(awk '{print $1}' <<<"$v" | sort -u | paste -sd' ' -)"
    else
      log_error "listening on non-loopback ports not in the allowlist:"
      while IFS= read -r l; do printf '    %s\n' "$l"; done <<<"$v" >&2
      die_group "would block listening ports: $(awk '{print $1}' <<<"$v" | sort -u | paste -sd' ' -) (add them to HARDEN_ALLOWED_*_PORTS or set HARDEN_FIREWALL_FORCE=true)"
    fi
  fi
  if [[ $OS_FAMILY == debian ]]; then apply_firewall_nftables; else apply_firewall_firewalld; fi
  touch "$LH_RUN_DIR/firewall_ok"
}

audit_firewall() {
  local kind val i z
  if fw_ufw_active; then audit_na "ufw active; firewall not managed"; return 0; fi
  if [[ $OS_FAMILY == debian ]]; then
    command -v nft >/dev/null 2>&1 || { audit_fail "nftables installed"; return 0; }
    if [[ -f $FW_NFT_FILE && "$(cat "$FW_NFT_FILE")" == "$(fw_render_nft)" ]]; then
      audit_pass "$FW_NFT_FILE up to date"; else audit_fail "$FW_NFT_FILE up to date"; fi
    audit_check "table inet hardening loaded" nft list table inet hardening
    audit_check "$FW_NFT_CONF includes /etc/nftables.d/*.nft" grep -qxF "$FW_NFT_INCLUDE" "$FW_NFT_CONF"
    audit_check "nftables.service enabled" systemctl is-enabled --quiet nftables
  else
    command -v firewall-cmd >/dev/null 2>&1 || { audit_fail "firewalld installed"; return 0; }
    audit_check "firewalld enabled" systemctl is-enabled --quiet firewalld
    if ! fw_running; then audit_fail "firewalld active"; return 0; fi
    audit_pass "firewalld active"
    z=$(firewall-cmd --get-default-zone 2>/dev/null || true)
    if [[ $z == "$FW_ZONE" ]]; then audit_pass "default zone $FW_ZONE"; else audit_fail "default zone $FW_ZONE (is $z)"; fi
    while IFS=$'\t' read -r kind val; do
      if [[ $kind == interface ]]; then
        z=$(firewall-cmd --get-zone-of-interface="$val" 2>/dev/null || true)
        if [[ $z == "$FW_ZONE" ]]; then audit_pass "interface $val in $FW_ZONE"; else audit_fail "interface $val in $FW_ZONE (is ${z:-none})"; fi
      else
        audit_check "zone $FW_ZONE $kind $val" firewall-cmd --permanent --zone="$FW_ZONE" "--query-$kind=$val"
      fi
    done < <(fw_desired_items)
    if [[ -n $HARDEN_ADMIN_SOURCES ]]; then
      if firewall-cmd --permanent --zone="$FW_ZONE" --query-port="$HARDEN_SSH_PORT/tcp" >/dev/null 2>&1; then
        audit_fail "SSH port restricted to HARDEN_ADMIN_SOURCES"; else audit_pass "SSH port restricted to HARDEN_ADMIN_SOURCES"; fi
    fi
  fi
  i=$(fw_listening_violations) || { audit_fail "listening-port check (ss unavailable)"; return 0; }
  if [[ -z $i ]]; then audit_pass "no listening ports outside the allowlist"
  else audit_fail "listening ports outside the allowlist: $(awk '{print $1}' <<<"$i" | sort -u | paste -sd' ' -)"; fi
}
