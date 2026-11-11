# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: sysctl — /etc/sysctl.d/99-hardening.conf from data/sysctl.conf.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

SYSCTL_FILE=/etc/sysctl.d/99-hardening.conf
# Per-interface copies are written for these IPv4 keys (values are OR'd with
# conf.all), for interfaces that exist at boot (not ephemeral virtual ones).
SYSCTL_PER_IF_KEYS="accept_redirects secure_redirects send_redirects accept_source_route"
SYSCTL_SKIP_IF_RE='^(lo|all|default|veth|docker|br-|cni|flannel|cali|lxc|virbr|vnet|tap|tun|wg|tailscale|kube|cilium|vxlan|genev)'

# sysctl.d key -> /proc/sys path. '.' separates components; a '/' inside a
# key stands for a literal '.' (interface names such as eth0.100).
_sysctl_path() {
  local k=${1//./$'\x01'}
  k=${k//\//.}
  k=${k//$'\x01'/\/}
  printf '/proc/sys/%s' "$k"
}

# Emit "key = value" if the key exists in /proc/sys. Keys use '.' separators;
# interface names containing '.' are passed already converted to '/'.
_sysctl_emit() {
  local key=$1 val=$2 path
  path=$(_sysctl_path "$key")
  [[ -e $path ]] && printf '%s = %s\n' "$key" "$val"
  return 0
}

sysctl_render() {
  local line key val ifp ifn k
  echo "# Managed by linux-hardening (from data/sysctl.conf). Missing keys are skipped."
  while IFS= read -r line; do
    [[ $line == *=* ]] || continue
    key=${line%%=*}; val=${line#*=}
    key=${key//[[:space:]]/}; val=$(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' <<<"$val")
    _sysctl_emit "$key" "$val"
  done < <(data_lines sysctl.conf)

  if is_true "$HARDEN_KEXEC_DISABLE"; then _sysctl_emit kernel.kexec_load_disabled 1; fi
  if is_true "$HARDEN_IPV6_ACCEPT_RA_OFF"; then
    _sysctl_emit net.ipv6.conf.all.accept_ra 0
    _sysctl_emit net.ipv6.conf.default.accept_ra 0
  fi
  if is_true "$HARDEN_DISABLE_IPV6"; then
    _sysctl_emit net.ipv6.conf.all.disable_ipv6 1
    _sysctl_emit net.ipv6.conf.default.disable_ipv6 1
  fi

  # Per-interface redirect/source-route keys, with the value used for conf.all.
  for ifp in /proc/sys/net/ipv4/conf/*; do
    ifn=${ifp##*/}
    [[ $ifn =~ $SYSCTL_SKIP_IF_RE ]] && continue
    for k in $SYSCTL_PER_IF_KEYS; do
      val=$(data_lines sysctl.conf | awk -F= -v k="net.ipv4.conf.all.$k" '{g=$1; gsub(/[[:space:]]/, "", g)} g == k {v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); print v; exit}')
      [[ -n $val ]] && _sysctl_emit "net.ipv4.conf.${ifn//./\/}.$k" "$val"
    done
  done
  return 0
}

# Lines whose runtime value differs: "key want have"
sysctl_mismatches() {
  local key val path have line
  while IFS= read -r line; do
    [[ $line == *=* && $line != \#* ]] || continue
    key=${line%% =*}; val=${line#*= }
    path=$(_sysctl_path "$key")
    [[ -r $path ]] || continue
    have=$(tr -s '[:space:]' ' ' <"$path" | sed 's/ $//')
    [[ $have == "$val" ]] || printf '%s want=%s have=%s\n' "$key" "$val" "$have"
  done <<<"$1"
}

apply_sysctl() {
  local content mm
  content=$(sysctl_render)
  install_content "$SYSCTL_FILE" 0644 root:root "$content"
  [[ $LH_MODE == check ]] && return 0
  if (( INSTALL_CHANGED )); then
    sysctl --system >/dev/null 2>&1 || mark_warn "sysctl --system reported errors"
  else
    mm=$(sysctl_mismatches "$content")
    if [[ -n $mm ]]; then
      mark_changed "runtime differs, applying $SYSCTL_FILE"
      sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
    fi
  fi
  mm=$(sysctl_mismatches "$content")
  if [[ -n $mm ]]; then mark_warn "runtime sysctl values differ (overridden later or read-only): $(awk '{print $1}' <<<"$mm" | paste -sd' ' -)"; fi
}

audit_sysctl() {
  local content mm key
  content=$(sysctl_render)
  audit_content "$SYSCTL_FILE" "$content"
  mm=$(sysctl_mismatches "$content")
  while IFS= read -r key; do
    [[ -z $key ]] && continue
    if grep -q "^$key " <<<"$mm"; then audit_fail "sysctl $(grep "^$key " <<<"$mm")"; else audit_pass "sysctl $key"; fi
  done < <(grep -v '^#' <<<"$content" | awk '{print $1}')
}
