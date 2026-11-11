# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: modules — block kernel modules from data/modules.list.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

MODULES_FILE=/etc/modprobe.d/99-hardening.conf

modules_render() {
  local m
  echo "# Managed by linux-hardening (from data/modules.list)."
  while IFS= read -r m; do
    printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m"
  done < <(data_lines modules.list)
}

modules_loaded() { # print listed modules currently loaded
  local m loaded
  loaded=$(awk '{print $1}' /proc/modules 2>/dev/null || true)
  while IFS= read -r m; do
    grep -qxF "${m//-/_}" <<<"$loaded" && echo "$m"
  done < <(data_lines modules.list)
  return 0
}

apply_modules() {
  local l
  install_content "$MODULES_FILE" 0644 root:root "$(modules_render)"
  l=$(modules_loaded | paste -sd' ' -)
  if [[ -n $l ]]; then mark_info "blocked modules currently loaded (unloaded at next boot): $l"; fi
}

audit_modules() {
  local m out
  if [[ -f $MODULES_FILE && "$(cat "$MODULES_FILE")" == "$(modules_render)" ]]; then audit_pass "$MODULES_FILE up to date"; else audit_fail "$MODULES_FILE up to date"; fi
  while IFS= read -r m; do
    out=$(modprobe -n -v "$m" 2>&1 || true)
    if [[ $out == *"/bin/false"* ]]; then audit_pass "module $m blocked"; else audit_fail "module $m blocked"; fi
  done < <(data_lines modules.list)
  out=$(modules_loaded | paste -sd' ' -)
  if [[ -z $out ]]; then audit_pass "no blocked module loaded"; else audit_fail "blocked modules loaded: $out"; fi
}
