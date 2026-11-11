# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR
# Group: banner — /etc/issue and /etc/issue.net from data/issue.net.
# shellcheck source=common.sh
[[ -n ${LH_COMMON_LOADED:-} ]] || source "${BASH_SOURCE[0]%/*}/common.sh"

apply_banner() {
  local src f
  src=$(data_file issue.net)
  [[ -r $src ]] || die_group "missing $src"
  for f in /etc/issue /etc/issue.net; do
    install_file "$src" "$f" 0644 root:root
  done
}

audit_banner() {
  local src f
  src=$(data_file issue.net)
  for f in /etc/issue /etc/issue.net; do
    if same_content "$src" "$f"; then audit_pass "$f matches data/issue.net"; else audit_fail "$f matches data/issue.net"; fi
  done
}
