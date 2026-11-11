# Hardening Spec

Single source of truth for **what** gets hardened. Both implementations —
`scripts/` (bash, no deps beyond the base OS) and `ansible/` (one role,
`ansible.builtin` modules only — no extra collections) — implement exactly
these controls with the same variable names and defaults.

Lists that would otherwise be duplicated live in `data/` and are consumed by
both implementations verbatim:

| File                     | Content                                                 |
|--------------------------|---------------------------------------------------------|
| `data/sysctl.conf`       | sysctl `key = value` lines (comments allowed)           |
| `data/modules.list`      | kernel modules to block, one per line                   |
| `data/services.list`     | systemd units to disable when *not running*             |
| `data/audit.rules`       | auditd rules (arch-specific lines use `ARCH` placeholders, see auditd) |
| `data/remove-packages.list` | `family:pkg` lines for packages to remove            |
| `data/issue.net`         | login banner text                                       |

## Supported distributions

| Family | Distros                                                | Pkg mgr | Firewall  | MAC      |
|--------|--------------------------------------------------------|---------|-----------|----------|
| debian | Debian 12/13, Ubuntu 22.04/24.04                       | apt     | nftables  | AppArmor |
| rhel   | RHEL/Rocky/Alma 9/10, CentOS Stream 9/10, Fedora 41+   | dnf     | firewalld | SELinux  |
| suse   | openSUSE Leap 15.6/16, Tumbleweed, SLES 15/16          | zypper  | firewalld | AppArmor (Leap ≤15/SLES 15) / SELinux (Leap 16, TW, SLES 16) — enable whatever is shipped |

Detection: `/etc/os-release` `ID` then `ID_LIKE`. Unknown → abort.

## Safety rules (non-negotiable)

1. **No SSH lockout.**
   - "Key-capable user" = a non-root user that (a) exists, (b) has a login
     shell, (c) is in `sudo` or `wheel`, (d) has a non-empty authorized keys
     file per `sshd -T` `authorizedkeysfile` (expand `%h`/`%u`), or
     `AuthorizedKeysCommand` is configured.
   - `PasswordAuthentication no` + `KbdInteractiveAuthentication no` only if a
     key-capable user exists (and, when `SSH_ALLOW_USERS` is set, that user is
     in it), or `HARDEN_FORCE_KEY_ONLY=true`. Otherwise warn, leave on.
   - `PermitRootLogin no` only if a key-capable user exists; otherwise, if
     root has authorized keys, `prohibit-password` (+ warning); if root has
     none either, leave PermitRootLogin unset (+ warning) — anything else
     would lock out a password-only root host.
   - Every name in `SSH_ALLOW_USERS` must exist, else abort the SSH group.
2. **Firewall can't cut existing services.** Before enabling, list listening
   TCP/UDP sockets on non-loopback addresses (`ss -Htulpn`). Any port not in
   the allowlist (SSH + `ALLOWED_*_PORTS` + dhcp client 68/546 udp +
   `FIREWALL_IGNORE_LISTENERS`) → abort the
   firewall group with a list of the ports, unless `HARDEN_FIREWALL_FORCE=true`.
3. **Auto-rollback for SSH and firewall changes.** Before reloading sshd or
   activating firewall rules, schedule a rollback with
   `systemd-run --on-active=<HARDEN_ROLLBACK_SECONDS> --unit=hardening-rollback-<group>`
   that restores the backup and reloads. Cancel it only after confirming
   connectivity:
   - Ansible: `meta: reset_connection` + `wait_for_connection` (a real new
     SSH connection), then stop the rollback unit.
   - Shell: if stdin is a TTY, ask the operator to confirm from a **new** SSH
     session (`harden.sh --confirm`) within the window; non-interactive runs
     (`--yes`) cancel the rollback once `sshd -t` passes and sshd is active
     and listening on the port. Because that check is local-only, `--yes`
     refuses (aborts the group) unless `HARDEN_UNATTENDED_FORCE=true` when:
     the SSH port changes; the SSH client address of the invoking session is
     outside `ADMIN_SOURCES` (when set); or the invoking user (`SUDO_USER`,
     else the SSH session owner) is not in `SSH_ALLOW_USERS` or would lose
     password auth without authorized keys.
   - The pending SSH and firewall rollbacks of a run are **one transaction**:
     they are cancelled together only when every group verified; if any
     group failed verification or its rollback already fired, all of them
     roll back immediately (a fired rollback also rolls back the others, and
     `--confirm` then cancels nothing). Timers use `RemainAfterElapse=no`;
     a fired rollback is detected by the marker the rollback script writes
     (`/run/linux-hardening/rolledback-<group>`).
4. Every file modified is backed up first to
   `/var/backups/linux-hardening/<timestamp>/<original path>` with a
   `manifest` listing created (vs modified) files. `--restore <timestamp>`
   reverts (delete created, restore modified, reload affected services).
   The two implementations keep different manifest formats (the shell one
   starts with `# linux-hardening backup`); each refuses to restore the
   other's backups and points to the right tool.
5. Drop-ins over editing vendor files. sshd: `/etc/ssh/sshd_config.d/00-hardening.conf`
   (sshd is first-match-wins, so it must sort **before** `50-cloud-init.conf`
   / `50-redhat.conf`). modprobe: `00-hardening.conf` (first `install`
   wins). Others: `99-hardening.*`.
6. Idempotent: second run reports no changes (Ansible CI asserts `changed=0`).
7. Dry-run: shell `--check`, Ansible `--check`.
8. Each group can be disabled (`HARDEN_<GROUP>=false` / `harden_<group>: false`).

## Variables

Shell reads (in increasing precedence) `/etc/linux-hardening.conf`, the file
given by `--config FILE`, then environment. Format: `KEY=value` shell
assignments. Ansible: lowercase `harden_*` in `defaults/main.yml`; lists are
YAML lists, shell uses space-separated strings.

| Shell                       | Default  | Notes |
|-----------------------------|----------|-------|
| HARDEN_SSH_PORT             | 22       | |
| HARDEN_SSH_ALLOW_USERS      | ""       | empty → no AllowUsers line |
| HARDEN_FORCE_KEY_ONLY       | false    | |
| HARDEN_ADMIN_SOURCES        | ""       | CIDRs; if set, SSH only allowed from these; also fail2ban ignoreip |
| HARDEN_ALLOWED_TCP_PORTS    | ""       | in addition to SSH |
| HARDEN_ALLOWED_UDP_PORTS    | ""       | |
| HARDEN_FIREWALL_FORCE       | false    | see safety rule 2 |
| HARDEN_FIREWALL_IGNORE_LISTENERS | udp/5353 tcp/5355 udp/5355 | listeners the precheck ignores (mDNS/LLMNR — meant to be blocked) |
| HARDEN_ROLLBACK_SECONDS     | 120      | |
| HARDEN_UNATTENDED_FORCE     | false    | let `--yes` apply the risky SSH changes of safety rule 3 anyway |
| HARDEN_DISABLE_IPV6         | false    | |
| HARDEN_IPV6_ACCEPT_RA_OFF   | false    | opt-in; breaks SLAAC/cloud v6 |
| HARDEN_KEXEC_DISABLE        | false    | true breaks kdump |
| HARDEN_APPLY_UPDATES        | true     | apply pending updates now |
| HARDEN_AUTO_REBOOT          | false    | |
| HARDEN_AUTO_REBOOT_TIME     | 04:00    | |
| HARDEN_FAIL2BAN_BANTIME     | 1h       | |
| HARDEN_FAIL2BAN_MAXRETRY    | 5        | |
| HARDEN_FAIL2BAN_IGNOREIP    | ""       | plus ADMIN_SOURCES, plus 127.0.0.1/8 ::1 |
| HARDEN_AUDIT_IMMUTABLE      | false    | `-e 2` |
| HARDEN_AUDIT_FIX_TASK_NEVER | false    | comment out `-a task,never` (Fedora/SUSE default) |
| HARDEN_SELINUX_FORCE        | false    | enforce despite recent AVC denials |

Group toggles (default `true`): `PACKAGES UPDATES SSH FIREWALL FAIL2BAN
SYSCTL MODULES AUDITD ACCOUNTS FILEPERMS SERVICES MAC LOGGING BANNER`.

## Controls

### packages
- Refresh metadata; if `APPLY_UPDATES`, apply all pending updates (separate step).
- Install: fail2ban (+ `python3-systemd` on debian), auditd (`auditd` debian,
  `audit` rhel/suse), chrony, firewall backend, auto-update tooling,
  `needrestart` (debian) / `dnf-utils`/`dnf-plugins-core` for `needs-restarting` (rhel).
- EPEL for fail2ban: Rocky/Alma/CentOS → `dnf install epel-release` (+ enable
  `crb`); RHEL proper → install from
  `https://dl.fedoraproject.org/pub/epel/epel-release-latest-<major>.noarch.rpm`
  and `subscription-manager repos --enable codeready-builder-for-rhel-<major>-<arch>-rpms`
  (failure → warn, skip fail2ban). Fedora: not needed.
- SLES: fail2ban needs PackageHub (`SUSEConnect -p PackageHub/...`); if not
  available → warn, skip fail2ban. openSUSE: in main repo.
- Remove packages in `data/remove-packages.list` if installed.

### updates (automatic security updates)
- debian: `unattended-upgrades`, security origins only, daily via
  `/etc/apt/apt.conf.d/20auto-upgrades`; settings in
  `/etc/apt/apt.conf.d/52hardening-unattended` (reboot per AUTO_REBOOT/TIME).
- rhel: `dnf-automatic` (Fedora 41+: `dnf5-plugin-automatic`, timer
  `dnf5-automatic.timer`, config `/etc/dnf/automatic.conf`), `upgrade_type =
  security` (Fedora: `default` — no security metadata), `apply_updates = yes`,
  `reboot = when-needed` if AUTO_REBOOT else `never`.
- suse: `hardening-autopatch.service` + `.timer` (daily, randomized delay 1h)
  running `zypper --non-interactive patch --category security`; reboot via
  `needs-rebooting`/`zypper needs-rebooting` if AUTO_REBOOT at REBOOT_TIME.

### ssh
- Main config: `/etc/ssh/sshd_config`, or on SUSE (Leap 16/TW/SLES 16) the
  vendor `/usr/etc/ssh/sshd_config` — never create `/etc/ssh/sshd_config`
  there. Make sure `Include /etc/ssh/sshd_config.d/*.conf` is in effect (it is
  in all supported defaults; if missing from `/etc/ssh/sshd_config`, add as
  first line).
- Drop-in `/etc/ssh/sshd_config.d/00-hardening.conf`:
```
Port <SSH_PORT>
PermitRootLogin no|prohibit-password   # safety rule 1
PasswordAuthentication no              # safety rule 1
KbdInteractiveAuthentication no        # safety rule 1
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
AllowUsers <list>                       # only if non-empty
# crypto, debian/suse only (see below):
KexAlgorithms sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```
- Crypto lists are filtered to what `sshd -Q kex|cipher|mac` supports.
  On rhel family crypto is **not** set in sshd (crypto-policies own it);
  instead ensure policy is at least `DEFAULT` (warn if `LEGACY`). Skip all
  crypto changes when FIPS is enabled (`/proc/sys/crypto/fips_enabled` = 1).
- Host keys and moduli are left alone.
- SELinux enabled and port ≠ 22 → `semanage port -a -t ssh_port_t -p tcp <port>`
  (`-m` if exists; `policycoreutils-python-utils`).
- Validate with `sshd -t` (full config). Fail → restore backup, abort group.
- Reload: debian unit `ssh`, others `sshd`. Ubuntu 22.10+ socket activation
  (`ssh.socket` enabled): on port change `systemctl daemon-reload` then
  `systemctl restart ssh.socket`; otherwise reload `ssh.service`.
- Wrap in auto-rollback (safety rule 3).

### firewall — default deny inbound, allow outbound
- If `ufw` is active → skip group with warning (don't fight it).
- Allowed in: established/related, loopback, ICMP + ICMPv6 (v4 echo rate-limited
  where backend supports), DHCPv4/v6 client replies, SSH port (from
  `ADMIN_SOURCES` only if set), `ALLOWED_TCP_PORTS`, `ALLOWED_UDP_PORTS`.
- debian (nftables): own file `/etc/nftables.d/hardening.nft` containing
  `table inet hardening` with an **input chain only** (`policy drop`, priority
  `filter`); file starts with `table inet hardening {}` + `delete table inet hardening`
  for idempotent reload; **no `flush ruleset`, no forward chain** (Docker,
  K8s, libvirt keep working). `/etc/nftables.conf` gets an `include
  "/etc/nftables.d/*.nft"` line if absent (keep existing content). Enable `nftables`.
- rhel/suse (firewalld): enable firewalld; move only
  the default-route interface(s) (from `ip route show default` /
  `ip -6 route show default`) into `drop` — never docker*/cni*/veth*/wg*/tailscale*/virbr*;
  permanently add SSH + allowed ports, `dhcpv6-client` service, protocols
  `icmp` and `ipv6-icmp`; if ADMIN_SOURCES set, SSH via rich rules per source
  instead of plain port; all of this goes into zone `drop`. Reload. The
  **default zone is left unchanged**: interfaces firewalld doesn't know
  (cni0, cali*, flannel.1, docker0/virbr0 created before firewalld) fall into
  it, and `drop` there would cut container/VM forwarding and egress.
- Docker caveat (documented, not managed): ports published with `-p` bypass
  INPUT; use `DOCKER-USER` or bind to 127.0.0.1.
- Wrap in auto-rollback (safety rule 3).

### fail2ban
- `/etc/fail2ban/jail.d/99-hardening.local`:
  `[DEFAULT] bantime=<BANTIME>, bantime.increment=true, findtime=10m,
  maxretry=<MAXRETRY>, ignoreip=127.0.0.1/8 ::1 <ADMIN_SOURCES> <IGNOREIP>,
  backend=systemd, banaction=nftables-multiport` (debian) /
  `firewallcmd-rich-rules` (rhel/suse); `[sshd] enabled=true, port=<SSH_PORT>`.
- Enable + start.

### sysctl — `/etc/sysctl.d/99-hardening.conf`, then `sysctl --system`
- Content from `data/sysctl.conf`, minus keys absent from `/proc/sys` (skip).
- Plus conditional keys:
  - `KEXEC_DISABLE` → `kernel.kexec_load_disabled = 1`
  - `IPV6_ACCEPT_RA_OFF` → `net.ipv6.conf.{all,default}.accept_ra = 0`
  - `DISABLE_IPV6` → `net.ipv6.conf.{all,default}.disable_ipv6 = 1`
- Redirect/source-route keys are also written for each existing interface
  (`net.ipv4.conf.<if>.accept_redirects` etc., excluding `lo`), since
  IPv4 values are OR'd with per-interface ones. Interface names with `.` are
  written with `/` per sysctl.d syntax.
- `net.ipv4.ip_forward` untouched; `rp_filter = 2` (loose; strict breaks
  Cilium/multi-homed).

### modules — `/etc/modprobe.d/00-hardening.conf`
For each in `data/modules.list`: `install <mod> /bin/false` + `blacklist <mod>`.
`00-` prefix because the first `install` line wins and SUSE ships
`install <fs> …/unblacklist` hooks that would shadow a later file.
Not blocked: squashfs (snap), udf (Azure provisioning), usb-storage (optional).

### auditd — `/etc/audit/rules.d/99-hardening.rules`, load with `augenrules --load`
- From `data/audit.rules`. Lines containing `ARCH` are emitted once with
  `b64` and, on x86_64 only, once more with `b32`.
- `-w <path>` lines are dropped when neither the path nor its parent
  directory exists (auditctl rejects them, e.g. `/var/run/faillock/` on debian).
- `auid!=unset` → use `auid!=4294967295` (works on all auditd versions).
- If an existing rules.d file contains `-a task,never` (Fedora default),
  warn that syscall rules are disabled; comment it out into the backup-tracked
  file only if `HARDEN_AUDIT_FIX_TASK_NEVER=true` (default false).
- `HARDEN_AUDIT_IMMUTABLE=true` → append `-e 2`.
- Enable auditd; load via `augenrules --load` (rhel refuses `systemctl restart auditd`).

### accounts
- `/etc/login.defs` (SUSE 16/TW: copy from `/usr/etc/login.defs` to
  `/etc/login.defs.d/99-hardening.defs` style drop-in if supported, else
  `/etc/login.defs`): `PASS_MAX_DAYS 365`, `PASS_MIN_DAYS 1`,
  `PASS_WARN_AGE 14`, `UMASK 027`; `ENCRYPT_METHOD` left if YESCRYPT/SHA512
  else SHA512. Applies to new accounts only.
- Report-only: UID 0 accounts other than root; system accounts with login shells.
- faillock: rhel only — `/etc/security/faillock.conf` `deny = 5`,
  `unlock_time = 900`, `fail_interval = 900`, and `authselect enable-feature
  with-faillock` if authselect is in use. Skip on debian/suse (PAM not wired;
  `--audit` reports N/A, not pass).
- `/etc/security/limits.d/99-hardening.conf`: `* hard core 0`.
- `/etc/systemd/coredump.conf.d/99-hardening.conf`: `Storage=none`, `ProcessSizeMax=0`.
- `/etc/sudoers.d/99-hardening` (0440): `Defaults use_pty`,
  `Defaults logfile="/var/log/sudo.log"`, `Defaults timestamp_timeout=5`;
  validate `visudo -cf` before installing. `/etc/logrotate.d/hardening-sudo`
  for `/var/log/sudo.log` (weekly, rotate 12, compress, missingok).

### fileperms
- `/etc/ssh/ssh_host_*_key` → not group/world readable (0600, or 0640
  root:ssh_keys on rhel — keep group if it's `ssh_keys`); `*.pub` 0644.
- `/etc/shadow`, `/etc/gshadow`: ensure not world-readable and not
  group-writable; keep distro owner/group.
- `/etc/passwd`, `/etc/group` 0644.
- `/etc/crontab` 0600; `/etc/cron.{d,daily,hourly,weekly,monthly}` 0700.
- `grub.cfg` under `/boot/grub*/` 0600 if present.
- `/dev/shm`: `nodev,nosuid,noexec` via fstab line (`tmpfs /dev/shm tmpfs
  defaults,nodev,nosuid,noexec 0 0` if no `/dev/shm` entry), `mount -o remount`.
- `/tmp`: if it's a tmpfs mount via `tmp.mount`, add drop-in
  `/etc/systemd/system/tmp.mount.d/99-hardening.conf` with
  `Options=mode=1777,strictatime,nosuid,nodev` and remount; otherwise report skipped.
- `--audit` only: list world-writable files and unowned files on local filesystems (slow).

### services
For each unit in `data/services.list` that exists: if **not active**, disable
+ mask; if active, warn (never stop a running service). `ctrl-alt-del.target`
masked. chrony enabled+started (`chrony` unit on debian, `chronyd` elsewhere).

### mac
- SELinux (rhel, suse where selinux is the shipped MAC):
  - `disabled` → set `permissive` in `/etc/selinux/config` + warn (relabel/reboot).
  - `permissive` → if `ausearch -m avc -ts recent` (or `-ts today`) shows
    denials and not `SELINUX_FORCE`, warn and stay permissive; else
    `setenforce 1` + persist `enforcing`.
- AppArmor (debian, suse w/ apparmor): install `apparmor` + `apparmor-utils`,
  enable service. No extra profiles.

### logging
- `/etc/systemd/journald.conf.d/99-hardening.conf`: `Storage=persistent`,
  `Compress=yes`, `SystemMaxUse=1G`; restart journald.
- rsyslog installed → `/etc/rsyslog.d/99-hardening.conf` with
  `$FileCreateMode 0640`.

### banner
`/etc/issue` and `/etc/issue.net` ← `data/issue.net` (no OS/version escapes).
`/etc/motd` untouched.

## Reporting
Per group: `changed` / `ok` / `skipped (reason)` / `warning (reason)`, plus
reboot-required (debian `/var/run/reboot-required`, rhel `needs-restarting -r`,
suse `zypper needs-rebooting`). Shell exit: 0 ok, 1 error, 2 warnings.

## Verify mode
`scripts/harden.sh --audit` and `ansible-playbook verify.yml` check each
control read-only; nonzero/failed if any check fails. N/A controls are
reported as N/A. CI runs the shell `--audit` against Ansible-hardened hosts
as a cross-check of the two implementations.
