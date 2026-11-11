# linux-hardening

Baseline hardening for Linux hosts that will be exposed to the public
internet. The same controls ship in two forms:

- **`scripts/harden.sh`**: a bash tool for one host. It needs nothing beyond
  the base OS.
- **`ansible/`**: a playbook and role for fleets. It uses only `ansible.builtin`
  modules, so no extra collections are needed.

Both forms implement [`docs/SPEC.md`](docs/SPEC.md) and read the same lists from
[`data/`](data/): sysctl keys, blocked kernel modules, services, audit rules,
packages to remove, and the login banner. A host hardened by either one passes
the other's audit.

## Supported distributions

| Family | Distros |
|--------|---------|
| Debian | Debian 12/13, Ubuntu 22.04/24.04 |
| RHEL   | RHEL / Rocky / Alma 9–10, CentOS Stream 9/10, Fedora 41+ |
| SUSE   | openSUSE Leap 15.6/16, Tumbleweed, SLES 15/16 |

## What it does

| Group       | Summary |
|-------------|---------|
| `packages`  | Applies pending updates. Installs fail2ban, auditd, chrony, the firewall backend, auto-update tooling and needrestart. Removes telnet/rsh/NIS/tftp/xinetd. |
| `updates`   | Turns on automatic security updates: unattended-upgrades on Debian, dnf-automatic on RHEL, a zypper patch timer on SUSE. Reboots are optional. |
| `ssh`       | Writes the drop-in `00-hardening.conf`. Turns off root login and password auth *when safe*, sets modern crypto, reduces forwarding and auth tries, and restricts `AllowUsers` if set. |
| `firewall`  | Denies inbound by default, using nftables on Debian and firewalld on RHEL/SUSE. Allows SSH and listed ports. Leaves Docker/K8s forwarding alone. |
| `fail2ban`  | Adds an sshd jail with incremental bans, using the systemd backend. |
| `sysctl`    | Restricts kernel pointers, dmesg, BPF, ptrace and sysrq. Hardens the network stack: no redirects or source routing, syncookies, loose rp_filter, martian logging. |
| `modules`   | Blocks rare filesystems, rare network protocols, firewire and thunderbolt. |
| `auditd`    | Watches identity files, sudoers, sshd, time, hostname, logins, module loading, root commands run by users, and cron. |
| `accounts`  | Sets login.defs aging and umask, faillock (RHEL), no core dumps, and sudo `use_pty` with logging. |
| `fileperms` | Fixes permissions on host keys, shadow, cron and grub. Mounts `/dev/shm` with nodev,nosuid,noexec and `/tmp` with nodev,nosuid where it is `tmp.mount`. |
| `services`  | Disables and masks avahi, cups, rpcbind, samba, ftp, telnet, snmp and similar **only if they are not running**. Masks ctrl-alt-del. |
| `mac`       | Turns on SELinux enforcing (it never jumps straight from disabled, and holds off if there are recent AVC denials), or enables AppArmor. |
| `logging`   | Makes the journal persistent with a size cap, and sets rsyslog file mode to 0640. |
| `banner`    | Sets an authorized-use banner on `/etc/issue` and `/etc/issue.net` that doesn't reveal the OS version. |

## Safety

These rules matter most on a remote host. See SPEC § Safety rules.

- **Avoiding SSH lockout.** Password auth and root login are turned off only
  when a non-root sudo/wheel user with authorized keys exists. Otherwise the
  tool warns and leaves them as they are. `HARDEN_FORCE_KEY_ONLY=true`
  overrides this.
- **Avoiding firewall surprises.** The firewall step aborts if a non-loopback
  port is listening that isn't on the allowlist. Add the port to
  `HARDEN_ALLOWED_TCP_PORTS` / `HARDEN_ALLOWED_UDP_PORTS`, or set
  `HARDEN_FIREWALL_FORCE=true`.
- **Auto-rollback.** SSH and firewall changes schedule a `systemd-run` timer,
  `HARDEN_ROLLBACK_SECONDS` long (default 120), that restores the previous
  config. Ansible cancels it after it reconnects over a *new* SSH connection.
  When the shell tool runs on a TTY, open a second session and run
  `harden.sh --confirm`. With `--yes`, the timer is cancelled once sshd is
  verified.
- **Backups.** Every changed file is backed up to
  `/var/backups/linux-hardening/<timestamp>/`. Undo with `--restore <timestamp>`
  or `restore.yml`.
- **Running services are never stopped.** IP forwarding is never changed.
  Docker/K8s/libvirt nftables rules are never flushed.

## Usage: shell

```bash
sudo git clone https://github.com/brett6320/linux-hardening /opt/linux-hardening
sudo cp /opt/linux-hardening/scripts/linux-hardening.conf.example /etc/linux-hardening.conf
sudoedit /etc/linux-hardening.conf          # ports, allow-users, admin CIDRs…

sudo /opt/linux-hardening/scripts/harden.sh --check   # dry run
sudo /opt/linux-hardening/scripts/harden.sh           # apply (interactive confirm)
sudo /opt/linux-hardening/scripts/harden.sh --audit   # verify, nonzero on failure
```

| Flag | |
|------|-|
| `--check` | Dry run: show what would change. |
| `--audit` | Read-only verification. |
| `--yes` | Non-interactive. |
| `--confirm` | Cancel the pending auto-rollback. Run it from a new SSH session. |
| `--only g1,g2` / `--skip g1,g2` | Choose control groups. |
| `--config FILE` | Extra config. Precedence: `/etc/linux-hardening.conf` < `--config` < environment. |
| `--list-backups` / `--restore TS` | Undo a run. |

Exit codes: `0` ok, `1` error or audit failure, `2` completed with warnings.

## Usage: Ansible

```bash
cd ansible
cp inventory.example.ini inventory.ini        # add hosts
ansible-playbook -i inventory.ini site.yml --check --diff
ansible-playbook -i inventory.ini site.yml
ansible-playbook -i inventory.ini verify.yml
ansible-playbook -i inventory.ini restore.yml -e harden_restore_timestamp=20261111-120000
```

Variables are the shell names in lowercase (`HARDEN_SSH_PORT` → `harden_ssh_port`),
with lists as YAML lists. See `ansible/roles/hardening/defaults/main.yml`.
Each control group is also a tag, for example `--tags ssh,firewall`.

## Things to know

- **Docker-published ports (`-p`) bypass the INPUT chain.** Filter them in
  `DOCKER-USER`, or bind them to `127.0.0.1`.
- **Off by default because they break common setups:**
  - `HARDEN_KEXEC_DISABLE` breaks kdump.
  - `HARDEN_IPV6_ACCEPT_RA_OFF` breaks SLAAC and cloud IPv6.
  - `HARDEN_DISABLE_IPV6`.
  - `HARDEN_AUDIT_IMMUTABLE`.
- **Not done:**
  - AIDE.
  - `pam_wheel` for `su`.
  - Blocking `usb-storage`, `squashfs` (snap) and `udf` (Azure).
  - `noexec` on `/tmp`.
  - Changing host keys.
- **Fedora and SUSE disable syscall auditing** with `-a task,never`. Set
  `HARDEN_AUDIT_FIX_TASK_NEVER=true` to re-enable it.
- **SELinux going from disabled to permissive needs a relabel and a reboot.**
  Run the tool again afterwards to reach enforcing.

## Testing

```bash
tests/container/run.sh debian:12 shell      # needs Docker; privileged systemd container
tests/container/run.sh fedora:42 ansible
```

Each test hardens the container, runs it again to check that nothing changes
on the second run, and runs `harden.sh --audit`. In the ansible mode, that
audit is a cross-check of the two implementations. CI
(`.github/workflows/ci.yml`) runs shellcheck, ansible-lint and syntax checks,
then a container matrix across all families.

Containers can't load audit rules, set kernel sysctls or enable an LSM. Those
groups produce warnings there, and container tests don't treat them as
failures.
