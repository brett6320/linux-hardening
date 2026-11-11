# Systemd-enabled test image. Build with --build-arg BASE=<image>.
ARG BASE=debian:12
FROM ${BASE}
ARG BASE
RUN set -eux; \
    if command -v apt-get >/dev/null; then \
      apt-get update; \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus openssh-server iproute2 sudo python3 python3-pip procps kmod ca-certificates; \
      grp=sudo; \
    elif command -v dnf >/dev/null; then \
      dnf install -y systemd dbus openssh-server iproute sudo python3 python3-pip procps-ng kmod passwd; \
      grp=wheel; \
    elif command -v zypper >/dev/null; then \
      zypper --non-interactive install systemd dbus-1 openssh-server iproute2 sudo python3 python3-pip procps kmod shadow; \
      if zypper --non-interactive search -x python311 >/dev/null 2>&1; then zypper --non-interactive install python311 python311-pip python311-rpm || zypper --non-interactive install python311 python311-pip; fi; \
      grp=wheel; getent group wheel || groupadd wheel; \
    fi; \
    useradd -m -s /bin/bash -G "$grp" admin; \
    install -d -m 700 -o admin -g admin /home/admin/.ssh; \
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg0ZXN0a2V5Zm9yY2l0ZXN0aW5nb25seTAwMDAwMDAw ci@test" \
      > /home/admin/.ssh/authorized_keys; \
    chown admin:admin /home/admin/.ssh/authorized_keys; chmod 600 /home/admin/.ssh/authorized_keys; \
    systemctl enable sshd.service 2>/dev/null || systemctl enable ssh.service 2>/dev/null || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
