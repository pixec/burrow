# A systemd guest with Docker as one of its services, for test.sh.
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus docker.io iptables busybox-static \
 && rm -rf /var/lib/apt/lists/*

# The guest kernel has legacy iptables, without the raw table, and no
# nf_tables.
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy \
 && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy \
 && mkdir -p /etc/systemd/system/docker.service.d \
 && printf '[Service]\nEnvironment=DOCKER_INSECURE_NO_IPTABLES_RAW=1\n' \
      > /etc/systemd/system/docker.service.d/no-raw-table.conf \
 && systemctl enable docker.service
