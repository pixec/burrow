#!/usr/bin/env bash
# Live test of the systemd guest mode against the dev harness: an Ubuntu
# template imported with --systemd, booting its own systemd under the agent
# with Docker as one of its services.
#
#   deploy/dev/systemd-docker/test.sh
#
# Checks that exec lands in systemd's namespaces, that file transfer sees its
# mounts, that Docker runs containers, that `systemctl reboot` restarts
# systemd without resetting the VM, and that a stop and start keeps a running
# container.
#
# Configuration, all optional:
#   BURROW                  the CLI (default: burrow on PATH)
#   BURROW_API_KEY          passed through to the CLI
#   BURROW_TEST_DOCKER      docker context that builds (colima-burrow)
#   BURROW_TEST_PUSH        image name builds push to
#   BURROW_TEST_PULL        the same image as a node names it
#   BURROW_TEST_KEEP        set to keep the sandbox and template afterwards
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
burrow="${BURROW:-burrow}"
docker_context="${BURROW_TEST_DOCKER:-colima-burrow}"
push="${BURROW_TEST_PUSH:-127.0.0.1:5000/burrow-test/systemd-docker:latest}"
pull="${BURROW_TEST_PULL:-test-registry:5000/burrow-test/systemd-docker:latest}"
template=systemd-docker-test
id=""

step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
guest() { "$burrow" exec "$id" -- "$@"; }
expect() {
	local want="$1" got
	shift
	got="$(guest "$@")" || fail "$* exited non-zero: $got"
	[[ "$got" == *"$want"* ]] || fail "$*: wanted '$want', got '$got'"
}
# Exec is unavailable for a moment while the VM comes back.
wait_for_systemd() {
	local state
	for _ in $(seq 60); do
		state="$(guest systemctl is-system-running 2>/dev/null || true)"
		case "$state" in
		running | degraded) return 0 ;;
		esac
		sleep 1
	done
	fail "systemd never finished booting (last state: '$state')"
}

cleanup() {
	[ -n "${BURROW_TEST_KEEP:-}" ] && return
	[ -z "$id" ] || "$burrow" rm "$id" >/dev/null 2>&1 || true
	"$burrow" templates rm "$template" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "building $push"
docker --context "$docker_context" buildx build "$here" --output "type=registry,name=$push"
docker --context "$docker_context" image rm -f "$push" >/dev/null 2>&1 || true

step "importing as $template"
"$burrow" templates import --systemd --name "$template" "$pull"
"$burrow" templates ls | grep -E "^$template .* systemd$" >/dev/null ||
	fail "templates ls does not show $template as a systemd template"

step "creating a sandbox"
# The guest's root is an overlay, and an overlay cannot take another as its
# upper layer, so Docker's and containerd's stores get tmpfs mounts of their
# own.
id="$("$burrow" create --template "$template" --mem-mib 1536 \
	--mount tmpfs:/var/lib/docker:size=512m \
	--mount tmpfs:/var/lib/containerd:size=512m | head -1 | cut -d' ' -f1)"
echo "$id"
wait_for_systemd

step "exec runs in systemd's namespaces"
expect systemd cat /proc/1/comm
expect burrow cat /run/systemd/container
expect masked-runtime systemctl is-enabled systemd-networkd.service

step "file transfer sees systemd's /run"
"$burrow" cp "$id:/run/systemd/container" - | grep -qx burrow ||
	fail "cp did not read /run/systemd/container from systemd's mount namespace"

step "docker runs a container"
expect active systemctl is-active docker
# Built from the guest's own busybox, so the test needs no registry access.
guest sh -c 'mkdir -p /tmp/bb/bin && cp /bin/busybox /tmp/bb/bin/ && cd /tmp/bb/bin &&
	for applet in $(./busybox --list); do [ "$applet" = busybox ] || ln -sf busybox "$applet"; done &&
	tar -C /tmp/bb -c . | docker import --change "ENV PATH=/bin" - local/busybox' >/dev/null
expect hello-from-docker docker run --rm local/busybox echo hello-from-docker
expect 172.17. docker run --rm local/busybox ip -4 addr show eth0

step "systemctl reboot restarts systemd, not the VM"
boot_id="$(guest cat /proc/sys/kernel/random/boot_id)"
guest touch /run/before-reboot
guest systemctl reboot || true
sleep 2
wait_for_systemd
[ "$(guest cat /proc/sys/kernel/random/boot_id)" = "$boot_id" ] ||
	fail "the VM rebooted; only systemd should have"
guest test ! -e /run/before-reboot || fail "/run survived the reboot"
expect active systemctl is-active docker

step "a running container survives stop and start"
guest docker run -d --name sleeper local/busybox sleep 3600 >/dev/null
"$burrow" stop "$id" >/dev/null
"$burrow" start "$id" >/dev/null
expect sleeper docker ps --format '{{.Names}}'
expect hello-again docker exec sleeper echo hello-again

echo "PASS"
