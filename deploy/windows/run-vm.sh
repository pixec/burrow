#!/bin/sh
# Runs the Windows 11 ARM64 spike VM under Cloud Hypervisor, inside a node
# container (docker --context colima-burrow exec -it burrow-node2-1 ...).
#
#   run-vm.sh install   win.raw (target, disk 0) + media.img (installer)
#   run-vm.sh run       win.raw only, tap spikewin0 on 172.31.250.0/30
#   run-vm.sh restore   restore from $DIR/snap
#
# Resources come from the environment, as a sandbox's `resources` would give
# them: VCPUS, MEMORY_MIB, DISK_MIB (the sparse win.raw made on install).
# Defaults are Windows 11's minimums, and less is refused.
# Extra disks: EXTRA_DISK=path appends one (e.g. an image with a new agent).
# Firmware output, bootmgr and EMS/SAC go to $DIR/serial.log (the PL011).
set -eu
mode=${1:-run}
dir=${DIR:-/var/lib/burrow/spike-win}
fw=/usr/local/share/cloud-hypervisor/CLOUDHV_EFI.fd
vcpus=${VCPUS:-2}
memory_mib=${MEMORY_MIB:-4096}
disk_mib=${DISK_MIB:-65536}
[ "$vcpus" -ge 2 ] || { echo "Windows 11 needs at least 2 vCPUs, got $vcpus" >&2; exit 2; }
[ "$memory_mib" -ge 4096 ] || { echo "Windows 11 needs at least 4096 MiB of memory, got $memory_mib" >&2; exit 2; }
[ "$disk_mib" -ge 65536 ] || { echo "Windows 11 needs at least a 65536 MiB disk, got $disk_mib" >&2; exit 2; }
cd "$dir"
mkdir -p tpm

# swtpm keeps running across VM restarts; stop-vm.sh stops it.
if [ ! -S swtpm.sock ]; then
  swtpm socket --tpm2 --ctrl type=unixio,path="$dir/swtpm.sock" --tpmstate dir="$dir/tpm" \
    --flags startup-clear --log file="$dir/swtpm.log",level=5 --daemon
fi

if [ "$mode" != install ] && ! ip link show spikewin0 >/dev/null 2>&1; then
  ip tuntap add spikewin0 mode tap
  ip addr add 172.31.250.1/30 dev spikewin0
  ip link set spikewin0 up
fi

rm -f ch.sock vsock.sock
case $mode in
  install)
    [ -f win.raw ] || truncate -s "${disk_mib}M" win.raw
    disks="path=win.raw,image_type=raw path=media.img,image_type=raw"
    net=""
    ;;
  run)
    disks="path=win.raw,image_type=raw"
    net="--net tap=spikewin0,mac=52:54:00:57:49:4e"
    ;;
  restore)
    exec cloud-hypervisor --api-socket "$dir/ch.sock" --restore source_url="file://$dir/snap" \
      --log-file "$dir/ch.log" -v
    ;;
esac
[ -n "${EXTRA_DISK:-}" ] && disks="$disks path=$EXTRA_DISK,image_type=raw,readonly=on"

# shellcheck disable=SC2086
exec cloud-hypervisor --api-socket "$dir/ch.sock" --log-file "$dir/ch.log" \
  --firmware "$fw" \
  --cpus boot="$vcpus" --memory size="${memory_mib}M" \
  --disk $disks \
  --tpm socket="$dir/swtpm.sock" \
  --vsock cid=3,socket="$dir/vsock.sock" \
  $net \
  --serial file="$dir/serial.log" --console off
