#!/bin/bash
# VMM-layer benchmark: burrowd vm agent / clones on both hypervisors, inside burrow-node-1.
# Usage: deploy/bench/vmm.sh <runs> <outdir>
set -euo pipefail
RUNS=${1:-10}
OUT=${2:-./bench-out}
mkdir -p "$OUT"
CTX=${CTX:-colima-burrow}
NODE=${NODE:-burrow-node-1}
N="docker --context $CTX exec -i $NODE"
WD=/var/lib/burrow/benchvm
$N sh -c "mkdir -p $WD && cd $WD && ln -f /var/lib/burrow/images/alpine-ch/vmlinux vmlinux && cp --sparse=always /var/lib/burrow/images/alpine-ch/rootfs.ext4 rootfs.ext4"
W="--workdir $WD --rootfs rootfs.ext4"
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
for h in firecracker cloud-hypervisor; do
  : > "$OUT/vmm-agent-$h.txt"; : > "$OUT/vmm-clones-$h.txt"
  for i in $(seq "$RUNS"); do
    $N /burrow/bin/burrowd vm agent --hypervisor $h $W 2>&1 | strip > /tmp/.vmm.$$ || true
    s=$(grep -o 'vmm start: *[0-9]*' /tmp/.vmm.$$ | grep -o '[0-9]*$')
    r=$(grep -o 'agent reachable: *[0-9]*' /tmp/.vmm.$$ | grep -o '[0-9]*$')
    t=$(grep -o 'ok in [0-9]*' /tmp/.vmm.$$ | grep -o '[0-9]*$')
    echo "$s $r $t" >> "$OUT/vmm-agent-$h.txt"
    $N /burrow/bin/burrowd vm clones --hypervisor $h $W 2>&1 | strip | grep -o 'restored in [0-9]*' | grep -o '[0-9]*$' | tr '\n' ' ' >> "$OUT/vmm-clones-$h.txt"
    echo >> "$OUT/vmm-clones-$h.txt"
  done
done
rm -f /tmp/.vmm.$$
$N rm -rf $WD
echo "columns: agent = vmm_start_ms agent_reachable_ms handshake_total_ms; clones = clone_a_ms clone_b_ms"
