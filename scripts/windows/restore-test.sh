#!/bin/sh
# Cold boots a clone of $DIR/golden.raw, snapshots it once settled, and
# restores the snapshot twice onto reflinked copies of the disk it was taken
# with, timing each step and checking the guest's clock, RNG and network.
# Needs an XFS or btrfs $DIR for the reflinks, and the run-vm.sh environment.
#
# usage: restore-test.sh   (from the directory holding the scripts)
set -u
here=$(cd "$(dirname "$0")" && pwd)
d=${DIR:-/var/lib/burrow/spike-win}
ch=${CH:-cloud-hypervisor}
cd "$d"
probe() { python3 "$here/agent-probe.py" "$d/vsock.sock" "$here/proto" "$@" 2>&1; }
now() { date +%s.%N; }
since() { echo "$(now) - $1" | bc; }
sh "$here/stop-vm.sh"
rm -rf snap
cp --reflink=always golden.raw win.raw
t=$(now)
setsid sh "$here/run-vm.sh" run > run.out 2>&1 < /dev/null &
until python3 "$here/vsping.py" "$d/vsock.sock" 2>/dev/null | grep -q OK; do sleep 0.1; done
echo "cold boot to agent: $(since "$t")s"
probe handshake | grep -E "handshake:"
sleep 45
cp --reflink=always win.raw snap-disk.raw
mkdir snap
t=$(now)
curl -s --unix-socket ch.sock -X PUT http://localhost/api/v1/vm.pause
curl -s --unix-socket ch.sock -X PUT -H content-type:application/json \
  -d "{\"destination_url\":\"file://$d/snap\"}" http://localhost/api/v1/vm.snapshot
echo "pause+snapshot: $(since "$t")s ($(du -sh snap | cut -f1))"
for i in 1 2; do
  for p in $(pgrep -f "$ch.*$d/ch.sock"); do kill "$p"; done
  sleep 1
  rm -f ch.sock vsock.sock
  cp --reflink=always snap-disk.raw win.raw
  t=$(now)
  setsid "$ch" --api-socket "$d/ch.sock" --restore source_url="file://$d/snap" --log-file "$d/ch.log" < /dev/null > /dev/null 2>&1 &
  until [ -S ch.sock ] && curl -s --unix-socket ch.sock http://localhost/api/v1/vm.info | grep -q '"state":"Paused"'; do sleep 0.02; done
  r=$(since "$t")
  curl -s --unix-socket ch.sock -X PUT http://localhost/api/v1/vm.resume
  h=$(probe handshake | grep -E "handshake:")
  echo "restore $i: restored ${r}s, handshake answered $(since "$t")s after launch ($h)"
  echo "  host $(date -u +%H:%M:%S.%N | cut -c1-12)"
  probe exec powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('HH:mm:ss.fff'); [guid]::NewGuid().ToString(); (Test-Connection 172.31.250.1 -Count 1 -Quiet)" |
    grep -o 'stdout: "[^\\]*' | sed 's/stdout: "/  guest /' | grep -v 'guest $'
done
