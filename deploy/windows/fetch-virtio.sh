#!/bin/sh
# Fetches Fedora's signed virtio-win driver ISO and unpacks the Windows 11
# ARM64 drivers into OUT/virtio-arm64/<driver>/. fedorapeople serves about
# 0.5 MB/s per connection, so the ISO comes down in 8 ranges.
# Needs: curl hdiutil (macOS).
set -eu
out=${1:-.}
url=${VIRTIO_URL:-https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.302-1/virtio-win.iso}
iso=$out/virtio-win.iso
if [ ! -f "$iso" ]; then
  size=$(curl -fsSIL "$url" | awk 'tolower($1)=="content-length:"{n=$2} END{print n+0}' | tr -d '\r')
  step=$(( (size + 7) / 8 ))
  for i in 0 1 2 3 4 5 6 7; do
    a=$(( i * step )); b=$(( a + step - 1 )); [ $b -ge "$size" ] && b=$(( size - 1 ))
    curl -fsSL --retry 5 -r "$a-$b" -o "$iso.part$i" "$url" &
  done
  wait
  cat "$iso".part? > "$iso" && rm "$iso".part?
fi
rm -rf "$out/virtio-arm64"
mkdir -p "$out/virtio-arm64"
# The ISO shares identical files between Windows versions as hard links,
# which bsdtar refuses to extract, so mount it instead.
mnt=$(mktemp -d)
hdiutil attach -quiet -readonly -nobrowse -mountpoint "$mnt" "$iso"
for d in "$mnt"/*/w11/ARM64; do
  name=$(basename "$(dirname "$(dirname "$d")")")
  cp -R "$d" "$out/virtio-arm64/$name"
  chmod -R u+w "$out/virtio-arm64/$name"
done
hdiutil detach -quiet "$mnt"
find "$out/virtio-arm64" -name '*.pdb' -delete
ls "$out/virtio-arm64"
