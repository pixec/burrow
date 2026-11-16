#!/bin/sh
# Fetches Fedora's signed virtio-win driver ISO and unpacks one Windows
# version's drivers for one arch into OUT/virtio-$ARCH/<driver>/.
# VIRTIO_OS is virtio-win's directory for the Windows version (w11, w10,
# 2k22, 2k19), VIRTIO_ARCH its arch (ARM64, amd64). fedorapeople serves about
# 0.5 MB/s per connection, so the ISO comes down in 8 ranges.
# Needs: curl, and hdiutil (macOS) or 7z.
set -eu
out=${1:-.}
os=${VIRTIO_OS:-w11}
arch=${VIRTIO_ARCH:-ARM64}
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
dest=$out/virtio-$arch
rm -rf "$dest"
mkdir -p "$dest"
mnt=$(mktemp -d)
if command -v hdiutil >/dev/null; then
  # The ISO shares identical files between Windows versions as hard links,
  # which bsdtar refuses to extract, so mount it instead.
  hdiutil attach -quiet -readonly -nobrowse -mountpoint "$mnt" "$iso"
else
  7z x -bd -o"$mnt" "$iso" "*/$os/$arch/*" >/dev/null
fi
for d in "$mnt"/*/"$os"/"$arch"; do
  name=$(basename "$(dirname "$(dirname "$d")")")
  cp -R "$d" "$dest/$name"
  chmod -R u+w "$dest/$name"
done
if command -v hdiutil >/dev/null; then hdiutil detach -quiet "$mnt"; fi
rm -rf "$mnt"
find "$dest" -name '*.pdb' -delete
ls "$dest"
