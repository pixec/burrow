#!/bin/sh
# Builds Cloud Hypervisor with Burrow's display device.
#
#   build.sh SOURCE DISPLAY OUT
#
# SOURCE is Cloud Hypervisor's vendored release tarball
# (cloud-hypervisor-<version>.tar.xz, checksummed by the caller), DISPLAY the
# burrow-display crate and OUT where the static binary goes. The patches in
# patches/ are applied in order; the first names burrow-display at
# ../burrow-display beside the source tree. The build is offline and locked
# to the patched Cargo.lock, so it fetches nothing.
set -eu
src=$1
display=$2
out=$3
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tar -xJf "$src" -C "$work"
tree=$(find "$work" -mindepth 1 -maxdepth 1 -type d -name 'cloud-hypervisor-*')
cp -R "$display" "$work/burrow-display"
for patch in "$here"/patches/*.patch; do
  patch -d "$tree" -p1 --quiet --forward < "$patch"
done

target=$(uname -m)-unknown-linux-musl
(cd "$tree" && cargo build --release --offline --locked --target "$target" --bin cloud-hypervisor)
install -m 0755 "$tree/target/$target/release/cloud-hypervisor" "$out"
