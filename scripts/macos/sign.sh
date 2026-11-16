#!/bin/sh
# Builds the vz dev driver and ad-hoc signs it with the virtualization
# entitlement, without which Virtualization.framework refuses to create a
# machine. The signed copy goes to target/vz-signed/vz: any cargo build that
# relinks the example (a workspace `--all-targets` run, say) drops the
# signature from the one in target/.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
profile=${PROFILE:-debug}
flag=
[ "$profile" = release ] && flag=--release
cargo build --manifest-path "$root/Cargo.toml" -p burrow-vmm --example vz $flag
mkdir -p "$root/target/vz-signed"
bin="$root/target/vz-signed/vz"
cp "$root/target/$profile/examples/vz" "$bin"
codesign --force --sign - --entitlements "$here/vz.entitlements" "$bin"
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q com.apple.security.virtualization
echo "$bin"
