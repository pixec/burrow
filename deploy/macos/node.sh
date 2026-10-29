#!/bin/sh
# Builds burrowd for this Mac, signs it with the virtualization entitlement and
# runs it as a `vz` node registered with the colima dev harness. Extra
# arguments go to `burrowd serve`.
#
# The data directory is short on purpose: each sandbox's vsock bridge binds a
# Unix socket in its directory, and macOS caps those paths at 104 bytes.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
data=${BURROW_DATA_DIR:-$HOME/.burrow}
cargo build --manifest-path "$root/Cargo.toml" -p burrow-daemon
# The macOS agent: a node hands its own build to any guest running another at
# handshake, and `vz-template` installs it.
cargo build --manifest-path "$root/Cargo.toml" -p burrow-guest --release
mkdir -p "$root/target/vz-signed" "$data"
bin="$root/target/vz-signed/burrowd"
cp "$root/target/debug/burrowd" "$bin"
codesign --force --sign - --entitlements "$here/vz.entitlements" "$bin"
# The harness orchestrator is published on the Mac's loopback, and reaches
# this node from inside colima as host.lima.internal, which lands on the
# Mac's loopback too.
exec env RUST_LOG="${RUST_LOG:-info}" "$bin" serve \
  --orchestrator http://127.0.0.1:7070 \
  --listen 127.0.0.1:7171 --advertise host.lima.internal:7171 \
  --access-listen 127.0.0.1:7173 --access-advertise http://host.lima.internal:7173 \
  --sandbox-proxy-listen 127.0.0.1:7172 \
  --node-id node_mac --label os=macos \
  --api-key dev-token --node-token dev-node-token \
  --guest-binary "${BURROW_GUEST_BINARY:-$root/target/release/burrow-guest}" \
  --data-dir "$data" --hypervisors vz \
  --dns-listen 127.0.0.1:5354 --proxy-listen 127.0.0.1:3129 \
  --no-tailcat "$@"
