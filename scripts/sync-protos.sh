#!/bin/sh
# Copies the .proto files into both SDKs. They are published separately and
# cannot reach into the workspace, so each carries its own copies; a test in
# burrow-proto fails when they fall behind. The Python SDK additionally
# commits generated code: regenerate with `python sdk/python/scripts/genproto.py`.
#
# `--check` reports drift and exits non-zero instead of writing (the CI form).
set -eu
cd "$(dirname "$0")/.."

src=crates/burrow-proto/proto
dsts="sdk/typescript/proto sdk/python/src/burrow/proto"
protos="common api node guest"

stale=""
for dst in $dsts; do
  for p in $protos; do
    if ! cmp -s "$src/$p.proto" "$dst/$p.proto"; then
      stale="$stale $dst/$p.proto"
      [ "${1:-}" = "--check" ] || cp "$src/$p.proto" "$dst/$p.proto"
    fi
  done
done

if [ -z "$stale" ]; then
  echo "sdk protos are in sync"
elif [ "${1:-}" = "--check" ]; then
  echo "sdk protos have drifted:$stale. Run scripts/sync-protos.sh." >&2
  exit 1
else
  echo "updated$stale"
fi
