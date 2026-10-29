#!/bin/sh
# Downloads a Windows 11 ARM64 UUP set from Microsoft's Windows Update CDN
# (tlu.dl.delivery.mp.microsoft.com). The UUP dump API only supplies the file
# list with Microsoft's signed URLs and SHA-1s. Cumulative updates are skipped
# (integrating them needs DISM), so the result is the build's base revision.
# Downloads one file at a time: the colima VM's NAT drops parallel streams
# (HTTP 408), so run this on the Mac host and copy the result in.
# Needs: curl python3 shasum (macOS) or sha1sum.
set -eu
work=${1:-./uup}
uuid=${UUP_ID:-578d50e9-f444-443f-91a2-fc780f52ecd5} # Windows 11 25H2 (26200) arm64
lang=${UUP_LANG:-en-us}
edition=${UUP_EDITION:-professional}
mkdir -p "$work/UUPs"
curl -fsS "https://api.uupdump.net/get.php?id=$uuid&lang=$lang&edition=$edition" > "$work/files.json"
python3 -I - "$work/files.json" > "$work/list.txt" <<'PY'
import json, sys
files = json.load(open(sys.argv[1]))["response"]["files"]
for name, f in sorted(files.items()):
    if not name.startswith("Windows11.0-KB"):
        print(name, f["sha1"], f["url"])
PY
sha1() { if command -v sha1sum >/dev/null; then sha1sum "$1"; else shasum -a 1 "$1"; fi | cut -d' ' -f1; }
while read -r name sum url; do
  f=$work/UUPs/$name
  [ -f "$f" ] && [ "$(sha1 "$f")" = "$sum" ] && continue
  curl -fsS --retry 5 --retry-delay 3 -o "$f" "$url"
  [ "$(sha1 "$f")" = "$sum" ] || { echo "sha1 mismatch: $name" >&2; exit 1; }
done < "$work/list.txt"
du -sh "$work/UUPs"
