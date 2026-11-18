#!/bin/sh
# Downloads an x86_64 evaluation ISO from Microsoft's direct links:
#   fetch-iso.sh server2022 OUT.iso   Windows Server 2022 (fwlink 2195280)
#   fetch-iso.sh win11 OUT.iso        Windows 11 IoT Enterprise LTSC 2024
#                                     (fwlink 2270353), build 26100
# Evaluation media takes no product key: build it with PRODUCT_KEY= .
# Needs: curl.
set -eu
case ${1:-} in
  server2022) link=2195280 ;;
  win11) link=2270353 ;;
  *) echo "usage: fetch-iso.sh server2022|win11 OUT.iso" >&2; exit 2 ;;
esac
out=${2:?usage: fetch-iso.sh server2022|win11 OUT.iso}
curl -fL --retry 5 -C - -o "$out" \
  "https://go.microsoft.com/fwlink/?linkid=$link&clcid=0x409&culture=en-us&country=us"
ls -lh "$out"
