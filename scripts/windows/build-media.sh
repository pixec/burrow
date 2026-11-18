#!/bin/sh
# Builds the installer disk for an unattended Windows install under Cloud
# Hypervisor, from a Microsoft ISO (an evaluation ISO's direct link) or a UUP
# set (fetch-uup.sh), and virtio-win's drivers for the same arch
# (fetch-virtio.sh).
#
# Cloud Hypervisor has no CD-ROM, AHCI or NVMe, only virtio-blk, so the media
# is a USB-stick style disk: MBR, one FAT32 partition, \EFI\BOOT\BOOT*.EFI,
# and install.wim (split into .swm files if over 4 GiB). boot.wim runs pe.cmd
# (winpeshl.ini) to load viostor and start Setup with the unattend.
# sources\$OEM$\$1 lands on C:\ of the installed system, with
# SetupComplete.cmd installing the remaining drivers and the agent.
#
# usage: build-media.sh ISO|UUP_DIR VIRTIO_DIR AGENT_EXE OUT_IMG
# Environment: ARCH (amd64 or arm64, default arm64), IMAGE (the install.wim
# image name to install, default the first matching "Windows 11"),
# PRODUCT_KEY (default Windows 11 Pro's generic key; empty for evaluation
# media, which takes none), ADMIN_PASSWORD (the built-in Administrator's;
# unset, a random one is made and printed once), RDP (1 turns Remote Desktop
# on and opens its firewall rule; off by default), APPLY (1 has pe.cmd apply
# the image itself instead of running Setup, which Windows 11 needs).
# Needs: wimlib-imagex cabextract mkfs.fat mcopy python3, 7z for an ISO.
set -eu
src=$1
virtio=$2
agent=$3
img=$4
arch=${ARCH:-arm64}
image=${IMAGE:-Windows 11}
key=${PRODUCT_KEY-VK7JG-NPHTM-C97JM-9MPGT-3V66T}
here=$(cd "$(dirname "$0")" && pwd)
work=$(dirname "$img")/media-work
rm -rf "$work"
mkdir -p "$work/iso" "$work/pe"
iso=$work/iso
# The image named exactly, else the first whose name contains it.
idx() { awk -v n="$2" '/^Index:/{i=$2} /^Name:/{sub(/^Name: +/,""); if ($0 == n) e=i; else if (!s && index($0, n)) s=i} END{print e ? e : s}' "$1"; }

if [ -f "$src" ]; then
  7z x -bd -o"$iso" "$src" >/dev/null
  mv "$iso/sources/boot.wim" "$work/boot.wim"
  mv "$iso/sources/install.wim" "$work/media-install.wim"
  wimlib-imagex info "$work/media-install.wim" > "$work/meta.txt"
  os=$(idx "$work/meta.txt" "$image")
  echo "os=$os"
  # Index 2 of an ISO's boot.wim is WinPE with Setup.
  wimlib-imagex export "$work/boot.wim" 2 "$iso/sources/boot.wim" --boot
  wimlib-imagex export "$work/media-install.wim" "$os" "$work/install.wim"
  rm -f "$work/boot.wim" "$work/media-install.wim"
else
  uups=$src/UUPs
  meta=$(ls "$uups"/*_*-*.esd | grep -v -i -E 'Microsoft-|Package' | head -1)
  wimlib-imagex info "$meta" > "$work/meta.txt"
  media=$(idx "$work/meta.txt" 'Setup Media')
  re=$(idx "$work/meta.txt" 'Recovery Environment')
  os=$(idx "$work/meta.txt" "$image")
  echo "media=$media re=$re os=$os"

  # Feature packages come as .cab files, whose files the edition's image
  # references by hash as it does the .ESD packages'. Repack each as a WIM
  # so wimlib can resolve them.
  mkdir -p "$work/refs" "$work/cab"
  for cab in "$uups"/*.cab; do
    case $(basename "$cab") in *AggregatedMetadata*|DesktopDeployment*) continue ;; esac
    rm -rf "$work/cab"/*
    cabextract -q -d "$work/cab" "$cab"
    wimlib-imagex capture "$work/cab" "$work/refs/$(basename "$cab" .cab).wim" --compress=none --no-acls >/dev/null
  done
  rm -rf "$work/cab"

  wimlib-imagex apply "$meta" "$media" "$iso" --no-acls
  mkdir -p "$iso/sources"
  wimlib-imagex export "$meta" "$re" "$work/winre.wim" --compress=LZX
  # The UUP set has no WinPE or Setup image (24H2 on), so boot.wim is WinRE,
  # which is WinPE underneath, with winpeshl.ini running pe.cmd instead of
  # the recovery UI. pe.cmd starts Setup from the media's own sources
  # directory.
  wimlib-imagex export "$meta" "$re" "$iso/sources/boot.wim" --compress=LZX --boot
  wimlib-imagex export "$meta" "$os" "$work/install.wim" --ref="$uups/*.[eE][sS][dD]" --ref="$uups/*.wim" --ref="$work/refs/*.wim" --compress=LZX
  wimlib-imagex update "$work/install.wim" 1 --command="add '$work/winre.wim' /Windows/System32/Recovery/Winre.wim"
  rm -f "$work/winre.wim"
fi

if [ "$(du -m "$work/install.wim" | cut -f1)" -lt 4000 ]; then
  mv "$work/install.wim" "$iso/sources/install.wim"
else
  wimlib-imagex split "$work/install.wim" "$iso/sources/install.swm" 3800
  rm -f "$work/install.wim"
fi
echo burrow > "$iso/burrow-media.txt"
[ "${APPLY:-0}" = 1 ] && echo apply > "$iso/burrow-apply.txt"

# WinPE (boot.wim): our launcher, the unattend and the drivers.
mkdir -p "$work/pe/drivers"
for d in viostor vioscsi NetKVM vioserial viosock viorng Balloon pvpanic; do
  [ -d "$virtio/$d" ] && cp -R "$virtio/$d" "$work/pe/drivers/"
done
crlf() { perl -pe 's/\r?\n/\r\n/' "$1" > "$2"; }
crlf "$here/pe.cmd" "$work/pe/pe.cmd"
crlf "$here/winpeshl.ini" "$work/winpeshl.ini"
ARCH=$arch KEY=$key RDP=${RDP:-0} python3 -I - "$here/autounattend.xml" "$work/pe/autounattend.xml" <<'PY'
import os, secrets, string, sys
from xml.sax.saxutils import escape
password = os.environ.get("ADMIN_PASSWORD") or ""
if not password:
    alphabet = string.ascii_letters + string.digits
    password = "".join(secrets.choice(alphabet) for _ in range(20)) + "-9a"
    print(f"Administrator password (not stored anywhere): {password}", file=sys.stderr)
rdp = os.environ["RDP"] == "1"
text = open(sys.argv[1]).read()
text = text.replace('processorArchitecture="arm64"', f'processorArchitecture="{os.environ["ARCH"]}"')
text = text.replace("@ADMIN_PASSWORD@", escape(password))
text = text.replace("@RDP_DENY@", str(not rdp).lower()).replace("@RDP@", str(rdp).lower())
key = os.environ["KEY"]
lines = text.splitlines(keepends=True)
if key:
    text = text.replace("@KEY@", key)
else:
    text = "".join(line for line in lines if "<ProductKey>" not in line)
open(sys.argv[2], "w").write(text)
PY
printf "add '%s' /burrow\nadd '%s' /Windows/System32/winpeshl.ini\n" "$work/pe" "$work/winpeshl.ini" |
  wimlib-imagex update "$iso/sources/boot.wim" 1

# Files for C:\ of the installed system.
oem=$iso/sources/\$OEM\$
mkdir -p "$oem/\$1/burrow" "$oem/\$\$/Setup/Scripts"
cp -R "$virtio" "$oem/\$1/burrow/drivers"
cp "$agent" "$oem/\$1/burrow/burrow-guest.exe"
crlf "$here/SetupComplete.cmd" "$oem/\$\$/Setup/Scripts/SetupComplete.cmd"

ls "$iso/efi/boot/" "$iso/EFI/BOOT/" 2>/dev/null || true

size_mb=$(( $(du -sk "$iso" | cut -f1) / 1024 + 512 ))
rm -f "$img"
python3 -I - "$img" "$size_mb" <<'PY'
import struct, sys
path, mb = sys.argv[1], int(sys.argv[2])
sectors = mb * 2048
with open(path, "wb") as f:
    f.truncate(sectors * 512)
    # One FAT32 LBA partition from 1 MiB to the end, CHS fields maxed out.
    entry = struct.pack("<B3sB3sII", 0x80, b"\xfe\xff\xff", 0x0C, b"\xfe\xff\xff", 2048, sectors - 2048)
    f.seek(446)
    f.write(entry + b"\0" * 48 + b"\x55\xaa")
PY
mkfs.fat -F 32 -n WINSETUP --offset 2048 "$img" $(( (size_mb - 1) * 1024 )) >/dev/null
MTOOLS_SKIP_CHECK=1 mcopy -i "$img@@1M" -s -Q "$iso"/* ::/
rm -rf "$work"
ls -lh "$img"
