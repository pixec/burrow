#!/bin/sh
# Builds the installer disk for an unattended Windows 11 ARM64 install under
# Cloud Hypervisor, from a UUP set (fetch-uup.sh) and virtio-win's ARM64
# drivers (fetch-virtio.sh).
#
# Cloud Hypervisor has no CD-ROM, AHCI or NVMe, only virtio-blk, so the media
# is a USB-stick style disk: MBR, one FAT32 partition, \EFI\BOOT\BOOTAA64.EFI,
# and install.wim (split into .swm files if over 4 GiB). boot.wim
# runs pe.cmd (winpeshl.ini) to load viostor and start Setup with the unattend.
# sources\$OEM$\$1 lands on C:\ of the installed system, with SetupComplete.cmd
# installing the remaining drivers and the agent.
#
# usage: build-media.sh UUP_DIR VIRTIO_DIR AGENT_EXE OUT_IMG
# Needs: wimlib-imagex cabextract mkfs.fat mcopy python3.
set -eu
uups=$1/UUPs
virtio=$2
agent=$3
img=$4
here=$(cd "$(dirname "$0")" && pwd)
work=$(dirname "$img")/media-work
rm -rf "$work"
mkdir -p "$work/iso" "$work/pe"

meta=$(ls "$uups"/*_*-*.esd | grep -v -i -E 'Microsoft-|Package' | head -1)
wimlib-imagex info "$meta" > "$work/meta.txt"
idx() { awk -v n="$1" '/^Index:/{i=$2} /^Name:/{sub(/^Name: +/,""); if (index($0, n)) {print i; exit}}' "$work/meta.txt"; }
media=$(idx 'Setup Media')
re=$(idx 'Recovery Environment')
os=$(idx 'Windows 11')
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

iso=$work/iso
wimlib-imagex apply "$meta" "$media" "$iso" --no-acls
mkdir -p "$iso/sources"
wimlib-imagex export "$meta" "$re" "$work/winre.wim" --compress=LZX
# The UUP set has no WinPE or Setup image (24H2 on), so boot.wim is WinRE,
# which is WinPE underneath, with winpeshl.ini running pe.cmd instead of the
# recovery UI. pe.cmd starts Setup from the media's own sources directory.
wimlib-imagex export "$meta" "$re" "$iso/sources/boot.wim" --compress=LZX --boot
wimlib-imagex export "$meta" "$os" "$work/install.wim" --ref="$uups/*.[eE][sS][dD]" --ref="$uups/*.wim" --ref="$work/refs/*.wim" --compress=LZX
wimlib-imagex update "$work/install.wim" 1 --command="add '$work/winre.wim' /Windows/System32/Recovery/Winre.wim"
if [ "$(du -m "$work/install.wim" | cut -f1)" -lt 4000 ]; then
  mv "$work/install.wim" "$iso/sources/install.wim"
else
  wimlib-imagex split "$work/install.wim" "$iso/sources/install.swm" 3800
  rm -f "$work/install.wim"
fi
rm -f "$work/winre.wim"
echo burrow > "$iso/burrow-media.txt"

# WinPE (boot.wim): our launcher, the unattend and the drivers.
mkdir -p "$work/pe/drivers"
for d in viostor vioscsi NetKVM vioserial viosock viorng Balloon pvpanic; do
  [ -d "$virtio/$d" ] && cp -R "$virtio/$d" "$work/pe/drivers/"
done
crlf() { perl -pe 's/\r?\n/\r\n/' "$1" > "$2"; }
crlf "$here/pe.cmd" "$work/pe/pe.cmd"
crlf "$here/winpeshl.ini" "$work/winpeshl.ini"
cp "$here/autounattend.xml" "$work/pe/"
printf "add '%s' /burrow\nadd '%s' /Windows/System32/winpeshl.ini\n" "$work/pe" "$work/winpeshl.ini" |
  wimlib-imagex update "$iso/sources/boot.wim" 1

# Files for C:\ of the installed system.
oem=$iso/sources/\$OEM\$
mkdir -p "$oem/\$1/burrow" "$oem/\$\$/Setup/Scripts"
cp -R "$virtio" "$oem/\$1/burrow/drivers"
cp "$agent" "$oem/\$1/burrow/burrow-guest.exe"
crlf "$here/SetupComplete.cmd" "$oem/\$\$/Setup/Scripts/SetupComplete.cmd"

# EFI fallback loader name for removable media; the Setup Media image has it.
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
