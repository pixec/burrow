# Windows 11 ARM64 under Cloud Hypervisor (spike, 2026-10-29)

Can Windows 11 ARM64 run as a Burrow guest under Cloud Hypervisor v54 on the
arm64 dev harness (colima `burrow` profile, Apple Silicon nested virt)?

**No, not on this harness.** The firmware boots the installer media and loads
Windows Boot Manager, and bootmgr dies on its first PMU access, in its startup
code 0xC94 bytes past the entry point:

```
BdsDxe: starting Boot0002 "UEFI Misc Device 2" from PciRoot(0x0)/Pci(0x2,0x0)
Synchronous Exception at 0x00000000FA410004
```

A `vm.snapshot` of the stuck VM gives the cause. `ESR_EL1 = 0x02000000` (EC 0,
an undefined instruction), and `ELR_EL1 = 0xFA410004` holds
`d53b9d09 mrs x9, pmccntr_el0`, in `bootaa64.efi` at file offset 0x32404.
The guest's `ID_AA64DFR0_EL1 = 0x10305006` has PMUVer 0. The colima VM has no
PMU of its own (`/sys/bus/event_source/devices` has no `armv8_pmuv3`), so its
KVM cannot give a guest one, and KVM makes PMU register accesses from a vCPU
without a PMU UNDEFINED. bootmgr reads PMCCNTR_EL0 without checking first
(`bootaa64.efi` has 416 `mrs xN, pmccntr_el0`).

This is not a Cloud Hypervisor bug. CH turns on `KVM_ARM_VCPU_PMU_V3` whenever
KVM offers it, and QEMU/KVM on this L1 would fail the same way. It could be
fixed by:

- Apple exposing PMUv3 to Virtualization.framework guests (nested virt);
- a patched L1 kernel whose KVM emulates a minimal cycle counter;
- running on real arm64 hardware (Graviton metal, Ampere), where KVM has a
  PMU. Untested past bootmgr.

So Windows on arm64 cannot be developed on this Mac harness. An arm64 bare-metal
host (or x86_64, where CH's Windows support is documented) is needed.

## What did work

- **ISO**: Microsoft's download API (`software-download-connector`, product
  edition 3816, SKU 27162 English) answers `Sentinel marked this request as
  rejected` to scripted calls, and getting past that is bot-check
  circumvention, so it was not done. `fetch-uup.sh` instead fetches the UUP
  set for Windows 11 25H2 (26100 base) arm64 Pro en-us from Microsoft's
  Windows Update CDN, with the UUP dump API supplying only the file list,
  signed URLs and SHA-1s. That is 62 files, 3.1 GB, without the cumulative
  updates, which need DISM to integrate. Run it on the Mac: the colima NAT
  fails parallel CDN streams with HTTP 408.
- **Media**: `build-media.sh`, on the Mac with
  `brew install wimlib cabextract mtools dosfstools`, about 1 minute. The 24H2+
  UUP metadata ESD has only Setup Media, WinRE and the OS image, with no WinPE
  or Setup image, and the feature .cab files have to be repacked as WIMs so
  that wimlib's `--ref` resolves them. CH has no CD-ROM/AHCI/NVMe, only
  virtio-blk, so the media is a USB-stick style disk (MBR + FAT32, 4.5 GB,
  `install.wim` 3.3 GB). `boot.wim` is WinRE with `winpeshl.ini` running
  `pe.cmd`, which sets the LabConfig bypasses, `drvload`s ARM64 viostor, finds
  the media and runs `sources\setup.exe /unattend` with `autounattend.xml`
  (local admin, RDP, DriverPaths). `$OEM$` carries the drivers, the agent and
  `SetupComplete.cmd` (`pnputil` all drivers, firewall, static IP,
  `burrow-guest.exe install --start`). None of this ran past bootmgr.
- **Firmware**: CLOUDHV_EFI.fd boots on aarch64 under CH v54, prints to the
  PL011 (`--serial file=`, `--console off`), finds `\EFI\BOOT\BOOTAA64.EFI` on
  the second virtio-blk disk, and accepts `--tpm socket=` (swtpm, TPM 2.0).
- **virtio-win 0.1.302** (`fetch-virtio.sh`) ships `w11/ARM64` builds of
  viostor, vioscsi, NetKVM, vioserial, viosock, viorng, Balloon, viofs,
  pvpanic, vioinput, viomem and viogpudo. viosock is complete: `viosock.sys`
  (PCI `VEN_1AF4&DEV_1053`, CH's modern virtio-vsock), `viosocklib.dll`, and
  `viosockwspsvc.exe`, an auto-start service its INF installs that registers
  the Winsock provider. So `pnputil /add-driver viosock.inf /install` should be
  all the agent needs. Not run.
- **VM Generation ID**: CH v54 always has one on x86_64 and aarch64, ACPI
  `_SB_.VGEN` with `_CID "VM_Gen_Counter"` (what Windows' vmgencounter binds),
  regenerated on every restore. Whether Windows binds it under CH aarch64 is
  untested.
- **Agent**: `cargo zigbuild -p burrow-guest --target aarch64-pc-windows-gnullvm
  --release` builds a 3.6 MB exe that imports only inbox DLLs (UCRT
  `api-ms-win-crt-*`, kernel32, ws2_32, netapi32, ...). It has still never run.

## Files

| File | What |
| --- | --- |
| `fetch-uup.sh` | UUP set from Microsoft's CDN (Mac) |
| `fetch-virtio.sh` | virtio-win ISO in 8 ranges, ARM64 drivers unpacked (Mac, hdiutil) |
| `build-media.sh` | installer disk: boot.wim + install.wim + drivers + agent (Mac or Linux) |
| `autounattend.xml`, `pe.cmd`, `winpeshl.ini`, `SetupComplete.cmd` | unattended install |
| `run-vm.sh`, `stop-vm.sh` | CH + swtpm in a node container; `VCPUS`, `MEMORY_MIB`, `DISK_MIB` (defaults and floors 2 / 4096 / 65536) |
| `agent-probe.py` | Handshake/Health/Exec/Fs stat over CH hybrid vsock (`CONNECT 1024`) |

Run it (on a host with a vPMU):

```sh
sh fetch-uup.sh ~/winspike/uup
sh fetch-virtio.sh ~/winspike
cargo zigbuild -p burrow-guest --target aarch64-pc-windows-gnullvm --release
sh build-media.sh ~/winspike/uup ~/winspike/virtio-arm64 \
  target/aarch64-pc-windows-gnullvm/release/burrow-guest.exe ~/winspike/media.img
# copy media.img and the scripts to $DIR on the host, then
sh run-vm.sh install       # then: sh run-vm.sh run; python3 agent-probe.py $DIR/vsock.sock proto health
```

Check for a PMU first: `ls /sys/bus/event_source/devices | grep pmu` on the
KVM host. With none, Windows on arm64 cannot boot.

## What Burrow's host side would need

- `burrow-vmm` CH config: `config.rs` builds a Windows VM. It takes
  `payload.firmware` (the node image's CLOUDHV_EFI.fd), `tpm.socket` =
  `swtpm.sock` in the workdir, the UART to `console.log` with the virtio
  console off, `kvm_hyperv` on x86_64, and vCPUs and memory from `VmSpec`,
  refusing less than 2 vCPUs / 4096 MiB. Still to do: `Capabilities` lists
  only Linux for CH; the daemon must start and stop swtpm per sandbox and
  snapshot its state directory with the VM; the firmware path could become a
  `CloudHypervisorConfig` field.
- Template import: Windows templates cannot come from OCI images. They need an
  installed raw disk made once per build (this pipeline) and then booted with
  a warm snapshot. A disk of at least 64 GB (sparse) means the disk_mib floor differs from Linux's.
- Node image tools for an on-node pipeline: wimtools, cabextract, mtools,
  dosfstools, swtpm (already there), python3; ntfs-3g to read guest logs
  offline.
