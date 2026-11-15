# Windows guests under Cloud Hypervisor

Windows Server 2022 runs as a Burrow sandbox under Cloud Hypervisor v54 on
x86_64 (bench server, 2026-11-15): create, exec, stop/start and delete all
work through `burrow`. Windows on arm64 does not boot on the Mac harness; see
the last section.

## Results on x86_64

Media: Windows Server 2022 Standard Evaluation (Desktop Experience), build
20348.587, from Microsoft's direct evaluation link (fwlink 2195280). Nothing
is activated.

- **Install**: `build-media.sh` turns the ISO into a 5.0 GB USB-style disk in
  34 s. The unattended install at 4 vCPU / 6 GiB reaches SetupComplete in
  about 9 minutes and uses 9.0 GB of a 64 GiB sparse disk. SetupComplete
  installs virtio-win's 2k22 amd64 drivers (all but smbus, refused for its
  certificate), opens the firewall, sets the static IP and installs the agent
  service.
- **Boot**: serial shows edk2, bootmgr and the SAC console. The agent answers
  on vsock 12 s after CH starts, and a cold handshake takes 2.6 s, most of it
  configuring the NIC. RDP (NLA) logs in as `burrow`. `VirtIO Socket Driver`
  and `Microsoft Hyper-V Generation Counter` are bound.
- **Snapshot/restore (raw CH)**: pause and snapshot of 6 GiB takes 12 s;
  restore 5.7 s cold, 2.7 s with a warm page cache, since CH copies all of
  memory in. The agent answers 70-160 ms after resume, with the clock set, the
  network up and fresh GUIDs in each clone. Whether Windows reseeds its RNG
  from the generation ID is untested beyond the driver being bound.
- **Burrow**: `burrow create --template win2022 --vcpus 4 --mem-mib 6144`
  cold-boots in 13.4 s (agent up 11.2 s, handshake 2.0 s). `cmd /c ver` runs
  as `nt authority\system`. `stop` takes 24 s, `start` 1.5 s, and a file
  written before the stop is there after it, with the clock right. `rm` takes
  0.2 s and leaves no CH process or tap.

## Making a template

A Windows template is a directory under the node's templates dir holding the
installed raw disk as `rootfs.ext4` and an `image.json`:

```json
{
  "env": [],
  "working_dir": "",
  "cmd": ["cmd.exe"],
  "hypervisor": "cloud-hypervisor",
  "guest_os": "windows"
}
```

`env` and `working_dir` must be there: without them the file silently loads
as a default Linux Firecracker template. There is no import command yet.

The node charges a template's full apparent size against its disk cap, so the
64 GiB install disk was shrunk to 24 GiB (NTFS shrunk inside, the GPT
rewritten with the same partition GUIDs, which the BCD names). It boots, and
also boots grown.

burrowd needs `--cloud-hypervisor-firmware` pointing at CH's edk2 build
(`CLOUDHV.fd` on x86_64) when it is not at the default path.

## How Burrow runs a Windows guest

- CH runs Windows on x86_64 only, with `kvm_hyperv` on.
- Disks are opened without `direct`. With it, CH gives the disk 4096-byte
  logical blocks, and the firmware cannot find the GPT of a disk installed
  with 512-byte sectors (`BdsDxe: failed to load Boot0002 ... Not Found`).
- No TPM: Server 2022 needs none. Windows 11 would need swtpm per sandbox, and
  Ubuntu's AppArmor profile for swtpm only lets it write under `$HOME` and
  libvirt's directories, so it needs a local rule for `/var/lib/burrow`.
- Creates and warm builds below 2 vCPUs / 4096 MiB are refused. The pinned
  1x512 warm shape is skipped for Windows templates, and a 4x6144 snapshot
  (24 GiB image plus memory) is over this node's default warm disk caps, so
  Windows sandboxes cold-boot here.
- Windows has no kernel command line, so the network settings travel in the
  handshake on every boot, and Windows guests are never sent the Linux agent
  as an upgrade.
- `shutdown /s` in the guest ends CH cleanly within about two minutes;
  `vm.power-button` does not shut Server 2022 down.

## Files

| File | What |
| --- | --- |
| `fetch-uup.sh` | UUP set from Microsoft's CDN (Windows 11 arm64) |
| `fetch-virtio.sh` | virtio-win drivers for `VIRTIO_OS` (w11, 2k22, ...) and `VIRTIO_ARCH` (ARM64, amd64); macOS or Linux |
| `build-media.sh` | installer disk from an ISO or UUP set; `ARCH`, `IMAGE`, `PRODUCT_KEY` |
| `autounattend.xml`, `pe.cmd`, `winpeshl.ini`, `SetupComplete.cmd` | unattended install |
| `run-vm.sh`, `stop-vm.sh` | install/run/restore by hand under CH; `CH`, `FW`, `TPM`, `TPM_DIR`, `VCPUS`, `MEMORY_MIB`, `DISK_MIB` |
| `restore-test.sh` | snapshot once, restore twice, time it and check clock, RNG and network |
| `agent-probe.py`, `vsping.py` | Handshake/Health/Exec over CH's hybrid vsock; whether the agent listens |

Server 2022 on x86_64:

```sh
VIRTIO_OS=2k22 VIRTIO_ARCH=amd64 sh fetch-virtio.sh ~/win
cargo zigbuild -p burrow-guest --target x86_64-pc-windows-gnullvm --release
ARCH=amd64 IMAGE="Desktop Experience" PRODUCT_KEY= \
  sh build-media.sh server2022-eval.iso ~/win/virtio-amd64 \
  target/x86_64-pc-windows-gnullvm/release/burrow-guest.exe ~/win/media.img
DIR=/var/lib/burrow/spike-win VCPUS=4 MEMORY_MIB=6144 sh run-vm.sh install
```

## Still to do

- A template import command for installed disks, and a disk-size floor for
  Windows against the node's disk cap.
- Warm snapshots for Windows: the warm disk caps count the template's whole
  image, which leaves no room on a small node.
- swtpm per sandbox, and the AppArmor rule, for Windows 11.
- Shipping the Windows agent build beside the Linux one, so Windows guests
  can be upgraded.

## Windows 11 arm64 on the Mac harness (2026-10-29)

Does not boot. The firmware loads Windows Boot Manager from the media, and
bootmgr takes an undefined-instruction exception on its first
`mrs x9, pmccntr_el0`:

```
BdsDxe: starting Boot0002 "UEFI Misc Device 2" from PciRoot(0x0)/Pci(0x2,0x0)
Synchronous Exception at 0x00000000FA410004
```

The colima VM has no PMU (`/sys/bus/event_source/devices` has no
`armv8_pmuv3`), so its KVM gives the guest none, and KVM makes PMU register
accesses from such a vCPU UNDEFINED. bootmgr reads PMCCNTR_EL0 without
checking. QEMU/KVM would fail the same way. It needs Apple to expose PMUv3 to
nested guests, a patched L1 KVM, or real arm64 hardware with a PMU. Check with
`ls /sys/bus/event_source/devices | grep pmu` on the KVM host.

Microsoft's ISO download API rejects scripted calls behind a bot check, which
was not circumvented; `fetch-uup.sh` fetches the 26100 arm64 Pro UUP set from
the Windows Update CDN instead. virtio-win 0.1.302 has complete `w11/ARM64`
drivers, including viosock.
