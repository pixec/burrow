# Windows guests under Cloud Hypervisor

Windows Server 2022 and Windows 11 IoT Enterprise LTSC 2024 run as Burrow
sandboxes under Cloud Hypervisor v54 on x86_64: create, exec, stop/start, delete, warm creates, fork, snapshots,
durable state and moves, passwords, Remote Desktop, activation and a
per-sandbox TPM all work through `burrow`. Windows on arm64 does not boot on
the Mac harness; see the last section.

## Results on x86_64

Media: Windows Server 2022 Standard Evaluation (Desktop Experience), build
20348.587, from Microsoft's direct evaluation link (fwlink 2195280). Nothing
is activated.

- **Install**: `build-media.sh` turns the ISO into a 5.0 GB USB-style disk in
  34 s. The unattended install at 4 vCPU / 6 GiB reaches SetupComplete in
  about 9 minutes and uses 9.0 GB of a 64 GiB sparse disk. SetupComplete
  installs virtio-win's 2k22 amd64 drivers (all but smbus, refused for its
  certificate), opens ICMP, sets the static IP and installs the agent
  service.
- **Boot**: serial shows edk2, bootmgr and the SAC console. The agent answers
  on vsock 12 s after CH starts, and a cold handshake takes 2.6 s, most of it
  configuring the NIC. With `RDP=1`, RDP (NLA) logs in. `VirtIO Socket Driver`
  and `Microsoft Hyper-V Generation Counter` are bound.
- **Snapshot/restore (raw CH)**: pause and snapshot of 6 GiB takes 12 s;
  restore 5.7 s cold, 2.7 s with a warm page cache, since CH copies all of
  memory in. The agent answers 70-160 ms after resume, with the clock set, the
  network up and fresh GUIDs in each clone.
- **Burrow**: `burrow create --template win2022 --vcpus 4 --mem-mib 6144`
  cold-boots in 13.4 s (agent up 11.2 s, handshake 2.0 s). `cmd /c ver` runs
  as `nt authority\system`. `stop` takes 24 s, `start` 1.5 s, and a file
  written before the stop is there after it, with the clock right. `rm` takes
  0.2 s and leaves no CH process or tap.
- **RNG after restore**: Cloud Hypervisor v54 gives every VM a VM
  generation ID and draws a new one on each restore; Windows binds its
  "Microsoft Hyper-V Generation Counter" driver to it and reseeds its root
  RNG when it changes, so clones of one snapshot draw different random
  numbers from the start. The agent does nothing with the handshake's
  entropy.

## Windows 11

Windows 11 IoT Enterprise LTSC 2024 (build 26100), from its evaluation ISO
(`fetch-iso.sh win11`, fwlink 2270353), installs and runs as a template with
`"tpm": true`. Cloud Hypervisor's documentation lists the same edition. Its
requirements are UEFI (`CLOUDHV.fd`), a TPM 2.0, 2 vCPUs and a disk of about
64 GiB; `run-vm.sh` defaults to all of them, and attaches swtpm unless
`TPM=off`. IoT Enterprise LTSC needs neither Secure Boot nor a TPM, and
`pe.cmd` sets WinPE's `LabConfig` bypasses for other editions all the same,
since `CLOUDHV.fd` has no Secure Boot.

```sh
sh fetch-iso.sh win11 ~/win/win11-iot-ltsc-eval.iso
VIRTIO_OS=w11 VIRTIO_ARCH=amd64 sh fetch-virtio.sh ~/win
APPLY=1 ARCH=amd64 IMAGE="IoT Enterprise LTSC" PRODUCT_KEY= ADMIN_PASSWORD=... \
  sh build-media.sh ~/win/win11-iot-ltsc-eval.iso ~/win/virtio-amd64 \
  target/x86_64-pc-windows-gnullvm/release/burrow-guest.exe ~/win/media.img
DIR=/var/lib/burrow/win11-build VCPUS=4 MEMORY_MIB=6144 sh run-vm.sh install
```

- 24H2 Setup checks that a driver package names the disk controller's
  hardware IDs, and refuses the disk otherwise (`Windows needs the driver
  for device [Red Hat VirtIO SCSI controller]`). viostor's INF names QEMU's
  subsystem ID (`SUBSYS_11001AF4`), and Cloud Hypervisor's virtio-blk has
  `SUBSYS_10421AF4`, which matches only the INF's compatible ID. Loading
  the driver with `drvload` or `pnputil` in WinPE does not change Setup's
  answer, and WinPE's Setup has no `/installdrivers`. So `APPLY=1` has
  `pe.cmd` do Setup's work itself: partition disk 0 as the unattend does,
  `dism /Apply-Image`, `dism /Add-Driver`, `bcdboot`, and the unattend in
  `Windows\Panther` with the `$OEM$` files in place for the specialize and
  oobe passes and `SetupComplete.cmd`. The install takes about 10 minutes.
- The VM installs without a NIC, so Plug and Play binds virtio-net on the
  first boot that has one, while the agent already answers. The agent waits
  up to 60 s for the adapter before it applies the handshake's network.
- `max_phys_bits`: Cloud Hypervisor's documentation notes Windows was tested
  with at least 39 address bits and that a host with more may need
  `max_phys_bits` set. Burrow does not set it, and Server 2022 and Windows
  11 boot with the host's 48 bits on AMD Zen 4.

## Credentials and identity

- The repo holds no password. `build-media.sh` sets the built-in
  Administrator's from `ADMIN_PASSWORD`, or makes a random one and prints it
  once, and every sandbox of the template starts with it.
- `burrow passwd <sandbox> [--user NAME] [--create] [--stdin]` sets a local
  account's password through the agent (`NetUserSetInfo`), Administrator
  when no user is named, and enables the account if it was disabled. Without
  `--stdin` the node generates one and the CLI prints it once; nothing keeps
  it. Linux guests take the same call, writing a SHA-512 crypt hash into
  `/etc/shadow` (root by default).
- `burrow create --rdp` gives Administrator a fresh password, turns Remote
  Desktop on (`fDenyTSConnections` 0 and the Remote Desktop firewall group,
  by its resource name so any language matches) and prints the logon once,
  which NLA accepts. The port is the
  guest's 3389; publish it with `burrow expose` or reach it over a private
  network.
- Computer name: the handshake carries the sandbox's hostname (its id with
  `_` turned to `-`, as on Linux), which the agent sets with
  `SetComputerNameExW` (DNS name, and its first 15 characters as the NetBIOS
  name). Windows applies a name only at boot, so a cold create restarts the
  guest once, a full reboot, and the node waits for the agent to come back. A
  restored guest (warm create, fork, snapshot) keeps its old name until its
  next boot (`burrow shutdown` and `burrow boot`), which then takes the new
  one without a further restart.
- Machine SID: every sandbox of a template still shares the template's.
  Microsoft supports exactly one way to give a Windows install a new SID,
  `sysprep /generalize`; NewSID was retired in 2009 and offline SID changers
  are unsupported, so Burrow does neither. Duplicate SIDs do not matter to a
  standalone machine, but Microsoft does not support them in a domain, and
  recent Windows releases fail NTLM and Kerberos between machines that share
  one. A generalized template gives every create a new machine SID: run
  `sysprep /generalize /oobe /shutdown /quiet /unattend:...` in a sandbox,
  with an unattend that skips OOBE and sets `ComputerName` to `*`, and take
  its disk as a template. Setup's specialize and OOBE then run on each first
  boot, which takes a few minutes more than an ungeneralized boot, and the
  agent does not answer until Setup has finished, so a node creating from
  such a template needs `--agent-timeout 300`. Clones restored from a
  snapshot share the SID the snapshot holds whichever way the template was
  made.

## Activation

Bring your own license, per sandbox:

```sh
echo XXXXX-XXXXX-XXXXX-XXXXX-XXXXX | burrow secret set winkey --product-key
burrow create --template win2022 --product-key-secret winkey
burrow create --template win2022 --kms-host kms.example.com:1688
```

Only a secret stored with `--product-key` serves as one. The orchestrator
reads the key out of the secret (scoped like any other) and hands it to the
node, which passes it to the agent once and keeps only whether one was
installed; the key is never logged, stored on the sandbox or returned. Unlike
a brokered credential it does reach the guest, where Windows keeps it, so
anyone who can create a sandbox the secret is scoped to can read the key.
Creates that activate, or turn Remote Desktop on, are refused for a sandbox
whose exec policy forbids commands. A status the guest reports is cut to 512
bytes, and an attempt that takes over five minutes is recorded as such. The agent runs `slmgr /ipk`, `/skms` and `/ato` and reads the
license state back. A KMS host is kept on the sandbox and activated against
again at every cold boot. `burrow inspect` shows the outcome, e.g. `not
activated via kms kms.invalid: out-of-box grace (... TIMEBASED_EVAL channel):
... Error: 0x80072EE7`. An orchestrator started with `--byol-node-label
KEY=VALUE` places every activating create on nodes carrying that label.

## TPM

A template whose `image.json` has `"tpm": true` gives each sandbox a TPM 2.0
of its own from swtpm (`--swtpm`, default `/usr/bin/swtpm`). Its state lives
in a directory per sandbox under `tpm/` in the data directory, or under
`--tpm-state-dir`, never in the working directory a jailed VMM owns, and is
removed with the sandbox. Each sandbox's swtpm runs as a uid of its own,
`--tpm-uid-base` (default 300000) plus the sandbox's address block, with its
own seccomp filter set to kill, in the VM's cgroup. Those 2^20 uids must
belong to no other user, and burrowd refuses a range holding `--jail-uid`.
The directory is that uid's alone (0700, under a root-owned 0711 parent); the
control socket in it is open to any uid, and a jailed VMM is shown that socket
alone. It is not chrooted, because Ubuntu's AppArmor profile for swtpm
refuses `CAP_SYS_CHROOT`. It starts before the VMM; stopping the VMM has it
save its volatile state, which a `start` (memory restore) resumes from, while
a cold boot drops it. Whether a sandbox has a TPM is fixed at create, on its
record.

A template keeps the TPM ownership Windows recorded during the install:
the SRK's hash and the owner and lockout authorizations under
`HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Admin`. Each sandbox's TPM
is new, so Windows has to clear it, take ownership and create an SRK again
(System log, TPM-WMI 519 "SRK has changed or is not present" and 1027), and
the Platform Crypto Provider only uses that SRK from the next boot. Left to
itself this went wrong two ways: `Tpm-Maintenance` failed with
`TBS_E_INTERNAL_ERROR` (0x80284001) before noticing the new TPM, and kept
failing against the stale record, which a warm snapshot then gave every
warm create; or it provisioned on the boot after the computer-name restart,
with no boot after it. Either way TPM-backed keys failed
(`NTE_PROV_TYPE_NOT_DEF`, `TPM 2.0: The Handle is not correct`) until a
restart. So on a cold boot's handshake the agent waits for TPM Base
Services, reads the SRK's persistent handle (`TPM2_ReadPublic` of
0x81000001) and, when it is missing, deletes the stale record, runs
`Tpm-Maintenance` until the SRK exists (up to 90 s) and restarts the guest,
together with the computer-name restart where there is one. A warm build
goes through the same handshake, so its snapshot holds a provisioned TPM.

Copies carry the TPM. Forks, snapshots, checkpoints (disk and memory),
stored state, moves and warm snapshots pack swtpm's state files
(`tpm2-00.permall`, and `tpm2-00.volatilestate` when there is one; the same
blobs swtpm's `CMD_GET_STATEBLOB` hands out for QEMU's migration) into one
file, `tpm.state`, beside the memory and disk. A sandbox restored from the
copy has it unpacked into its own state directory, chowned to its own uid by
swtpm's start, before its VMM starts; restoring rewrites the snapshot's TPM
socket to that sandbox's. The file is created 0600 root, never handed to a
jail, and in the object store it is a blob named in the manifest
(`tpm_digest`). Every copy holds the same TPM: the same EK and SRK, so a key
sealed to it (a BitLocker TPM protector, a TPM-backed certificate key)
works in every copy.

The state must match the paused guest's memory, so it is read after the
emulator has stored its volatile state. swtpm serves one control connection
at a time and the running VMM holds it, so the state cannot be asked for
while the VMM runs. A suspended or warm-built guest's VMM is gone already;
a running guest being forked, snapshotted or memory-checkpointed is paused
and snapshotted, its VMM is stopped (swtpm stores its volatile state), the
state is packed, and the guest is restored from the snapshot just written,
resuming from the stored volatile state. That costs the guest a CH restore
on top of the pause. A disk checkpoint carries the permanent state as it is.
The packed captures of running guests sit beside the TPM directories and
are swept with them at startup.

Ubuntu's AppArmor profile for swtpm lets it write only to files it owns under
a few directories, among them `/var/lib/swtpm`. On such a host either set
`--tpm-state-dir /var/lib/swtpm/burrow`, or keep the default, under the data
directory, with a local rule in `/etc/apparmor.d/local/usr.bin.swtpm`:

```
owner /var/lib/burrow/tpm/** rwk,
```

What works and what does not under Cloud Hypervisor v54:

- The device shows as `Trusted Platform Module 2.0` (IBM, spec 1.83),
  `tpmtool getdeviceinformation` reports it ready for storage, the
  endorsement key is readable, and its hash is the same after `stop`/`start`
  and after `shutdown`/`boot`.
- BitLocker cannot use it: `manage-bde -protectors -add C: -tpm` fails with
  `0x80284001`, as does `Get-Tpm`.
- It is not ready for attestation: there is no measured-boot event log.
- Windows 11 IoT Enterprise LTSC runs with it, and a TPM-backed key
  (Microsoft Platform Crypto Provider) signs; see Windows 11.

The cause is what Cloud Hypervisor gives the guest, not Burrow. Its ACPI
`TPM2` table (revision 3, 52 bytes, CRB) has no event-log area, and its
`MSFT0101` device has `_HID`, `_STA` and `_CRS` but no `_DSM`, so Windows
finds no Physical Presence Interface: the PPI methods of `Win32_Tpm` and
`GetTcgLog` fail with `0x80284001`, and the TPM driver logs event 15 with
`0xC0000034` (object name not found) from the first boot. The edk2 firmware
adds no measured-boot log of its own. A `_DSM` in Cloud Hypervisor's TPM
device, and a firmware build with the Tcg2 stack, would be needed.

## Making a template

A Windows template is a build imported from the installed disk. Put
`win.raw` in the node's imports directory, `<data-dir>/imports`, and import
it there; the build is distributed to other nodes as any other is:

```sh
mv win.raw /var/lib/burrow/imports/win2022.raw
burrow templates import-disk win2022 --disk win2022.raw --node node_a
burrow templates import-disk win11 --disk win11.raw --node node_a --tpm
```

The import takes a file name, never a path, so a caller cannot have a node
read an arbitrary file into a build. The node clones the disk as the
build's `rootfs.ext4` (a reflink where the filesystem has them), hashes it
and records the image config every sandbox boots with: `guest_os`
`windows`, `hypervisor` `cloud-hypervisor`, `cmd` `cmd.exe`, and `tpm` when
asked. The disk is left in place. The API is `BuildTemplateRequest` with
`from_disk`, `node_id` and `is_tpm`; the SDKs' builders take
`from_disk(disk, node, tpm=...)` and `fromDisk(disk, node, { tpm })`.

Every sandbox's root disk is charged at its full size against the node's disk
cap, so the 64 GiB install disk was shrunk to 24 GiB (NTFS shrunk inside, the
GPT rewritten with the same partition GUIDs, which the BCD names). It boots,
and also boots grown. Warm snapshots are charged by what they add: their
memory and the blocks of their disk not shared with the image.

burrowd needs `--cloud-hypervisor-firmware` pointing at CH's edk2 build
(`CLOUDHV.fd` on x86_64) when it is not at the default path. A Windows
sandbox's agent gets 120 s to answer (`GuestOs::agent_timeout`), against
Linux's 30 s: at 2 vCPUs / 4096 MiB it is up 25-30 s after CH starts with the
image in the page cache, and later without it. `--agent-timeout` can only
raise these.

## How Burrow runs a Windows guest

- CH runs Windows on x86_64 only, with `kvm_hyperv` on.
- Disks are opened without `direct`. With it, CH gives the disk 4096-byte
  logical blocks, and the firmware cannot find the GPT of a disk installed
  with 512-byte sectors (`BdsDxe: failed to load Boot0002 ... Not Found`).
- The node's firmware (`--cloud-hypervisor-firmware`) is copied into each
  sandbox's working directory as `firmware.fd` and booted from there, as a
  Linux sandbox boots the `vmlinux` beside its disk. Forks, snapshots, warm
  snapshots, durable state and moves carry it the same way, and stored
  manifests record its digest (`firmware_digest`) where a Linux sandbox's
  record its kernel's. A `boot` takes the node's current firmware.
- Creates below 2 vCPUs / 4096 MiB are refused, and so are warm shapes below
  it; the pinned default 1x512 is skipped for Windows templates. A warm
  build waits up to five minutes for the guest to go quiet before
  snapshotting, so clones do not each redo its startup work.
- vCPUs and memory grow live. Windows has no virtio-mem driver, so a Windows
  VM's hotplug region is ACPI DIMM slots (`hotplug_method` `Acpi`), up to its
  `max_mem_mib`, in 128 MiB steps and at most eight additions per boot; its
  vCPUs are CH's ACPI CPU hotplug up to the node's CPU count, as a Linux
  guest's. Server 2022 Standard Evaluation brings both online at once, as
  Datacenter does. Windows 11 brings memory online at once, and lists added
  vCPUs as processor devices but schedules on them only after a restart
  (inside the guest, which CH serves at its new count, or a `burrow boot`). Windows ejects neither again, and CH, asked for less,
  would record the smaller shape in the config a snapshot carries while the
  guest kept the larger, so a smaller vCPU count or memory for a running
  guest is never sent to CH: it is kept on the sandbox as
  `pending_resources` (`PENDING` in the response, `next boot` in `burrow
  inspect`) and taken at its next `burrow boot`. An ACPI addition moves CH's
  recorded `memory.size`, so a restore expects boot plus plugged memory there.
  Forks and snapshot restores grow to a larger shape the same way, and are
  refused a smaller one.
- The disk grows, running or shut down; it never shrinks, NTFS being beyond
  the ext4 resize helper. The agent reads the disk's new size with
  `IOCTL_DISK_UPDATE_PROPERTIES` and, when space lies past the system
  partition, which the unattended install makes the last, extends it with
  `Resize-Partition` over the disk's free extent. `Get-PartitionSupportedSize`
  is not used: it refuses a volume whose dirty bit is set, as the shrunk
  template's is, which `Resize-Partition` extends all the same. A running
  guest does it when the host grows the disk; a guest grown while shut down,
  or created larger than its template, does it after its first handshake of
  a boot. A warm snapshot serves creates of a larger disk too, grown under
  the restored guest.
- Windows has no kernel command line, so the network settings travel in the
  handshake on every boot, including every restore.
- The node ships the Windows agent beside the Linux one
  (`--guest-binary-windows`; the node image has it at
  `/burrow/bin/burrow-guest.exe`) and upgrades a Windows guest running
  another build in place on handshake, as it does for Linux: the agent
  verifies the digest, renames itself aside, and exits so the service's
  restart action starts the new binary.
- `shutdown /s` in the guest ends CH cleanly within about two minutes;
  `vm.power-button` does not shut Server 2022 down.

## Files

| File | What |
| --- | --- |
| `fetch-iso.sh` | x86_64 evaluation ISO: Server 2022 or Windows 11 IoT Enterprise LTSC 2024 |
| `fetch-uup.sh` | UUP set from Microsoft's CDN (Windows 11 arm64) |
| `fetch-virtio.sh` | virtio-win drivers for `VIRTIO_OS` (w11, 2k22, ...) and `VIRTIO_ARCH` (ARM64, amd64); macOS or Linux |
| `build-media.sh` | installer disk from an ISO or UUP set; `ARCH`, `IMAGE`, `PRODUCT_KEY`, `ADMIN_PASSWORD`, `RDP`, `APPLY` |
| `autounattend.xml`, `pe.cmd`, `winpeshl.ini`, `SetupComplete.cmd` | unattended install |
| `run-vm.sh`, `stop-vm.sh` | install/run/restore by hand under CH; `CH`, `FW`, `TPM`, `TPM_DIR`, `VCPUS`, `MEMORY_MIB`, `DISK_MIB` |
| `restore-test.sh` | snapshot once, restore twice, time it and check clock, RNG and network |
| `agent-probe.py`, `vsping.py` | Handshake/Health/Exec over CH's hybrid vsock; whether the agent listens |

Server 2022 on x86_64:

```sh
VIRTIO_OS=2k22 VIRTIO_ARCH=amd64 sh fetch-virtio.sh ~/win
cargo zigbuild -p burrow-guest --target x86_64-pc-windows-gnullvm --release
ARCH=amd64 IMAGE="Desktop Experience" PRODUCT_KEY= ADMIN_PASSWORD=... \
  sh build-media.sh server2022-eval.iso ~/win/virtio-amd64 \
  target/x86_64-pc-windows-gnullvm/release/burrow-guest.exe ~/win/media.img
DIR=/var/lib/burrow/spike-win VCPUS=4 MEMORY_MIB=6144 sh run-vm.sh install
```

## Still to do

- PPI and a measured-boot log for the TPM, in Cloud Hypervisor and its
  firmware.

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
