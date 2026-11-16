# Windows guests under Cloud Hypervisor

Windows Server 2022 runs as a Burrow sandbox under Cloud Hypervisor v54 on
x86_64 (bench server, 2026-11-15/16): create, exec, stop/start, delete, warm
creates, fork, snapshots, durable state, passwords, Remote Desktop,
activation and a per-sandbox TPM all work through `burrow`. Moves between
nodes go through the same durable path but were not run (one node). Windows
on arm64 does not boot on the Mac harness; see the last section.

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
- **Burrow, 2026-11-16** (4 vCPUs, 15 GiB host): a cold create of 2x4096 or
  4x6144 takes 36-47 s: agent up 11-25 s, an in-place agent upgrade 4-5 s
  while the template's agent is older than the node's, and 20-30 s for the
  restart that takes the computer name. A warm create of 2x4096 returns in
  0.6 s and its first exec in 1.3-2.2 s, the clock within 0.15 s of the host
  and the address re-applied. `commit` of a 4x6144 sandbox takes 18.5 s;
  each create from the snapshot 9.5-17 s (CH copies memory in); `fork` 6-8 s.
  `stop` writes 6 GiB in 12-27 s and `start` restores in 0.5-30 s depending
  on the page cache. A durable suspend uploads in 49 s the first time (the
  9 GB image once, chunked), a durable commit in 5 s, and a create from that
  snapshot on a node without it fetches and restores in 8.2 s.
- **RNG after restore**: the VM generation counter, read through
  `\\.\VmGenerationCounter`, differs in the source and in every clone of a
  snapshot (CH v54 always provides the device and draws a new ID on each
  restore), and the first `[guid]::NewGuid()` and `CryptGenRandom` bytes of
  two clones differ. Windows reseeds its root RNG on the change, so the agent
  does nothing with the handshake's entropy.

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
  by its resource name so any language matches) and prints the logon once.
  NLA logs in with it (checked with `xfreerdp3 /auth-only`). The port is the
  guest's 3389; publish it with `burrow expose` or reach it over a private
  network.
- Computer name: the handshake carries the sandbox's hostname (its id with
  `_` turned to `-`, as on Linux), which the agent sets with
  `SetComputerNameExW` (DNS name, and its first 15 characters as the NetBIOS
  name). Windows applies a name only at boot, so a cold create restarts the
  guest once (20-30 s) and the node waits for the agent to come back. A
  restored guest (warm create, fork, snapshot) keeps its old name until its
  next boot (`burrow shutdown` and `burrow boot`), which then takes the new
  one without a further restart.
- Machine SID: every sandbox of a template still shares the template's.
  Microsoft supports exactly one way to give a Windows install a new SID,
  `sysprep /generalize`; NewSID was retired in 2009 and offline SID changers
  are unsupported, so Burrow does neither. Duplicate SIDs do not matter to a
  standalone machine, but Microsoft does not support them in a domain, and
  recent Windows releases fail NTLM and Kerberos between machines that share
  one. A generalized template works: running
  `sysprep /generalize /oobe /shutdown /quiet /unattend:...` in a sandbox
  (44 s to power off, with an unattend that skips OOBE and sets
  `ComputerName` to `*`) and taking its disk as a template gives every
  create a new machine SID. Setup's specialize and OOBE then run on each
  first boot: about 110 s at 4 vCPUs before Setup reports
  `IMAGE_STATE_COMPLETE`, against 11-25 s for the agent of an ungeneralized
  template, and a create from it took 184 s with the restart for the name
  (measured 2026-11-16). The agent does not answer until Setup has finished,
  so the node needs `--agent-timeout 300` for such a template. Clones
  restored from a snapshot share the SID the snapshot holds whichever way
  the template was made.

## Activation

Bring your own license, per sandbox:

```sh
echo XXXXX-XXXXX-XXXXX-XXXXX-XXXXX | burrow secret set winkey
burrow create --template win2022 --product-key-secret winkey
burrow create --template win2022 --kms-host kms.example.com:1688
```

The orchestrator reads the key out of the secret (scoped like any other) and
hands it to the node, which passes it to the agent once and keeps only
whether one was installed; the key is never logged, stored on the sandbox or
returned. The agent runs `slmgr /ipk`, `/skms` and `/ato` and reads the
license state back. A KMS host is kept on the sandbox and activated against
again at every cold boot. `burrow inspect` shows the outcome, e.g. `not
activated via kms kms.invalid: out-of-box grace (... TIMEBASED_EVAL channel):
... Error: 0x80072EE7`. An orchestrator started with `--byol-node-label
KEY=VALUE` places every activating create on nodes carrying that label.

Tested only with the public KMS client key for Server 2022 Standard (refused
by the evaluation edition, `0xC004F069`) and with a KMS host that does not
resolve; no retail key was used.

## TPM

A template whose `image.json` has `"tpm": true` gives each sandbox a TPM 2.0
of its own from swtpm (`--swtpm`, default `/usr/bin/swtpm`). Its state lives
in the sandbox's working directory, or under `--tpm-state-dir`, one
directory per sandbox, removed with it. The emulator starts before the VMM;
stopping the VMM has it save its volatile state, which a `start` (memory
restore) resumes from, while a cold boot drops it. Snapshots, forks, warm
builds, checkpoints and moves of a TPM sandbox are refused: a copy would hold
the same TPM's keys.

Ubuntu's AppArmor profile for swtpm lets it write only to files it owns under
a few directories, among them `/var/lib/swtpm`; the bench node runs with
`--tpm-state-dir /var/lib/swtpm/burrow`. Keeping the state in the sandbox's
working directory instead needs a local rule, in
`/etc/apparmor.d/local/usr.bin.swtpm`:

```
owner /var/lib/burrow/sandboxes/*/tpm/** rwk,
owner /var/lib/burrow/jail/cloud-hypervisor/*/root/tpm/** rwk,
```

On Server 2022 the device shows as `Trusted Platform Module 2.0` (IBM,
spec 1.83), `tpmtool getdeviceinformation` reports it ready for storage, and
the endorsement key's hash is the same after `stop`/`start` and after
`shutdown`/`boot`. `Get-Tpm` itself fails under the agent with `0x80284001`;
the WMI class it reads (`Win32_Tpm`) answers. A Windows 11 template was not
installed.

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
  it; the pinned default 1x512 is skipped for Windows templates. A Windows
  guest's memory cannot change while it runs, so its warm shapes have no
  hotplug region, and a warm snapshot is used only for a create of exactly
  its disk size (Windows does not grow its volume from inside). A warm build
  waits up to five minutes for the guest to go quiet before snapshotting, so
  clones do not each redo its startup work.
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
| `fetch-uup.sh` | UUP set from Microsoft's CDN (Windows 11 arm64) |
| `fetch-virtio.sh` | virtio-win drivers for `VIRTIO_OS` (w11, 2k22, ...) and `VIRTIO_ARCH` (ARM64, amd64); macOS or Linux |
| `build-media.sh` | installer disk from an ISO or UUP set; `ARCH`, `IMAGE`, `PRODUCT_KEY`, `ADMIN_PASSWORD`, `RDP` |
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

- A template import command for installed disks.
- Moves between two nodes, which take the durable path tested here.
- A Windows 11 template, for the TPM path.
- `Get-Tpm` under the agent.

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
