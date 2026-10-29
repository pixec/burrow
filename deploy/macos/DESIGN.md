# A Virtualization.framework backend (spike notes)

Measured on an Apple M5 (24 GB) running macOS 27.2 (26B123), guest macOS 27.2
(26B123), 4 vCPUs and 8 GiB per guest, never more than two at once. Code:
`crates/burrow-vmm/src/vz/` behind `burrow-vmm`'s `vz` feature, driven by
`crates/burrow-vmm/examples/vz.rs`.

## How it fits burrow-vmm

`vz` is a third backend behind the same `Vm`, `VmSpec`, `Capabilities` and
`Layout` as Firecracker and Cloud Hypervisor, not a parallel lifecycle:

| burrow-vmm | vz |
|---|---|
| `Hypervisor::Vz` (`"vz"`), `GuestOs::MacOs` (`"macos"`), `Backend::Vz(VzConfig)`, `Vm::Vz` | all `#[cfg(all(target_os = "macos", feature = "vz"))]` |
| `VmSpec::boot` | `Boot::MacOs(MacOsBoot { aux, hardware_model, machine_id, requirements })`, paths relative to `workdir` |
| `VmSpec::drives` | virtio-blk disks in order; the first is the installed `disk.img` |
| `VmSpec::vcpus`, `mem_mib` | validated against `requirements` (from `VZMacOSConfigurationRequirements`) and the framework's maxima before anything is built |
| `VmSpec::net` | `Some` gives the guest a virtio NIC with `guest_mac`; `tap` is ignored. Where it leads is `VzConfig::network`: framework NAT, or a datagram socket pair |
| `VmSpec::is_vsock_enabled` | a virtio-socket device plus a bridge on `<workdir>/vsock.sock` |
| `kernel`, `boot_args`, `is_pci_enabled`, dirty pages, lazy memory, chains, prefetch, limits, cgroup | no meaning; unused |
| `Vm::boot` | `startWithOptions` (with `VzConfig::provisioning` for a template's first boot) |
| `Vm::restore(spec, resume)` | `restoreMachineStateFrom` the layout's file, then `resume` if asked |
| `Vm::snapshot` (paused) | `saveMachineStateTo` the layout's file |
| `Vm::pause` / `resume` | the framework's |
| `Vm::kill` | `stop` unless the guest already stopped itself; the bridge closes with it |
| `Vm::guest()` | `GuestAddr::in_workdir`: the bridge speaks the same `CONNECT <port>` / `OK <port>` handshake as Firecracker's hybrid vsock, so `guestconn` and `wait_for_vsock` work unchanged |
| `Vm::pid`, `cpu_usage_usec` | `None`: each guest runs in a framework XPC service (`com.apple.Virtualization.VirtualMachine.xpc`) whose pid the API does not give |
| `Vm::console_tail` / `console_write` | empty / `ConsoleUnavailable`: a macOS guest writes nothing to a serial port |
| `snapshot_diff`, `attach_drive` | `Unsupported` |

Capabilities:

```rust
Capabilities {
    is_diff_snapshot_supported: false, // one opaque save file per snapshot
    is_lazy_memory_supported: false,   // the framework reads (and decrypts) it itself
    is_drive_hotplug_supported: false, // storage is fixed at configuration
    is_jailable: false,                // no chroot or uid switch; the XPC service is Apple's
    guest_oses: &[GuestOs::MacOs],
    memory_headroom_mib: 0,            // no cgroup on macOS to size
}
```

`Layout { state: "snapshot.vzsave", memory: "snapshot.vzsave" }`:
`Layout::is_memory_in_state()` says the memory is not a file of its own.

Templates and sandboxes: `vz::install(ipsw, InstallSpec { template, vcpus,
mem_mib, disk_bytes })` is the template build step (the macOS counterpart of
OCI import), following Apple's InstallationTool. `vz::clone_machine(template,
workdir, is_identity_kept)` is "new sandbox from template": `clonefile(2)` of
`disk.img` and `aux.img`, copies of the hardware model and requirements, and a
fresh machine identifier (or the template's, with a clone of its save file,
to restore that state).

Internally `VzVm` owns a private serial dispatch queue per machine; every
framework call is dispatched onto it and its completion block answers a tokio
oneshot, so the backend is async like the others. The vsock bridge calls
`VZVirtioSocketDevice.connectToPort` on the queue and splices a `dup` of the
connection's socket.

### Shared-model changes

- `Hypervisor::Vz`, `GuestOs::MacOs`, `Backend::Vz`, `Vm::Vz`, all gated on
  the `vz` feature and macOS. `Hypervisor::ALL` has three members when they
  exist; the `FromStr` error lists `ALL` instead of two hard-coded names.
- `VmSpec::boot: Boot` with `Kernel` (the default, today's path, reading
  `kernel` and `boot_args`), `Firmware { firmware: Option<PathBuf> }` and
  `MacOs(MacOsBoot)`. Firecracker refuses anything but `Kernel`. Cloud
  Hypervisor's builder honours `Firmware` (a named file, else its edk2 build)
  and keeps booting a Windows guest from firmware whatever `boot` says, as it
  did when the guest OS alone chose; it refuses macOS.
- `Layout::is_memory_in_state()`.
- Firecracker and Cloud Hypervisor behave as before for every spec the daemon
  builds today (`Boot::Kernel` by default): their existing tests pass
  unchanged, plus one for a named firmware.

Two things are deliberately not done yet because they would mean editing the
daemon:

- `kernel` and `boot_args` stay top-level `VmSpec` fields read by
  `Boot::Kernel`, rather than moving into `Boot::Kernel { kernel, cmdline }`.
  The daemon assigns them in `sandbox.rs` (two sites) and `devvm.rs` (five).
- `Layout::memory` stays a `&str` (equal to `state` for vz) rather than
  `Option<&str>`. The daemon reads `layout.memory` as a file in `durable.rs`,
  `snapshot.rs` and `devvm.rs`; for a vz sandbox each of those must skip it.
- The `vz` feature exists because `serve.rs` (two matches) and `devvm.rs`
  (one) match `Hypervisor` exhaustively; with the variants always present on
  macOS the daemon would stop building there. Wiring the daemon means adding
  those arms and enabling the feature for a Mac build.

## Results

| | |
|---|---|
| IPSW | `UniversalMac_27.2_26B123_Restore.ipsw`, 25.6 GB (the catalog's only entry for this host); `fetchLatestSupported` itself failed with VZErrorDomain 10001 from this shell, so the URL came from Apple's catalog XML |
| Requirements | minimum 2 vCPUs, 4096 MiB |
| Install | 274 s onto a 64 GiB ASIF image; 373 s onto 32 GiB |
| Disk minimum | the installed volumes use 25.4 GB of the container; a 32 GiB image installs and boots with 2.8 GB free; below about 28 GiB it cannot hold the install. 64 GiB (26 GB allocated) is a practical template size |
| Setup Assistant | none needed: `VZMacGuestProvisioningOptions` (macOS 27) created admin `burrow` with Remote Login on during the first headless boot |
| Configure | 13 to 50 ms |
| Cold boot | `start` 0.2 to 0.8 s; SSH banner 11.4 s after launch |
| Pause / resume | 4 to 38 ms / under 1 ms to 1.5 ms |
| Save (paused, 8 GiB guest) | 9.5 to 31 s for 2.7 to 3.0 GB |
| Restore + resume | 8 to 20 s, guest processes and vsock listeners intact, SSH 17.7 s after launch |
| APFS clone | under 2 ms for a 26 GB disk plus aux storage |
| Host-to-guest vsock | connect plus handshake 0.7 to 3 ms through the bridge; 256 MiB echoed in 3.8 s through a Python client; a port with no listener closes without a reply, as Firecracker's does |

Save and restore work for macOS guests on this host, with limits that
shape a design:

- **Restore is not faster than a cold boot.** An idle 8 GiB guest restores in
  8 to 20 s; it boots to SSH in 11 s. Suspend still preserves processes, but
  as a startup accelerator (warm pools) it buys nothing here.
- **The state is host-bound.** Apple encrypts the save file with a key tied
  to the host, so it cannot move to another node or rehydrate from the object
  store: no durable suspend across nodes, no move with state.
- **A restore needs the identical machine.** Same machine identifier, same
  MAC, same vCPUs and memory, and the disk and aux storage as they were at
  the save (Apple's sample deletes the save after any restore for this
  reason). Restoring with a fresh identifier, or the same identifier and a
  different MAC, failed with "invalid argument" (VZErrorDomain 12). So a
  burrow snapshot is the save file plus clones of `disk.img` and `aux.img`
  taken while stopped, and it restores only into the identity it came from.
- **One restore per identity at a time.** Restoring a save while another
  machine of the same identity (and so the same MAC) was running failed the
  same way, though two
  cold boots of one identity (with or without the same MAC) ran side by side.
  A save restored serially into successive kept-identity clones worked every
  time. Fork-from-snapshot therefore means one fork running at once.

With the two-guest licence cap these are less limiting than they look: a Mac
node runs at most two macOS sandboxes, so suspend/resume in place is the use
that matters, and it works.

## AF_VSOCK in a macOS guest

Real. The SDK has had `<sys/vsock.h>` (`AF_VSOCK` = 40, `struct sockaddr_vm`,
`IOCTL_VM_SOCKETS_GET_LOCAL_CID`); on the host it fails with ENODEV, inside the
guest `deploy/macos/vsock-echo.c` ran as an ordinary user: `socket`, `bind`
on `VMADDR_CID_ANY:1024`, `listen` and `accept` all work, the local CID is 3,
the peer is CID 2. The host reached it through `connectToPort` (via the
bridge), and the listener survived a save and restore. `netstat -f vsock`
shows Apple's own `remoted` holding ports 1025 to 1033 and a connection to the
host's port 1, so the agent should keep to 1024 (burrow's `AGENT_PORT`) or
below.

## A macOS guest agent

Built: `crates/burrow-guest/src/macos/` over `src/unix/`, documented in
`crates/burrow-guest/README.md`. The sketch it started from:

`crates/burrow-guest/src/macos/` on top of `src/unix/`, with
`[target.'cfg(target_os = "macos")'.dependencies]`:

- vsock: a `tokio` listener over a raw `AF_VSOCK` socket (`socket2` or
  `libc`; `tokio-vsock` is Linux-only), fed to the existing `agent::service()`.
- `unix/files.rs` resolves paths with Linux `openat2` (`RESOLVE_IN_ROOT`,
  `RESOLVE_NO_SYMLINKS`) and `/proc/<pid>/root`. macOS has neither: it needs
  `openat` with `O_RESOLVE_BENEATH` / `O_NOFOLLOW_ANY` (both in the SDK) or a
  component-by-component walk, and no chroot-per-user. `fs.rs` and `pty.rs`
  (`posix_openpt`) should carry over; `main.rs` currently builds `unix` only
  for Linux.
- Service: a LaunchDaemon plist in `/Library/LaunchDaemons` (`KeepAlive`,
  `RunAtLoad`, root), installed into the template over SSH after
  provisioning, then the template is shut down and becomes read-only.
- Users and groups: `sysadminctl -addUser` (needs an admin's credentials for
  the secure token) or `dscl . -create`; `dseditgroup` for groups.
- Network: the guest DHCPs on its one NIC; nothing for the agent to
  configure unless a userspace stack hands out static leases, in which case
  `networksetup -setmanual`.
- Resume: reseed the RNG and step the clock on the handshake after a
  restore, as the Linux agent does (not checked in the spike).
- exec as a user: `posix_spawn` after `setgid`/`initgroups`/`setuid`, or
  `launchctl asuser` for a GUI session.

## Egress

`VZNATNetworkDeviceAttachment` is the framework's own NAT through
`vmnetd`: no hook for policy, every guest can reach the LAN and the host's
listeners. The options:

1. **`VZFileHandleNetworkDeviceAttachment` plus a userspace stack in burrowd
   (recommended).** The guest's NIC is one end of a connected `SOCK_DGRAM`
   socket pair, one Ethernet frame per datagram (MTU 1500 to 65535 since
   macOS 13). Verified: with `vz run --capture` the guest's DHCP discovers,
   ARP and IPv6 ND arrive as frames on the daemon's end, and the
   configuration still passes `validateSaveRestoreSupport`. burrowd runs a
   small stack per sandbox (smoltcp, or a gvisor-tap-vsock style one): DHCP
   handing out the sandbox's lease, DNS answered by burrow's existing
   resolver, TCP 80/443 terminated and handed to the existing egress proxy
   with the stream's SNI or Host, everything else dropped. The socket pair is
   the "input interface" burrow's policy keys on, so antispoofing is free (a
   frame can only have come from that guest), the host is unreachable unless
   the stack chooses to forward, and no root, pf or entitlement beyond
   `com.apple.security.virtualization` is needed. This is the design Lima
   (`usernet`), Docker Desktop (vpnkit) and Podman (gvproxy) use on macOS.
2. **`VZVmnetNetworkDeviceAttachment` with a custom vmnet network (macOS
   26).** `vmnet_network_create` worked unprivileged from a binary carrying
   only the virtualization entitlement (it failed without it), and the
   configuration offers shared or host mode, subnet, DHCP reservations, port
   forwards, MTU and turning NAT44/NAT66/DHCP/DNS proxy off. It has no
   filtering: shared mode is NAT to everything, host mode lets the guest reach
   every listener on the host (the node API included, which burrow's policy
   forbids), and burrowd cannot see or redirect the flows without pf, which
   needs root. Useful later for guest-to-guest private networks, not for
   policy.
3. **`VZBridgedNetworkDeviceAttachment`**: needs the restricted
   `com.apple.vm.networking` entitlement and puts the guest on the LAN.
   Unsuitable.

## Deviations from Apple's sample

- Disk: ASIF via `diskutil image create blank --format ASIF`, as the sample
  does by default; sized by the caller (`--disk-gib`) rather than a fixed
  128 GB.
- CPU and memory come from the spec, validated against the restore image's
  minimums and the framework's maxima, instead of the sample's "all host
  CPUs but one, 4 GB".
- No audio device and no USB controller (the sample adds virtio sound with
  host input/output, and XHCI for accessory passthrough): a sandbox has no
  use for either, and host audio input needs the microphone entitlement.
- MAC: a per-machine MAC derived from the machine identifier (in the dev
  driver) instead of the sample's fixed one, so two machines never share an
  address by accident; a restore must reuse it.
- Each machine runs on a private serial queue (`initWithConfiguration:queue:`)
  rather than the main queue; only the Setup Assistant window path (`vz gui`)
  uses the main queue, because `VZVirtualMachineView` requires it.
- No delegate: `Vm::kill` asks the machine's state instead of being told of a
  guest stop by `guestDidStop`, and the window path polls state once a second
  to exit. The daemon will want the delegate (via `define_class!`) to notice a
  guest that shut itself down.
- Restore failure: the sample deletes the save file and cold boots on any
  restore failure. `Vm::restore` returns the error and leaves the file to the
  caller (the daemon owns snapshot files); the dev driver does what the
  sample does.
- Provisioning: the sample's `VZMacGuestProvisioningOptions` (fixed user,
  auto login, Remote Login) is used on the template's first boot, reached by
  class name because objc2-virtualization 0.3.2 predates it.

## What a real macOS node still needs

- The daemon wired to the feature: match arms for `Hypervisor::Vz`, a Mac
  build of burrowd signed with the entitlement, Linux-only daemon code
  (nftables, taps, cgroups, uffd, jailer) behind `cfg(target_os = "linux")`,
  `NodeInfo.hypervisors = ["vz"]`, and a node capacity of two macOS guests.
- The macOS template pipeline: `vz::install`, a provisioned first boot,
  installing the agent LaunchDaemon over SSH, shutdown, publish. Templates are
  26 GB per macOS version; ASIF keeps them compact for the object store.
- The guest agent's remaining gaps (volumes, keychain trust; see its README).
- The userspace network stack and its policy wiring.
- Snapshots as save file plus disk and aux clones, kept local to the node;
  durable state and move limited to a cold disk copy (no memory).
- A `VZVirtualMachineDelegate` for guest-initiated stops and errors, and some
  way to attribute host CPU to a guest (the XPC service's pid via
  `proc_listpids` matching on the service name and start time, or
  `responsibility_get_pid_responsible_for_pid`).
- The orchestrator in colima reaching the Mac node at `host.lima.internal`.
