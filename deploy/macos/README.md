# macOS guests under Virtualization.framework (spike)

`crates/burrow-vmm/examples/vz.rs` is a dev driver over `burrow_vmm::Vm` with
the `vz` backend (`burrow-vmm` feature `vz`, macOS only). It builds a template
from an IPSW, makes sandbox machines from it, and boots, pauses, snapshots,
restores and stops them headless, with the guest's vsock ports bridged onto
`<dir>/vsock.sock` the way Firecracker exposes them. Design notes and
measurements are in [DESIGN.md](DESIGN.md).

Machines live outside the repo, under
`~/Library/Application Support/burrow-vz-spike/`. Apple's licence allows at
most two macOS VMs running at once per Mac.

`install`, `run` and `gui` take a machine's resources as `--cpus N` and
`--memory-mib N`, as a sandbox's `resources` would supply them. Each defaults
to the minimum the restore image declares (`VZMacOSConfigurationRequirements`,
recorded in the template's `requirements.json`; 2 vCPUs and 4096 MiB for
macOS 27.2), and a value below that minimum or above the host's
`maximumAllowedCPUCount` / `maximumAllowedMemorySize` is refused. `install`
also needs `--disk-gib N`. The spike ran with `--cpus 4 --memory-mib 8192
--disk-gib 64`, since colima holds 8 GB of this Mac.

## Build and sign

```sh
deploy/macos/sign.sh        # builds the example and signs a copy at target/vz-signed/vz
```

Virtualization.framework refuses to create a machine in a process without the
`com.apple.security.virtualization` entitlement. An ad-hoc signature
(`codesign -s -`) carrying it is enough; no developer account is needed. Any
cargo build that relinks the example drops its signature, which is why the
script signs a copy outside `target/debug`.

## Build a template

```sh
VZ=target/vz-signed/vz
M="$HOME/Library/Application Support/burrow-vz-spike"
# The latest IPSW for this host is in Apple's catalog,
# https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml
curl -L -o "$M/restore.ipsw" <UniversalMac_..._Restore.ipsw URL>
$VZ install "$M/restore.ipsw" "$M/template" --disk-gib 64 --cpus 4 --memory-mib 8192
```

`install` writes the template: `disk.img` (an ASIF image of the given size,
sparse), `aux.img` (auxiliary storage), `hardware-model` and `machine-id` (the
framework's data representations) and `requirements.json`, then runs
`VZMacOSInstaller`, reporting progress every 10 s. Keep this directory as it
is; boot copies of it.

## First boot: the account

A fresh install boots into Setup Assistant. With a macOS 27 host and guest
the framework completes it unattended:

```sh
$VZ new "$M/template" "$M/base"
$VZ run "$M/base" --cpus 4 --memory-mib 8192 --provision
```

`--provision` passes `VZMacGuestProvisioningOptions` on the boot: user
`burrow`, password `burrow` (override with `BURROW_VZ_USER` /
`BURROW_VZ_PASSWORD`), automatic login, Remote Login (SSH) on. The guest only
honours it on the first boot after an install. In the spike this worked with
no person involved: SSH answered within two minutes of the first boot.

Only where provisioning is unavailable (a guest older than macOS 27) does a
person have to do it once, in a window:

1. `$VZ gui "$M/base"` and wait for Setup Assistant.
2. Pick a country and language; skip accessibility, Migration Assistant,
   Apple Account, Location Services, analytics, Screen Time and Siri.
3. Create the admin account `burrow` / `burrow`, so the steps below work
   unchanged.
4. Once at the desktop: System Settings > General > Sharing > Remote Login
   on, with "Allow full disk access for remote users".
5. System Settings > Users & Groups > automatically log in as `burrow`;
   Lock Screen > never require a password or turn off the display.
6. Shut down from the Apple menu. The driver exits when the guest stops.

## Run headless

```sh
$VZ run "$M/base" --cpus 4 --memory-mib 8192 &
# vsock:   <dir>/vsock.sock, "CONNECT <port>\n", "OK <port>\n", then a byte pipe
# control: <dir>/ctl.sock, one command per line: pause, resume, snapshot,
#          stop, suspend (pause, snapshot, stop)
echo suspend | nc -U "$M/base/ctl.sock"
$VZ run "$M/base" --cpus 4 --memory-mib 8192   # restores snapshot.vzsave, then deletes it
```

A restore needs the same vCPUs, memory, MAC and machine identity the state was
saved with; the driver derives the MAC from the machine identifier, so pass
the same `--cpus`/`--memory-mib` and leave `--mac` alone. The guest takes a
NAT address from the framework's DHCP server; its lease is in
`/var/db/dhcpd_leases` under that MAC. `ssh burrow@<address>`.

## New sandboxes

```sh
$VZ new "$M/base" "$M/sb1"                  # a new Mac: fresh identity, cold boot
$VZ new "$M/base" "$M/sb1" --keep-identity  # same identity, with a clone of its saved state
```

Both clone `disk.img` and `aux.img` with `clonefile(2)` (about a millisecond
for a 26 GB disk); the source must be stopped. A kept-identity clone restores
the saved state only while no other machine of that identity is running.

## vsock inside the guest

`vsock-echo.c` listens on an `AF_VSOCK` port inside a macOS guest and greets
each connection. Build it on the host (the binary runs unchanged in the
guest), copy it in and run it:

```sh
cc -O2 -o /tmp/vsock-echo deploy/macos/vsock-echo.c
scp /tmp/vsock-echo burrow@<address>:
ssh burrow@<address> 'nohup ./vsock-echo 1024 >/dev/null 2>&1 </dev/null &'
printf 'CONNECT 1024\nping\n' | nc -U "$M/base/vsock.sock"
```

## The guest agent

`burrow-guest` builds natively on a Mac (`cargo build --release -p
burrow-guest`) and runs unchanged in the guest. A template gets it after the
provisioned first boot, over SSH, before it is shut down and published:

```sh
A=target/release/burrow-guest
scp $A burrow@<address>:burrow-guest
ssh burrow@<address> 'sudo ./burrow-guest install && rm burrow-guest'
ssh burrow@<address> 'sudo shutdown -h now'
```

`install` copies the binary to `/usr/local/libexec/burrow-guest`, writes the
LaunchDaemon `/Library/LaunchDaemons/dev.burrow.guest.plist` (root,
`RunAtLoad`, `KeepAlive`) and bootstraps it, so the agent is listening on
vsock port 1024 from then on and on every boot of a machine cloned from the
template. Its log is `/var/log/burrow-guest.log`; set `RUST_LOG` in the
plist's `EnvironmentVariables` for more. Running `install` again replaces the
binary and restarts the daemon; a running agent replaces itself through the
`Upgrade` RPC.

To drive it from the host through the machine's vsock socket:

```sh
cargo run -p burrow-guest --example guest_probe -- "$M/base/vsock.sock" [ca.pem]
```

which exercises health, handshake, exec, a pty, signals, the feed, `Fs` with
and without scopes, upload and download, and accounts (it creates a user and a
group; use a scratch clone). What the agent does on macOS and how its path
checks compare with Linux's is in `crates/burrow-guest/README.md`.

## Egress capture

`$VZ run <dir> --capture` gives the guest a `SOCK_DGRAM` socket pair instead
of NAT and prints the Ethernet frames it sends (DHCP, ARP, IPv6 ND). It is the
attachment a userspace network stack in burrowd would sit behind; see
DESIGN.md.

## burrowd as a macOS node

`deploy/macos/node.sh` builds burrowd for the Mac, signs it with the
entitlement and runs `burrowd serve --hypervisors vz` against the colima
harness orchestrator (127.0.0.1:7070 from the Mac; the orchestrator dials the
node back at `host.lima.internal:7171`). The node advertises `vz` with the
host's macOS version.

Templates are built on the node, not pulled:

```sh
cargo build -p burrow-guest --release            # the macOS agent
target/vz-signed/burrowd vz-template --data-dir ~/.burrow \
  --ipsw "$M/restore.ipsw" --name macos-27 --disk-gib 64 \
  --guest-binary target/release/burrow-guest
# or, for a template installed earlier and never booted:
target/vz-signed/burrowd vz-template --data-dir ~/.burrow --existing \
  --name macos-27 --guest-binary target/release/burrow-guest
```

That installs the restore image (or clones the existing template), boots it
once with provisioning and NAT, copies the agent in over SSH as the
provisioned admin, runs `burrow-guest install`, waits for the agent on
vsock, turns Remote Login off and shuts the guest down from inside; the
result replaces `~/.burrow/images/<name>` with an `image.json` naming
`vz`/`macos`. SSH rather than writing the disk offline: the agent's files
must be root-owned on the guest's Data volume, which the host can write only
as root, and a booted guest proves the agent answers before the template is
published. The `--existing` upgrade of the 26 GB template took 65 s.

`burrow create --template macos-27 --vcpus 4 --mem-mib 4096` is placed on the
Mac node, which clones the template's disk and aux storage into the sandbox
directory with a fresh machine identity and boots it cold; about 15 s from
create to the first exec. A third running macOS guest is refused (Apple's
licence). Exec, files, users, suspend/resume (the save file, on this Mac
only), recovery across a node restart and the agent upgrade at handshake work
as on Linux.

The guest's NIC is a datagram socket pair served by `burrow_net::usernet` in
burrowd, which is handed the same policy the Linux firewall renders: DHCP
gives the guest its lease, DNS goes through burrow's resolver, allowlist mode
goes through the egress proxy, policy updates apply to the next flow, and
`burrow expose` publishes through the stack on every host address. There is
no warm pool (a restore is slower than a cold boot), and a macOS sandbox
cannot be stored, moved or snapshotted by name (its memory lives in a
host-bound save file).

Use `--route orchestrator` (or `BURROW_ROUTE=orchestrator`) for exec and file
calls from the Mac: the node advertises its Access service as
`host.lima.internal`, which resolves inside colima but not on the Mac.
