# burrow-guest

The agent inside every sandbox. It serves the `Guest` gRPC service
(`crates/burrow-proto/proto/guest.proto`) to the node daemon over vsock port
1024. One crate, one binary name (`burrow-guest`, `burrow-guest.exe` on
Windows), with the code split by what it depends on:

```
src/
  main.rs        picks the platform
  agent.rs       the Guest service: one wiring for every platform
  commands.rs    command registry, attach, output feed (OS-neutral)
  paths.rs       path scope matching; paths/windows.rs maps SDK paths onto drives
  errno.rs       errno names and Linux numbers, and the Win32 error table
  unix/          POSIX, Linux and macOS: Fs ops, file transfer as a user, exec,
                 pty, reaper, signal numbers, async fds
  linux/         PID 1, init, netlink, systemd mode, resume, users, vsock
  macos/         LaunchDaemon and install, handshake, Open Directory users,
                 GUI sessions, volumes, vsock
  windows/       service, ConPTY, job objects, viosock, S4U, NetApi, Windows Fs
examples/
  guest_probe.rs drives an agent end to end through a vsock UDS
```

Build for a guest:

```sh
cargo zigbuild --release --target aarch64-unknown-linux-musl -p burrow-guest
cargo build --release -p burrow-guest            # on a Mac: the macOS agent
cargo zigbuild --release --target x86_64-pc-windows-gnu -p burrow-guest
```

`cargo test -p burrow-guest` on macOS runs the OS-neutral tests (the registry
and feed, scope matching, Windows path mapping, command-line quoting, the errno
tables, mode mapping, the netsh argv builder) and the `unix/` ones against the
Mac's own filesystem; the Linux build runs the same `unix/` tests against
Linux's.

## macOS

A LaunchDaemon in a macOS guest under Virtualization.framework (see
`deploy/macos/`). Verified live against a macOS 27.2 guest with
`examples/guest_probe.rs`: every row below that says so.

| RPC | Status |
| --- | --- |
| Handshake | clock, entropy, inspection CA (below); network accepted and logged; volumes and tmpfs mounted (below). Verified |
| Health | `files-as-user`, `attach-input`, `output-feed`, `fs-scoped`, `gui-session`, `inspection-root-trusted` (below). Verified |
| Exec, Attach, AttachCommand, ListCommands, GetCommand, SignalCommand, PruneCommands, Feed | `unix/exec.rs`, the Linux code: pipes or a pty from openpty(3), a process group or session per command, the user's groups (initgroups(2)), gid and uid set before exec, in the user's GUI session when they have one (below). Exec, pty, resize, stdin, signals, list and feed verified |
| UploadFile, DownloadFile, ListDir, Watch | `unix/files.rs`, a link anywhere on the path refused. Verified but Watch, which is unit tested |
| Fs | every op, scopes and the write cap enforced (below). Verified |
| CreateUser, CreateGroup, AddUserToGroup, RemoveUserFromGroup | `dscl` and `dseditgroup` on the local node. Verified |
| DeleteUser, DeleteGroup | `dscl . -delete` (below), with the Full Disk Access the node grants. Verified |
| Upgrade | replaces `/usr/local/libexec/burrow-guest` and execs it in place; open `Fs` handles and the command table carry over. Verified |

### Install

`burrow-guest install`, as root, copies the running binary to
`/usr/local/libexec/burrow-guest` and loads the LaunchDaemon
`dev.burrow.guest` (`src/macos/burrow-guest.plist`, written to
`/Library/LaunchDaemons`): root, `RunAtLoad`, `KeepAlive` with a one-second
throttle, logs to `/var/log/burrow-guest.log`. Run again, it replaces both and
restarts the daemon. A template build does it over SSH after the provisioned
first boot; `deploy/macos/README.md` has the steps.

### What maps onto what

- vsock: `AF_VSOCK` (40) from `libc`, bound on `VMADDR_CID_ANY:1024` and
  driven through tokio's `AsyncFd`; only cid 2, the host, is served. A process
  in the guest dialling its own cid 3 is dropped.
- Running as a user: commands get the user's groups, gid and uid before exec.
  The groups go in through initgroups(2) (syscall 243, what initgroups(3)
  ends in) with the user as the credential's membership uid: the credential
  holds the first 16 from getgrouplist(3), and the kernel asks opendirectoryd
  about any other group on each check, so a user in 20 groups reads a file
  only the 20th may (verified; setgroups(2) with the same 16 is refused).
  File work runs on a thread of its own given the user's credentials by
  `pthread_setugid_np` followed by the same initgroups(2), which on a thread
  with assumed credentials sets that thread's groups alone; the process stays
  root's. A thread started from it inherits them, and none is.
- GUI session: a command as a user logged in at the console (the template's
  auto-login user) runs in that login, as `launchctl asuser` runs one. The
  agent finds the login's audit session among the user's processes
  (`auditon(A_GETPINFO_ADDR)`, the session with graphic access); the child
  joins it while still root, drops to the user, and execs `/bin/launchctl
  asuser <uid> <program> <args>`, which as the user in their session takes
  the bootstrap port of their Aqua domain (launchd hands it out through a
  private interface) and execs the program in place: same pid, no shell. The
  program is resolved on `PATH` first, so a missing one fails the request as
  for anyone else. Automatic rather than an exec option: it changes nothing
  for a user with no console login, and for the one user who has one it is
  what running as them means on a Mac, with nothing in Exec or either SDK to
  learn. Verified as the auto-login user: `launchctl managername` says
  `Aqua`, `security list-keychains` lists their login keychain, `osascript
  -e 'tell app "Finder" to get name'` answers; a user with no console login
  stays in `System` as before.
- Accounts: Open Directory, read by querying it on the search node
  (`macos/directory.rs`, the OpenDirectory framework) rather than through
  getpwnam_r(3), whose answers come from libinfo's cache in the agent's
  process; memberships through getgrouplist(3); written with
  `dscl . -create`. An account created or deleted outside the agent is seen
  as it is on the next call (verified with records made and removed with
  `dscl` in the guest). A user gets a group of its own with the same id (from 501,
  the first free for both) rather than `staff`, home `/Users/NAME` 0700,
  password `*` and `IsHidden`. `CreateGroup` shares `/Users/Shared/NAME`
  (root:group 2770), since `/srv` is on the sealed system volume. macOS gives a
  new file its directory's group, not its creator's, so what a user creates in
  `/tmp` is group `wheel`.
- Deleting accounts: the same safety rules as Linux's (only ids create could
  have made, 501 to 59999; not root, nobody, daemon, wheel, admin or staff
  by name; not the agent's own; not a member of `admin`; not the auto-login
  user, whose desktop session would go with it), refused while any process
  runs as the user, nothing killed. The user record goes first, so a refusal
  leaves the account whole; then their memberships, and their own group
  unless another account uses it. The home is kept, handed to root 0700,
  unless asked to be removed. macOS 27's opendirectoryd deletes a user record
  only for a caller with Full Disk Access ("disallowed by sandbox" otherwise,
  `sysadminctl -deleteUser` included). TCC's database is under SIP in a
  running guest, so the node grants it on the disk before every cold boot:
  a row for the agent's path (root-only, so it survives upgrades) in
  `/Library/Application Support/com.apple.TCC/TCC.db`. Commands the agent
  runs inherit it as their responsible process. A guest that booted without
  it (the node logs why) gets `FAILED_PRECONDITION` saying so. Verified:
  users created and deleted, with and without their homes.
- Volumes: a macOS node keeps a volume as a raw image, sparse until written,
  attached as a virtio disk after the system disk in mount order. The guest
  shows no disk identifier, so the agent finds each by position among the
  block devices that are not the root one, formats a blank one journaled HFS+
  on its first writable mount, and mounts it with mount_hfs(8) at the path,
  `nobrowse`, ownership honoured. A read-only mount is read-only at the
  hypervisor too, and ignores the journal (`-j`), as Linux mounts ext4
  `norecovery`; the node replays a journal a departed writer left
  (`fsck_hfs -p` on the image) before a reader attaches, and a delete or stop
  runs `sync` in a writer first, so a reader sees the writer's last writes.
  Not APFS: on a virtio disk the guest formats APFS with inline
  encryption keyed to that machine ("can not find key for volume" in any
  other), so no second sandbox could mount it. Not virtio-fs: a shared
  directory shows up as a network volume, which TCC keeps the agent out of
  (`kTCCServiceSystemPolicyNetworkVolumes`) without an MDM grant. Mounted by
  the kernel, not Disk Arbitration, which defers external disks until a
  console login and then mounts them under /Volumes with ownership ignored.
  A mount point must be on the data volume (`/Users`, `/opt`, `/usr/local`,
  `/Volumes`, `/private/var`); the root is the sealed system volume. tmpfs is
  mount_tmpfs(8). Verified: a volume written in one sandbox (as root and as a
  user), kept across suspend and resume, read back read-only in another,
  where a write fails with `EROFS`.
- Numbers on the wire are Linux's. Signals are translated both ways (SIGUSR1
  is 10 on the wire and 30 here; an exit by it reports 10 and 138), FsOpen
  flags are read as Linux's and mapped, and an `FsError` names macOS's errno
  and gives Linux's number for that name; `ENOTCAPABLE`, what macOS says where
  Linux says `EXDEV` for a resolution leaving its directory, goes as `EXDEV`,
  and unlink(2) of a directory goes as `EISDIR` rather than macOS's `EPERM`.
- Entropy: written to `/dev/random`, which XNU mixes into its generator. There
  is no call that credits it as Linux's `RNDADDENTROPY` does; XNU's Fortuna
  also reseeds itself from interrupt timing. A restored clone's generator
  diverges from the next reseed on.
- Clock: settimeofday(2).
- Inspection root: written to `/private/etc/ssl/certs/burrow-inspection-ca.pem`,
  and into `/etc/ssl/cert.pem` and any bundle the image named between
  `# BEGIN burrow inspection ca` and `# END burrow inspection ca`, replacing
  what an earlier handshake wrote there. The system curl (LibreSSL) verifies
  through it; verified against a server in the guest. Also added to the
  System keychain, where trustd finds a root a server's chain leaves out (the
  proxy sends a node CA, not the fleet root), in place of the one the last
  handshake added. Whether the Security framework (URLSession, Safari, Swift,
  Go's crypto/x509 on darwin) takes it as an anchor is the admin trust
  settings, which nothing in a running guest can change unattended (tried as
  root): `security add-trusted-cert -d` fails with "no user interaction was
  possible"; root may rewrite `com.apple.trust-settings.admin` (and even
  `authenticate-admin`) to `allow` in `/var/db/auth.db`, which the client
  side then passes, but trustd authorizes again in its own process and authd
  still answers "session has no ui access" (-60007), or puts up a dialog in
  the console user's session; `security authorizationdb write` is denied
  (-60005); trustd's store under `/private/var/protected/trustd/private` is
  closed to root even with Full Disk Access; a restricted entitlement on an
  ad hoc signed binary is killed by AMFI; `profiles install` no longer
  installs. So the node writes them before every cold boot, with the guest's
  Data volume mounted on the host: the root as the one Burrow-marked entry of
  trustd's `Admin.plist`, replacing a root an earlier boot wrote, removed
  when the sandbox is not inspected. Health reports `inspection-root-trusted`
  when the Security framework takes the installed root as an anchor, and the
  node warns at create when it does not. Verified: `security verify-cert`,
  curl, `nscurl` and a URLSession client through the inspecting proxy; after
  the node's root changed and the sandbox was shut down and booted, the new
  root trusted, the old one not, and only the new one in the keychain.
- Network: the guest DHCPs on its one NIC from whatever the host puts behind
  it; nothing to apply.
- Upgrade: the new binary is renamed over the installed one and exec'd, so
  launchd sees the same pid and does not restart or throttle the daemon.

### Paths and scopes

Linux holds everything by descriptor. `openat2` resolves a whole path in one
call, inside the guest root, refusing links (`RESOLVE_NO_SYMLINKS`) or `..`
out of a directory (`RESOLVE_BENEATH`); `O_PATH` opens any object without
access to it; `/proc/self/fd/N` names what a descriptor is open on. A scope is
checked against that name, re-resolved without links to the same inode, and
the call then acts through the descriptor it checked.

macOS has the resolution flags and not the rest:

| Linux | macOS | Strength |
| --- | --- | --- |
| `RESOLVE_NO_SYMLINKS` | `O_NOFOLLOW_ANY`, `AT_SYMLINK_NOFOLLOW_ANY` | the same: one kernel resolution that fails on any link |
| `RESOLVE_BENEATH` | `O_RESOLVE_BENEATH` | the same |
| `RESOLVE_IN_ROOT` | plain openat(2) from `/` | the same here: there is no other root (no systemd mount namespace) |
| `/proc/self/fd/N` name | `fcntl(F_GETPATH)` | the same check: the name must reach the same inode again with no link on it |
| listing by `/proc/self/fd/N` | `pthread_fchdir_np` to the descriptor, then `.` | the same: the listing is of the vnode the descriptor holds |
| `O_PATH` objects (stat, chmod, utimes, truncate, realpath, access, chown) | the path resolved by the agent to a name with no link in it, the name checked, and the call made on that name with `AT_SYMLINK_NOFOLLOW_ANY` | see below |
| setfsuid/setfsgid per thread | `pthread_setugid_np` plus setgroups(2) per thread | the same: every kernel check on the thread is the user's |
| faccessat2 `AT_EACCESS` | faccessat(2) `AT_EACCESS` | the same, against the thread's credentials |
| statx birth time | `st_birthtime` | the same |

The one place macOS is not as strong is the `O_PATH` row. On Linux the object
is pinned by its descriptor from the check to the call; on macOS the name is.
A link swapped in anywhere along the name after the check fails the call with
`ELOOP` rather than being followed, so nothing outside the scope is reached
through a link. What can still differ is which object sits at the checked name
when the call lands: a rename between the two can put a different object
there, but only at that name, inside the scope, by someone allowed to rename
into it. Every other op (open, readdir, mkdir, remove, rename, copy, symlink,
link, readlink, lstat, and every handle op) holds its object or its parent
directory by descriptor as on Linux.

Paths the system aliases: `/tmp`, `/var` and `/etc` are links into
`/private` on the sealed system volume, which nobody can change while it
runs. Upload, download and listing, which refuse every link, read a leading
`/tmp`, `/var` or `/etc` as its `/private` target, and a scope written that
way is matched as the kernel names what is in it. A scope has to be written
with the firmlinked names (`/Users/...`, not `/System/Volumes/Data/Users/...`)
and in the case the volume has: names are compared as strings, so a mismatch
fails closed.

### Not done

- A root changed while a guest runs reaches the Security framework only at
  its next cold boot (above).

## Windows

Untested on Windows: there was no Windows machine to run it on. It checks,
lints and links for `x86_64-pc-windows-gnu` and `aarch64-pc-windows-gnullvm`
from macOS, and the logic that does not call Windows is unit tested. Everything
that calls Windows has run nowhere yet.

### What it implements

| RPC | Status |
| --- | --- |
| Handshake | clock, inspection CA, network, volumes (below); entropy accepted and not used (below) |
| Health | `files-as-user`, `attach-input`, `output-feed`, `fs-scoped` |
| Exec, Attach, AttachCommand, ListCommands, GetCommand, SignalCommand, PruneCommands, Feed | as on Linux: the same registry and feed code |
| UploadFile, DownloadFile, ListDir | as on Linux, a link anywhere on the path refused |
| Watch | `ReadDirectoryChangesW`; `interval_ms` is ignored |
| Fs | every op; chown is accepted and changes nothing, as in Node on Windows |
| CreateUser, CreateGroup, AddUserToGroup, RemoveUserFromGroup | NetApi local accounts and groups |
| DeleteUser, DeleteGroup | `NetUserDel`, `NetLocalGroupDel`; only accounts with a machine SID and a RID from 1000, never an administrator; the profile kept unless asked to go (`DeleteProfileW`) |
| Upgrade | replaces the binary and restarts the service |

Not implemented: tmpfs mounts, which Windows has no equivalent of, and open
`Fs` handles surviving an upgrade (they read as EBADF after one; a new process
cannot take over the old one's handles).

### Volumes

`windows/volumes.rs`. The host gives each volume's virtio disk the identifier
the handshake names (`burrow-volumeN`) as its serial number, and the agent
finds the disk by it: Windows numbers disks in no order the host controls. The
work is the Storage module's cmdlets, in one PowerShell script run as an
encoded command with the values in its environment: the disk is marked
read-only or writable to match the mount and brought online; a blank one
(`PartitionStyle` RAW, which includes the untouched ext4 a Linux node makes)
is initialized GPT and formatted NTFS on its first writable mount, and refused
on a read-only one; the partition is then given the path, `/data` as the
folder mount point `C:\data\`, `/d` as drive `D:`, and any letter Windows
assigned on its own is removed. A fresh volume's root also grants
Authenticated Users modify, so accounts `CreateUser` made can write; `mode` is
not applied. The path rules and the environment are unit tested; the script
has run nowhere.

### Inspection root

The handshake adds the root to the machine's Trusted Root store
(`LocalMachine\Root`), which Schannel and everything built on it (.NET,
PowerShell, Edge, Chrome) verify against, and names it
`Burrow inspection CA`. Every certificate in the store carrying that friendly
name that is not the root just given is deleted first, so a sandbox told
another root stops trusting the last one; a certificate the store already held
is the image's and is neither named nor removed. The PEM goes to
`inspection-ca.pem` in the agent's state directory and into each bundle the
image named, between the same markers as on Linux.

Firefox keeps its own certificate store and ignores the machine's unless told
to read it. A template that runs Firefox under inspection turns that on with
an enterprise policy, in `distribution\policies.json` beside `firefox.exe`:

```json
{ "policies": { "Certificates": { "ImportEnterpriseRoots": true } } }
```

or the `HKLM\Software\Policies\Mozilla\Firefox\Certificates\ImportEnterpriseRoots`
DWORD set to 1. Firefox then trusts what is in `LocalMachine\Root`, the
inspection root included. Java has its own `cacerts` too, which the image has to
import the root into (`keytool -importcert -cacerts`) or point at with
`-Djavax.net.ssl.trustStoreType=Windows-ROOT`.

### vsock: what it relies on

Windows has no AF_VSOCK. virtio-win's viosock driver adds one: a kernel driver
for the virtio-vsock device and a Winsock provider (installed with
`viosocklib`) that registers an address family. The family's number is not
fixed; the agent asks the driver for it with `IOCTL_GET_AF` (`0x0801300C`) on
`\\.\Viosock`, as viosock's own `ViosockGetAF()` does, then uses plain
`WSASocketW`/`bind`/`listen`/`accept` with viosock's `SOCKADDR_VM` (family,
reserved u16, port u32, cid u32). Only connections from cid 2, the host, are
served. Sockets are used blocking on threads and bridged into tokio, because
tokio's reactor on Windows polls through AFD, which a third-party provider's
sockets are not guaranteed to support.

### Installing it in a template

1. Install the virtio-win drivers: at least `viostor`/`vioscsi` for the disk,
   `NetKVM` for the network, `viosock` for vsock, with its Winsock provider
   registered (`viosocklib`). Burrow gives the VM its vsock device under
   Cloud Hypervisor.
2. Copy `burrow-guest.exe` somewhere permanent, e.g.
   `C:\Program Files\Burrow\burrow-guest.exe`, and from there run
   `burrow-guest.exe install --start`. That registers the `burrow-guest`
   service: LocalSystem, automatic start, restarted a second after any
   failure exit. A failure at startup (viosock not ready yet) is retried the
   same way.
3. Optionally put a POSIX shell on the image and point `BURROW_SH` at it as a
   machine environment variable (see shell mapping).

`burrow-guest.exe console` runs it in the foreground with logs on stderr. The
service logs to `%ProgramData%\burrow\burrow-guest.log`; `RUST_LOG` raises the
level from the default `warn`.

### Paths

SDKs send POSIX paths. Every path is mapped before it is opened:

- `C:\x`, `C:/x`, `\\?\C:\x`: as written.
- `/c/x`: drive `C:`, the MSYS and Git Bash convention. A top-level directory
  with a one-letter name is therefore only reachable in drive form.
- Any other absolute POSIX path lands on the system drive: `/work` is
  `C:\work`, `/` is `C:\`.
- Relative paths are relative to the system drive's root.
- UNC shares and `\\.\` devices are refused.

`.` and `..` are resolved lexically, as Win32 would. Paths the agent returns
(realpath, mkdtemp, mkdir -p, watch events, a user's home) are in drive form.
Scopes are matched on whole components, case-insensitively.

### Shell mapping

`sh -c SCRIPT`, `bash -c`, `/bin/sh -c`, `/bin/bash -c` and their `-lc` forms,
which is how SDKs send shell commands:

- with a POSIX shell on the guest (`BURROW_SH`, else an `sh.exe` on `PATH`,
  else Git for Windows' `sh.exe`), the argv runs under it unchanged;
- otherwise as `cmd.exe /d /s /c "SCRIPT"`. cmd.exe is on every image and
  takes `&&`, `||`, `|` and redirections. Positional arguments after the
  script are refused, since cmd.exe has no `$0`/`$1`.

`bash.exe` on `PATH` is never used: on most images that is WSL's launcher.

Any other argv is joined with the inverse of `CommandLineToArgvW`'s quoting,
after the program is found on `PATH` with `PATHEXT`. A `.bat`/`.cmd` program
runs through `cmd.exe /d /s /c`, with arguments quoted for cmd.exe; an argument
holding `"`, `%` or a line break is refused, since cmd.exe expands those
however they are quoted.

### Running as a user

The agent runs as LocalSystem. A command or file operation as a user is done
with an S4U logon: `LsaLogonUser` with `MSV1_0_S4U_LOGON`, which LocalSystem
may call for a local account without its password. The logon type is
`Network`, a right every local account has by default. Commands then start
through `CreateProcessAsUserW` with the user's profile loaded and their
environment block, on a desktop of their own logon session; file operations
impersonate the user on a dedicated thread. A token without a password cannot
authenticate to other machines as the user.

`""`, `root` and `system` mean the agent's own identity.

`CreateUser` makes a local account with a random password nobody is told and
loads its profile once, which creates the home under `C:\Users`. `uid` is the
account's RID; `gid` is 513, "None", every local user's primary group.
`CreateGroup` makes a local group and `C:\srv\NAME` with an ACL that gives
SYSTEM and Administrators full control, the group modify rights, inherited,
and nobody else access.

### Signals

Each command runs in its own Job Object, assigned before it runs.

- SIGINT: Ctrl+C. Typed into a pseudo console as `0x03`; for a pipe command,
  which runs on a windowless console of its own, raised there by the helper
  `burrow-guest.exe ctrl-event PID c`.
- SIGQUIT: CTRL_BREAK_EVENT, through the same helper.
- SIGTERM, SIGKILL, SIGHUP: `TerminateJobObject` with exit code 128 plus the
  signal, reported back as that signal.
- Anything else is refused as having no Windows equivalent.

Exit codes are the process's, as a signed 32-bit value: a crash reads as an
NTSTATUS such as -1073741819.

### Entropy

Windows has no call that credits outside entropy to the kernel RNG, as Linux's
`RNDADDENTROPY` does. The handshake's entropy is accepted and not used. What
reseeds a restored Windows guest is the VM Generation ID, which Windows
reseeds on when the identifier changes. Burrow's Cloud Hypervisor VM config
adds no vmgenid device, so restored clones of one Windows snapshot share RNG
state until the guest reseeds on its own.

### Stat

`dev` is the volume serial number, `ino` the file index, `nlink` the link
count, times are the file's own (with `ctime` the NTFS change time and
`birthtime` its creation time). Mode follows Node on Windows: directories
0777, files 0666 or 0444 when read-only, plus 0111 for `.exe`, `.com`,
`.bat`, `.cmd`; symlinks and junctions are links. chmod sets or clears the
read-only attribute by the owner's write bit.
