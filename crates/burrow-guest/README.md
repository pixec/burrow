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
  macos/         LaunchDaemon and install, handshake, Open Directory users, vsock
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
| Handshake | clock, entropy, inspection CA (below); network accepted and logged; volumes refused with `UNIMPLEMENTED`. Verified |
| Health | `files-as-user`, `attach-input`, `output-feed`, `fs-scoped`. Verified |
| Exec, Attach, AttachCommand, ListCommands, GetCommand, SignalCommand, PruneCommands, Feed | `unix/exec.rs`, the Linux code: pipes or a pty from openpty(3), a process group or session per command, the user's groups, gid and uid set before exec. Exec, pty, resize, stdin, signals, list and feed verified |
| UploadFile, DownloadFile, ListDir, Watch | `unix/files.rs`, a link anywhere on the path refused. Verified but Watch, which is unit tested |
| Fs | every op, scopes and the write cap enforced (below). Verified |
| CreateUser, CreateGroup, AddUserToGroup, RemoveUserFromGroup | `dscl` and `dseditgroup` on the local node. Verified |
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
- Running as a user: commands get the user's groups (getgrouplist(3), at most
  16, setgroups(2)'s limit here), gid and uid before exec. File work runs on a
  thread of its own given the user's credentials by `pthread_setugid_np`
  followed by setgroups(2), which on a thread with assumed credentials sets
  that thread's groups alone; the process stays root's. A thread started from
  it inherits them, and none is.
- Accounts: Open Directory through getpwnam_r(3), getgrouplist(3) and
  `dscl . -create`. A user gets a group of its own with the same id (from 501,
  the first free for both) rather than `staff`, home `/Users/NAME` 0700,
  password `*` and `IsHidden`. `CreateGroup` shares `/Users/Shared/NAME`
  (root:group 2770), since `/srv` is on the sealed system volume. macOS gives a
  new file its directory's group, not its creator's, so what a user creates in
  `/tmp` is group `wheel`.
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
- Inspection CA: written to `/private/etc/ssl/certs/burrow-inspection-ca.pem`,
  appended to `/etc/ssl/cert.pem` and to any bundle the image named. The
  system curl (LibreSSL) verifies through it; verified against a server in the
  guest. Not the keychain: adding trust settings needs the
  `com.apple.trust-settings.admin` right, which is an entitlement or an
  administrator in a dialog, and `security add-trusted-cert` and
  `security authorizationdb write` both fail without one; macOS 27 keeps
  trustd's settings where root cannot write them. So the Security framework
  (URLSession, Safari, Swift, Go's crypto/x509 on darwin) does not trust the
  CA. A template meant for inspection has to carry it already, from a
  configuration profile installed with a person present or by MDM.
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

- Volume mounts.
- Trusting the inspection CA in the keychain (above).
- GUI sessions: a command as a user runs in the system bootstrap context, not
  the user's Aqua session (no login keychain, no window server). `launchctl
  asuser` would be the route.
- Accounts deleted outside the agent stay found for a while: libinfo caches
  lookups in the agent's process. Nothing in the API deletes one.
- More than 16 groups per user (setgroups(2)'s limit on macOS).

## Windows

Untested on Windows: there was no Windows machine to run it on. It checks,
lints and links for `x86_64-pc-windows-gnu` and `aarch64-pc-windows-gnullvm`
from macOS, and the logic that does not call Windows is unit tested. Everything
that calls Windows has run nowhere yet.

### What it implements

| RPC | Status |
| --- | --- |
| Handshake | clock, inspection CA, network; entropy accepted and not used (below); volumes refused with `UNIMPLEMENTED` |
| Health | `files-as-user`, `attach-input`, `output-feed`, `fs-scoped` |
| Exec, Attach, AttachCommand, ListCommands, GetCommand, SignalCommand, PruneCommands, Feed | as on Linux: the same registry and feed code |
| UploadFile, DownloadFile, ListDir | as on Linux, a link anywhere on the path refused |
| Watch | `ReadDirectoryChangesW`; `interval_ms` is ignored |
| Fs | every op; chown is accepted and changes nothing, as in Node on Windows |
| CreateUser, CreateGroup, AddUserToGroup, RemoveUserFromGroup | NetApi local accounts and groups |
| Upgrade | replaces the binary and restarts the service |

Not implemented: volume mounts, and open `Fs` handles surviving an upgrade
(they read as EBADF after one; a new process cannot take over the old one's
handles).

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
   registered (`viosocklib`). QEMU needs `-device vhost-vsock-pci,guest-cid=N`.
   For RNG reseeding on restore, add `-device vmgenid,guid=auto`.
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
reseeds a restored Windows guest is the VM Generation ID: give QEMU
`-device vmgenid,guid=auto` and Windows reseeds when the identifier changes.

### Stat

`dev` is the volume serial number, `ino` the file index, `nlink` the link
count, times are the file's own (with `ctime` the NTFS change time and
`birthtime` its creation time). Mode follows Node on Windows: directories
0777, files 0666 or 0444 when read-only, plus 0111 for `.exe`, `.com`,
`.bat`, `.cmd`; symlinks and junctions are links. chmod sets or clears the
read-only attribute by the owner's write bit.
