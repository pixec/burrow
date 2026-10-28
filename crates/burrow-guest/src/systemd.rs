//! Systemd guest mode.
//!
//! A template that asks for it (`burrow.systemd=1` on the kernel command line)
//! boots its own systemd as a child of the agent. The agent stays PID 1 and
//! keeps every duty it has without systemd; systemd runs in new PID, mount
//! and cgroup namespaces the way a container manager would run it, under a
//! cgroup subtree delegated to it. The network namespace is shared, so the
//! address a restore reapplies is the one systemd's services use.
//!
//! Exec enters systemd's namespaces and file operations resolve against its
//! root, so both see the guest the way its own services do.

use std::ffi::CString;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use nix::libc;
use nix::mount::{MsFlags, mount};

use crate::reaper;

const CANDIDATES: [&str; 2] = ["/usr/lib/systemd/systemd", "/lib/systemd/systemd"];

/// Units masked for every boot, without touching the image's disk.
///
/// The getty would take over the agent's console, which nobody can log in on.
/// The rest manage the network burrow configures: they would fight it for the
/// interface, a restore re-addresses it under them, and their wait-online
/// units would hold boot for minutes on a DHCP lease nothing hands out.
const MASKED: [&str; 11] = [
    "console-getty.service",
    "systemd-networkd.service",
    "systemd-networkd.socket",
    "systemd-networkd-wait-online.service",
    "NetworkManager.service",
    "NetworkManager-wait-online.service",
    "cloud-init-local.service",
    "cloud-init.service",
    "cloud-init-network.service",
    "cloud-config.service",
    "cloud-final.service",
];
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Where systemd reports readiness. Abstract, so it needs no path both mount
/// namespaces can see; the network namespace they share is what scopes it.
const NOTIFY_SOCKET: &str = "burrow-systemd-notify";

/// Carries systemd's pid across an agent upgrade, which re-executes the agent
/// but leaves its children running.
pub const PID_MARK: &str = "BURROW_GUEST_SYSTEMD";

/// Running systemd's pid, 0 when there is none.
static PID: AtomicI32 = AtomicI32::new(0);
/// Counts systemd boots, to give each a cgroup of its own.
static BOOTS: AtomicU32 = AtomicU32::new(0);

/// Whether the guest is ready for the host: always in agent-only mode, and in
/// systemd mode once systemd has finished starting up.
fn ready() -> &'static tokio::sync::watch::Sender<bool> {
    static READY: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();
    READY.get_or_init(|| tokio::sync::watch::Sender::new(true))
}

pub fn is_requested() -> bool {
    std::fs::read_to_string("/proc/cmdline").is_ok_and(|cmdline| {
        cmdline
            .split_whitespace()
            .any(|arg| arg == "burrow.systemd=1")
    })
}

pub fn pid() -> Option<i32> {
    match PID.load(Ordering::Acquire) {
        0 => None,
        pid => Some(pid),
    }
}

/// Waits for systemd to report it has started, up to `timeout`.
///
/// A guest whose systemd is slow or never reports is still usable through the
/// agent, so running out of time is logged rather than failed.
pub async fn wait_ready(timeout: std::time::Duration) {
    let mut rx = ready().subscribe();
    if tokio::time::timeout(timeout, rx.wait_for(|ready| *ready))
        .await
        .is_err()
    {
        tracing::warn!(?timeout, "systemd has not reported ready; continuing");
    }
}

/// Starts systemd on a fresh boot and keeps it running for the life of the
/// guest.
pub fn start() {
    let Some(binary) = locate() else {
        tracing::error!("burrow.systemd=1 but the image has no systemd; running agent-only");
        return;
    };
    if let Err(err) = delegate_cgroups() {
        tracing::error!(%err, "cannot delegate cgroups to systemd; running agent-only");
        return;
    }
    listen_for_notify();
    ready().send_replace(false);
    let _gate = reaper::hold();
    match spawn(binary) {
        Ok(pid) => supervise(binary, pid),
        Err(err) => {
            tracing::error!(%err, "systemd did not start; running agent-only");
            ready().send_replace(true);
        }
    }
}

/// Takes over the systemd a previous agent started, after an upgrade.
///
/// Must run before the reaper starts, so an exit during the re-exec is still
/// delivered here rather than discarded as an orphan's.
pub fn adopt() {
    let Some(pid) = std::env::var(PID_MARK)
        .ok()
        .and_then(|pid| pid.parse::<i32>().ok())
    else {
        return;
    };
    let Some(binary) = locate() else {
        return;
    };
    listen_for_notify();
    supervise(binary, pid);
}

fn locate() -> Option<&'static str> {
    CANDIDATES
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
}

/// Mounts the cgroup2 hierarchy and enables every controller for children of
/// the root, where each systemd boot gets its subtree. The agent and the
/// commands it runs stay in the root, which is exempt from the rule that a
/// cgroup with controllers enabled holds no processes.
///
/// The root is made shared so the slave copy systemd gets keeps receiving the
/// volumes a later handshake mounts.
fn delegate_cgroups() -> anyhow::Result<()> {
    std::fs::create_dir_all(CGROUP_ROOT)?;
    match mount(
        Some("cgroup2"),
        CGROUP_ROOT,
        Some("cgroup2"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    ) {
        Ok(()) | Err(nix::errno::Errno::EBUSY) => {}
        Err(err) => anyhow::bail!("mounting cgroup2: {err}"),
    }
    let controllers = std::fs::read_to_string(format!("{CGROUP_ROOT}/cgroup.controllers"))?;
    for controller in controllers.split_whitespace() {
        if let Err(err) = std::fs::write(
            format!("{CGROUP_ROOT}/cgroup.subtree_control"),
            format!("+{controller}"),
        ) {
            tracing::debug!(controller, %err, "controller not delegated");
        }
    }
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_SHARED | MsFlags::MS_REC,
        None::<&str>,
    )?;
    Ok(())
}

fn listen_for_notify() {
    use std::os::linux::net::SocketAddrExt as _;

    let socket = std::os::unix::net::SocketAddr::from_abstract_name(NOTIFY_SOCKET)
        .and_then(|addr| std::os::unix::net::UnixDatagram::bind_addr(&addr))
        .and_then(|socket| {
            socket.set_nonblocking(true)?;
            tokio::net::UnixDatagram::from_std(socket)
        });
    let socket = match socket {
        Ok(socket) => socket,
        Err(err) => {
            // Without it the handshake waits out its timeout on every boot,
            // which is slow but not broken.
            tracing::warn!(%err, "cannot listen for systemd notifications");
            return;
        }
    };
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok(len) = socket.recv(&mut buf).await {
            let message = String::from_utf8_lossy(&buf[..len]);
            if message.lines().any(|line| line == "READY=1") {
                tracing::debug!("systemd reported ready");
                ready().send_replace(true);
            }
        }
    });
}

/// Watches systemd and acts on how it ended.
///
/// systemd in a PID namespace cannot reset the machine: its `reboot(2)` ends
/// the namespace instead, killing its init with SIGHUP for a reboot and
/// SIGINT for a power-off or halt. A reboot is a fresh systemd on the same
/// disk; a power-off resets the VM, which Firecracker treats as the VM
/// shutting down.
fn supervise(binary: &'static str, pid: i32) {
    let exit = reaper::watch(pid);
    PID.store(pid, Ordering::Release);
    tokio::spawn(async move {
        let code = exit.await.map(|exit| exit.code).unwrap_or(-1);
        PID.store(0, Ordering::Release);
        ready().send_replace(false);
        match code {
            code if code == 128 + libc::SIGINT => {
                tracing::warn!("systemd powered off; shutting the VM down");
                nix::unistd::sync();
                // SAFETY: a bare syscall; the guest ends here if it succeeds.
                unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_RESTART) };
                return;
            }
            code if code == 128 + libc::SIGHUP => tracing::warn!("systemd rebooting"),
            code => {
                tracing::error!(code, "systemd exited; restarting it");
                // A systemd that dies at once would otherwise spin.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        let _gate = reaper::hold();
        match spawn(binary) {
            Ok(pid) => supervise(binary, pid),
            Err(err) => {
                tracing::error!(%err, "systemd did not restart; running agent-only");
                ready().send_replace(true);
            }
        }
    });
}

/// Starts systemd as PID 1 of a new PID namespace, in a cgroup of its own.
///
/// A process's PID namespace is fixed when it is forked, so the namespace is
/// unshared on a thread of its own before the fork and goes away with it; the
/// rest is unshared by the child itself between fork and exec.
fn spawn(binary: &'static str) -> std::io::Result<i32> {
    let boot = BOOTS.fetch_add(1, Ordering::Relaxed);
    let cgroup = format!("{CGROUP_ROOT}/guest-{boot}");
    // An earlier boot's tree, emptied by its namespace ending. Best effort: a
    // straggler only costs an empty cgroup.
    if boot > 0 {
        remove_cgroup(std::path::Path::new(&format!(
            "{CGROUP_ROOT}/guest-{}",
            boot - 1
        )));
    }
    std::fs::create_dir_all(&cgroup)?;
    let procs = CString::new(format!("{cgroup}/cgroup.procs")).expect("no nul in path");

    // Not the console: Firecracker emulates it a byte at a time, and systemd's
    // boot output alone would add whole seconds. Its journal has the same.
    let console = || {
        if tracing::enabled!(tracing::Level::DEBUG) {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    };
    let mut command = Command::new(binary);
    // In a container systemd reads these from its own arguments rather than
    // the kernel's. Status goes to /dev/console whatever stdout is.
    command.args(MASKED.map(|unit| format!("systemd.mask={unit}")));
    if !tracing::enabled!(tracing::Level::DEBUG) {
        command.args(["systemd.show_status=0", "systemd.log_target=journal"]);
    }
    command
        .env_clear()
        .env("container", "burrow")
        .env("NOTIFY_SOCKET", format!("@{NOTIFY_SOCKET}"))
        .stdin(Stdio::null())
        .stdout(console())
        .stderr(console());
    // SAFETY: runs between fork and exec, so only async-signal-safe calls:
    // these are bare syscalls on strings prepared before the fork.
    unsafe { command.pre_exec(move || isolate(&procs)) };

    std::thread::spawn(move || {
        // SAFETY: a bare syscall, on this thread alone.
        check(unsafe { libc::unshare(libc::CLONE_NEWPID) })?;
        command.spawn().map(|child| child.id() as i32)
    })
    .join()
    .map_err(|_| std::io::Error::other("systemd spawner panicked"))?
}

/// The child's half of [`spawn`]: into its cgroup, then a mount namespace with
/// the views a PID 1 of its own namespace needs.
fn isolate(procs: &CString) -> std::io::Result<()> {
    // SAFETY: bare syscalls on NUL-terminated strings that outlive them.
    unsafe {
        // Before the cgroup namespace: it is rooted wherever its creator is.
        let fd = check(libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC))?;
        let written = libc::write(fd, c"0".as_ptr().cast(), 1);
        libc::close(fd);
        if written < 0 {
            return Err(std::io::Error::last_os_error());
        }
        check(libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP))?;
        // Slave, so mounts the agent makes later still arrive and nothing
        // systemd mounts leaks back.
        check(libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_SLAVE,
            std::ptr::null(),
        ))?;
        // The agent's proc shows the outer namespace, where PID 1 is the agent.
        libc::umount2(c"/proc".as_ptr(), libc::MNT_DETACH);
        check(libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            std::ptr::null(),
        ))?;
        // Mounted from inside the cgroup namespace, so its root is the
        // delegated subtree.
        libc::umount2(c"/sys/fs/cgroup".as_ptr(), libc::MNT_DETACH);
        check(libc::mount(
            c"cgroup2".as_ptr(),
            c"/sys/fs/cgroup".as_ptr(),
            c"cgroup2".as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            std::ptr::null(),
        ))?;
        // The agent's /run holds its upgrade binary and state.
        check(libc::mount(
            c"tmpfs".as_ptr(),
            c"/run".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=0755".as_ptr().cast(),
        ))?;
    }
    Ok(())
}

fn check(ret: libc::c_int) -> std::io::Result<libc::c_int> {
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Removes a cgroup tree, deepest first: a cgroup with children cannot go.
fn remove_cgroup(path: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                remove_cgroup(&entry.path());
            }
        }
    }
    let _ = std::fs::remove_dir(path);
}

/// systemd's namespaces, held open for one spawn.
pub struct Namespaces {
    pid: OwnedFd,
    mnt: OwnedFd,
    cgroup: OwnedFd,
}

impl Namespaces {
    /// The running systemd's, or `None` when the guest has none.
    pub fn current() -> std::io::Result<Option<Self>> {
        let Some(pid) = pid() else {
            return Ok(None);
        };
        let open =
            |kind: &str| std::fs::File::open(format!("/proc/{pid}/ns/{kind}")).map(OwnedFd::from);
        Ok(Some(Self {
            pid: open("pid")?,
            mnt: open("mnt")?,
            cgroup: open("cgroup")?,
        }))
    }

    /// Makes `command` start in systemd's mount and cgroup namespaces, in
    /// `cwd`.
    ///
    /// Registered before any other `pre_exec`, since entering needs the
    /// privilege a later one may drop. The working directory is set here
    /// rather than with `current_dir`, which std applies before any `pre_exec`
    /// and which entering a mount namespace resets to its root.
    pub fn enter(&self, command: &mut Command, cwd: Option<&str>) -> std::io::Result<()> {
        let (mnt, cgroup) = (self.mnt.as_raw_fd(), self.cgroup.as_raw_fd());
        let cwd = cwd.map(CString::new).transpose()?;
        // SAFETY: runs between fork and exec, so only async-signal-safe calls:
        // bare syscalls on descriptors this struct holds open across the spawn.
        unsafe {
            command.pre_exec(move || {
                check(libc::setns(mnt, libc::CLONE_NEWNS))?;
                check(libc::setns(cgroup, libc::CLONE_NEWCGROUP))?;
                if let Some(cwd) = &cwd {
                    check(libc::chdir(cwd.as_ptr()))?;
                }
                Ok(())
            });
        }
        Ok(())
    }

    /// Spawns `command` into systemd's PID namespace.
    ///
    /// From a thread of its own, for the reason [`spawn`] gives: entering a
    /// PID namespace only moves the children forked afterwards, and the
    /// thread takes the change with it when it ends.
    pub fn spawn(&self, command: &mut Command) -> std::io::Result<std::process::Child> {
        let pid = self.pid.as_raw_fd();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // SAFETY: a bare syscall on a descriptor held open by self.
                    check(unsafe { libc::setns(pid, libc::CLONE_NEWPID) })?;
                    command.spawn()
                })
                .join()
                .map_err(|_| std::io::Error::other("spawner panicked"))?
        })
    }
}
