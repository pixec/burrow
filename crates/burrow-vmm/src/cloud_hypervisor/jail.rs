//! Confinement for Cloud Hypervisor, which has no jailer of its own.
//!
//! burrowd runs itself again as a short helper ([`HELPER_ARG`]), which builds
//! the jail and execs the VMM inside it:
//!
//! - started inside the VM's cgroup, joined before the helper execs, so the
//!   VMM it forks is counted and capped from its first instruction;
//! - new mount, IPC, PID and network namespaces. The VMM is PID 1 of its own
//!   and sees no other process; its NIC is a tap descriptor burrowd opened and
//!   handed over the API socket, so it needs no network of its own either;
//! - a root that is a fresh read-only tmpfs mounted over the VM's working
//!   directory, holding the working directory itself at [`VMM_WORKDIR`], device
//!   nodes for `/dev/kvm` (owned by the jail uid) and `/dev/urandom`, and,
//!   read-only at their own paths, the host files the VM config names
//!   absolutely (a node-wide kernel, the UEFI firmware). Nothing else of the
//!   host's filesystem exists inside;
//! - every capability dropped, bounding set included, then the jail's uid and
//!   gid with no supplementary groups, `no_new_privs`, and a parent-death
//!   signal, so the VMM does not outlive the helper;
//! - an empty environment: burrowd's carries the object store's credentials.
//!
//! The helper stays as the namespace's parent, reaping the VMM and exiting
//! with its status, so burrowd supervises it as it would the VMM itself; a
//! SIGTERM to the helper kills the VMM and reaps it before exiting. Inside,
//! Cloud Hypervisor's own seccomp filter stays on and its Landlock is enabled
//! for the working directory alone.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::process::Command;

/// The first argument that makes burrowd the helper instead of itself.
pub const HELPER_ARG: &str = "__cloud-hypervisor-jail";

/// Where the VM's working directory is inside the jail, and the VMM's cwd.
pub const VMM_WORKDIR: &str = "/work";

/// How Cloud Hypervisor is confined on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChJail {
    /// The binary that runs as the helper: burrowd itself. `/proc/self/exe`
    /// rather than its path, so a binary replaced on disk while the node runs
    /// still starts helpers that speak its own plan.
    pub helper: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

/// What the helper is told, as JSON in its one argument after [`HELPER_ARG`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Plan {
    pub workdir: PathBuf,
    pub uid: u32,
    pub gid: u32,
    /// Host files bound read-only into the jail at the same absolute path.
    pub read_only: Vec<PathBuf>,
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl Plan {
    pub(crate) fn command(&self, jail: &ChJail) -> Command {
        let mut command = Command::new(&jail.helper);
        command
            .arg(HELPER_ARG)
            .arg(serde_json::to_string(self).expect("a plan serialises"));
        command
    }
}

/// The host files a VM config names by absolute path, which have to be bound
/// into the jail where the VMM will look for them. Everything else in it is
/// relative to the working directory.
pub(crate) fn absolute_paths(vm_config: &serde_json::Value) -> Vec<PathBuf> {
    ["kernel", "firmware", "initramfs"]
        .iter()
        .filter_map(|field| vm_config["payload"][field].as_str())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .collect()
}

/// Turns Cloud Hypervisor's Landlock on for a VM config, allowing the working
/// directory, or off. The config-derived rules Cloud Hypervisor adds itself
/// cover the disks, kernel and firmware; the directory is allowed as a whole
/// because a snapshot is written into it and a hotplugged volume is opened
/// from it, neither of which exists when the ruleset is made.
pub(crate) fn set_landlock(vm_config: &mut serde_json::Value, is_enabled: bool) {
    match is_enabled {
        true => {
            vm_config["landlock_enable"] = serde_json::json!(true);
            vm_config["landlock_rules"] =
                serde_json::json!([{ "path": VMM_WORKDIR, "access": "rw" }]);
        }
        false => {
            if let Some(vm) = vm_config.as_object_mut() {
                vm.remove("landlock_enable");
                vm.remove("landlock_rules");
            }
        }
    }
}

/// Points a snapshot's NICs at how the restoring VMM gets its taps. Jailed,
/// it is a descriptor handed over with the restore, which Cloud Hypervisor
/// applies only to a NIC the config records as descriptor-backed; unjailed,
/// it is the tap by name, and a NIC recorded with descriptors would wait for
/// ones that never come.
pub(crate) fn address_nics(vm_config: &mut serde_json::Value, is_jailed: bool) {
    let nics = vm_config["net"].as_array_mut().into_iter().flatten();
    for nic in nics.filter_map(serde_json::Value::as_object_mut) {
        if is_jailed {
            nic.remove("tap");
            nic.insert("fds".into(), serde_json::json!([-1]));
        } else {
            nic.remove("fds");
        }
    }
}

/// Runs as the helper and never returns, when this process was started as
/// one; returns at once otherwise. Called first thing in `main`, before any
/// thread exists: a process with threads cannot unshare its mount namespace.
pub fn run_if_helper() {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_none_or(|arg| arg != HELPER_ARG) {
        return;
    }
    let plan = args
        .next()
        .and_then(|plan| serde_json::from_str::<Plan>(&plan.to_string_lossy()).ok());
    let Some(plan) = plan else {
        eprintln!("cloud-hypervisor jail: no plan");
        std::process::exit(125);
    };
    #[cfg(target_os = "linux")]
    match linux::supervise(&plan) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("cloud-hypervisor jail: {err}");
            std::process::exit(125);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "cloud-hypervisor jail: {} cannot be jailed off Linux",
            plan.program.display()
        );
        std::process::exit(125);
    }
}

/// Opens a tap the way Cloud Hypervisor would by name, for it to be handed
/// the descriptor instead: attaching to a tap needs `CAP_NET_ADMIN`, which
/// the jailed VMM does not have.
#[cfg(target_os = "linux")]
pub(crate) fn open_tap(name: &str) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt as _;

    #[repr(C)]
    struct IfReq {
        name: [u8; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    if name.len() >= libc::IFNAMSIZ {
        return Err(std::io::Error::other(format!(
            "tap name {name} is too long"
        )));
    }
    let tun: OwnedFd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/net/tun")?
        .into();
    let mut req = IfReq {
        name: [0; libc::IFNAMSIZ],
        flags: (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short,
        _pad: [0; 22],
    };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: TUNSETIFF reads and writes an ifreq, which `req` is laid out as.
    if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, &mut req) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(tun)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use nix::mount::{MntFlags, MsFlags, mount, umount2};
    use nix::sched::{CloneFlags, unshare};
    use nix::sys::signal::{SigSet, Signal, kill};
    use nix::sys::stat::{Mode, SFlag, mknod};
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::{ForkResult, Gid, Uid, fexecve, fork};

    use super::{Plan, VMM_WORKDIR};

    /// The helper's own half: unshares, forks the VMM into the new
    /// namespaces and waits for it.
    pub(super) fn supervise(plan: &Plan) -> std::io::Result<i32> {
        // Opened before the pivot hides the host, and exec'd by descriptor.
        let program = std::fs::File::open(&plan.program)?;
        let args = plan
            .args
            .iter()
            .map(|arg| CString::new(arg.as_str()))
            .collect::<Result<Vec<_>, _>>()?;
        let argv: Vec<CString> = std::iter::once(CString::new("cloud-hypervisor")?)
            .chain(args)
            .collect();

        let signals = {
            let mut set = SigSet::empty();
            for signal in [
                Signal::SIGTERM,
                Signal::SIGINT,
                Signal::SIGHUP,
                Signal::SIGCHLD,
            ] {
                set.add(signal);
            }
            set
        };
        signals.thread_block()?;
        unshare(
            CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWNET,
        )?;
        // SAFETY: this process has one thread; the child only makes system
        // calls on memory prepared above before it execs.
        let child = match unsafe { fork() }? {
            ForkResult::Child => {
                let err = confine(plan).and_then(|()| {
                    SigSet::empty().thread_set_mask()?;
                    fexecve(&program, &argv, &[] as &[CString])?;
                    Ok(())
                });
                eprintln!(
                    "cloud-hypervisor jail: {}",
                    err.err().map_or_else(String::new, |err| err.to_string())
                );
                // SAFETY: leaving the forked child without unwinding.
                unsafe { libc::_exit(126) }
            }
            ForkResult::Parent { child } => child,
        };
        loop {
            match signals.wait()? {
                Signal::SIGCHLD => match waitpid(child, Some(WaitPidFlag::WNOHANG))? {
                    WaitStatus::Exited(_, code) => return Ok(code),
                    WaitStatus::Signaled(_, signal, _) => return Ok(128 + signal as i32),
                    _ => {}
                },
                _ => {
                    let _ = kill(child, Signal::SIGKILL);
                }
            }
        }
    }

    /// Builds the jail around the process that is about to become the VMM:
    /// PID 1 of its namespace, still root, about to be nobody.
    fn confine(plan: &Plan) -> std::io::Result<()> {
        let root = &plan.workdir;
        let devices = [
            ("kvm", 0o600, Some((plan.uid, plan.gid))),
            ("urandom", 0o666, None),
        ]
        .map(|(name, mode, owner)| {
            std::fs::metadata(Path::new("/dev").join(name))
                .map(|meta| (name, meta.rdev(), mode, owner))
        });
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )?;
        // The working directory is held open across the tmpfs that covers it,
        // and bound back in through the descriptor.
        let workdir = std::fs::File::open(root)?;
        mount(
            Some("tmpfs"),
            root,
            Some("tmpfs"),
            MsFlags::MS_NOSUID,
            Some("mode=0755,size=1m"),
        )?;
        let inside = |path: &str| root.join(path.trim_start_matches('/'));
        std::fs::create_dir(inside(VMM_WORKDIR))?;
        mount(
            Some(
                Path::new("/proc/self/fd")
                    .join(workdir.as_raw_fd().to_string())
                    .as_path(),
            ),
            &inside(VMM_WORKDIR),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
        mount(
            None::<&str>,
            &inside(VMM_WORKDIR),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None::<&str>,
        )?;
        drop(workdir);

        std::fs::create_dir(inside("/dev"))?;
        for device in devices {
            let (name, rdev, mode, owner) = device?;
            let path = inside("/dev").join(name);
            mknod(&path, SFlag::S_IFCHR, Mode::from_bits_truncate(mode), rdev)?;
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
            if let Some((uid, gid)) = owner {
                std::os::unix::fs::chown(&path, Some(uid), Some(gid))?;
            }
        }
        for file in &plan.read_only {
            let target = inside(&file.to_string_lossy());
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::File::create(&target)?;
            mount(
                Some(file.as_path()),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )?;
            mount(
                None::<&str>,
                &target,
                None::<&str>,
                MsFlags::MS_BIND
                    | MsFlags::MS_REMOUNT
                    | MsFlags::MS_RDONLY
                    | MsFlags::MS_NOSUID
                    | MsFlags::MS_NODEV,
                None::<&str>,
            )?;
        }

        nix::unistd::chdir(root)?;
        nix::unistd::pivot_root(".", ".")?;
        umount2(".", MntFlags::MNT_DETACH)?;
        nix::unistd::chdir("/")?;
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID,
            None::<&str>,
        )?;
        nix::unistd::chdir(VMM_WORKDIR)?;

        for cap in 0..=libc::c_ulong::from(u8::MAX) {
            // SAFETY: PR_CAPBSET_DROP takes a capability number and nothing
            // else. Past the last one the kernel knows it fails, and the
            // loop is done.
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } < 0 {
                break;
            }
        }
        nix::unistd::setgroups(&[])?;
        let (uid, gid) = (Uid::from_raw(plan.uid), Gid::from_raw(plan.gid));
        nix::unistd::setresgid(gid, gid, gid)?;
        nix::unistd::setresuid(uid, uid, uid)?;
        nix::sys::prctl::set_no_new_privs()?;
        // After the uid change, which clears it.
        nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)?;
        Ok(())
    }
}

/// The working directory as the VMM addresses it, jailed or not: the `file://`
/// URLs a snapshot and a restore name have to be absolute.
pub(crate) fn vmm_workdir(workdir: &Path, jail: Option<&ChJail>) -> std::io::Result<PathBuf> {
    match jail {
        Some(_) => Ok(PathBuf::from(VMM_WORKDIR)),
        None => std::path::absolute(workdir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jail() -> ChJail {
        ChJail {
            helper: "/proc/self/exe".into(),
            uid: 65534,
            gid: 65534,
        }
    }

    /// The helper is burrowd with the plan in one argument, which it reads
    /// back unchanged.
    #[test]
    fn the_helper_is_handed_the_whole_plan() {
        let plan = Plan {
            workdir: "/var/lib/burrow/jail/firecracker/sbx-1/root".into(),
            uid: 65534,
            gid: 65534,
            read_only: vec!["/usr/local/share/cloud-hypervisor/CLOUDHV_EFI.fd".into()],
            program: "/usr/local/bin/cloud-hypervisor".into(),
            args: vec!["--api-socket".into(), "path=ch.sock".into()],
        };
        let command = plan.command(&jail());
        let std = command.as_std();
        assert_eq!(std.get_program(), "/proc/self/exe");
        let args: Vec<_> = std.get_args().collect();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], HELPER_ARG);
        let read: Plan = serde_json::from_str(&args[1].to_string_lossy()).unwrap();
        assert_eq!(read, plan);
    }

    /// Paths in the config are relative to the working directory, except
    /// what the node keeps for every VM, which has to be bound in.
    #[test]
    fn only_absolute_payload_paths_are_bound_in() {
        let linux = json!({ "payload": { "kernel": "vmlinux", "cmdline": "console=hvc0" } });
        assert!(absolute_paths(&linux).is_empty());
        let node_kernel = json!({ "payload": { "kernel": "/var/lib/burrow/vmlinux-ch" } });
        assert_eq!(
            absolute_paths(&node_kernel),
            [PathBuf::from("/var/lib/burrow/vmlinux-ch")]
        );
        let windows = json!({ "payload": { "firmware": "/usr/local/share/cloud-hypervisor/CLOUDHV_EFI.fd" } });
        assert_eq!(absolute_paths(&windows).len(), 1);
    }

    #[test]
    fn landlock_allows_the_working_directory_alone() {
        let mut vm = json!({ "payload": { "kernel": "vmlinux" } });
        set_landlock(&mut vm, true);
        assert_eq!(vm["landlock_enable"], true);
        assert_eq!(
            vm["landlock_rules"],
            json!([{ "path": "/work", "access": "rw" }])
        );
        // A jailed VM's snapshot restored unjailed, on a node without the
        // jail, must not carry rules for paths that do not exist there.
        set_landlock(&mut vm, false);
        assert!(vm.get("landlock_enable").is_none());
        assert!(vm.get("landlock_rules").is_none());
    }

    /// A snapshot moves between jailed and unjailed VMMs: a warm snapshot
    /// built before the jail, or a sandbox adopted across nodes.
    #[test]
    fn a_restored_nic_takes_its_tap_the_way_this_vmm_can() {
        let by_name =
            json!({ "net": [{ "id": "net0", "tap": "bt3", "mac": "06:00:0a:00:00:0e" }] });
        let mut jailed = by_name.clone();
        address_nics(&mut jailed, true);
        assert_eq!(
            jailed["net"],
            json!([{ "id": "net0", "fds": [-1], "mac": "06:00:0a:00:00:0e" }])
        );
        let mut unjailed = jailed.clone();
        unjailed["net"][0]["tap"] = json!("bt3");
        address_nics(&mut unjailed, false);
        assert_eq!(unjailed, by_name);
    }

    #[test]
    fn a_jailed_vmm_addresses_its_workdir_from_inside() {
        let workdir = Path::new("/var/lib/burrow/jail/firecracker/sbx-1/root");
        assert_eq!(
            vmm_workdir(workdir, Some(&jail())).unwrap(),
            Path::new("/work")
        );
        assert_eq!(vmm_workdir(workdir, None).unwrap(), workdir);
    }
}
