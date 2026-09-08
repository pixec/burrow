//! PID 1 duties.
//!
//! The agent runs as init inside the guest: no systemd, no udev, no getty.
//! This module brings up the filesystems: the writable overlay root and the
//! pseudo-filesystems. Reaping, init's other duty, lives in [`crate::reaper`].

use std::path::Path;

use nix::mount::{MntFlags, MsFlags, mount, umount2};

/// Second virtio drive, if the node attached one.
const SCRATCH_DEV: &str = "/dev/vdb";
const SCRATCH_MNT: &str = "/scratch";

/// Turns the read-only template rootfs into a writable filesystem by union
/// mounting a per-sandbox scratch disk over it, then pivoting into the union.
///
/// Without this the sandbox can only write to tmpfs, which is RAM-backed and
/// far too small for package installs. Failure is not fatal: the sandbox still
/// boots read-only, which is degraded but usable and much easier to debug than
/// a boot loop.
pub fn setup_writable_root() -> bool {
    // /dev must exist before the scratch device node is visible.
    mount_one("devtmpfs", "/dev", "devtmpfs", MsFlags::MS_NOSUID, None);

    if !Path::new(SCRATCH_DEV).exists() {
        tracing::debug!("no scratch disk attached; root stays read-only");
        return false;
    }
    match try_pivot_to_overlay() {
        Ok(()) => {
            tracing::debug!("writable overlay root active");
            true
        }
        Err(err) => {
            tracing::error!(%err, "overlay root setup failed; continuing read-only");
            false
        }
    }
}

fn try_pivot_to_overlay() -> anyhow::Result<()> {
    // pivot_root refuses to work when the root's parent mount is shared.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )?;

    std::fs::create_dir_all(SCRATCH_MNT)?;
    mount(
        Some(SCRATCH_DEV),
        SCRATCH_MNT,
        Some("ext4"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    let upper = format!("{SCRATCH_MNT}/upper");
    let work = format!("{SCRATCH_MNT}/work");
    let newroot = format!("{SCRATCH_MNT}/newroot");
    for dir in [&upper, &work, &newroot] {
        std::fs::create_dir_all(dir)?;
    }

    // upperdir and workdir must be on the same filesystem as each other and a
    // different one from lowerdir, which is why they live on the scratch disk.
    mount(
        Some("overlay"),
        newroot.as_str(),
        Some("overlay"),
        MsFlags::empty(),
        Some(format!("lowerdir=/,upperdir={upper},workdir={work}").as_str()),
    )?;

    std::env::set_current_dir(&newroot)?;
    std::fs::create_dir_all(format!("{newroot}/oldroot"))?;
    // Relative to the new root, so this is <newroot>/oldroot.
    nix::unistd::pivot_root(".", "oldroot")?;
    std::env::set_current_dir("/")?;

    // Detach rather than unmount: the overlay holds live references to the
    // scratch mount, so it stays alive while leaving the namespace clean.
    umount2("/oldroot", MntFlags::MNT_DETACH)?;
    let _ = std::fs::remove_dir("/oldroot");
    Ok(())
}

/// Mounts the pseudo-filesystems userspace expects. Missing ones are created;
/// already-mounted ones are ignored, so this is safe to call more than once.
///
/// Order matters: `/dev` must be a mounted devtmpfs before `/dev/pts` can be
/// created inside it, and without devpts `openpty` fails, so interactive exec
/// depends on this list staying in sequence.
pub fn mount_essentials() -> anyhow::Result<()> {
    // (source, target, fstype, flags, options)
    let mounts: &[(&str, &str, &str, MsFlags)] = &[
        (
            "proc",
            "/proc",
            "proc",
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        ),
        (
            "sysfs",
            "/sys",
            "sysfs",
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        ),
        ("devtmpfs", "/dev", "devtmpfs", MsFlags::MS_NOSUID),
        (
            "tmpfs",
            "/tmp",
            "tmpfs",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        ),
        (
            "tmpfs",
            "/run",
            "tmpfs",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        ),
    ];

    for (source, target, fstype, flags) in mounts {
        mount_one(source, target, fstype, *flags, None);
    }

    // devpts needs /dev mounted first, and needs explicit options: gid=5 is
    // the conventional `tty` group and ptmxmode makes /dev/pts/ptmx usable.
    mount_one(
        "devpts",
        "/dev/pts",
        "devpts",
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0620,gid=5,ptmxmode=0666"),
    );
    Ok(())
}

/// Writes `/etc/resolv.conf` from the `burrow.dns=` kernel argument.
///
/// The kernel's `ip=` argument configures the interface but never the
/// resolver, and the guest has no DHCP client, so without this a sandbox has
/// working IP connectivity and no working name resolution, which looks like a
/// network failure to anything running inside it.
///
/// Requires a writable root, so it runs after the overlay pivot.
pub fn write_resolv_conf() {
    let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") else {
        return;
    };
    let Some(dns) = cmdline
        .split_whitespace()
        .find_map(|arg| arg.strip_prefix("burrow.dns="))
    else {
        return;
    };
    if dns.is_empty() {
        return;
    }
    if let Err(err) = std::fs::write("/etc/resolv.conf", format!("nameserver {dns}\n")) {
        tracing::warn!(dns, %err, "could not write /etc/resolv.conf");
    } else {
        tracing::debug!(dns, "resolver configured");
    }
}

fn mount_one(source: &str, target: &str, fstype: &str, flags: MsFlags, options: Option<&str>) {
    if !Path::new(target).exists()
        && let Err(err) = std::fs::create_dir_all(target)
    {
        tracing::warn!(target, %err, "cannot create mount point");
        return;
    }
    match mount(Some(source), target, Some(fstype), flags, options) {
        Ok(()) => tracing::debug!(target, fstype, "mounted"),
        // EBUSY means it is already mounted, which is fine.
        Err(nix::errno::Errno::EBUSY) => {}
        Err(err) => tracing::warn!(target, fstype, %err, "mount failed"),
    }
}

/// Mounts the volumes the host attached, at the paths it named.
///
/// Called on every handshake rather than only at boot: a mount does not
/// survive the VM it was made in, so a resumed guest has the block devices but
/// an empty mount point until this runs again.
///
/// A failure here is reported to the host. A sandbox whose volume is missing
/// would otherwise write to the underlying directory instead, and the caller
/// would find the data gone rather than be told the mount never happened.
pub fn mount_volumes(volumes: &[burrow_proto::agent::v1::VolumeMount]) -> anyhow::Result<()> {
    for volume in volumes {
        // Checked again here, not only on the host: the path arrived over the
        // wire, and this is the code that turns it into a mount.
        if !volume.path.starts_with('/')
            || volume.path.split('/').any(|part| part == "..")
            || !volume.device.starts_with("/dev/")
        {
            anyhow::bail!(
                "refusing volume mount {:?} at {:?}",
                volume.device,
                volume.path
            );
        }
        // A hotplugged device does not exist until the bus is rescanned:
        // firecracker has no way to tell the guest one arrived. Only done when
        // the device is missing, so a cold boot, where the drive was there
        // from the start, pays nothing.
        if !Path::new(&volume.device).exists() {
            rescan_pci_bus();
            wait_for_device(&volume.device)?;
        }
        std::fs::create_dir_all(&volume.path)?;

        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        if volume.read_only {
            flags |= MsFlags::MS_RDONLY;
        }
        // `norecovery` for a read-only mount: the device is read-only at the
        // hypervisor, so ext4 cannot replay a journal even to mount, and a
        // volume last used by a writer has one. Without this the mount fails
        // with EROFS rather than coming up.
        let data = volume.read_only.then_some("norecovery");
        match mount(
            Some(volume.device.as_str()),
            volume.path.as_str(),
            Some("ext4"),
            flags,
            data,
        ) {
            Ok(()) => tracing::debug!(
                device = volume.device,
                path = volume.path,
                read_only = volume.read_only,
                "volume mounted"
            ),
            // Already mounted, which a second handshake on one boot would hit.
            Err(nix::errno::Errno::EBUSY) => {}
            Err(err) => {
                anyhow::bail!("mounting {} at {}: {err}", volume.device, volume.path)
            }
        }
    }
    Ok(())
}

/// Asks the kernel to look for devices that appeared since boot.
fn rescan_pci_bus() {
    match std::fs::write("/sys/bus/pci/rescan", "1") {
        Ok(()) => tracing::debug!("rescanned the pci bus"),
        // Not fatal on its own: the caller reports the missing device, which
        // is the more useful error than one about a sysfs path.
        Err(err) => tracing::warn!(%err, "could not rescan the pci bus"),
    }
}

/// Waits for a device node to appear after a rescan.
///
/// Enumeration and the devtmpfs node that follows it are asynchronous, so the
/// device is not there the instant the write returns.
fn wait_for_device(device: &str) -> anyhow::Result<()> {
    const WAIT: std::time::Duration = std::time::Duration::from_secs(5);
    let deadline = std::time::Instant::now() + WAIT;
    while std::time::Instant::now() < deadline {
        if Path::new(device).exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    anyhow::bail!("volume device {device} did not appear within {WAIT:?} of a bus rescan")
}
