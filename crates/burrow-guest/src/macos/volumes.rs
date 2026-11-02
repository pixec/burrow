//! Volume and tmpfs mounts on macOS.
//!
//! A macOS node keeps a volume as a raw image and attaches it as a virtio
//! disk after the system disk; the agent finds it by its position, formats
//! it journaled HFS+ the first time it is mounted writable, and mounts it at
//! the path asked for, read-only when the mount is. Not APFS: on a virtio
//! disk the guest formats APFS with inline encryption keyed to that one
//! machine, so no other sandbox could mount the volume. Not a shared
//! directory over virtio-fs: the guest presents one as a network volume, and
//! TCC keeps the agent out of network volumes without an MDM grant. A tmpfs
//! is `mount_tmpfs`.
//!
//! The sealed system volume is read-only, so a mount point has to be
//! somewhere the data volume backs (`/Users`, `/opt`, `/usr/local`,
//! `/Volumes`, `/private/var`); one at the root fails its mkdir.

#![allow(clippy::result_large_err)]

use std::os::unix::fs::PermissionsExt as _;

use tonic::Status;

use burrow_proto::guest::v1 as guestpb;

use super::users::run_tool;

/// What the host names a volume's disk with; see the daemon's
/// `volume::disk_id`.
const DISK_PREFIX: &str = "burrow-volume";
/// The HFS+ volume a fresh disk is formatted with.
const VOLUME_NAME: &str = "burrow-volume";

/// Mounts what the host attached, at the paths it named. One already
/// mounted there, as on a second handshake in one boot, is left as it is.
pub async fn mount(volumes: &[guestpb::VolumeMount]) -> Result<(), Status> {
    for volume in volumes {
        check(volume)?;
        let mode = match volume.mode.as_str() {
            "" => None,
            mode => Some(u32::from_str_radix(mode, 8).map_err(|_| {
                Status::invalid_argument(format!("mount mode {mode:?} is not octal"))
            })?),
        };
        std::fs::create_dir_all(&volume.path).map_err(|err| {
            Status::failed_precondition(format!(
                "creating mount point {}: {err}{}",
                volume.path,
                if err.raw_os_error() == Some(nix::libc::EROFS) {
                    " (the system volume is read-only; mount under /Users, /opt or /Volumes)"
                } else {
                    ""
                }
            ))
        })?;
        if is_mount_point(&volume.path) {
            continue;
        }
        let mut args = Vec::new();
        let size;
        if volume.is_tmpfs {
            if volume.size_mib > 0 {
                size = format!("{}m", volume.size_mib);
                args.extend(["-s", size.as_str()]);
            }
            if volume.is_read_only {
                args.extend(["-o", "rdonly"]);
            }
            args.push(&volume.path);
            run_tool("/sbin/mount_tmpfs", &args).await?;
        } else {
            mount_disk(volume).await?;
        }
        tracing::debug!(
            device = volume.device,
            path = volume.path,
            read_only = volume.is_read_only,
            "volume mounted"
        );
        // A default for a new volume, not an instruction to reset one that
        // has data and permissions of its own.
        if let Some(mode) = mode
            && !volume.is_read_only
            && (volume.is_tmpfs || is_empty(&volume.path)?)
        {
            std::fs::set_permissions(&volume.path, std::fs::Permissions::from_mode(mode)).map_err(
                |err| Status::internal(format!("chmod {} to {mode:o}: {err}", volume.path)),
            )?;
        }
    }
    Ok(())
}

/// Finds the volume's disk, formats it if nothing ever has, and mounts its
/// filesystem at the path.
///
/// Mounted by the kernel rather than through Disk Arbitration, which holds
/// an external disk's mount back until someone logs in at the console and
/// then mounts it under /Volumes with ownership ignored; one it has mounted
/// there already is unmounted first. A read-only mount ignores the journal,
/// as on Linux: the disk is read-only at the hypervisor, so a journal a
/// writer left could not be replayed even to mount it.
async fn mount_disk(volume: &guestpb::VolumeMount) -> Result<(), Status> {
    let devices = run_tool(
        "/usr/sbin/ioreg",
        &["-r", "-c", "IOBlockStorageDevice", "-l"],
    )
    .await?;
    let disk = disk_named(&devices, &volume.device).ok_or_else(|| {
        Status::failed_precondition(format!("no disk {} in the guest", volume.device))
    })?;
    let mut partition = hfs_partition(&run_tool("/usr/sbin/diskutil", &["list", &disk]).await?);
    if partition.is_none() {
        if volume.is_read_only {
            return Err(Status::failed_precondition(format!(
                "the volume at {} has never been mounted writable, so it has no filesystem \
                 to mount read-only",
                volume.path
            )));
        }
        run_tool(
            "/usr/sbin/diskutil",
            &["eraseDisk", "JHFS+", VOLUME_NAME, "GPT", &disk],
        )
        .await?;
        partition = hfs_partition(&run_tool("/usr/sbin/diskutil", &["list", &disk]).await?);
    }
    let partition = partition.ok_or_else(|| {
        Status::internal(format!("{disk} has no HFS+ partition after formatting it"))
    })?;
    let device = format!("/dev/{partition}");
    let mounts = run_tool("/sbin/mount", &[]).await?;
    if mounts
        .lines()
        .any(|line| line.starts_with(&format!("{device} on ")))
    {
        // Forced: Spotlight opens a volume Disk Arbitration has just mounted,
        // which makes a plain unmount fail as busy.
        run_tool("/usr/sbin/diskutil", &["unmount", "force", &device]).await?;
    }
    let mut args = vec!["-o"];
    match volume.is_read_only {
        true => args.extend(["rdonly,nobrowse", "-j"]),
        false => args.push("nobrowse"),
    }
    args.extend([device.as_str(), volume.path.as_str()]);
    run_tool("/sbin/mount_hfs", &args).await?;
    if !is_mount_point(&volume.path) {
        return Err(Status::internal(format!(
            "{device} did not stay mounted at {}",
            volume.path
        )));
    }
    Ok(())
}

/// The whole disk volume `id` (`burrow-volumeN`) was attached as, from
/// `ioreg -r -l` over the block storage devices. The guest does not show a
/// disk's identifier, so the volume is found by position: the host attaches
/// the system disk first and the volumes after it in order, the registry
/// numbers devices in the order they attach, and the system disk is the one
/// marked as the root.
fn disk_named(ioreg: &str, id: &str) -> Option<String> {
    let index: usize = id.strip_prefix(DISK_PREFIX)?.parse().ok()?;
    let mut disks: Vec<(u64, String)> = format!("\n{ioreg}")
        .split("\n+-o ")
        .skip(1)
        .filter(|device| !device.contains("\"EmbeddedDeviceTypeRoot\" = Yes"))
        .filter_map(|device| {
            let (_, rest) = device.split_once(", id 0x")?;
            let registry = u64::from_str_radix(rest.split(',').next()?, 16).ok()?;
            let name = device.lines().find_map(|line| {
                let (_, value) = line.split_once("\"BSD Name\" = \"")?;
                Some(value.trim_end_matches('"').to_string())
            })?;
            Some((registry, name))
        })
        .collect();
    disks.sort();
    disks.into_iter().nth(index).map(|(_, name)| name)
}

/// The HFS+ partition in `diskutil list` of one disk.
fn hfs_partition(list: &str) -> Option<String> {
    list.lines()
        .find(|line| line.contains("Apple_HFS "))
        .and_then(|line| line.split_whitespace().last())
        .map(str::to_string)
}

/// Checked here as well as on the host: this is the code that turns the
/// request into a mount.
fn check(volume: &guestpb::VolumeMount) -> Result<(), Status> {
    let tag_ok = volume.is_tmpfs
        || volume
            .device
            .strip_prefix(DISK_PREFIX)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    if !volume.path.starts_with('/')
        || volume
            .path
            .split('/')
            .any(|part| part == ".." || part == ".")
        || volume.path.trim_end_matches('/').is_empty()
        || !tag_ok
    {
        return Err(Status::invalid_argument(format!(
            "refusing volume mount {:?} at {:?}",
            volume.device, volume.path
        )));
    }
    Ok(())
}

/// Whether something is mounted at `path` itself.
fn is_mount_point(path: &str) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let (Ok(real), Ok(c_path)) = (std::fs::canonicalize(path), std::ffi::CString::new(path)) else {
        return false;
    };
    // SAFETY: all zeroes is a valid statfs, which the call fills.
    let mut stat: nix::libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a buffer of the right type.
    if unsafe { nix::libc::statfs(c_path.as_ptr(), &mut stat) } != 0 {
        return false;
    }
    // SAFETY: the kernel NUL-terminates the name within the array.
    let mounted = unsafe { std::ffi::CStr::from_ptr(stat.f_mntonname.as_ptr()) };
    mounted.to_bytes() == real.as_os_str().as_bytes()
}

fn is_empty(path: &str) -> Result<bool, Status> {
    let mut entries = std::fs::read_dir(path)
        .map_err(|err| Status::internal(format!("reading {path}: {err}")))?;
    Ok(entries.next().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(device: &str, path: &str, is_tmpfs: bool) -> guestpb::VolumeMount {
        guestpb::VolumeMount {
            device: device.into(),
            path: path.into(),
            is_tmpfs,
            ..Default::default()
        }
    }

    #[test]
    fn only_a_volume_tag_and_a_plain_path_are_mounted() {
        assert!(check(&volume("burrow-volume0", "/Users/Shared/data", false)).is_ok());
        assert!(check(&volume("burrow-volume12", "/opt/cache", false)).is_ok());
        assert!(check(&volume("", "/opt/scratch", true)).is_ok());
        for (device, path) in [
            ("/dev/vdc", "/opt/data"),
            ("burrow-volume", "/opt/data"),
            ("burrow-volumex", "/opt/data"),
            ("burrow-volume0", "opt/data"),
            ("burrow-volume0", "/opt/../etc"),
            ("burrow-volume0", "/"),
        ] {
            assert!(
                check(&volume(device, path, false)).is_err(),
                "{device} {path}"
            );
        }
    }

    #[test]
    fn a_volume_disk_is_found_by_its_position() {
        let ioreg = r#"+-o AppleVirtIODiskStorageDevice@1  <class AppleVirtIODiskStorageDevice, id 0x1000001d1, registered>
  |   "EmbeddedDeviceTypeRoot" = Yes
  +-o Apple Inc. VirtIO Block Media  <class IOMedia, id 0x1000001d8>
  |     "BSD Name" = "disk0"
+-o AppleVirtIODiskStorageDevice@1  <class AppleVirtIODiskStorageDevice, id 0x1000001f0, registered>
  |   "AvpVirtioBlockDeviceRole" = 3
  +-o Apple Inc. VirtIO Block Media  <class IOMedia, id 0x1000001f4>
  |     "BSD Name" = "disk5"
+-o AppleVirtIODiskStorageDevice@1  <class AppleVirtIODiskStorageDevice, id 0x1000001dc, registered>
  |   "AvpVirtioBlockDeviceRole" = 3
  +-o Apple Inc. VirtIO Block Media  <class IOMedia, id 0x1000001e0>
  |     "BSD Name" = "disk4"
  | +-o IOMedia
  |     "BSD Name" = "disk4s1"
"#;
        assert_eq!(
            disk_named(ioreg, "burrow-volume0").as_deref(),
            Some("disk4")
        );
        assert_eq!(
            disk_named(ioreg, "burrow-volume1").as_deref(),
            Some("disk5")
        );
        assert_eq!(disk_named(ioreg, "burrow-volume2"), None);
        assert_eq!(disk_named(ioreg, "disk4"), None);
    }

    #[test]
    fn the_hfs_partition_of_a_disk_is_found() {
        let small = "/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *2.1 GB     disk0
   1:                  Apple_HFS burrow-volume           2.0 GB     disk0s1
";
        let large = "/dev/disk4 (internal, physical):
   0:      GUID_partition_scheme                        *21.5 GB    disk4
   1:                        EFI EFI                     209.7 MB   disk4s1
   2:                  Apple_HFS burrow-volume           21.1 GB    disk4s2
";
        assert_eq!(hfs_partition(small).as_deref(), Some("disk0s1"));
        assert_eq!(hfs_partition(large).as_deref(), Some("disk4s2"));
        assert_eq!(hfs_partition("/dev/disk4 (internal, physical):\n"), None);
    }

    #[test]
    fn the_root_is_a_mount_point_and_a_directory_in_it_is_not() {
        assert!(is_mount_point("/"));
        let dir = std::env::temp_dir().join(format!("burrow-mnt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!is_mount_point(dir.to_str().unwrap()));
        assert!(is_empty(dir.to_str().unwrap()).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
