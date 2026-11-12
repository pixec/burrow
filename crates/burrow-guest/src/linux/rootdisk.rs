//! The root filesystem as a disk of its own.
//!
//! The guest boots from one writable ext4 disk mounted as
//! `/`. The host makes it bigger by growing the file, and asks the guest to
//! flush, trim or freeze it before it captures the disk without the guest's
//! memory. Everything here acts on `/` through the kernel; nothing reads or
//! rewrites the filesystem from outside it.

use std::os::fd::AsRawFd as _;

use nix::libc;

const EXT4_SUPER_MAGIC: libc::c_long = 0xEF53;

/// How long a grow waits for the guest to see the size the host set.
const DEVICE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// `struct fstrim_range`.
#[repr(C)]
struct TrimRange {
    start: u64,
    len: u64,
    minlen: u64,
}

nix::ioctl_readwrite!(fitrim, b'X', 121, TrimRange);
nix::ioctl_readwrite!(fifreeze, b'X', 119, libc::c_int);
nix::ioctl_readwrite!(fithaw, b'X', 120, libc::c_int);
nix::ioctl_write_ptr!(ext4_resize_fs, b'f', 16, u64);

fn root() -> std::io::Result<std::fs::File> {
    std::fs::File::open("/")
}

/// The root filesystem's block size and size in bytes.
fn statfs() -> std::io::Result<(u64, u64, libc::c_long)> {
    let root = root()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and `stat` is a valid out-pointer.
    if unsafe { libc::fstatfs(root.as_raw_fd(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let block = stat.f_bsize as u64;
    Ok((
        block,
        stat.f_blocks as u64 * block,
        stat.f_type as libc::c_long,
    ))
}

pub fn size_bytes() -> std::io::Result<u64> {
    statfs().map(|(_, size, _)| size)
}

pub fn sync() {
    nix::unistd::sync();
}

pub fn trim() -> std::io::Result<()> {
    let root = root()?;
    let mut range = TrimRange {
        start: 0,
        len: u64::MAX,
        minlen: 0,
    };
    // SAFETY: the descriptor is open and `range` lives across the call.
    unsafe { fitrim(root.as_raw_fd(), &mut range) }?;
    Ok(())
}

fn mount_points(paths: &[String]) -> Vec<&str> {
    match paths.is_empty() {
        true => vec!["/"],
        false => paths.iter().map(String::as_str).collect(),
    }
}

/// Syncs, then freezes each mount point in turn. One that fails thaws the
/// ones already frozen, so a failed freeze leaves nothing still.
pub fn freeze(paths: &[String]) -> std::io::Result<()> {
    sync();
    let points = mount_points(paths);
    for (done, point) in points.iter().enumerate() {
        let frozen = std::fs::File::open(point).and_then(|dir| {
            let mut unused = 0;
            // SAFETY: the descriptor is open and `unused` lives across the call.
            match unsafe { fifreeze(dir.as_raw_fd(), &mut unused) } {
                Ok(_) | Err(nix::errno::Errno::EBUSY) => Ok(()),
                Err(err) => Err(std::io::Error::from(err)),
            }
        });
        if let Err(err) = frozen {
            let _ = thaw_points(&points[..done]);
            return Err(std::io::Error::other(format!("freezing {point}: {err}")));
        }
    }
    Ok(())
}

pub fn thaw(paths: &[String]) -> std::io::Result<()> {
    thaw_points(&mount_points(paths))
}

fn thaw_points(points: &[&str]) -> std::io::Result<()> {
    let mut first = None;
    for point in points {
        let thawed = std::fs::File::open(point).and_then(|dir| {
            let mut unused = 0;
            // SAFETY: as above.
            match unsafe { fithaw(dir.as_raw_fd(), &mut unused) } {
                // Not frozen, which a thaw after a failed freeze finds.
                Ok(_) | Err(nix::errno::Errno::EINVAL) => Ok(()),
                Err(err) => Err(std::io::Error::from(err)),
            }
        });
        if let Err(err) = thawed {
            first.get_or_insert(err);
        }
    }
    first.map_or(Ok(()), Err)
}

/// Bytes of the block device `/` is mounted from, from sysfs.
fn device_bytes() -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let dev = std::fs::metadata("/")?.dev();
    let (major, minor) = (libc::major(dev), libc::minor(dev));
    let sectors = std::fs::read_to_string(format!("/sys/dev/block/{major}:{minor}/size"))?;
    sectors
        .trim()
        .parse::<u64>()
        .map(|sectors| sectors * 512)
        .map_err(std::io::Error::other)
}

/// Grows an ext4 root to fill its device, online. The kernel does nothing for
/// one that already fills it, and a root that is not ext4 is left alone.
///
/// `expected` is the device size the host set. The guest hears of it through
/// a config interrupt handled on a workqueue, so the call that follows the
/// host's can arrive first; it waits until the device is that big.
pub fn grow(expected: u64) -> std::io::Result<()> {
    let (block, _, kind) = statfs()?;
    if kind != EXT4_SUPER_MAGIC {
        return Ok(());
    }
    let deadline = std::time::Instant::now() + DEVICE_WAIT;
    let mut device = device_bytes()?;
    while device < expected {
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::other(format!(
                "the disk is still {device} bytes, not the {expected} the host set"
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        device = device_bytes()?;
    }
    let blocks = device / block;
    let root = root()?;
    // SAFETY: the descriptor is open and `blocks` lives across the call.
    unsafe { ext4_resize_fs(root.as_raw_fd(), &blocks) }?;
    Ok(())
}

/// The disk a resize helper is given, after its own root.
const HELPER_DISK: &str = "/dev/vdb";
/// Where the node puts the e2fsprogs tools in a resize helper's root.
const E2FSCK: &str = "/usr/sbin/e2fsck";
const RESIZE2FS: &str = "/usr/sbin/resize2fs";

/// Whether the host booted this agent as a resize helper rather than a
/// sandbox's guest.
pub fn is_helper() -> bool {
    std::fs::read_to_string("/proc/cmdline").is_ok_and(|cmdline| {
        cmdline
            .split_whitespace()
            .any(|arg| arg == "burrow.mode=resize-disk")
    })
}

/// The block size and the filesystem's size in bytes, from an ext4
/// superblock.
fn superblock_size(superblock: &[u8; 1024]) -> std::io::Result<(u64, u64)> {
    let u32_at = |at: usize| u32::from_le_bytes(superblock[at..at + 4].try_into().unwrap());
    if u16::from_le_bytes([superblock[0x38], superblock[0x39]]) as libc::c_long != EXT4_SUPER_MAGIC
    {
        return Err(std::io::Error::other("the disk holds no ext4 filesystem"));
    }
    let block = 1024u64 << u32_at(0x18);
    let mut blocks = u64::from(u32_at(0x04));
    // INCOMPAT_64BIT.
    if u32_at(0x60) & 0x80 != 0 {
        blocks |= u64::from(u32_at(0x150)) << 32;
    }
    Ok((block, blocks * block))
}

fn helper_size() -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::FileExt as _;
    let mut superblock = [0u8; 1024];
    std::fs::File::open(HELPER_DISK)?.read_exact_at(&mut superblock, 1024)?;
    superblock_size(&superblock)
}

/// e2fsck's exit codes 0 and 1 are a clean filesystem and one it fixed.
async fn check(args: &[&str]) -> Result<(), tonic::Status> {
    let (code, output) = crate::linux::users::run(std::path::Path::new(E2FSCK), args).await?;
    match code {
        0 | 1 => Ok(()),
        code => Err(tonic::Status::failed_precondition(format!(
            "e2fsck exited {code}; the filesystem needs repair before it can shrink: {}",
            output.trim()
        ))),
    }
}

/// Shrinks the unmounted filesystem on the helper's disk to `target` bytes:
/// a forced check, the filesystem's own estimate of its minimum, the shrink,
/// and a read-only check after. Returns its size and the minimum; a target
/// below the minimum changes nothing.
pub async fn shrink(target: u64) -> Result<(u64, u64), tonic::Status> {
    let internal = |err: std::io::Error| tonic::Status::internal(format!("{HELPER_DISK}: {err}"));
    check(&["-f", "-p", HELPER_DISK]).await?;
    let (code, output) =
        crate::linux::users::run(std::path::Path::new(RESIZE2FS), &["-P", HELPER_DISK]).await?;
    let estimate = output
        .lines()
        .find_map(|line| line.strip_prefix("Estimated minimum size of the filesystem: "))
        .and_then(|blocks| blocks.trim().parse::<u64>().ok());
    let Some(estimate) = estimate.filter(|_| code == 0) else {
        return Err(tonic::Status::internal(format!(
            "resize2fs -P exited {code}: {}",
            output.trim()
        )));
    };
    let (block, size) = helper_size().map_err(internal)?;
    let minimum = crate::unix::rootdisk::minimum(estimate * block);
    if target < minimum || target >= size {
        return Ok((size, minimum));
    }
    let blocks = (target / block).to_string();
    let (code, output) =
        crate::linux::users::run(std::path::Path::new(RESIZE2FS), &[HELPER_DISK, &blocks]).await?;
    if code != 0 {
        return Err(tonic::Status::internal(format!(
            "resize2fs exited {code}: {}",
            output.trim()
        )));
    }
    check(&["-f", "-n", HELPER_DISK]).await?;
    sync();
    std::fs::OpenOptions::new()
        .write(true)
        .open(HELPER_DISK)
        .and_then(|disk| disk.sync_all())
        .map_err(internal)?;
    let (_, size) = helper_size().map_err(internal)?;
    Ok((size, minimum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_superblock_gives_the_filesystem_size() {
        let mut superblock = [0u8; 1024];
        superblock[0x38..0x3a].copy_from_slice(&0xEF53u16.to_le_bytes());
        superblock[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes());
        superblock[0x04..0x08].copy_from_slice(&1000u32.to_le_bytes());
        assert_eq!(superblock_size(&superblock).unwrap(), (4096, 4096 * 1000));
        superblock[0x60..0x64].copy_from_slice(&0x80u32.to_le_bytes());
        superblock[0x150..0x154].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            superblock_size(&superblock).unwrap().1,
            4096 * ((1u64 << 32) + 1000)
        );
        superblock[0x38] = 0;
        assert!(superblock_size(&superblock).is_err());
    }
}
