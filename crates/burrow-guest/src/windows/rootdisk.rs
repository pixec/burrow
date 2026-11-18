//! The system volume, grown into the disk beneath it once the host has made
//! the disk bigger.
//!
//! The disk's new size is read with `IOCTL_DISK_UPDATE_PROPERTIES`, which has
//! the disk driver ask virtio-blk for its capacity again. Only when space
//! lies past the system partition is it extended, through the Storage
//! module's `Resize-Partition`, which moves the backup GPT, grows the
//! partition and extends NTFS online to fill it in one step. A boot with
//! nothing to fill costs a few IOCTLs and no PowerShell.

#![allow(clippy::result_large_err)]
#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
use tonic::Status;

/// Space past the system partition left alone: the backup GPT and the
/// alignment a partition ends on.
pub const SLACK: u64 = 16 << 20;
/// How long a grow waits for the disk to report the size the host set.
#[cfg(windows)]
const SIZE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Extends the system partition, the disk's last, and its volume over the
/// free space after it. `Get-PartitionSupportedSize` is not used: it refuses
/// a volume whose dirty bit is set, which `Resize-Partition` extends.
const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
$letter = $env:SystemDrive.Substring(0, 1)
Update-HostStorageCache
$part = Get-Partition -DriveLetter $letter
$free = (Get-Disk -Number $part.DiskNumber).LargestFreeExtent
if ($free -gt 1MB) { Resize-Partition -DriveLetter $letter -Size ($part.Size + $free) }
"#;

/// Whether a partition ending at `end` leaves space worth filling on a disk
/// of `length` bytes.
pub fn has_room(length: u64, end: u64) -> bool {
    length.saturating_sub(end) > SLACK
}

/// Serializes grows: the one a boot starts and one the host asks for.
#[cfg(windows)]
static GROWING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Waits for the system disk to be at least `expected` bytes, 0 being any
/// size, extends the system volume into what lies past it, and returns the
/// volume's size. Nothing to do is not an error.
#[cfg(windows)]
pub fn grow(expected: u64) -> Result<u64, Status> {
    let _held = GROWING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let internal = |what: &str, err: std::io::Error| Status::internal(format!("{what}: {err}"));
    let (disk, end) = system_disk().map_err(|err| internal("finding the system disk", err))?;
    let started = std::time::Instant::now();
    let length = loop {
        let length = disk_length(&disk).map_err(|err| internal("reading the disk's size", err))?;
        if length >= expected {
            break length;
        }
        if started.elapsed() > SIZE_WAIT {
            return Err(Status::deadline_exceeded(format!(
                "the system disk is {length} bytes {}s after the host grew it to {expected}",
                SIZE_WAIT.as_secs()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    };
    if has_room(length, end) {
        run_script()?;
        tracing::info!(disk_bytes = length, "extended the system volume");
    }
    volume_size().map_err(|err| internal("reading the volume's size", err))
}

/// Fills the disk in the background, for a boot after the host grew it
/// while the guest was shut down.
#[cfg(windows)]
pub fn fill_in_background() {
    std::thread::spawn(|| {
        if let Err(err) = grow(0) {
            tracing::warn!(err = err.message(), "could not extend the system volume");
        }
    });
}

/// Writes back what the system volume has cached, so the host's copy of the
/// disk holds every write the guest has acknowledged.
#[cfg(windows)]
pub fn sync() -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
    let volume = open(
        &format!(r"\\.\{}:", crate::windows::win::system_drive()),
        GENERIC_READ | GENERIC_WRITE,
    )?;
    // SAFETY: a volume handle opened for writing, as the call requires.
    crate::windows::win::check(unsafe { FlushFileBuffers(volume.as_raw_handle()) })
}

/// The disk holding the system volume, opened, and the offset its partition
/// ends at.
#[cfg(windows)]
fn system_disk() -> std::io::Result<(std::os::windows::io::OwnedHandle, u64)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::VOLUME_DISK_EXTENTS;
    let volume = open(&format!(r"\\.\{}:", crate::windows::win::system_drive()), 0)?;
    let mut extents: VOLUME_DISK_EXTENTS = unsafe { std::mem::zeroed() };
    let mut returned = 0u32;
    // SAFETY: `extents` is the output buffer, sized as passed. The system
    // volume of a basic disk has one extent, so it fits.
    crate::windows::win::check(unsafe {
        DeviceIoControl(
            volume.as_raw_handle(),
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null(),
            0,
            (&raw mut extents).cast(),
            std::mem::size_of::<VOLUME_DISK_EXTENTS>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    })?;
    let extent = extents.Extents[0];
    let disk = open(
        &format!(r"\\.\PhysicalDrive{}", extent.DiskNumber),
        windows_sys::Win32::Foundation::GENERIC_READ,
    )?;
    Ok((disk, (extent.StartingOffset + extent.ExtentLength) as u64))
}

#[cfg(windows)]
fn open(path: &str, access: u32) -> std::io::Result<std::os::windows::io::OwnedHandle> {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let name = crate::windows::win::wide(path);
    // SAFETY: `name` is NUL-terminated; the handle is owned by the caller.
    crate::windows::win::owned(unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    })
}

/// The disk's size, after having its driver read it again.
#[cfg(windows)]
fn disk_length(disk: &std::os::windows::io::OwnedHandle) -> std::io::Result<u64> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO, IOCTL_DISK_UPDATE_PROPERTIES,
    };
    let mut returned = 0u32;
    // SAFETY: no buffers.
    crate::windows::win::check(unsafe {
        DeviceIoControl(
            disk.as_raw_handle(),
            IOCTL_DISK_UPDATE_PROPERTIES,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    })?;
    let mut info = GET_LENGTH_INFORMATION { Length: 0 };
    // SAFETY: `info` is the output buffer, sized as passed.
    crate::windows::win::check(unsafe {
        DeviceIoControl(
            disk.as_raw_handle(),
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null(),
            0,
            (&raw mut info).cast(),
            std::mem::size_of::<GET_LENGTH_INFORMATION>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    })?;
    Ok(info.Length as u64)
}

/// The system volume's size in bytes.
#[cfg(windows)]
fn volume_size() -> std::io::Result<u64> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let root = crate::windows::win::wide(&format!("{}:\\", crate::windows::win::system_drive()));
    let mut total = 0u64;
    // SAFETY: `root` is NUL-terminated and `total` is written.
    crate::windows::win::check(unsafe {
        GetDiskFreeSpaceExW(
            root.as_ptr(),
            std::ptr::null_mut(),
            &mut total,
            std::ptr::null_mut(),
        )
    })?;
    Ok(total)
}

/// Runs [`SCRIPT`] as an encoded command, as the volume mounts run theirs.
#[cfg(windows)]
fn run_script() -> Result<(), Status> {
    use base64::Engine as _;
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
    let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|err| Status::internal(format!("powershell: {err}")))?;
    if !output.status.success() {
        return Err(Status::internal(format!(
            "extending the system volume: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_space_past_the_slack_is_filled() {
        let gib = 1u64 << 30;
        assert!(!has_room(24 * gib, 24 * gib - (1 << 20)));
        assert!(!has_room(24 * gib, 24 * gib - SLACK));
        assert!(has_room(32 * gib, 24 * gib - (1 << 20)));
        assert!(!has_room(24 * gib, 32 * gib));
    }
}
