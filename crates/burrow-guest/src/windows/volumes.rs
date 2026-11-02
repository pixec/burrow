//! Volume mounts on Windows.
//!
//! The host attaches each volume as a virtio disk whose serial number is the
//! identifier the handshake names (`burrow-volumeN`), since Windows numbers
//! disks in no order the host controls. The first writable mount of a blank
//! disk initializes it GPT and formats one NTFS partition; a mount then
//! gives that partition the path asked for, as a folder mount point (`/data`
//! is `C:\data`) or, for a path naming a drive (`/d`), as that drive letter.
//! A letter Windows assigned on its own is taken away again, so the volume is
//! reached only where it was asked for.
//!
//! A read-only mount is read-only at the hypervisor, and the disk is marked
//! read-only before it is brought online, so NTFS mounts it read-only rather
//! than failing its first write.
//!
//! Done with the Storage module's cmdlets rather than the IOCTLs beneath
//! them: initializing, partitioning and formatting by hand is most of what
//! `Format-Volume` is. The values go to the script in its environment, never
//! in its text.
//!
//! A fresh volume's root gives Administrators and SYSTEM full control, as
//! Windows formats it, and every signed-in user modify, so the accounts
//! `CreateUser` makes can write to it. A mount's `mode` is not applied:
//! Windows has no mode bits, and chown is a no-op here throughout.

#![allow(clippy::result_large_err)]
#![cfg_attr(not(windows), allow(dead_code))]

use tonic::Status;

use burrow_proto::guest::v1 as guestpb;

/// The serial number the host gives a volume's disk; see the daemon's
/// `volume::disk_id`.
const DISK_PREFIX: &str = "burrow-volume";

/// Where a volume is mounted.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// A drive of its own.
    Letter(char),
    /// A folder mount point, with the trailing separator the cmdlets want.
    Folder(String),
}

/// Where `volume` goes, checked: this is the code that turns the request
/// into a mount.
pub fn target(volume: &guestpb::VolumeMount, system_drive: char) -> Result<Target, Status> {
    if volume.is_tmpfs {
        return Err(Status::invalid_argument(format!(
            "Windows has no tmpfs to mount at {}",
            volume.path
        )));
    }
    let tag_ok = volume
        .device
        .strip_prefix(DISK_PREFIX)
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    let refused = || {
        Status::invalid_argument(format!(
            "refusing volume mount {:?} at {:?}",
            volume.device, volume.path
        ))
    };
    if !tag_ok || !volume.path.starts_with('/') {
        return Err(refused());
    }
    let mapped =
        crate::paths::windows::to_windows(&volume.path, system_drive).map_err(|_| refused())?;
    let letter = mapped.as_bytes()[0] as char;
    if mapped.len() > 3 {
        return Ok(Target::Folder(format!("{mapped}\\")));
    }
    if letter == system_drive.to_ascii_uppercase() {
        return Err(Status::invalid_argument(format!(
            "{} is the system drive, {letter}:\\; mount a volume at a directory such as /data, \
             or at a drive of its own such as /d",
            volume.path
        )));
    }
    Ok(Target::Letter(letter))
}

/// What [`SCRIPT`] is told, as its environment.
pub fn script_env(
    volume: &guestpb::VolumeMount,
    target: &Target,
) -> Vec<(&'static str, String)> {
    let (letter, folder) = match target {
        Target::Letter(letter) => (letter.to_string(), String::new()),
        Target::Folder(folder) => (String::new(), folder.clone()),
    };
    vec![
        ("BURROW_SERIAL", volume.device.clone()),
        ("BURROW_LETTER", letter),
        ("BURROW_FOLDER", folder),
        ("BURROW_PATH", volume.path.clone()),
        (
            "BURROW_READ_ONLY",
            if volume.is_read_only { "1" } else { "" }.to_string(),
        ),
    ]
}

/// Finds the disk, formats it if nothing ever has, and gives its partition
/// the path. A path it already has is left alone, so a second handshake in
/// one boot changes nothing.
const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
trap { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
$readOnly = $env:BURROW_READ_ONLY -eq '1'
$disk = Get-Disk | Where-Object { "$($_.SerialNumber)".Trim() -eq $env:BURROW_SERIAL } | Select-Object -First 1
if (-not $disk) { throw "no disk $($env:BURROW_SERIAL) in the guest" }
$number = $disk.Number
if ($disk.IsReadOnly -ne $readOnly) { Set-Disk -Number $number -IsReadOnly $readOnly }
if ($disk.IsOffline) { Set-Disk -Number $number -IsOffline $false }
$fresh = $false
if ((Get-Disk -Number $number).PartitionStyle -eq 'RAW') {
    if ($readOnly) {
        throw "the volume at $($env:BURROW_PATH) has never been mounted writable, so it has no filesystem to mount read-only"
    }
    Initialize-Disk -Number $number -PartitionStyle GPT
    $new = New-Partition -DiskNumber $number -UseMaximumSize
    Format-Volume -Partition $new -FileSystem NTFS -NewFileSystemLabel 'burrow-volume' -Confirm:$false | Out-Null
    $fresh = $true
}
$part = Get-Partition -DiskNumber $number | Where-Object Type -eq 'Basic' | Select-Object -First 1
if (-not $part) { throw "disk $($env:BURROW_SERIAL) has no NTFS partition; it holds a filesystem another guest OS made" }
$at = @{ DiskNumber = $number; PartitionNumber = $part.PartitionNumber }
$assigned = "$($part.DriveLetter)".Trim([char]0).Trim()
if ($env:BURROW_LETTER) {
    if ($assigned -ne $env:BURROW_LETTER) { Set-Partition @at -NewDriveLetter $env:BURROW_LETTER }
    $root = "$($env:BURROW_LETTER):\"
} else {
    if (@($part.AccessPaths) -notcontains $env:BURROW_FOLDER) {
        New-Item -ItemType Directory -Force -Path $env:BURROW_FOLDER | Out-Null
        Add-PartitionAccessPath @at -AccessPath $env:BURROW_FOLDER
    }
    if ($assigned) { Remove-PartitionAccessPath @at -AccessPath "$($assigned):\" }
    $root = $env:BURROW_FOLDER
}
if ($fresh) {
    $acl = Get-Acl -LiteralPath $root
    $users = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-11'
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($users, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $root -AclObject $acl
}
"#;

/// Mounts what the host attached, at the paths it named.
#[cfg(windows)]
pub async fn mount(volumes: &[guestpb::VolumeMount]) -> Result<(), Status> {
    for volume in volumes {
        let target = target(volume, crate::windows::win::system_drive())?;
        let env = script_env(volume, &target);
        tokio::task::spawn_blocking(move || run(&env))
            .await
            .map_err(|err| Status::internal(format!("volume mount did not run: {err}")))??;
        tracing::debug!(
            device = volume.device,
            path = volume.path,
            read_only = volume.is_read_only,
            "volume mounted"
        );
    }
    Ok(())
}

/// Runs [`SCRIPT`] as an encoded command, which PowerShell takes as UTF-16
/// in base64, so nothing in it passes through command-line quoting.
#[cfg(windows)]
fn run(env: &[(&'static str, String)]) -> Result<(), Status> {
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
        .envs(env.iter().map(|(key, value)| (*key, value.as_str())))
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|err| Status::internal(format!("powershell: {err}")))?;
    if !output.status.success() {
        return Err(Status::failed_precondition(format!(
            "mounting a volume: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(device: &str, path: &str) -> guestpb::VolumeMount {
        guestpb::VolumeMount {
            device: device.into(),
            path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_path_is_a_folder_mount_point_or_a_drive_of_its_own() {
        assert_eq!(
            target(&volume("burrow-volume0", "/data"), 'C').unwrap(),
            Target::Folder("C:\\data\\".into())
        );
        assert_eq!(
            target(&volume("burrow-volume1", "/work/cache"), 'C').unwrap(),
            Target::Folder("C:\\work\\cache\\".into())
        );
        assert_eq!(
            target(&volume("burrow-volume0", "/d"), 'C').unwrap(),
            Target::Letter('D')
        );
        // A folder on another drive, which has to exist already.
        assert_eq!(
            target(&volume("burrow-volume0", "/e/data"), 'C').unwrap(),
            Target::Folder("E:\\data\\".into())
        );
    }

    #[test]
    fn the_system_drive_a_tmpfs_and_a_bad_tag_are_refused() {
        assert!(target(&volume("burrow-volume0", "/c"), 'C').is_err());
        let mut tmpfs = volume("", "/scratch");
        tmpfs.is_tmpfs = true;
        assert!(target(&tmpfs, 'C').is_err());
        for (device, path) in [
            ("/dev/vdc", "/data"),
            ("burrow-volume", "/data"),
            ("burrow-volume0x", "/data"),
            ("burrow-volume0", "data"),
            ("burrow-volume0", "//server/share"),
        ] {
            assert!(target(&volume(device, path), 'C').is_err(), "{device} {path}");
        }
    }

    #[test]
    fn the_script_is_told_the_values_in_its_environment() {
        let mut read_only = volume("burrow-volume2", "/data");
        read_only.is_read_only = true;
        let target = target(&read_only, 'C').unwrap();
        let env = script_env(&read_only, &target);
        let get = |key: &str| {
            env.iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(get("BURROW_SERIAL"), Some("burrow-volume2"));
        assert_eq!(get("BURROW_FOLDER"), Some("C:\\data\\"));
        assert_eq!(get("BURROW_LETTER"), Some(""));
        assert_eq!(get("BURROW_READ_ONLY"), Some("1"));
        for (name, _) in &env {
            assert!(SCRIPT.contains(&format!("$env:{name}")), "{name} unused");
        }
    }
}
