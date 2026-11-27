//! The file a guest boots from, kept beside its disk in its working
//! directory and carried wherever its state goes: snapshots, forks, moves and
//! stored state. A Linux guest boots its template's kernel. A guest booted by
//! UEFI firmware, Windows, boots the node's firmware, copied in when the
//! sandbox is made, so that a copy of the sandbox restores and reboots with
//! the firmware it booted, whatever the node it lands on ships.

use std::collections::HashSet;
use std::path::Path;

use burrow_vmm::GuestOs;

pub const KERNEL: &str = "vmlinux";
pub const FIRMWARE: &str = "firmware.fd";

/// The boot file of a `guest_os` guest.
pub fn file(guest_os: GuestOs) -> &'static str {
    match guest_os.profile().boots_firmware {
        true => FIRMWARE,
        false => KERNEL,
    }
}

/// What a working directory shares with its template or source by hard link,
/// which a jail must not take ownership of.
pub fn shared() -> HashSet<String> {
    [KERNEL, FIRMWARE, crate::rootdisk::IMAGE]
        .map(String::from)
        .into()
}

/// The `Boot` of a firmware guest whose firmware is in its working directory.
pub fn firmware_boot() -> burrow_vmm::Boot {
    burrow_vmm::Boot::Firmware {
        firmware: Some(FIRMWARE.into()),
    }
}

/// Puts `firmware` into `workdir` as the guest's boot file, unless the one
/// there already is it. Copied rather than linked: the node's firmware sits on
/// another filesystem, and it is a few MiB.
pub async fn take_firmware(firmware: &Path, workdir: &Path) -> std::io::Result<()> {
    let dest = workdir.join(FIRMWARE);
    if crate::kernels::digest_unfollowed(&dest).await?
        == Some(crate::kernels::digest(firmware).await?)
    {
        return Ok(());
    }
    // Made afresh, never written through: the working directory may be a
    // jail's, where whatever sits at the name could be a link out of it.
    let next = workdir.join(format!("{FIRMWARE}.next"));
    let _ = tokio::fs::remove_file(&next).await;
    let mut to = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&next)
        .await?;
    tokio::io::copy(&mut tokio::fs::File::open(firmware).await?, &mut to).await?;
    to.sync_all().await?;
    tokio::fs::rename(&next, &dest).await
}
