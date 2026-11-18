//! A TPM sandbox's emulator state as its copies carry it.
//!
//! Every copy of a TPM sandbox (a fork, a snapshot, a warm snapshot, stored
//! state, a move) carries its TPM's state packed into one file, [`FILE`],
//! beside the memory and disk it was captured with. A sandbox restored from
//! the copy has the file unpacked into its own state directory, under its own
//! uid, before its VMM starts, so the copy holds the same TPM: the same
//! endorsement key and everything sealed to it.
//!
//! The file is never the jail's. It sits in a working directory only while
//! no VMM runs there, is created readable by root alone, and is left out of
//! what a jail is given.

use std::path::{Path, PathBuf};

use tonic::Status;

/// The packed state in a copy's directory.
pub const FILE: &str = "tpm.state";

/// Packs the TPM state in `dir`, whose emulator has stopped, into `dest`.
pub async fn pack(dir: &Path, dest: &Path) -> Result<(), Status> {
    burrow_vmm::cloud_hypervisor::tpm::pack(dir, dest)
        .await
        .map_err(|err| Status::internal(format!("capturing the TPM: {err}")))
}

/// Unpacks the TPM state a copy brought into `workdir`, if it brought one,
/// into `dir`, and removes it from `workdir`. Returns whether there was one.
pub async fn take(workdir: &Path, dir: &Path) -> Result<bool, Status> {
    let packed = workdir.join(FILE);
    if !tokio::fs::try_exists(&packed).await.unwrap_or(false) {
        return Ok(false);
    }
    burrow_vmm::cloud_hypervisor::tpm::unpack(&packed, dir)
        .await
        .map_err(|err| Status::internal(format!("restoring the TPM: {err}")))?;
    let _ = tokio::fs::remove_file(&packed).await;
    Ok(true)
}

/// Moves a packed state to `dest`, or copies it across filesystems.
pub async fn place(packed: &Path, dest: &Path) -> std::io::Result<()> {
    if tokio::fs::rename(packed, dest).await.is_ok() {
        return Ok(());
    }
    tokio::fs::copy(packed, dest).await?;
    let _ = tokio::fs::remove_file(packed).await;
    Ok(())
}

/// Where a running sandbox's TPM is captured beside the disk capture
/// `capture`: under the TPM root, never in the working directory its VMM
/// owns, and named after the sandbox, which [`capture_owner`] reads back.
pub fn capture_path(tpm_root: &Path, id: &str, capture: &Path) -> PathBuf {
    let name = capture
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    tpm_root.join(format!("{id}{name}.tpm"))
}

/// The sandbox a capture in the TPM root was taken of.
pub fn capture_owner(name: &std::ffi::OsStr) -> &str {
    name.to_str()
        .and_then(|name| name.split('.').next())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capture_is_named_after_its_sandbox_and_disk_capture() {
        assert_eq!(
            capture_path(
                Path::new("/var/lib/burrow/tpm"),
                "sbx_a",
                Path::new("/var/lib/burrow/sandboxes/sbx_a/.capture-sbx_b")
            ),
            Path::new("/var/lib/burrow/tpm/sbx_a.capture-sbx_b.tpm")
        );
        assert_eq!(
            capture_owner(std::ffi::OsStr::new("sbx_a.capture-sbx_b.tpm")),
            "sbx_a"
        );
    }
}
