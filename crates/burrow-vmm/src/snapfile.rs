//! Replacing the files a snapshot is written to.
//!
//! Sandboxes created from a warm snapshot **hard-link** the template's
//! snapshot files into their working directory, which is what makes a create
//! cheap. A later snapshot of such a sandbox goes to those same relative
//! paths, and writing through a hard link writes into the template: one
//! sandbox's entire guest memory becomes the image every later sandbox
//! restores from. That is a cross-sandbox leak of whatever was in RAM,
//! credentials included, not merely a corrupted template.
//!
//! Every backend therefore gives a snapshot a fresh inode: Firecracker and vz
//! unlink the target before the VMM writes it ([`replace_target`]), and Cloud
//! Hypervisor writes elsewhere and renames over it.

use std::path::Path;

use crate::error::Result;

/// Unlinks `path`, if present, so the snapshot about to be written there gets
/// a fresh inode and leaves whatever it was linked to untouched.
///
/// It is safe while the VM is running: an open mapping of the old inode (a
/// page-fault handler's) keeps serving the memory the guest is still using
/// until the VMM exits.
pub(crate) async fn replace_target(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err.into()),
        _ => Ok(()),
    }
}
