//! Carrying chosen paths from a sandbox's old root disk to its new one.
//!
//! The old disk was written by the guest, so the host neither mounts it nor
//! parses it: a confined reader ([`burrow_diskread`]) streams each tree out
//! of it as a tar archive, and the new guest's agent unpacks that as root.
//! The host writes nothing into either filesystem.

#![allow(clippy::result_large_err)]

use std::path::Path;

use tonic::Status;

use burrow_proto::common::v1 as common;
use burrow_proto::guest::v1 as guestpb;

use crate::sandbox::RunningSandbox;

/// The most file data one recreate carries.
pub const MAX_BYTES: u64 = 16 << 30;
/// The most files, directories and links one recreate carries.
pub const MAX_ENTRIES: u64 = 1_000_000;
/// How long carrying them all may take.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// What an agent that unpacks archives lists in its health response.
const EXTRACT_TAR: &str = "extract-tar";

/// Checks the paths a recreate keeps against what the sandbox is and will be,
/// returning them normalized.
pub fn check(
    paths: &[String],
    volumes: &[common::VolumeMount],
    old: burrow_vmm::GuestOs,
    new: burrow_vmm::GuestOs,
) -> Result<Vec<String>, Status> {
    let paths = burrow_common::keep::validate(paths).map_err(Status::invalid_argument)?;
    if !cfg!(target_os = "linux") {
        return Err(Status::unimplemented(
            "--keep reads the old disk with a reader only a Linux node can confine",
        ));
    }
    if old != burrow_vmm::GuestOs::Linux || new != burrow_vmm::GuestOs::Linux {
        return Err(Status::failed_precondition(format!(
            "--keep carries files between Linux root disks, not from a {} guest to a {} one",
            old.as_str(),
            new.as_str()
        )));
    }
    for path in &paths {
        let mounted = volumes.iter().find(|mount| {
            burrow_common::keep::covers(path, &mount.path)
                || burrow_common::keep::covers(&mount.path, path)
        });
        if let Some(mount) = mounted {
            return Err(Status::invalid_argument(format!(
                "--keep {path}: a volume is mounted at {}, and what is on it stays with it",
                mount.path
            )));
        }
    }
    Ok(paths)
}

/// Copies each of `paths` from the root disk image at `disk` into the
/// running `sandbox`, replacing what its own disk has there.
pub async fn carry(sandbox: &RunningSandbox, disk: &Path, paths: &[String]) -> Result<(), Status> {
    if !sandbox.agent_has(EXTRACT_TAR).await? {
        return Err(Status::failed_precondition(
            "the new guest's agent cannot unpack the kept files; build the template with a \
             current burrow-guest, or run the node with --guest-binary",
        ));
    }
    tokio::time::timeout(TIMEOUT, carry_all(sandbox, disk, paths))
        .await
        .map_err(|_| {
            Status::deadline_exceeded(format!(
                "--keep took longer than {} minutes",
                TIMEOUT.as_secs() / 60
            ))
        })?
}

async fn carry_all(sandbox: &RunningSandbox, disk: &Path, paths: &[String]) -> Result<(), Status> {
    let limits = burrow_diskread::Limits {
        cpu_secs: TIMEOUT.as_secs(),
        ..Default::default()
    };
    let mut reader = burrow_diskread::Reader::spawn(Path::new("/proc/self/exe"), disk, limits)
        .map_err(|err| Status::internal(format!("starting the disk reader: {err}")))?;
    let (mut bytes, mut entries) = (0, 0);
    for path in paths {
        let parent = match path.rsplit_once('/') {
            Some(("", _)) | None => "/",
            Some((parent, _)) => parent,
        };
        let (chunks, mut received) = tokio::sync::mpsc::channel(8);
        let first = guestpb::TarChunk {
            path: parent.to_string(),
            data: Vec::new(),
        };
        let outbound = async_stream::stream! {
            yield first;
            while let Some(data) = received.recv().await {
                yield guestpb::TarChunk { path: String::new(), data };
            }
        };
        let mut agent = sandbox.agent().await?;
        let (read, unpacked) = tokio::join!(
            reader.tar(path, MAX_BYTES - bytes, MAX_ENTRIES - entries, chunks),
            agent.extract_tar(outbound)
        );
        let summary = match (read, unpacked) {
            (Ok(summary), Ok(_)) => summary,
            (Err(err), Ok(_)) => {
                return Err(Status::failed_precondition(format!("--keep: {err}")));
            }
            (Err(err), Err(_)) if err != burrow_diskread::RECEIVER_GONE => {
                return Err(Status::failed_precondition(format!("--keep: {err}")));
            }
            (_, Err(err)) => {
                return Err(Status::new(
                    err.code(),
                    format!(
                        "--keep {path}: unpacking in the new guest: {}",
                        err.message()
                    ),
                ));
            }
        };
        bytes += summary.bytes;
        entries += summary.entries;
        tracing::info!(
            sandbox = sandbox.id(),
            path,
            entries = summary.entries,
            bytes = summary.bytes,
            skipped = summary.skipped,
            "kept a path across a recreate"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use burrow_vmm::GuestOs;

    #[cfg(target_os = "linux")]
    fn mount(path: &str) -> common::VolumeMount {
        common::VolumeMount {
            volume: "data".into(),
            path: path.into(),
            ..Default::default()
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_path_a_volume_holds_is_refused() {
        let volumes = [mount("/home/me/data")];
        for path in ["/home", "/home/me/data", "/home/me/data/x"] {
            let err = check(&[path.into()], &volumes, GuestOs::Linux, GuestOs::Linux).unwrap_err();
            assert!(err.message().contains("volume"), "{}", err.message());
        }
        assert_eq!(
            check(
                &["/home/you/".into()],
                &volumes,
                GuestOs::Linux,
                GuestOs::Linux
            )
            .unwrap(),
            ["/home/you"]
        );
    }

    #[test]
    fn only_linux_disks_are_kept() {
        let err = check(&["/home".into()], &[], GuestOs::Linux, GuestOs::Windows).unwrap_err();
        assert_ne!(err.code(), tonic::Code::Ok);
        let err = check(&["/".into()], &[], GuestOs::Linux, GuestOs::Linux).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
