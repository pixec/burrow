//! Persistent volumes: disk images that outlive the sandboxes mounting them.
//!
//! A volume is an ext4 image attached to the guest as a virtio block device,
//! because that is the only storage firecracker offers: there is no virtio-fs
//! and no 9p, so there is no way to hand several guests one filesystem. That
//! shapes everything here.
//!
//! Access is therefore many readers or one writer, never both. ext4 is not a
//! cluster filesystem: two guests writing one image corrupt it, and a guest
//! reading one that another is writing sees its own cached metadata go stale
//! underneath it. Worse, a filesystem a writer has mounted has a dirty journal,
//! and mounting that read-only makes ext4 attempt a recovery it cannot perform
//! on a read-only device, so the mount fails outright.
//!
//! Claims are held by *running* sandboxes rather than by whichever sandbox
//! mounted the volume first, so a volume is a handoff between jobs: stop the
//! holders and the next sandbox can take it. Claims live in memory, which is
//! what makes a node restart release them, and is correct because nothing is
//! touching the image while no VM is running.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use burrow_proto::common::v1 as common;
use serde::{Deserialize, Serialize};
use tonic::Status;

/// Ceiling on one volume, so a create cannot ask for the node's whole disk.
pub const MAX_SIZE_MIB: u64 = 1024 * 1024;
pub const MIN_SIZE_MIB: u64 = 1;

/// Guest devices volumes are attached as.
///
/// `/dev/vda` is the template rootfs and `/dev/vdb` the scratch disk, so
/// volumes start at `/dev/vdc`. The cap keeps the naming to one letter, which
/// is all the kernel's own scheme gives without a second character.
pub const FIRST_DEVICE: u8 = b'c';
pub const MAX_MOUNTS: usize = 8;

const IMAGE: &str = "volume.ext4";
const META: &str = "volume.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    pub size_mib: u64,
    /// RFC 3339.
    pub created_at: String,
}

/// Who currently holds one volume.
///
/// Readers and a writer are mutually exclusive, so only one of the two is ever
/// populated.
#[derive(Default)]
struct Claim {
    writer: Option<String>,
    readers: std::collections::HashSet<String>,
}

impl Claim {
    fn is_free(&self) -> bool {
        self.writer.is_none() && self.readers.is_empty()
    }

    /// Any sandbox holding it, for messages and for refusing a delete.
    fn any_holder(&self) -> Option<String> {
        self.writer
            .clone()
            .or_else(|| self.readers.iter().next().cloned())
    }
}

/// The node's volume store: one directory per volume under `volumes/`.
#[derive(Clone)]
pub struct VolumeStore {
    root: PathBuf,
    claims: Arc<Mutex<HashMap<String, Claim>>>,
}

impl VolumeStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("volumes"),
            claims: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Path of a volume's image, for attaching it as a drive.
    pub fn image(&self, name: &str) -> PathBuf {
        self.dir(name).join(IMAGE)
    }

    pub async fn create(&self, name: &str, size_mib: u64) -> Result<common::Volume, Status> {
        validate_name(name)?;
        if !(MIN_SIZE_MIB..=MAX_SIZE_MIB).contains(&size_mib) {
            return Err(Status::invalid_argument(format!(
                "size_mib {size_mib} out of range ({MIN_SIZE_MIB}..={MAX_SIZE_MIB})"
            )));
        }
        let dir = self.dir(name);
        if tokio::fs::try_exists(dir.join(META)).await.unwrap_or(false) {
            return Err(Status::already_exists(format!("volume {name} exists")));
        }
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|err| Status::internal(format!("volume dir: {err}")))?;

        // Built beside the destination and renamed, so a failed mkfs never
        // leaves a half-written image where a mountable one is expected.
        let pending = dir.join("volume.ext4.building");
        let _ = tokio::fs::remove_file(&pending).await;
        crate::template::run(
            "mkfs.ext4",
            &[
                "-q",
                "-F",
                "-L",
                "burrow-volume",
                "-b",
                "4096",
                &pending.to_string_lossy(),
                &format!("{size_mib}M"),
            ],
        )
        .await?;

        let meta = Meta {
            name: name.to_string(),
            size_mib,
            created_at: burrow_core::now_rfc3339(),
        };
        let json = serde_json::to_vec_pretty(&meta)
            .map_err(|err| Status::internal(format!("volume metadata: {err}")))?;
        tokio::fs::write(dir.join(META), json)
            .await
            .map_err(|err| Status::internal(format!("writing volume metadata: {err}")))?;
        tokio::fs::rename(&pending, dir.join(IMAGE))
            .await
            .map_err(|err| Status::internal(format!("publishing volume: {err}")))?;

        Ok(self.to_proto(&meta))
    }

    pub async fn meta(&self, name: &str) -> Result<Meta, Status> {
        validate_name(name)?;
        let bytes = tokio::fs::read(self.dir(name).join(META))
            .await
            .map_err(|_| Status::not_found(format!("no volume {name}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|err| Status::internal(format!("volume {name} metadata: {err}")))
    }

    pub async fn get(&self, name: &str) -> Result<common::Volume, Status> {
        let meta = self.meta(name).await?;
        Ok(self.to_proto(&meta))
    }

    pub async fn list(&self) -> Vec<common::Volume> {
        let Ok(mut entries) = tokio::fs::read_dir(&self.root).await else {
            return Vec::new();
        };
        let mut volumes = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if let Ok(meta) = self.meta(&name).await {
                volumes.push(self.to_proto(&meta));
            }
        }
        volumes.sort_by(|a, b| a.name.cmp(&b.name));
        volumes
    }

    /// Removes a volume and its contents.
    ///
    /// Refused while a sandbox holds it writable: the image is a live block
    /// device in that guest, and deleting it underneath would fault the guest
    /// rather than free anything.
    pub async fn delete(&self, name: &str) -> Result<(), Status> {
        validate_name(name)?;
        if let Some(holder) = self.holder(name) {
            return Err(Status::failed_precondition(format!(
                "volume {name} is attached to sandbox {holder}"
            )));
        }
        let dir = self.dir(name);
        if !tokio::fs::try_exists(dir.join(META)).await.unwrap_or(false) {
            return Err(Status::not_found(format!("no volume {name}")));
        }
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|err| Status::internal(format!("removing volume {name}: {err}")))
    }

    fn holder(&self, name: &str) -> Option<String> {
        self.claims
            .lock()
            .unwrap()
            .get(name)
            .and_then(Claim::any_holder)
    }

    /// Takes the claims for one sandbox's mounts, all or nothing.
    ///
    /// All or nothing so a sandbox that cannot have every volume it asked for
    /// starts with none of them, rather than booting half configured.
    pub fn claim(&self, sandbox_id: &str, mounts: &[common::VolumeMount]) -> Result<(), Status> {
        let mut claims = self.claims.lock().unwrap();
        let mut taken = Vec::new();
        for mount in mounts {
            let claim = claims.entry(mount.volume.clone()).or_default();
            // A sandbox re-claiming what it already holds is a resume, not a
            // conflict with itself.
            let held_by_someone_else = |who: &Option<String>| {
                who.as_deref().is_some_and(|holder| holder != sandbox_id)
            };
            let refusal = if mount.read_only {
                held_by_someone_else(&claim.writer).then(|| {
                    format!(
                        "volume {} is attached writable to sandbox {}; a read-only mount \
                         cannot be taken while a sandbox is writing to it",
                        mount.volume,
                        claim.writer.clone().unwrap_or_default()
                    )
                })
            } else {
                let readers: Vec<&String> =
                    claim.readers.iter().filter(|r| *r != sandbox_id).collect();
                if held_by_someone_else(&claim.writer) {
                    Some(format!(
                        "volume {} is already attached writable to sandbox {}",
                        mount.volume,
                        claim.writer.clone().unwrap_or_default()
                    ))
                } else if !readers.is_empty() {
                    Some(format!(
                        "volume {} is attached read-only to {} sandbox(es), including {}; \
                         a writer cannot be taken while it is being read",
                        mount.volume,
                        readers.len(),
                        readers[0]
                    ))
                } else {
                    None
                }
            };
            if let Some(message) = refusal {
                drop(claims);
                self.release_named(sandbox_id, &taken);
                return Err(Status::failed_precondition(message));
            }
            if mount.read_only {
                claim.readers.insert(sandbox_id.to_string());
            } else {
                claim.writer = Some(sandbox_id.to_string());
            }
            taken.push(mount.volume.clone());
        }
        Ok(())
    }

    /// Drops every claim one sandbox holds, on stop, suspend or delete.
    pub fn release_all(&self, sandbox_id: &str) {
        let mut claims = self.claims.lock().unwrap();
        for claim in claims.values_mut() {
            if claim.writer.as_deref() == Some(sandbox_id) {
                claim.writer = None;
            }
            claim.readers.remove(sandbox_id);
        }
        claims.retain(|_, claim| !claim.is_free());
    }

    /// Rolls back a partial claim, leaving other sandboxes' holds alone.
    fn release_named(&self, sandbox_id: &str, volumes: &[String]) {
        let mut claims = self.claims.lock().unwrap();
        for name in volumes {
            if let Some(claim) = claims.get_mut(name) {
                if claim.writer.as_deref() == Some(sandbox_id) {
                    claim.writer = None;
                }
                claim.readers.remove(sandbox_id);
            }
        }
        claims.retain(|_, claim| !claim.is_free());
    }

    fn to_proto(&self, meta: &Meta) -> common::Volume {
        common::Volume {
            name: meta.name.clone(),
            // Stamped by the orchestrator from its own view of the fleet, like
            // a snapshot's.
            node_id: String::new(),
            size_mib: meta.size_mib,
            created_at: meta.created_at.clone(),
            attached_to: self.holder(&meta.name).unwrap_or_default(),
        }
    }
}

/// Checks a name before it becomes a path.
pub fn validate_name(name: &str) -> Result<(), Status> {
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && !name.starts_with('-');
    if !ok {
        return Err(Status::invalid_argument(format!(
            "volume name {name:?} must be 1 to 64 characters of [a-z0-9_-] and not start with '-'"
        )));
    }
    Ok(())
}

/// Checks the mounts a create asked for, before any of them is acted on.
pub fn validate_mounts(mounts: &[common::VolumeMount]) -> Result<(), Status> {
    if mounts.len() > MAX_MOUNTS {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_MOUNTS} volume mounts, got {}",
            mounts.len()
        )));
    }
    let mut paths: Vec<&String> = Vec::new();
    let mut names: Vec<&String> = Vec::new();
    for mount in mounts {
        validate_name(&mount.volume)?;
        validate_path(&mount.path)?;
        // Not just equal paths: one mount nested inside another is shadowed by
        // it, so the caller would find an empty directory rather than a
        // volume, with nothing to say why.
        let trimmed = mount.path.trim_end_matches('/');
        if let Some(clash) = paths.iter().find(|other: &&&String| {
            let other = other.trim_end_matches('/');
            other == trimmed
                || trimmed.starts_with(&format!("{other}/"))
                || other.starts_with(&format!("{trimmed}/"))
        }) {
            return Err(Status::invalid_argument(format!(
                "mount paths overlap: {} and {clash}",
                mount.path
            )));
        }
        // One volume at two paths would be one block device mounted twice,
        // which ext4 refuses in the guest rather than here.
        if names.contains(&&mount.volume) {
            return Err(Status::invalid_argument(format!(
                "volume {} mounted twice",
                mount.volume
            )));
        }
        paths.push(&mount.path);
        names.push(&mount.volume);
    }
    Ok(())
}

/// Checks a mount point.
///
/// The guest checks it again: this value came from a caller, and the agent is
/// the one that turns it into a mount.
fn validate_path(path: &str) -> Result<(), Status> {
    let ok = path.starts_with('/')
        && path.len() <= 255
        && !path.contains('\0')
        && !path.split('/').any(|part| part == ".." || part == ".")
        && path != "/";
    if !ok {
        return Err(Status::invalid_argument(format!(
            "mount path {path:?} must be absolute, not the root, and free of . and .. components"
        )));
    }
    // Mounting over these breaks the guest in ways that look like anything but
    // a bad mount point.
    const RESERVED: [&str; 8] = ["/proc", "/sys", "/dev", "/tmp", "/run", "/etc", "/usr", "/bin"];
    let trimmed = path.trim_end_matches('/');
    if RESERVED.iter().any(|reserved| {
        trimmed == *reserved || trimmed.starts_with(&format!("{reserved}/"))
    }) {
        return Err(Status::invalid_argument(format!(
            "mount path {path:?} is inside a reserved directory"
        )));
    }
    Ok(())
}

/// Guest device a mount lands on, in the order the drives were attached.
pub fn device_for(index: usize) -> String {
    format!("/dev/vd{}", (FIRST_DEVICE + index as u8) as char)
}

/// What the guest is told: devices rather than volume names, since the name is
/// a host-side handle and the guest only has the block device.
///
/// The order here must be the order the drives were attached, which is why
/// both come from the same slice.
pub fn agent_mounts(
    mounts: &[common::VolumeMount],
) -> Vec<burrow_proto::agent::v1::VolumeMount> {
    mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| burrow_proto::agent::v1::VolumeMount {
            device: device_for(index),
            path: mount.path.clone(),
            read_only: mount.read_only,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(volume: &str, path: &str, read_only: bool) -> common::VolumeMount {
        common::VolumeMount {
            volume: volume.into(),
            path: path.into(),
            read_only,
        }
    }

    #[test]
    fn a_name_that_would_escape_the_store_is_refused() {
        for bad in ["..", "a/b", "../etc", "", "-lead", "Upper", "with space"] {
            assert!(validate_name(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(validate_name("cache").is_ok());
        assert!(validate_name("build_cache-1").is_ok());
    }

    #[test]
    fn a_mount_point_that_would_break_the_guest_is_refused() {
        for bad in ["relative", "/", "/etc", "/usr/lib", "/proc/self", "/a/../b"] {
            assert!(
                validate_mounts(&[mount("v", bad, false)]).is_err(),
                "{bad:?} should be refused"
            );
        }
        assert!(validate_mounts(&[mount("v", "/data", false)]).is_ok());
        // A path that merely starts with the same letters as a reserved one is
        // not inside it.
        assert!(validate_mounts(&[mount("v", "/etcetera", false)]).is_ok());
    }

    #[test]
    fn one_path_or_one_volume_cannot_be_used_twice() {
        assert!(validate_mounts(&[mount("a", "/data", false), mount("b", "/data", false)]).is_err());
        // Nested, not equal: the inner mount would be hidden by the outer one.
        assert!(
            validate_mounts(&[mount("a", "/data", false), mount("b", "/data/cache", false)])
                .is_err()
        );
        assert!(
            validate_mounts(&[mount("a", "/data/cache", false), mount("b", "/data", false)])
                .is_err()
        );
        // Sharing a prefix is not being nested inside it.
        assert!(
            validate_mounts(&[mount("a", "/data", false), mount("b", "/database", false)]).is_ok()
        );
        assert!(validate_mounts(&[mount("a", "/one", false), mount("a", "/two", false)]).is_err());
        assert!(validate_mounts(&[mount("a", "/one", false), mount("b", "/two", false)]).is_ok());
    }

    /// Many readers or one writer, never both: a reader alongside a writer
    /// sees its cached metadata go stale, and cannot even mount a filesystem
    /// whose journal the writer left dirty.
    #[test]
    fn a_volume_admits_many_readers_or_one_writer() {
        let store = VolumeStore::new(Path::new("/tmp/burrow-volume-test"));
        let writable = [mount("cache", "/data", false)];
        let readable = [mount("cache", "/data", true)];

        assert!(store.claim("sbx_a", &writable).is_ok());
        assert!(store.claim("sbx_b", &writable).is_err());
        // A reader cannot join while a writer holds it.
        assert!(store.claim("sbx_c", &readable).is_err());
        // Re-claiming what you already hold is a resume, not a conflict.
        assert!(store.claim("sbx_a", &writable).is_ok());

        store.release_all("sbx_a");

        // Readers share freely with each other.
        assert!(store.claim("sbx_c", &readable).is_ok());
        assert!(store.claim("sbx_d", &readable).is_ok());
        // But a writer cannot take it while they are reading.
        assert!(store.claim("sbx_b", &writable).is_err());

        store.release_all("sbx_c");
        store.release_all("sbx_d");
        assert!(store.claim("sbx_b", &writable).is_ok());
    }

    /// A sandbox that cannot have every volume it asked for takes none, so it
    /// never starts holding half its mounts.
    #[test]
    fn a_partial_claim_is_rolled_back() {
        let store = VolumeStore::new(Path::new("/tmp/burrow-volume-test"));
        assert!(store.claim("sbx_a", &[mount("taken", "/t", false)]).is_ok());

        let both = [mount("free", "/f", false), mount("taken", "/t", false)];
        assert!(store.claim("sbx_b", &both).is_err());
        // "free" was claimed before the conflict was found, and gave it back.
        assert!(store.claim("sbx_c", &[mount("free", "/f", false)]).is_ok());
        // Rolling back must not disturb the holder that caused the refusal.
        assert!(store.claim("sbx_d", &[mount("taken", "/t", false)]).is_err());
    }
}
