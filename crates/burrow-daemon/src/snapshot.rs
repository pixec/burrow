//! Snapshots as objects: a sandbox's saved state, kept outside the sandbox.
//!
//! A sandbox's own suspend state lives in its working directory and dies with
//! it. A snapshot is the same bytes lifted out into `snapshots/<id>/`, where it
//! outlives its source and can start any number of new sandboxes.
//!
//! Three properties the layout exists to guarantee:
//!
//! - **Self-contained.** The kernel and rootfs are hard-linked in beside the
//!   state, so deleting the source sandbox or the template leaves the snapshot
//!   restorable. Links cost nothing and share the template's pages.
//! - **One memory image.** The source's chain of a base plus diffs is flattened
//!   on create, so restoring costs the same however many times the sandbox had
//!   been suspended before the snapshot was taken.
//! - **Atomic.** Everything is built in a temporary directory and renamed into
//!   place, and the manifest is written last, so a crash never leaves a
//!   half-copied snapshot that reads as complete.
//!
//! Node-local, like a template: a snapshot encodes host cpu features and the
//! exact Firecracker version, so it is never moved between nodes.

#![allow(clippy::result_large_err)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tonic::Status;

use burrow_proto::common::v1 as common;

/// Written last, and the only thing that makes a directory a snapshot.
const MANIFEST: &str = "manifest.json";
/// The one memory image a snapshot holds, flattened on create.
const SCRATCH_IMAGE: &str = "scratch.ext4";
const TEMPLATE_KERNEL: &str = "vmlinux";
const TEMPLATE_ROOTFS: &str = "rootfs.ext4";

/// Prefix of the directory a snapshot is assembled in before it is renamed.
///
/// Dotted so it cannot collide with a snapshot id, which the validator below
/// refuses to let start with a dot.
const STAGING_PREFIX: &str = ".staging-";

/// A manifest this build does not understand describes files it cannot safely
/// restore, so the snapshot is ignored rather than guessed at.
const MANIFEST_FORMAT: u32 = 1;

/// How long a staging directory may sit before it is read as a crash rather
/// than a create still copying. Far longer than any snapshot takes to write.
const STAGING_ORPHAN_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);

/// Ceiling on `keep_last_snapshots`.
///
/// Every retained snapshot is a full memory image plus a scratch disk on the
/// node's disk, so the depth a caller may ask to keep is bounded.
pub const MAX_KEEP_LAST: u32 = 10;

/// What a snapshot is, on disk.
///
/// Serialised rather than derived from the files, because a shape cannot be
/// read back out of a Firecracker vmstate and a create from the snapshot has to
/// be refused when it asks for a different one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub id: String,
    pub sandbox_id: String,
    pub template: String,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub scratch_disk_mib: u32,
    /// RFC 3339, for reporting.
    pub created_at: String,
    /// The same instant in milliseconds, for ordering.
    ///
    /// Retention evicts the oldest first, and two snapshots taken inside one
    /// second would otherwise be ordered arbitrarily, by their random ids.
    pub created_unix_ms: i64,
    pub size_bytes: u64,
    /// Unix seconds; 0 means the snapshot never expires.
    pub expires_at: i64,
    /// Seconds the TTL is re-armed for on every use. 0 means no expiry, which
    /// is why it is kept beside `expires_at` rather than recomputed from it.
    pub expiration_secs: u64,
    /// Passed over by retention once, and left to expire on its own.
    ///
    /// Without this a snapshot the policy declined to delete would be counted
    /// and passed over again on every later pass. Defaulted so manifests
    /// written before the field existed read as not evicted.
    #[serde(default)]
    pub evicted: bool,
}

impl Manifest {
    fn to_proto(&self) -> common::Snapshot {
        common::Snapshot {
            id: self.id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            template: self.template.clone(),
            // The orchestrator stamps this from its own view of the fleet.
            node_id: String::new(),
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            scratch_disk_mib: self.scratch_disk_mib,
            created_at: self.created_at.clone(),
            size_bytes: self.size_bytes,
            expires_at: match self.expires_at {
                0 => String::new(),
                at => burrow_core::rfc3339_from_unix_secs(at),
            },
        }
    }
}

/// Checks an id before it becomes a path.
///
/// Only the orchestrator mints snapshot ids, so the accepted shape is exactly
/// what it generates: `snap_` and the simple form of a uuid. Anything else is
/// someone writing a path, and is refused rather than sanitised.
pub fn validate_id(id: &str) -> Result<(), Status> {
    let ok = matches!(id.strip_prefix("snap_"), Some(rest)
        if (1..=64).contains(&rest.len())
            && rest.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    if !ok {
        return Err(Status::invalid_argument(format!(
            "snapshot id {id:?} is not a burrow snapshot id"
        )));
    }
    Ok(())
}

/// The node's snapshot store: one directory per snapshot under `snapshots/`.
#[derive(Clone)]
pub struct SnapshotStore {
    root: PathBuf,
}

/// Everything a create needs from the sandbox it is snapshotting, gathered
/// under the sandbox's vm lock so a suspend cannot move it half way through.
pub struct Staged {
    pub sandbox_id: String,
    pub template: String,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub scratch_disk_mib: u32,
    /// Memory files in the staging directory, oldest first.
    pub chain: Vec<String>,
}

impl SnapshotStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("snapshots"),
        }
    }

    fn dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    /// A directory to assemble a snapshot in, beside the store it will join.
    ///
    /// Beside rather than in `/tmp`: the rename that publishes it has to be
    /// within one filesystem, and so do the hard links and reflinks that make
    /// staging cheap.
    fn staging(&self, id: &str) -> PathBuf {
        self.root.join(format!("{STAGING_PREFIX}{id}"))
    }

    /// Opens the store's directory, creating it on first use.
    async fn ensure_root(&self) -> Result<(), Status> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(|err| Status::internal(format!("snapshot store: {err}")))
    }

    /// Assembles a staging directory for `id` and hands its path back.
    ///
    /// The caller stages the sandbox's files into it, under the sandbox's vm
    /// lock, and then calls [`Self::publish`].
    pub async fn begin(&self, id: &str) -> Result<PathBuf, Status> {
        validate_id(id)?;
        self.ensure_root().await?;
        let dir = self.staging(id);
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|err| Status::internal(format!("staging a snapshot: {err}")))?;
        Ok(dir)
    }

    /// Flattens the staged memory chain, writes the manifest, and renames the
    /// directory into the store.
    ///
    /// The flattening happens here rather than on restore so a snapshot's cost
    /// is constant: a source suspended a dozen times still produces one image.
    pub async fn publish(
        &self,
        id: &str,
        staged: Staged,
        expiration_secs: u64,
    ) -> Result<common::Snapshot, Status> {
        let dir = self.staging(id);
        flatten(&dir, &staged.chain).await?;

        let size_bytes = directory_size(&dir).await;
        let now = burrow_core::unix_now();
        let manifest = Manifest {
            format: MANIFEST_FORMAT,
            id: id.to_string(),
            sandbox_id: staged.sandbox_id,
            template: staged.template,
            vcpus: staged.vcpus,
            mem_mib: staged.mem_mib,
            scratch_disk_mib: staged.scratch_disk_mib,
            created_at: burrow_core::now_rfc3339(),
            created_unix_ms: unix_now_ms(),
            size_bytes,
            expires_at: match expiration_secs {
                0 => 0,
                secs => now + secs as i64,
            },
            expiration_secs,
            evicted: false,
        };
        write_manifest(&dir, &manifest).await?;

        let live = self.dir(id);
        // An id is generated per create, so a collision means a retry of a
        // create that already finished; the newer bytes win.
        let _ = tokio::fs::remove_dir_all(&live).await;
        tokio::fs::rename(&dir, &live)
            .await
            .map_err(|err| Status::internal(format!("publishing the snapshot: {err}")))?;
        Ok(manifest.to_proto())
    }

    /// Removes a staging directory a failed create left behind.
    pub async fn abandon(&self, id: &str) {
        let _ = tokio::fs::remove_dir_all(self.staging(id)).await;
    }

    pub async fn get(&self, id: &str) -> Result<common::Snapshot, Status> {
        Ok(self.manifest(id).await?.to_proto())
    }

    pub async fn manifest(&self, id: &str) -> Result<Manifest, Status> {
        validate_id(id)?;
        read_manifest(&self.dir(id))
            .await
            .ok_or_else(|| Status::not_found(format!("no snapshot {id} on this node")))
    }

    /// Every snapshot the node holds, newest first, optionally one sandbox's.
    pub async fn list(&self, sandbox_id: Option<&str>) -> Vec<common::Snapshot> {
        let mut out: Vec<(common::Snapshot, (i64, String))> = Vec::new();
        let Ok(mut entries) = tokio::fs::read_dir(&self.root).await else {
            return Vec::new();
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Staging directories and anything else that is not a snapshot id.
            if validate_id(&name).is_err() {
                continue;
            }
            let Some(manifest) = read_manifest(&entry.path()).await else {
                continue;
            };
            if sandbox_id.is_some_and(|wanted| manifest.sandbox_id != wanted) {
                continue;
            }
            // Paired with the ordering key, so the sort below does not have to
            // reach back into a manifest the proto does not carry.
            out.push((manifest.to_proto(), (manifest.created_unix_ms, manifest.id)));
        }
        // Newest first, which is the order retention evicts from the far end of
        // and the order a listing is read in.
        out.sort_by(|(_, a), (_, b)| b.cmp(a));
        out.into_iter().map(|(snapshot, _)| snapshot).collect()
    }

    /// Ids of every snapshot held, for the orchestrator to reconcile against.
    pub async fn ids(&self) -> Vec<String> {
        self.list(None)
            .await
            .into_iter()
            .map(|snapshot| snapshot.id)
            .collect()
    }

    pub async fn delete(&self, id: &str) -> Result<(), Status> {
        validate_id(id)?;
        let dir = self.dir(id);
        if read_manifest(&dir).await.is_none() {
            return Err(Status::not_found(format!("no snapshot {id} on this node")));
        }
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|err| Status::internal(format!("removing snapshot: {err}")))?;
        tracing::info!(snapshot = id, "snapshot deleted");
        Ok(())
    }

    /// Copies a snapshot into a sandbox's working directory.
    ///
    /// The same shape as forking a sandbox, and for the same reason: Firecracker
    /// requires a restore's resource paths to match what they were at snapshot
    /// time, so the files have to be under the sandbox's own directory with the
    /// names they had. Read-only artifacts are linked; what the guest writes is
    /// copied, sparsely and by reflink where the filesystem allows it.
    pub async fn stage_into(&self, id: &str, dest: &Path) -> Result<Vec<String>, Status> {
        let dir = self.dir(id);
        if read_manifest(&dir).await.is_none() {
            return Err(Status::not_found(format!("no snapshot {id} on this node")));
        }
        let io = |what: &str, err: std::io::Error| {
            Status::internal(format!("staging snapshot {id} ({what}): {err}"))
        };

        for file in [TEMPLATE_KERNEL, TEMPLATE_ROOTFS] {
            tokio::fs::hard_link(dir.join(file), dest.join(file))
                .await
                .map_err(|err| io(file, err))?;
        }
        // Copied, not linked: the sandbox writes its own over it on its first
        // suspend, and a shared inode would have that land in the snapshot.
        tokio::fs::copy(
            dir.join(burrow_vmm::SNAPSHOT_FILE),
            dest.join(burrow_vmm::SNAPSHOT_FILE),
        )
        .await
        .map_err(|err| io(burrow_vmm::SNAPSHOT_FILE, err))?;

        for file in [SCRATCH_IMAGE, burrow_vmm::SNAPSHOT_MEM_FILE] {
            crate::warm::copy_sparse(&dir.join(file), &dest.join(file))
                .await
                .map_err(|err| io(file, err))?;
        }
        Ok(vec![burrow_vmm::SNAPSHOT_MEM_FILE.to_string()])
    }

    /// Re-arms a snapshot's TTL, because it was just used.
    ///
    /// Expiry is measured from last use rather than from creation, and a create
    /// from the snapshot is the only evidence of use the node ever sees.
    pub async fn touch(&self, id: &str) {
        let Ok(mut manifest) = self.manifest(id).await else {
            return;
        };
        if manifest.expiration_secs == 0 {
            return;
        }
        manifest.expires_at = burrow_core::unix_now() + manifest.expiration_secs as i64;
        if let Err(err) = write_manifest(&self.dir(id), &manifest).await {
            tracing::warn!(snapshot = id, %err, "could not refresh a snapshot's expiry");
        }
    }

    /// Removes directories in the store that hold no manifest at all.
    ///
    /// The publish is a rename, so a snapshot either has its manifest or was
    /// never published; what is left here is a staging directory a crash
    /// orphaned, and it holds a memory image and a scratch disk that nothing
    /// else would ever reclaim.
    ///
    /// A directory whose manifest is present but unreadable, say a format a
    /// downgraded node does not know, is left alone and merely reported: it may
    /// still be restorable by the build that wrote it.
    pub async fn collect_orphans(&self) {
        let Ok(mut entries) = tokio::fs::read_dir(&self.root).await else {
            return;
        };
        let mut removed = 0;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            let staging = name.starts_with(STAGING_PREFIX);
            if !staging && validate_id(&name).is_err() {
                continue;
            }
            let manifest = entry.path().join(MANIFEST);
            if tokio::fs::try_exists(&manifest).await.unwrap_or(false) {
                if read_manifest(&entry.path()).await.is_none() {
                    tracing::warn!(
                        snapshot = name,
                        "snapshot manifest is unreadable by this build; leaving it in place"
                    );
                }
                continue;
            }
            // A staging directory may belong to a create that is still copying,
            // so only a stale one is a crash rather than work in progress. A
            // published directory cannot be mid-write: the rename that names it
            // happens after its manifest is on disk.
            if staging && !older_than(&entry.path(), STAGING_ORPHAN_AFTER).await {
                continue;
            }
            if tokio::fs::remove_dir_all(entry.path()).await.is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            tracing::info!(removed, "removed half-written snapshot directories");
        }
    }

    /// Deletes snapshots whose TTL has run out, returning their ids.
    pub async fn sweep_expired(&self) -> Vec<String> {
        let now = burrow_core::unix_now();
        let mut swept = Vec::new();
        for snapshot in self.list(None).await {
            let Ok(manifest) = self.manifest(&snapshot.id).await else {
                continue;
            };
            if manifest.expires_at == 0 || manifest.expires_at > now {
                continue;
            }
            match self.delete(&snapshot.id).await {
                Ok(()) => {
                    tracing::info!(
                        snapshot = snapshot.id,
                        sandbox = manifest.sandbox_id,
                        "snapshot expired and was swept"
                    );
                    swept.push(snapshot.id);
                }
                Err(err) => {
                    tracing::warn!(snapshot = snapshot.id, %err, "could not sweep an expired snapshot")
                }
            }
        }
        swept
    }

    /// Keeps only the `keep` newest snapshots of one sandbox.
    ///
    /// Applied as a snapshot is taken, so the count is bounded at the moment it
    /// would otherwise grow. 0 keeps everything.
    ///
    /// `keep_evicted` leaves what falls past the cap on disk to expire on its
    /// own rather than deleting it. Such a snapshot is marked, and a marked one
    /// neither counts toward the cap nor is considered again, so a sandbox that
    /// keeps snapshotting does not re-walk everything it has ever released.
    pub async fn retain_newest(
        &self,
        sandbox_id: &str,
        keep: u32,
        keep_evicted: bool,
    ) -> Vec<String> {
        if keep == 0 {
            return Vec::new();
        }
        let held = self.list(Some(sandbox_id)).await;
        let mut live = Vec::new();
        for snapshot in held {
            // A released snapshot is still listable and still restorable until
            // it expires; it has just stopped being retained.
            match self.manifest(&snapshot.id).await {
                Ok(manifest) if manifest.evicted => continue,
                Ok(_) => live.push(snapshot),
                Err(_) => continue,
            }
        }

        let mut evicted = Vec::new();
        // `list` is newest first, so everything past the cap is the oldest.
        for snapshot in live.into_iter().skip(keep as usize) {
            if keep_evicted {
                if let Err(err) = self.release(&snapshot.id).await {
                    tracing::warn!(snapshot = snapshot.id, %err, "could not release a snapshot");
                    continue;
                }
                tracing::info!(
                    snapshot = snapshot.id,
                    sandbox = sandbox_id,
                    keep,
                    "released the oldest snapshot from retention; it expires on its own"
                );
                evicted.push(snapshot.id);
                continue;
            }
            match self.delete(&snapshot.id).await {
                Ok(()) => {
                    tracing::info!(
                        snapshot = snapshot.id,
                        sandbox = sandbox_id,
                        keep,
                        "evicted the oldest snapshot to stay within keep_last_snapshots"
                    );
                    evicted.push(snapshot.id);
                }
                Err(err) => {
                    tracing::warn!(snapshot = snapshot.id, %err, "could not evict a snapshot")
                }
            }
        }
        evicted
    }

    /// Marks a snapshot as no longer retained, leaving its files and its TTL.
    async fn release(&self, id: &str) -> Result<(), Status> {
        let mut manifest = self.manifest(id).await?;
        manifest.evicted = true;
        write_manifest(&self.dir(id), &manifest).await
    }
}

/// Whether a path was last written longer ago than `age`.
///
/// Unreadable metadata reads as "recent", so a directory is never collected on
/// the strength of a failed stat.
async fn older_than(path: &Path, age: std::time::Duration) -> bool {
    let Ok(meta) = tokio::fs::metadata(path).await else {
        return false;
    };
    meta.modified()
        .ok()
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|elapsed| elapsed > age)
}

/// Milliseconds since the epoch, for ordering snapshots taken close together.
fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Merges the staged memory chain down to the single image a snapshot holds.
async fn flatten(dir: &Path, chain: &[String]) -> Result<(), Status> {
    if chain.is_empty() {
        return Err(Status::failed_precondition(
            "sandbox has no state to snapshot",
        ));
    }
    let target = dir.join(burrow_vmm::SNAPSHOT_MEM_FILE);
    if chain.len() > 1 {
        let paths: Vec<PathBuf> = chain.iter().map(|name| dir.join(name)).collect();
        let target = target.clone();
        tokio::task::spawn_blocking(move || merge_chain(&paths, &target))
            .await
            .map_err(|err| Status::internal(format!("flattening did not run: {err}")))?
            .map_err(|err| Status::internal(format!("flattening the memory chain: {err}")))?;
    }
    // Whether merged or already single-layered, only the base image is kept.
    for name in chain.iter().skip(1) {
        let _ = tokio::fs::remove_file(dir.join(name)).await;
    }
    if !tokio::fs::try_exists(&target).await.unwrap_or(false) {
        return Err(Status::internal(
            "the flattened memory image is missing after staging",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn merge_chain(paths: &[PathBuf], target: &Path) -> std::io::Result<()> {
    burrow_vmm::merge_chain(paths, target)
}

#[cfg(not(target_os = "linux"))]
fn merge_chain(_paths: &[PathBuf], _target: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("merging is linux-only"))
}

async fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<(), Status> {
    let json = serde_json::to_vec_pretty(manifest)
        .map_err(|err| Status::internal(format!("encoding the manifest: {err}")))?;
    tokio::fs::write(dir.join(MANIFEST), json)
        .await
        .map_err(|err| Status::internal(format!("writing the manifest: {err}")))
}

/// Reads a snapshot's manifest, or `None` for anything that is not one.
///
/// A directory without a readable manifest of a format this build knows is not
/// a snapshot: it is a staging directory, a half-written create, or something
/// written by a version that arranged the files differently.
async fn read_manifest(dir: &Path) -> Option<Manifest> {
    let bytes = tokio::fs::read(dir.join(MANIFEST)).await.ok()?;
    let manifest: Manifest = serde_json::from_slice(&bytes).ok()?;
    (manifest.format == MANIFEST_FORMAT).then_some(manifest)
}

/// What the snapshot actually occupies, counting allocated blocks rather than
/// apparent length: the memory image and the scratch disk are both sparse, and
/// their apparent size is the guest's memory rather than the node's disk.
async fn directory_size(dir: &Path) -> u64 {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return 0;
    };
    let mut total = 0;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            // Hard-linked kernel and rootfs are shared with the template and
            // cost the node nothing extra, so they are not counted.
            if meta.nlink() > 1 {
                continue;
            }
            total += meta.blocks() * 512;
        }
        #[cfg(not(unix))]
        {
            total += meta.len();
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: &str, sandbox: &str, created_at: &str) -> Manifest {
        Manifest {
            format: MANIFEST_FORMAT,
            id: id.into(),
            sandbox_id: sandbox.into(),
            template: "default".into(),
            vcpus: 2,
            mem_mib: 1024,
            scratch_disk_mib: 2048,
            created_at: created_at.into(),
            created_unix_ms: burrow_core::unix_from_rfc3339(created_at).unwrap_or(0) * 1_000,
            size_bytes: 12_345,
            expires_at: 0,
            expiration_secs: 0,
            evicted: false,
        }
    }

    fn store() -> (SnapshotStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "burrow-snapshots-{}-{}",
            std::process::id(),
            burrow_core::SnapshotId::generate()
        ));
        (SnapshotStore::new(&dir), dir)
    }

    /// The shape is the one thing a restore cannot rediscover, so it has to
    /// survive the round trip exactly.
    #[tokio::test]
    async fn a_manifest_round_trips_through_its_file() {
        let (store, root) = store();
        let dir = store.begin("snap_abc123").await.unwrap();
        let mut written = manifest("snap_abc123", "sbx_a", "2026-09-02T10:00:00Z");
        written.expires_at = 1_800_000_000;
        written.expiration_secs = 3_600;
        write_manifest(&dir, &written).await.unwrap();

        let read = read_manifest(&dir).await.expect("a manifest");
        assert_eq!(read.id, "snap_abc123");
        assert_eq!(read.sandbox_id, "sbx_a");
        assert_eq!(
            (read.vcpus, read.mem_mib, read.scratch_disk_mib),
            (2, 1024, 2048)
        );
        assert_eq!(read.expires_at, 1_800_000_000);
        assert_eq!(read.expiration_secs, 3_600);

        let proto = read.to_proto();
        assert_eq!(proto.expires_at, "2027-01-15T08:00:00Z");
        assert_eq!(proto.template, "default");
        // The node cannot know its own id here; the orchestrator stamps it.
        assert!(proto.node_id.is_empty());

        // A format this build does not understand reads as "not a snapshot",
        // which is what stops it being restored from.
        let mut future = written.clone();
        future.format = MANIFEST_FORMAT + 1;
        write_manifest(&dir, &future).await.unwrap();
        assert!(read_manifest(&dir).await.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Only the orchestrator mints these, so anything that could become a path
    /// of its own is refused rather than sanitised.
    #[test]
    fn only_a_generated_snapshot_id_is_accepted() {
        assert!(validate_id(&burrow_core::SnapshotId::generate().to_string()).is_ok());
        for bad in [
            "",
            "snap_",
            "sbx_abc",
            "snap_../etc",
            "snap_ABC",
            "snap_a-b",
            "../snapshots",
            ".staging-snap_a",
            &format!("snap_{}", "a".repeat(65)),
        ] {
            assert!(validate_id(bad).is_err(), "{bad:?} should be refused");
        }
    }

    /// Writes manifests straight into the store, skipping the memory flatten.
    async fn seed(store: &SnapshotStore, entries: &[(&str, &str, &str)]) {
        for (id, sandbox, created_at) in entries {
            let dir = store.begin(id).await.unwrap();
            write_manifest(&dir, &manifest(id, sandbox, created_at))
                .await
                .unwrap();
            tokio::fs::rename(&dir, store.dir(id)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn retention_evicts_the_oldest_first() {
        let (store, root) = store();
        seed(
            &store,
            &[
                ("snap_aaa1", "sbx_a", "2026-09-01T10:00:00Z"),
                ("snap_aaa2", "sbx_a", "2026-09-02T10:00:00Z"),
                ("snap_aaa3", "sbx_a", "2026-09-03T10:00:00Z"),
                ("snap_bbb1", "sbx_b", "2026-08-01T10:00:00Z"),
            ],
        )
        .await;

        // Another sandbox's snapshots are not this sandbox's to evict.
        let evicted = store.retain_newest("sbx_a", 2, false).await;
        assert_eq!(evicted, vec!["snap_aaa1".to_string()]);
        let left: Vec<String> = store
            .list(Some("sbx_a"))
            .await
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(left, vec!["snap_aaa3".to_string(), "snap_aaa2".to_string()]);
        assert_eq!(store.list(Some("sbx_b")).await.len(), 1);

        // 0 is unlimited, not "keep none": the difference between a knob left
        // unset and one that deletes everything.
        assert!(store.retain_newest("sbx_a", 0, false).await.is_empty());
        assert_eq!(store.list(Some("sbx_a")).await.len(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Keeping what retention evicts must not mean walking it again forever:
    /// a released snapshot stops counting toward the cap and stops being
    /// reconsidered, so the newest `keep` are still the retained ones.
    #[tokio::test]
    async fn a_released_snapshot_is_left_to_expire_and_not_reconsidered() {
        let (store, root) = store();
        seed(
            &store,
            &[
                ("snap_ddd1", "sbx_a", "2026-09-01T10:00:00Z"),
                ("snap_ddd2", "sbx_a", "2026-09-02T10:00:00Z"),
                ("snap_ddd3", "sbx_a", "2026-09-03T10:00:00Z"),
            ],
        )
        .await;

        let released = store.retain_newest("sbx_a", 2, true).await;
        assert_eq!(released, vec!["snap_ddd1".to_string()]);
        // Still on disk and still restorable, unlike an eviction.
        assert!(store.get("snap_ddd1").await.is_ok());
        assert!(store.manifest("snap_ddd1").await.unwrap().evicted);

        // A second pass has nothing to do: the release is remembered.
        assert!(store.retain_newest("sbx_a", 2, true).await.is_empty());

        // And a released snapshot does not fill the cap, so the next snapshot
        // releases a live one rather than being refused a slot.
        seed(&store, &[("snap_ddd4", "sbx_a", "2026-09-04T10:00:00Z")]).await;
        assert_eq!(
            store.retain_newest("sbx_a", 2, true).await,
            vec!["snap_ddd2".to_string()]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn only_snapshots_past_their_expiry_are_swept() {
        let (store, root) = store();
        let now = burrow_core::unix_now();
        seed(
            &store,
            &[
                ("snap_ccc1", "sbx_a", "2026-09-01T10:00:00Z"),
                ("snap_ccc2", "sbx_a", "2026-09-02T10:00:00Z"),
                ("snap_ccc3", "sbx_a", "2026-09-03T10:00:00Z"),
            ],
        )
        .await;
        // Expired, still live, and never expires.
        for (id, expires_at) in [("snap_ccc1", now - 1), ("snap_ccc2", now + 3_600)] {
            let mut manifest = store.manifest(id).await.unwrap();
            manifest.expires_at = expires_at;
            manifest.expiration_secs = 3_600;
            write_manifest(&store.dir(id), &manifest).await.unwrap();
        }

        assert_eq!(store.sweep_expired().await, vec!["snap_ccc1".to_string()]);
        assert!(store.get("snap_ccc1").await.is_err());
        assert!(store.get("snap_ccc2").await.is_ok());
        assert!(store.get("snap_ccc3").await.is_ok());

        // A use re-arms the TTL, which is what makes expiry "since last use".
        store.touch("snap_ccc2").await;
        let refreshed = store.manifest("snap_ccc2").await.unwrap();
        assert!(refreshed.expires_at >= now + 3_600);
        // A snapshot with no TTL is not given one by being used.
        store.touch("snap_ccc3").await;
        assert_eq!(store.manifest("snap_ccc3").await.unwrap().expires_at, 0);

        let _ = std::fs::remove_dir_all(&root);
    }
}
