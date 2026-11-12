//! Snapshots as objects: a sandbox's saved state, kept outside the sandbox.
//!
//! A sandbox's own suspend state lives in its working directory and dies with
//! it. A snapshot is the same bytes lifted out into `snapshots/<id>/`, where it
//! outlives its source and can start any number of new sandboxes.
//!
//! Three properties the layout exists to guarantee:
//!
//! - **Self-contained.** The kernel and the template's image are hard-linked
//!   in beside the state, so deleting the source sandbox or the template
//!   leaves the snapshot restorable. Links cost nothing and share the
//!   template's pages. The sandbox's own disk is a clone, taken while its
//!   guest was paused for the memory beside it.
//! - **One memory image.** The source's chain of a base plus diffs is flattened
//!   on create, so restoring costs the same however many times the sandbox had
//!   been suspended before the snapshot was taken.
//! - **Atomic.** Everything is built in a temporary directory and renamed into
//!   place, and the manifest is written last, so a crash never leaves a
//!   half-copied snapshot that reads as complete.
//!
//! Node-local by default, like a template: a snapshot encodes host cpu
//! features and the exact Firecracker version. With an object store
//! configured a published snapshot is also uploaded, behind the create, and a
//! node that lacks one fetches it on the first create that asks; the
//! orchestrator only sends such a create to a node of the same architecture
//! running the same Firecracker. A root disk is stored as the chunks it
//! changed from its image, and the image once for every disk made from it:
//! the image is never uploaded per snapshot, and a fetching node clones its
//! own copy of it and fetches only the changed chunks. The fetch takes
//! everything but the memory image up front; memory arrives behind the
//! restored guest, served page by page as it faults, see [`crate::chunks`].

#![allow(clippy::result_large_err)]

use std::path::{Path, PathBuf};

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tonic::Status;

use burrow_vmm::HypervisorExt;

use crate::chunks::Hydrator;

use burrow_proto::common::v1 as common;

/// Written last, and the only thing that makes a directory a snapshot.
const MANIFEST: &str = "manifest.json";
const TEMPLATE_KERNEL: &str = "vmlinux";
const TEMPLATE_ROOTFS: &str = crate::rootdisk::IMAGE;
/// The source's command logs, as far as its guest had produced them: the
/// restored guest remembers those commands and is asked about them.
pub const COMMAND_LOGS: &str = "command-logs";

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
/// Every retained snapshot is a full memory image plus a disk on the node's
/// disk, so the depth a caller may ask to keep is bounded.
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
    pub disk_mib: u32,
    /// What the VM booted with, of `mem_mib`, and what it could grow to.
    pub boot_mem_mib: u32,
    pub max_mem_mib: u32,
    /// Unix milliseconds. Retention evicts the oldest first, and two
    /// snapshots taken inside one second would otherwise be ordered
    /// arbitrarily, by their random ids.
    pub created_unix_ms: i64,
    pub size_bytes: u64,
    /// Unix milliseconds; 0 means the snapshot never expires.
    pub expires_at_ms: i64,
    /// Seconds the TTL is re-armed for on every use. 0 means no expiry, which
    /// is why it is kept beside `expires_at` rather than recomputed from it.
    pub expiration_secs: u64,
    /// Passed over by retention once, and left to expire on its own.
    ///
    /// Without this a snapshot the policy declined to delete would be counted
    /// and passed over again on every later pass.
    pub is_evicted: bool,
    /// What the snapshot was taken on, which bounds where it can be restored.
    pub arch: String,
    /// The version of `hypervisor` that wrote it, which is the only one its
    /// state is known to restore under.
    pub hypervisor_version: String,
    /// The hypervisor that took it, and so the one it restores under.
    pub hypervisor: String,
    /// The CPU it was taken on; see [`crate::cpuid`].
    pub cpu: crate::cpuid::Cpu,
    /// Set once every object is in the store and the remote manifest is
    /// written, so a half-finished upload never reads as restorable.
    pub is_durable: bool,
    /// The kernel and the template's image by content, filled in when
    /// uploaded. The kernel goes to the store as a blob under its digest; the
    /// image as chunks under `images/`, which the disk's index is a diff
    /// against.
    pub kernel_digest: String,
    pub rootfs_digest: String,
    /// The inspection root its guest trusted, when it was inspected; see
    /// [`crate::durable::Manifest::inspection_root`].
    #[serde(default)]
    pub inspection_root: String,
}

impl Manifest {
    pub fn hypervisor(&self) -> Result<burrow_vmm::Hypervisor, Status> {
        burrow_vmm::Hypervisor::from_record(&self.hypervisor).ok_or_else(|| {
            Status::failed_precondition(format!(
                "snapshot {} was taken under {:?}, which this build does not know",
                self.id, self.hypervisor
            ))
        })
    }

    fn layout(&self) -> Result<burrow_vmm::Layout, Status> {
        self.hypervisor().map(burrow_vmm::Hypervisor::layout)
    }

    /// `base` with the machine it holds, which a restore cannot change.
    pub fn resources(&self, base: common::ResourcePolicy) -> common::ResourcePolicy {
        common::ResourcePolicy {
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            disk_mib: self.disk_mib,
            max_mem_mib: self.max_mem_mib,
            boot_mem_mib: self.boot_mem_mib,
            ..base
        }
    }

    fn to_proto(&self) -> common::Snapshot {
        common::Snapshot {
            id: self.id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            template: self.template.clone(),
            // The orchestrator stamps this from its own view of the fleet.
            node_id: String::new(),
            resources: Some(self.resources(Default::default())),
            created_at_unix_ms: self.created_unix_ms,
            size_bytes: self.size_bytes,
            expires_at_unix_ms: self.expires_at_ms,
            is_durable: self.is_durable,
            arch: self.arch.clone(),
            hypervisor_version: self.hypervisor_version.clone(),
            cpu: self.cpu.fingerprint(),
            hypervisor: self
                .hypervisor()
                .map_or_else(|_| self.hypervisor.clone(), |h| h.to_string()),
            inspection_root_fingerprint: self.inspection_root.clone(),
        }
    }
}

/// Object keys of a snapshot's files in the store.
/// The memory image a snapshot is made of. A backend whose memory lives
/// inside a host-bound state file has none to chunk, share or serve, so it
/// cannot take or restore named snapshots.
fn memory_file(layout: burrow_vmm::Layout) -> Result<&'static str, Status> {
    layout.memory.ok_or_else(|| {
        Status::failed_precondition(
            "this hypervisor keeps guest memory inside its saved state; it cannot snapshot",
        )
    })
}

fn remote_key(id: &str, file: &str) -> String {
    format!("snapshots/{id}/{file}")
}

fn blob_key(digest: &str) -> String {
    format!("blobs/{digest}")
}

fn index_key(id: &str, file: &str) -> String {
    remote_key(id, &format!("{file}.index.json"))
}

/// One command log's index, beside the images' so the chunk sweep finds it.
fn log_index_key(id: &str, name: &str) -> String {
    index_key(id, &format!("{COMMAND_LOGS}/{name}"))
}

/// The names of the command logs a stored snapshot carries.
fn log_names_key(id: &str) -> String {
    remote_key(id, &format!("{COMMAND_LOGS}.json"))
}

/// What [`log_names_key`] holds; none when it is absent, as it is for an
/// upload that did not get that far.
async fn remote_log_names(
    remote: &crate::objstore::ObjectStore,
    id: &str,
) -> Result<Vec<String>, Status> {
    let key = log_names_key(id);
    let Some(bytes) = remote.get_bytes(&key).await? else {
        return Ok(Vec::new());
    };
    let names: Vec<String> = serde_json::from_slice(&bytes)
        .map_err(|err| Status::data_loss(format!("{key} is unreadable: {err}")))?;
    Ok(names
        .into_iter()
        .filter(|name| name.ends_with(".log") && !name.contains('/'))
        .collect())
}

/// Removes a snapshot's objects from the store. Blobs are left, since other
/// snapshots may share them.
///
/// Manifest first, so a fetch racing this sees nothing rather than a manifest
/// naming files that are going. Every backend's names, since a snapshot whose
/// local manifest is gone says nothing about which one took it. A delete of an
/// object that is not there is not an error.
async fn delete_remote(remote: &crate::objstore::ObjectStore, id: &str) -> Result<(), Status> {
    remote.delete(&remote_key(id, MANIFEST)).await?;
    for name in remote_log_names(remote, id).await? {
        remote.delete(&log_index_key(id, &name)).await?;
    }
    remote.delete(&log_names_key(id)).await?;
    for layout in burrow_vmm::Hypervisor::ALL.map(burrow_vmm::Hypervisor::layout) {
        remote.delete(&remote_key(id, layout.state)).await?;
        for file in layout
            .memory
            .into_iter()
            .chain([crate::rootdisk::ROOT_DISK])
        {
            remote.delete(&index_key(id, file)).await?;
        }
    }
    Ok(())
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
    blobs: std::sync::Arc<crate::blobs::BlobStore>,
    remote: Option<crate::objstore::ObjectStore>,
    /// What each hypervisor this node runs reports, recorded on the snapshots
    /// it takes.
    versions: std::sync::Arc<HashMap<burrow_vmm::Hypervisor, String>>,
    /// Memory images of fetched snapshots still arriving, by snapshot id.
    hydrators: std::sync::Arc<std::sync::Mutex<HashMap<String, Arc<Hydrator>>>>,
    /// Held across a fetch, so two creates from one remote snapshot fetch it
    /// once rather than racing to rename the same directory into place.
    fetching: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// Held by a delete, and by an upload while it publishes the remote
    /// manifest. Without it a delete landing mid-upload found nothing in the
    /// store, and the upload then wrote a manifest for a snapshot already
    /// gone: listed from the store with no node holding it, and every later
    /// delete of it answered that there was no such snapshot.
    publishing: std::sync::Arc<tokio::sync::Mutex<()>>,
}

/// Everything a create needs from the sandbox it is snapshotting, gathered
/// under the sandbox's vm lock so a suspend cannot move it half way through.
pub struct Staged {
    pub sandbox_id: String,
    pub template: String,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub boot_mem_mib: u32,
    pub max_mem_mib: u32,
    pub disk_mib: u32,
    pub hypervisor: burrow_vmm::Hypervisor,
    /// Memory files in the staging directory, oldest first.
    pub chain: Vec<String>,
    /// The inspection root the source's guest trusted, if it was inspected.
    pub inspection_root: String,
}

impl SnapshotStore {
    pub fn new(
        data_dir: &Path,
        remote: Option<crate::objstore::ObjectStore>,
        versions: HashMap<burrow_vmm::Hypervisor, String>,
    ) -> Self {
        Self {
            root: data_dir.join("snapshots"),
            blobs: std::sync::Arc::new(crate::blobs::BlobStore::new(data_dir)),
            remote,
            versions: std::sync::Arc::new(versions),
            hydrators: Default::default(),
            fetching: Default::default(),
            publishing: Default::default(),
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
        flatten(&dir, &staged.chain, staged.hypervisor.layout()).await?;

        let size_bytes = directory_size(&dir).await;
        let manifest = Manifest {
            format: MANIFEST_FORMAT,
            id: id.to_string(),
            sandbox_id: staged.sandbox_id,
            template: staged.template,
            vcpus: staged.vcpus,
            mem_mib: staged.mem_mib,
            boot_mem_mib: staged.boot_mem_mib,
            max_mem_mib: staged.max_mem_mib,
            disk_mib: staged.disk_mib,
            created_unix_ms: burrow_common::unix_now_ms(),
            size_bytes,
            expires_at_ms: match expiration_secs {
                0 => 0,
                secs => burrow_common::unix_now_ms() + secs as i64 * 1000,
            },
            expiration_secs,
            is_evicted: false,
            arch: std::env::consts::ARCH.to_string(),
            hypervisor_version: self
                .versions
                .get(&staged.hypervisor)
                .cloned()
                .unwrap_or_default(),
            hypervisor: staged.hypervisor.to_string(),
            cpu: crate::cpuid::host().clone(),
            is_durable: false,
            kernel_digest: String::new(),
            rootfs_digest: String::new(),
            inspection_root: staged.inspection_root,
        };
        write_manifest(&dir, &manifest).await?;
        // Every file on the disk, then the directory, before the rename that
        // makes it a snapshot: the memory image and the disk are copies and
        // links made moments ago, and a snapshot reported taken must not be
        // one a power cut can tear.
        crate::fsync::tree(&dir)
            .await
            .map_err(|err| Status::internal(format!("syncing the snapshot to disk: {err}")))?;

        let live = self.dir(id);
        // An id is generated per create, so a collision means a retry of a
        // create that already finished; the newer bytes win.
        let _ = tokio::fs::remove_dir_all(&live).await;
        tokio::fs::rename(&dir, &live)
            .await
            .map_err(|err| Status::internal(format!("publishing the snapshot: {err}")))?;
        // And the rename itself, which lives in the store's directory.
        crate::fsync::dir(&self.root)
            .await
            .map_err(|err| Status::internal(format!("syncing the snapshot store: {err}")))?;
        // Behind the response: the caller has its snapshot the moment it is on
        // this node's disk, and the upload is what makes it outlive the node.
        if self.remote.is_some() {
            let store = self.clone();
            let id = id.to_string();
            tokio::spawn(async move {
                if let Err(err) = store.upload(&id).await {
                    tracing::warn!(snapshot = id, %err, "snapshot upload failed; it stays node-local");
                }
            });
        }
        Ok(manifest.to_proto())
    }

    /// Copies a snapshot to the object store and marks it durable.
    ///
    /// Blobs first, then the state, then the manifest: the remote manifest is
    /// the only thing a fetching node reads to decide a snapshot is there, so
    /// it is written last and a crash anywhere before it leaves nothing that
    /// reads as complete.
    async fn upload(&self, id: &str) -> Result<(), Status> {
        let Some(remote) = &self.remote else {
            return Ok(());
        };
        let dir = self.dir(id);
        let mut manifest = self.manifest(id).await?;
        let layout = manifest.layout()?;
        let started = std::time::Instant::now();

        let kernel_digest = put_blob(remote, &dir.join(TEMPLATE_KERNEL)).await?;
        // The image goes once for every snapshot of it.
        let image = crate::rootdisk::image_of(&self.blobs, &dir.join(TEMPLATE_ROOTFS)).await?;
        crate::rootdisk::upload_image(remote, &image).await?;
        let rootfs_digest = image.digest.clone();
        remote
            .put_file(&remote_key(id, layout.state), &dir.join(layout.state))
            .await?;
        // As chunks, so the memory image can be served page by page on a node
        // restoring it, and so what the snapshot shares with its sandbox's own
        // stored state, and its disk with its image, is stored once.
        let memory = memory_file(layout)?;
        let index = crate::chunks::put_image(
            remote,
            &dir,
            &[memory.to_string()],
            None,
            &Default::default(),
        )
        .await?;
        let json = serde_json::to_vec(&index)
            .map_err(|err| Status::internal(format!("encoding an index: {err}")))?;
        remote.put_bytes(&index_key(id, memory), json).await?;
        let disk = crate::rootdisk::ROOT_DISK;
        let index =
            crate::chunks::put_disk(remote, &dir.join(disk), Some(&image), &Default::default())
                .await?;
        let json = serde_json::to_vec(&index)
            .map_err(|err| Status::internal(format!("encoding an index: {err}")))?;
        remote.put_bytes(&index_key(id, disk), json).await?;
        let logs = dir.join(COMMAND_LOGS);
        let names = log_names(&logs);
        for name in &names {
            let index = crate::chunks::put_image(
                remote,
                &logs,
                std::slice::from_ref(name),
                None,
                &Default::default(),
            )
            .await?;
            let json = serde_json::to_vec(&index)
                .map_err(|err| Status::internal(format!("encoding an index: {err}")))?;
            remote.put_bytes(&log_index_key(id, name), json).await?;
        }
        let json = serde_json::to_vec(&names)
            .map_err(|err| Status::internal(format!("encoding log names: {err}")))?;
        remote.put_bytes(&log_names_key(id), json).await?;
        manifest.kernel_digest = kernel_digest;
        manifest.rootfs_digest = rootfs_digest;
        manifest.is_durable = true;
        let json = serde_json::to_vec_pretty(&manifest)
            .map_err(|err| Status::internal(format!("encoding the manifest: {err}")))?;
        let _publishing = self.publishing.lock().await;
        // Deleted while uploading: what went up is dropped rather than
        // published, since a manifest written now would resurrect it.
        if read_manifest(&dir).await.is_none() {
            delete_remote(remote, id).await?;
            tracing::info!(
                snapshot = id,
                "snapshot deleted while uploading; not published"
            );
            return Ok(());
        }
        remote.put_bytes(&remote_key(id, MANIFEST), json).await?;
        write_manifest(&dir, &manifest).await?;
        tracing::info!(
            snapshot = id,
            size_bytes = manifest.size_bytes,
            took_ms = started.elapsed().as_millis() as u64,
            "snapshot uploaded to the object store"
        );
        Ok(())
    }

    /// Brings a snapshot held only in the object store onto this node.
    ///
    /// Staged and renamed like a create, so a failed fetch leaves a directory
    /// the orphan sweep removes rather than a snapshot that lists but does not
    /// restore. Kernel and image are verified against the digests the manifest
    /// carries and adopted into the blob store, so a second snapshot of the
    /// same template costs the state alone, and a root disk costs only the
    /// chunks it changed from its image.
    async fn fetch(&self, id: &str) -> Result<(), Status> {
        let Some(remote) = &self.remote else {
            return Err(Status::not_found(format!("no snapshot {id} on this node")));
        };
        let Some(bytes) = remote.get_bytes(&remote_key(id, MANIFEST)).await? else {
            return Err(Status::not_found(format!(
                "no snapshot {id} on this node or in the object store"
            )));
        };
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|err| {
            Status::internal(format!(
                "snapshot {id} in the object store: bad manifest: {err}"
            ))
        })?;
        if manifest.format != MANIFEST_FORMAT || !manifest.is_durable {
            return Err(Status::failed_precondition(format!(
                "snapshot {id} in the object store was written by another build or is incomplete"
            )));
        }
        let layout = manifest.layout()?;
        let started = std::time::Instant::now();
        let dir = self.begin(id).await?;
        let memory = match self.fetch_into(remote, &manifest, &dir).await {
            Ok(memory) => memory,
            Err(err) => {
                self.abandon(id).await;
                return Err(err);
            }
        };
        // Synced as a published snapshot is, before the manifest that makes
        // it one: a fetch is a write like any other, and a power cut must not
        // leave a manifest naming files still in the page cache.
        crate::fsync::tree(&dir)
            .await
            .map_err(|err| Status::internal(format!("syncing the fetched snapshot: {err}")))?;
        write_manifest(&dir, &manifest).await?;
        let live = self.dir(id);
        let _ = tokio::fs::remove_dir_all(&live).await;
        tokio::fs::rename(&dir, &live)
            .await
            .map_err(|err| Status::internal(format!("publishing the fetched snapshot: {err}")))?;
        crate::fsync::dir(&self.root)
            .await
            .map_err(|err| Status::internal(format!("syncing the snapshot store: {err}")))?;
        // Begun at the path it will be served from: a hydrator names its file
        // by path, for the links it hands out. Readers of a snapshot all
        // arrive through `fetching`, which this call still holds.
        let path = live.join(memory_file(layout)?);
        let hydrator = Hydrator::begin(remote.clone(), memory, &path)
            .map_err(|err| Status::internal(format!("preparing {}: {err}", path.display())))?;
        hydrator.start();
        self.hydrators
            .lock()
            .unwrap()
            .insert(id.to_string(), hydrator);
        tracing::info!(
            snapshot = id,
            size_bytes = manifest.size_bytes,
            took_ms = started.elapsed().as_millis() as u64,
            "snapshot fetched from the object store"
        );
        Ok(())
    }

    /// The memory image of a snapshot that is still arriving, picking up a
    /// fill a restart interrupted.
    fn hydrator(&self, id: &str, memory: &str) -> Result<Option<Arc<Hydrator>>, Status> {
        let mut hydrators = self.hydrators.lock().unwrap();
        if let Some(hydrator) = hydrators.get(id) {
            if !hydrator.is_complete() {
                return Ok(Some(Arc::clone(hydrator)));
            }
            hydrators.remove(id);
            return Ok(None);
        }
        let Some(remote) = &self.remote else {
            return Ok(None);
        };
        let path = self.dir(id).join(memory);
        match Hydrator::resume(remote.clone(), &path) {
            None => Ok(None),
            Some(Ok(hydrator)) => {
                hydrator.start();
                hydrators.insert(id.to_string(), Arc::clone(&hydrator));
                Ok(Some(hydrator))
            }
            Some(Err(err)) => Err(Status::internal(format!(
                "resuming the fetch of snapshot {id}'s memory: {err}"
            ))),
        }
    }

    /// Fetches a snapshot from the store unless this node already has it.
    async fn ensure_local(&self, id: &str) -> Result<(), Status> {
        let _fetching = self.fetching.lock().await;
        if read_manifest(&self.dir(id)).await.is_none() {
            self.fetch(id).await?;
        }
        Ok(())
    }

    /// Fetches everything a restore needs before it can start, returning the
    /// memory image's index, which arrives behind the guest.
    async fn fetch_into(
        &self,
        remote: &crate::objstore::ObjectStore,
        manifest: &Manifest,
        dir: &Path,
    ) -> Result<crate::chunks::ImageIndex, Status> {
        let id = &manifest.id;
        self.fetch_blob(remote, &manifest.kernel_digest, &dir.join(TEMPLATE_KERNEL))
            .await?;
        let image = crate::rootdisk::fetch_image(
            remote,
            &self.blobs,
            &self.templates_dir(),
            &manifest.rootfs_digest,
        )
        .await?;
        tokio::fs::hard_link(&image.path, dir.join(TEMPLATE_ROOTFS))
            .await
            .map_err(|err| Status::internal(format!("linking the image: {err}")))?;
        let missing = |file: &str| {
            Status::not_found(format!(
                "snapshot {id} is missing {file} in the object store"
            ))
        };
        let layout = manifest.layout()?;
        let file = layout.state;
        if remote
            .get_to_file(&remote_key(id, file), &dir.join(file))
            .await?
            .is_none()
        {
            return Err(missing(file));
        }
        for name in remote_log_names(remote, id).await? {
            let index = read_index(remote, &log_index_key(id, &name))
                .await?
                .ok_or_else(|| missing(&name))?;
            create_private_dir(&dir.join(COMMAND_LOGS))
                .map_err(|err| Status::internal(format!("fetching snapshot {id}'s logs: {err}")))?;
            crate::chunks::get_image(remote, &index, &dir.join(COMMAND_LOGS).join(&name)).await?;
        }
        let disk = crate::rootdisk::ROOT_DISK;
        let index = read_index(remote, &index_key(id, disk))
            .await?
            .ok_or_else(|| missing(disk))?;
        crate::rootdisk::materialise(remote, &index, Some(&image), &dir.join(disk)).await?;
        let memory_file = memory_file(layout)?;
        read_index(remote, &index_key(id, memory_file))
            .await?
            .ok_or_else(|| missing(memory_file))
    }

    /// Brings a blob onto this node at `dest`: linked from the node's blob
    /// store when it is there, fetched and verified when it is not.
    pub async fn fetch_blob(
        &self,
        remote: &crate::objstore::ObjectStore,
        digest: &str,
        dest: &Path,
    ) -> Result<(), Status> {
        let digest = crate::blobs::Digest::parse(digest)
            .ok_or_else(|| Status::internal(format!("{digest:?} is not a blob digest")))?;
        if self.blobs.has(&digest).await {
            return self
                .blobs
                .materialise(&digest, dest)
                .await
                .map_err(|err| Status::internal(format!("linking blob {digest}: {err}")));
        }
        if remote
            .get_to_file(&blob_key(digest.as_str()), dest)
            .await?
            .is_none()
        {
            return Err(Status::not_found(format!(
                "blob {digest} is missing from the object store"
            )));
        }
        let actual = crate::blobs::hash_file(dest)
            .await
            .map_err(|err| Status::internal(format!("hashing fetched blob {digest}: {err}")))?;
        if actual != digest {
            return Err(Status::data_loss(format!(
                "blob {digest} from the object store hashed as {actual}"
            )));
        }
        let _ = self.blobs.insert(dest).await;
        Ok(())
    }

    /// Every chunk digest the stored snapshots' indexes reference, and into
    /// `images` the images their root disks were cloned from.
    pub async fn remote_chunk_refs(
        &self,
        out: &mut std::collections::HashSet<String>,
        images: &mut std::collections::HashSet<String>,
    ) -> Result<(), Status> {
        let Some(remote) = &self.remote else {
            return Ok(());
        };
        for key in remote.list("snapshots/").await? {
            if key.ends_with(&format!("/{MANIFEST}")) {
                if let Some(bytes) = remote.get_bytes(&key).await?
                    && let Ok(manifest) = serde_json::from_slice::<Manifest>(&bytes)
                {
                    images.insert(manifest.rootfs_digest);
                }
                continue;
            }
            if !key.ends_with(".index.json") {
                continue;
            }
            if let Some(index) = read_index(remote, &key).await? {
                out.extend(index.digests().map(str::to_string));
            }
        }
        Ok(())
    }

    /// The node's blob store, which holds the images root disks are cloned
    /// from.
    pub fn blobs(&self) -> &crate::blobs::BlobStore {
        &self.blobs
    }

    /// Where the node's templates are, whose images a root disk may have
    /// been cloned from.
    pub fn templates_dir(&self) -> PathBuf {
        self.root.with_file_name("images")
    }

    /// Snapshots in the object store, whether or not this node holds them.
    ///
    /// A node without a store refuses rather than answering empty: the
    /// orchestrator forgets durable snapshots a listing leaves out, and an
    /// empty answer from here would read as a store that holds nothing.
    pub async fn list_remote(&self) -> Result<Vec<common::Snapshot>, Status> {
        let Some(remote) = &self.remote else {
            return Err(Status::failed_precondition(
                "this node has no object store configured",
            ));
        };
        let mut out = Vec::new();
        for key in remote.list("snapshots/").await? {
            let Some(rest) = key.strip_prefix("snapshots/") else {
                continue;
            };
            let Some((id, file)) = rest.split_once('/') else {
                continue;
            };
            if file != MANIFEST || validate_id(id).is_err() {
                continue;
            }
            let Some(bytes) = remote.get_bytes(&key).await? else {
                continue;
            };
            if let Ok(manifest) = serde_json::from_slice::<Manifest>(&bytes)
                && manifest.format == MANIFEST_FORMAT
                && manifest.is_durable
            {
                out.push(manifest.to_proto());
            }
        }
        Ok(out)
    }

    /// Ids of the snapshots here whose upload has finished.
    pub async fn durable_ids(&self) -> Vec<String> {
        self.list(None)
            .await
            .into_iter()
            .filter(|snapshot| snapshot.is_durable)
            .map(|snapshot| snapshot.id)
            .collect()
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

    /// The manifest of a snapshot a create is about to restore, fetching the
    /// snapshot from the object store first when this node does not hold it.
    /// Only a create pays that: a read of a snapshot stays a read.
    pub async fn manifest_for_restore(&self, id: &str) -> Result<Manifest, Status> {
        validate_id(id)?;
        self.ensure_local(id).await?;
        self.manifest(id).await
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

    /// Removes a snapshot here and from the object store.
    ///
    /// Remote first: a delete that removed the local copy and then failed
    /// remotely would leave a snapshot the node no longer lists but any node
    /// can still fetch. Blobs are left, since other snapshots may share them.
    pub async fn delete(&self, id: &str) -> Result<(), Status> {
        validate_id(id)?;
        let _publishing = self.publishing.lock().await;
        let dir = self.dir(id);
        let is_local = read_manifest(&dir).await.is_some();
        let mut is_remote = false;
        if let Some(remote) = &self.remote
            && remote.exists(&remote_key(id, MANIFEST)).await?
        {
            is_remote = true;
            delete_remote(remote, id).await?;
        }
        if let Some(hydrator) = self.hydrators.lock().unwrap().remove(id) {
            for layout in burrow_vmm::Hypervisor::ALL.map(burrow_vmm::Hypervisor::layout) {
                if let Some(memory) = layout.memory {
                    hydrator.detach(&dir.join(memory));
                }
            }
        }
        if !is_local && !is_remote {
            return Err(Status::not_found(format!("no snapshot {id} on this node")));
        }
        if is_local {
            tokio::fs::remove_dir_all(&dir)
                .await
                .map_err(|err| Status::internal(format!("removing snapshot: {err}")))?;
        }
        tracing::info!(snapshot = id, is_remote, "snapshot deleted");
        Ok(())
    }

    /// Copies a snapshot into a sandbox's working directory.
    ///
    /// The same shape as forking a sandbox, and for the same reason: Firecracker
    /// requires a restore's resource paths to match what they were at snapshot
    /// time, so the files have to be under the sandbox's own directory with the
    /// names they had. Read-only artifacts are linked; what the guest writes is
    /// copied, sparsely and by reflink where the filesystem allows it.
    ///
    /// A memory image still arriving is linked rather than copied, and handed
    /// back so the restore serves it through the same fill: the link shares
    /// the inode, so every byte the fill writes lands in both.
    pub async fn stage_into(
        &self,
        id: &str,
        dest: &Path,
        logs: &Path,
    ) -> Result<(Vec<String>, Option<Arc<Hydrator>>), Status> {
        validate_id(id)?;
        let dir = self.dir(id);
        self.ensure_local(id).await?;
        let manifest = self.manifest(id).await?;
        let layout = manifest.layout()?;
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
        tokio::fs::copy(dir.join(layout.state), dest.join(layout.state))
            .await
            .map_err(|err| io(layout.state, err))?;

        let disk = crate::rootdisk::ROOT_DISK;
        crate::rootdisk::clone(&dir.join(disk), &dest.join(disk))
            .await
            .map_err(|err| io(disk, err))?;
        let held = dir.join(COMMAND_LOGS);
        let names = log_names(&held);
        if !names.is_empty() {
            create_private_dir(logs).map_err(|err| io(COMMAND_LOGS, err))?;
        }
        for name in names {
            tokio::fs::copy(held.join(&name), logs.join(&name))
                .await
                .map_err(|err| io(&name, err))?;
        }
        let memory = memory_file(layout)?;
        let arriving = match self.hydrator(id, memory)? {
            Some(hydrator) => hydrator
                .link_to(&dest.join(memory))
                .map_err(|err| io(memory, err))?
                .then_some(hydrator),
            None => None,
        };
        if arriving.is_none()
            && !tokio::fs::try_exists(dest.join(memory))
                .await
                .unwrap_or(false)
        {
            crate::rootdisk::clone(&dir.join(memory), &dest.join(memory))
                .await
                .map(drop)
                .map_err(|err| io(memory, err))?;
        }
        Ok((vec![memory.to_string()], arriving))
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
        manifest.expires_at_ms =
            burrow_common::unix_now_ms() + manifest.expiration_secs as i64 * 1000;
        if let Err(err) = write_manifest(&self.dir(id), &manifest).await {
            tracing::warn!(snapshot = id, %err, "could not refresh a snapshot's expiry");
        }
    }

    /// Removes directories in the store that hold no manifest at all.
    ///
    /// The publish is a rename, so a snapshot either has its manifest or was
    /// never published; what is left here is a staging directory a crash
    /// orphaned, and it holds a memory image and a root disk that nothing
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
            if staging && !is_older_than(&entry.path(), STAGING_ORPHAN_AFTER).await {
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
        let now_ms = burrow_common::unix_now_ms();
        let mut swept = Vec::new();
        for snapshot in self.list(None).await {
            let Ok(manifest) = self.manifest(&snapshot.id).await else {
                continue;
            };
            if manifest.expires_at_ms == 0 || manifest.expires_at_ms > now_ms {
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
                Ok(manifest) if manifest.is_evicted => continue,
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
        manifest.is_evicted = true;
        write_manifest(&self.dir(id), &manifest).await
    }
}

/// Puts a file in the store under its digest unless it is already there,
/// returning the digest.
pub async fn put_blob(
    remote: &crate::objstore::ObjectStore,
    path: &Path,
) -> Result<String, Status> {
    let digest = crate::blobs::hash_file(path)
        .await
        .map_err(|err| Status::internal(format!("hashing {}: {err}", path.display())))?;
    let key = blob_key(digest.as_str());
    if !remote.exists(&key).await? {
        remote.put_file(&key, path).await?;
    }
    Ok(digest.to_string())
}

pub async fn read_index(
    remote: &crate::objstore::ObjectStore,
    key: &str,
) -> Result<Option<crate::chunks::ImageIndex>, Status> {
    let Some(bytes) = remote.get_bytes(key).await? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|err| Status::data_loss(format!("index {key} is unreadable: {err}")))
}

/// Whether a path was last written longer ago than `age`.
///
/// Unreadable metadata reads as "recent", so a directory is never collected on
/// the strength of a failed stat.
async fn is_older_than(path: &Path, age: std::time::Duration) -> bool {
    let Ok(meta) = tokio::fs::metadata(path).await else {
        return false;
    };
    meta.modified()
        .ok()
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|elapsed| elapsed > age)
}

/// Merges the staged memory chain down to the single image a snapshot holds.
async fn flatten(dir: &Path, chain: &[String], layout: burrow_vmm::Layout) -> Result<(), Status> {
    if chain.is_empty() {
        return Err(Status::failed_precondition(
            "sandbox has no state to snapshot",
        ));
    }
    let target = dir.join(memory_file(layout)?);
    if chain.len() > 1 {
        let paths: Vec<PathBuf> = chain.iter().map(|name| dir.join(name)).collect();
        let target = target.clone();
        tokio::task::spawn_blocking(move || burrow_vmm::merge_chain(&paths, &target))
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

/// Writes a snapshot's manifest, atomically.
///
/// Via a temporary and a rename, the same way a publish stages a whole
/// directory and renames it into place: the manifest is the marker that says a
/// directory *is* a snapshot, so a crash part way through overwriting one (a
/// `touch` refreshing a TTL, a `release` clearing retention) would leave a
/// truncated file, and [`read_manifest`] reads that as "not a snapshot",
/// which is exactly what [`SnapshotStore::collect_orphans`] deletes.
async fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<(), Status> {
    let json = serde_json::to_vec_pretty(manifest)
        .map_err(|err| Status::internal(format!("encoding the manifest: {err}")))?;
    let temp = dir.join(format!(".{MANIFEST}.{}.tmp", std::process::id()));
    // Synced before and after the rename, so a power cut leaves the old
    // manifest or the new one, never an empty file that reads as no snapshot.
    crate::fsync::replace(&dir.join(MANIFEST), &temp, json)
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
/// apparent length: the memory image and the root disk are both sparse, and
/// their apparent size is the guest's memory rather than the node's disk.
/// The log files in `dir`, which may not exist.
fn log_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".log"))
        .collect();
    names.sort();
    names
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

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
            mem_mib: 3072,
            boot_mem_mib: 1024,
            max_mem_mib: 16384,
            disk_mib: 2048,
            created_unix_ms: burrow_common::unix_from_rfc3339(created_at).unwrap_or(0) * 1_000,
            size_bytes: 12_345,
            expires_at_ms: 0,
            expiration_secs: 0,
            is_evicted: false,
            arch: String::new(),
            hypervisor_version: String::new(),
            hypervisor: String::new(),
            cpu: Default::default(),
            is_durable: false,
            kernel_digest: String::new(),
            rootfs_digest: String::new(),
            inspection_root: String::new(),
        }
    }

    fn store() -> (SnapshotStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "burrow-snapshots-{}-{}",
            std::process::id(),
            burrow_common::SnapshotId::generate()
        ));
        (SnapshotStore::new(&dir, None, HashMap::new()), dir)
    }

    /// The shape is the one thing a restore cannot rediscover, so it has to
    /// survive the round trip exactly.
    #[tokio::test]
    async fn a_manifest_round_trips_through_its_file() {
        let (store, root) = store();
        let dir = store.begin("snap_abc123").await.unwrap();
        let mut written = manifest("snap_abc123", "sbx_a", "2026-09-02T10:00:00Z");
        written.expires_at_ms = 1_800_000_000_000;
        written.expiration_secs = 3_600;
        write_manifest(&dir, &written).await.unwrap();

        let read = read_manifest(&dir).await.expect("a manifest");
        assert_eq!(read.id, "snap_abc123");
        assert_eq!(read.sandbox_id, "sbx_a");
        assert_eq!((read.vcpus, read.mem_mib, read.disk_mib), (2, 3072, 2048));
        assert_eq!((read.boot_mem_mib, read.max_mem_mib), (1024, 16384));
        assert_eq!(read.expires_at_ms, 1_800_000_000_000);
        assert_eq!(read.expiration_secs, 3_600);

        let proto = read.to_proto();
        assert_eq!(proto.expires_at_unix_ms, 1_800_000_000_000);
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
        assert!(validate_id(&burrow_common::SnapshotId::generate().to_string()).is_ok());
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
        assert!(store.manifest("snap_ddd1").await.unwrap().is_evicted);

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
        let now_ms = burrow_common::unix_now_ms();
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
        for (id, expires_at_ms) in [("snap_ccc1", now_ms - 1), ("snap_ccc2", now_ms + 3_600_000)] {
            let mut manifest = store.manifest(id).await.unwrap();
            manifest.expires_at_ms = expires_at_ms;
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
        assert!(refreshed.expires_at_ms >= now_ms + 3_600_000);
        // A snapshot with no TTL is not given one by being used.
        store.touch("snap_ccc3").await;
        assert_eq!(store.manifest("snap_ccc3").await.unwrap().expires_at_ms, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A delete that lands while the snapshot is uploading finds no manifest
    /// in the store yet. The upload used to write one anyway, publishing a
    /// snapshot that was gone, which every replica then listed from the store.
    #[tokio::test]
    async fn a_snapshot_deleted_while_uploading_is_not_published() {
        let remote = crate::objstore::fake::store(true).await;
        let root = std::env::temp_dir().join(format!(
            "burrow-snapshots-upload-{}",
            burrow_common::SnapshotId::generate()
        ));
        let store = SnapshotStore::new(&root, Some(remote.clone()), HashMap::new());
        let id = burrow_common::SnapshotId::generate().to_string();
        let dir = store.dir(&id);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let written = manifest(&id, "sbx_a", "2026-09-02T10:00:00Z");
        let layout = written.layout().unwrap();
        for file in [
            TEMPLATE_KERNEL,
            TEMPLATE_ROOTFS,
            layout.state,
            layout.memory.unwrap(),
            crate::rootdisk::ROOT_DISK,
        ] {
            tokio::fs::write(dir.join(file), vec![7u8; 8192])
                .await
                .unwrap();
        }
        write_manifest(&dir, &written).await.unwrap();

        // Held as a delete would hold it, so the upload stops just short of
        // publishing, which is where the delete has to land to race it.
        let held = store.publishing.lock().await;
        let upload = tokio::spawn({
            let store = store.clone();
            let id = id.clone();
            async move { store.upload(&id).await }
        });
        while !remote
            .exists(&index_key(&id, crate::rootdisk::ROOT_DISK))
            .await
            .unwrap()
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        tokio::fs::remove_dir_all(&dir).await.unwrap();
        drop(held);
        upload.await.unwrap().unwrap();

        assert!(!remote.exists(&remote_key(&id, MANIFEST)).await.unwrap());
        assert!(!remote.exists(&remote_key(&id, layout.state)).await.unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A sandbox restored from a snapshot on another node remembers the
    /// commands its source ran, so their logs go through the store with it.
    #[tokio::test]
    async fn a_stored_snapshot_brings_its_command_logs() {
        let remote = crate::objstore::fake::store(true).await;
        let scratch = std::env::temp_dir().join(format!(
            "burrow-snapshots-logs-{}",
            burrow_common::SnapshotId::generate()
        ));
        let taken = SnapshotStore::new(&scratch.join("a"), Some(remote.clone()), HashMap::new());
        let id = burrow_common::SnapshotId::generate().to_string();
        let dir = taken.dir(&id);
        tokio::fs::create_dir_all(dir.join(COMMAND_LOGS))
            .await
            .unwrap();
        let written = manifest(&id, "sbx_a", "2026-09-02T10:00:00Z");
        let layout = written.layout().unwrap();
        for file in [
            TEMPLATE_KERNEL,
            TEMPLATE_ROOTFS,
            layout.state,
            layout.memory.unwrap(),
            crate::rootdisk::ROOT_DISK,
        ] {
            tokio::fs::write(dir.join(file), vec![7u8; 8192])
                .await
                .unwrap();
        }
        let log = b"a whole command log".to_vec();
        tokio::fs::write(dir.join(COMMAND_LOGS).join("cmd_1.0.log"), &log)
            .await
            .unwrap();
        write_manifest(&dir, &written).await.unwrap();
        taken.upload(&id).await.unwrap();

        let elsewhere =
            SnapshotStore::new(&scratch.join("b"), Some(remote.clone()), HashMap::new());
        let (dest, logs) = (scratch.join("sandbox"), scratch.join("logs"));
        tokio::fs::create_dir_all(&dest).await.unwrap();
        elsewhere.stage_into(&id, &dest, &logs).await.unwrap();
        assert_eq!(
            tokio::fs::read(logs.join("cmd_1.0.log")).await.unwrap(),
            log
        );

        delete_remote(&remote, &id).await.unwrap();
        assert!(
            !remote
                .exists(&log_index_key(&id, "cmd_1.0.log"))
                .await
                .unwrap()
        );
        assert!(!remote.exists(&log_names_key(&id)).await.unwrap());
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// A snapshot is reported taken only once every file in it, the manifest
    /// included, is on the disk, then its directory, then the store directory
    /// the rename published it into.
    #[tokio::test]
    async fn a_published_snapshot_is_synced_file_by_file_then_by_directory() {
        let (store, root) = store();
        let id = burrow_common::SnapshotId::generate().to_string();
        let dir = store.begin(&id).await.unwrap();
        let layout = burrow_vmm::Hypervisor::Firecracker.layout();
        let memory = layout.memory.unwrap();
        for file in [
            TEMPLATE_KERNEL,
            TEMPLATE_ROOTFS,
            layout.state,
            memory,
            crate::rootdisk::ROOT_DISK,
        ] {
            tokio::fs::write(dir.join(file), b"bytes").await.unwrap();
        }
        let staged = Staged {
            sandbox_id: "sbx_a".into(),
            template: "default".into(),
            vcpus: 1,
            mem_mib: 512,
            boot_mem_mib: 512,
            max_mem_mib: 512,
            disk_mib: 1024,
            hypervisor: burrow_vmm::Hypervisor::Firecracker,
            chain: vec![memory.to_string()],
            inspection_root: String::new(),
        };
        store.publish(&id, staged, 0).await.unwrap();

        use crate::fsync::Synced;
        let syncs = crate::fsync::record::under(&root);
        let staged_dir = store.staging(&id);
        let files: Vec<&Synced> = syncs
            .iter()
            .filter(
                |s| matches!(s, Synced::File(path) if path.parent() == Some(staged_dir.as_path())),
            )
            .collect();
        for name in [
            TEMPLATE_KERNEL,
            TEMPLATE_ROOTFS,
            layout.state,
            memory,
            crate::rootdisk::ROOT_DISK,
            MANIFEST,
        ] {
            assert!(
                files.contains(&&Synced::File(staged_dir.join(name))),
                "{name} was not synced: {syncs:?}"
            );
        }
        let position = |want: &Synced| syncs.iter().rposition(|s| s == want).unwrap();
        let staged_sync = position(&Synced::Dir(staged_dir.clone()));
        let root_sync = position(&Synced::Dir(store.root.clone()));
        let last_file = syncs
            .iter()
            .rposition(|s| matches!(s, Synced::File(_)))
            .unwrap();
        assert!(last_file < staged_sync, "{syncs:?}");
        assert!(staged_sync < root_sync, "{syncs:?}");
        assert!(store.dir(&id).join(MANIFEST).exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
