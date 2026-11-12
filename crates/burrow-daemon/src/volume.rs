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
//!
//! A writer that goes without unmounting, deleted, stopped, crashed or killed
//! with the node, leaves its last writes in the journal. A reader cannot
//! replay that, since its disk is read-only, so the node does before the
//! reader attaches: see [`VolumeStore::prepare`].
//!
//! With an object store the volume is uploaded there too ([`crate::volstore`])
//! and is held by one node at a time, so every claim on it is on the node
//! holding it and the rule above holds across the fleet.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use burrow_proto::common::v1 as common;
use serde::{Deserialize, Serialize};
use tonic::Status;

/// Ceiling on one volume, so a create cannot ask for the node's whole disk.
pub const MAX_SIZE_MIB: u64 = 1024 * 1024;
pub const MIN_SIZE_MIB: u64 = 1;

/// Volumes a sandbox mounts at most. They follow the sandbox's own disks
/// (`/dev/vda` its root, and `/dev/vdb` an overlay sandbox's scratch disk),
/// and the cap keeps their names to one letter, which is all the kernel's own
/// scheme gives without a second character.
pub const MAX_MOUNTS: usize = 8;

#[cfg(not(target_os = "macos"))]
const IMAGE: &str = "volume.ext4";
/// On a Mac a volume is a raw image the size of the volume, sparse until
/// written, which the macOS guest formats journaled HFS+ on its first mount:
/// macOS mounts no ext4. Not a shared directory over virtio-fs, which a
/// guest presents as a network volume and TCC keeps the agent out of without
/// an MDM grant.
#[cfg(target_os = "macos")]
const IMAGE: &str = "volume.img";
const META: &str = "volume.json";
/// Read-only copies of durable volumes other nodes hold, by name and
/// generation, for the sandboxes here that mount them read-only.
const READERS: &str = ".readers";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    pub size_mib: u64,
    pub created_at_ms: i64,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// The guest OS whose filesystem the image holds, from the first
    /// writable mount: ext4 from a Linux guest, NTFS from a Windows one,
    /// HFS+ from a macOS one. Empty until then.
    #[serde(default)]
    pub guest_os: String,
    /// Another node took the volume over while this one was away, so this
    /// copy is no longer the volume: never listed, claimed or uploaded, and
    /// removed once nothing holds it.
    #[serde(default)]
    pub is_lost: bool,
}

/// Who currently holds one volume.
///
/// Readers and a writer are mutually exclusive, so only one of the two is ever
/// populated.
#[derive(Default)]
struct Claim {
    writer: Option<String>,
    readers: std::collections::HashSet<String>,
    /// Who owned the image before a jailed sandbox was given write access to
    /// it, if anyone had to be displaced.
    ///
    /// A writable mount under the jailer has to be writable by the uid the VMM
    /// drops to, and the image is the volume's own inode rather than a copy of
    /// it, so that chown lands on storage every future sandbox will mount. It
    /// is put back the moment the claim goes, which makes the grant last
    /// exactly as long as the mount: see [`VolumeStore::remember_owner`].
    restore_owner: Option<(u32, u32)>,
    /// Readers attached over a journal nobody could replay, because a
    /// suspended writer still has the filesystem mounted. Replaying under
    /// them would move the disk beneath their caches, so it waits for them to
    /// go.
    is_stale: bool,
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
    /// Held across [`Self::prepare`], so a reader whose claim arrived while
    /// another was replaying the journal waits for the replay, and finds the
    /// image clean.
    preparing: Arc<tokio::sync::Mutex<()>>,
    object_store: Option<crate::objstore::ObjectStore>,
    node_id: Arc<std::sync::OnceLock<Arc<Mutex<String>>>>,
    /// Held across a capture and its upload, one per volume, so uploads land
    /// in the order their captures were taken.
    uploads: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl VolumeStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("volumes"),
            claims: Arc::new(Mutex::new(HashMap::new())),
            preparing: Arc::default(),
            object_store: None,
            node_id: Arc::default(),
            uploads: Arc::default(),
        }
    }

    pub fn with_object_store(self, store: Option<crate::objstore::ObjectStore>) -> Self {
        Self {
            object_store: store,
            ..self
        }
    }

    /// Where the node's id is once registration fills it in. A volume's
    /// manifest names its holder, so nothing is uploaded before then.
    pub fn bind_node_id(&self, node_id: Arc<Mutex<String>>) {
        let _ = self.node_id.set(node_id);
    }

    fn node_id(&self) -> String {
        self.node_id
            .get()
            .map(|id| id.lock().unwrap().clone())
            .unwrap_or_default()
    }

    /// Whether volumes here are kept in the object store.
    pub fn is_durable(&self) -> bool {
        self.object_store.is_some()
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Path of a volume's image, for attaching it as a drive.
    pub fn image(&self, name: &str) -> PathBuf {
        self.dir(name).join(IMAGE)
    }

    pub async fn create(
        &self,
        name: &str,
        size_mib: u64,
        labels: HashMap<String, String>,
    ) -> Result<common::Volume, Status> {
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
        let pending = dir.join(format!("{IMAGE}.building"));
        let _ = tokio::fs::remove_file(&pending).await;
        #[cfg(target_os = "macos")]
        tokio::fs::File::create(&pending)
            .await
            .map_err(|err| Status::internal(format!("volume image: {err}")))?
            .set_len(size_mib << 20)
            .await
            .map_err(|err| Status::internal(format!("volume image: {err}")))?;
        #[cfg(not(target_os = "macos"))]
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
            created_at_ms: burrow_common::unix_now_ms(),
            labels,
            guest_os: String::new(),
            is_lost: false,
        };
        self.write_meta(&meta).await?;
        tokio::fs::rename(&pending, dir.join(IMAGE))
            .await
            .map_err(|err| Status::internal(format!("publishing volume: {err}")))?;

        let volume = self.to_proto(&meta, None);
        if self.is_durable() {
            let store = self.clone();
            let name = name.to_string();
            tokio::spawn(async move { store.sync_logged(&name).await });
        }
        Ok(volume)
    }

    async fn write_meta(&self, meta: &Meta) -> Result<(), Status> {
        let json = serde_json::to_vec_pretty(meta)
            .map_err(|err| Status::internal(format!("volume metadata: {err}")))?;
        tokio::fs::write(self.dir(&meta.name).join(META), json)
            .await
            .map_err(|err| Status::internal(format!("writing volume metadata: {err}")))
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
        if meta.is_lost {
            return Err(Status::not_found(format!("no volume {name}")));
        }
        let local = crate::volstore::load_local(&self.dir(name)).await;
        Ok(self.to_proto(&meta, local.as_ref()))
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
            if let Ok(meta) = self.meta(&name).await
                && !meta.is_lost
            {
                let local = crate::volstore::load_local(&self.dir(&name)).await;
                volumes.push(self.to_proto(&meta, local.as_ref()));
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
        let meta = self.meta(name).await?;
        let _uploading = self.upload_lock(name).lock_owned().await;
        if let Some(store) = &self.object_store
            && !meta.is_lost
            && crate::volstore::load_local(&dir)
                .await
                .is_some_and(|local| local.is_published)
        {
            crate::volstore::purge(store, name, Some(&self.node_id())).await?;
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
        for (_, mount) in block_mounts(mounts) {
            let claim = claims.entry(mount.volume.clone()).or_default();
            // A sandbox re-claiming what it already holds is a resume, not a
            // conflict with itself.
            let held_by_someone_else =
                |who: &Option<String>| who.as_deref().is_some_and(|holder| holder != sandbox_id);
            let refusal = if mount.is_read_only {
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
            if mount.is_read_only {
                claim.readers.insert(sandbox_id.to_string());
            } else {
                claim.writer = Some(sandbox_id.to_string());
            }
            taken.push(mount.volume.clone());
        }
        Ok(())
    }

    /// Readies the images a claim was just taken on, before anything attaches
    /// them: holds each volume to one guest OS, and replays the journal a
    /// departed writer left in one about to be read.
    ///
    /// Done here rather than when the writer goes, because a writer can go
    /// without anyone being told: a VMM killed with the node, or one that
    /// crashed, leaves a journal exactly as a delete does. So the image says
    /// whether it needs it, and nothing has to have been recorded. A writer
    /// that unmounted cleanly left nothing, and costs a read of one block.
    ///
    /// `dormant` names the volumes a suspended sandbox has mounted writable.
    /// Its guest still has the filesystem mounted and will resume onto it,
    /// so the journal is its own: a reader of one of those sees what that
    /// writer had written back to the filesystem, and nothing it had only
    /// journaled.
    ///
    /// The claim is already held, so no writer can take the volume while
    /// this runs; on an error the caller gives the claims back.
    pub async fn prepare(
        &self,
        mounts: &[common::VolumeMount],
        guest_os: &str,
        dormant: &std::collections::HashSet<String>,
    ) -> Result<(), Status> {
        let _held = self.preparing.lock().await;
        for (_, mount) in block_mounts(mounts) {
            let name = &mount.volume;
            // A copy of another node's volume, readied when it was fetched.
            if mount.is_read_only && !self.is_local(name) {
                continue;
            }
            let mut meta = self.meta(name).await?;
            if meta.is_lost {
                return Err(Status::failed_precondition(format!(
                    "volume {name} was taken over by another node while this one was away; the \
                     copy here is no longer the volume"
                )));
            }
            let image = self.image(name);
            if meta.guest_os.is_empty()
                && let Some(made_by) = ondisk::made_by(&image).await
            {
                meta.guest_os = made_by.to_string();
            }
            if !meta.guest_os.is_empty() && meta.guest_os != guest_os {
                return Err(Status::failed_precondition(format!(
                    "volume {name} holds the filesystem a {} guest made ({}), which a {guest_os} \
                     guest cannot mount",
                    meta.guest_os,
                    filesystem(&meta.guest_os)
                )));
            }
            if !mount.is_read_only {
                meta.guest_os = guest_os.to_string();
                self.write_meta(&meta).await?;
                continue;
            }
            if !ondisk::is_needed(&image, &meta.guest_os).await {
                continue;
            }
            if let Some(claim) = self.claims.lock().unwrap().get_mut(name)
                && (claim.is_stale || dormant.contains(name))
            {
                claim.is_stale = true;
                continue;
            }
            tracing::info!(volume = name, "replaying the journal a writer left");
            ondisk::run(&image).await.map_err(|err| {
                Status::failed_precondition(format!(
                    "volume {name} has a journal its last writer left, and replaying it \
                     failed ({err}); mount it writable once to let the guest recover it"
                ))
            })?;
        }
        Ok(())
    }

    /// Records who owns a volume's image before a jailed sandbox writes to it.
    ///
    /// Called with the claim already taken, so the owner recorded is the one
    /// that was in place before this sandbox's [`crate::sandbox`] chown. What
    /// is recorded is whatever the inode says now: if an earlier release could
    /// not put the ownership back, this hands on the owner it actually has
    /// rather than inventing one.
    pub async fn remember_owner(&self, volume: &str) {
        use std::os::unix::fs::MetadataExt as _;

        let Ok(meta) = tokio::fs::metadata(self.image(volume)).await else {
            return;
        };
        let owner = (meta.uid(), meta.gid());
        let mut claims = self.claims.lock().unwrap();
        if let Some(claim) = claims.get_mut(volume) {
            // Only the first writer of a claim records one; a resume re-taking
            // its own claim must not record the jail uid as the original.
            claim.restore_owner.get_or_insert(owner);
        }
    }

    /// Drops every claim one sandbox holds, on stop, suspend or delete.
    pub fn release_all(&self, sandbox_id: &str) {
        let mut written = Vec::new();
        let mut read = Vec::new();
        let restore = {
            let mut claims = self.claims.lock().unwrap();
            for (name, claim) in claims.iter_mut() {
                if claim.writer.as_deref() == Some(sandbox_id) {
                    claim.writer = None;
                    written.push(name.clone());
                }
                if claim.readers.remove(sandbox_id) {
                    read.push(name.clone());
                }
            }
            let restore = Self::drop_free(&mut claims);
            read.retain(|name| !claims.contains_key(name));
            restore
        };
        self.restore_owners(restore);
        self.upload_released(written);
        self.drop_reader_copies(&read);
    }

    /// Removes the read-only copies of volumes nobody here reads any more. A
    /// suspended reader keeps its own link to the copy it mounted, so it
    /// resumes on the same generation.
    fn drop_reader_copies(&self, names: &[String]) {
        for name in names {
            let _ = std::fs::remove_dir_all(self.root.join(READERS).join(name));
        }
    }

    /// Uploads what a writer that just let go left, behind the release.
    fn upload_released(&self, names: Vec<String>) {
        if !self.is_durable() || names.is_empty() {
            return;
        }
        let store = self.clone();
        tokio::spawn(async move {
            for name in names {
                store.sync_logged(&name).await;
            }
        });
    }

    /// Forgets the claims nobody holds, naming the images whose ownership has
    /// to travel back with them.
    fn drop_free(claims: &mut HashMap<String, Claim>) -> Vec<(String, (u32, u32))> {
        let mut restore = Vec::new();
        claims.retain(|name, claim| {
            if !claim.is_free() {
                return true;
            }
            if let Some(owner) = claim.restore_owner.take() {
                restore.push((name.clone(), owner));
            }
            false
        });
        restore
    }

    /// Undoes the chown a writable mount under the jailer needed.
    ///
    /// Without this the grant is permanent: every jailed VMM on the node runs
    /// as one uid, so an image left owned by it is host-level writable by every
    /// other sandbox on the node for as long as the volume exists, whether or
    /// not they were ever allowed to mount it.
    fn restore_owners(&self, restore: Vec<(String, (u32, u32))>) {
        for (name, (uid, gid)) in restore {
            let image = self.image(&name);
            if let Err(err) = std::os::unix::fs::chown(&image, Some(uid), Some(gid)) {
                tracing::warn!(
                    volume = name,
                    %err,
                    "could not put a volume image's owner back; it stays writable by \
                     the jail uid until a later release succeeds"
                );
            }
        }
    }

    /// Rolls back a partial claim, leaving other sandboxes' holds alone.
    fn release_named(&self, sandbox_id: &str, volumes: &[String]) {
        let restore = {
            let mut claims = self.claims.lock().unwrap();
            for name in volumes {
                if let Some(claim) = claims.get_mut(name) {
                    if claim.writer.as_deref() == Some(sandbox_id) {
                        claim.writer = None;
                    }
                    claim.readers.remove(sandbox_id);
                }
            }
            Self::drop_free(&mut claims)
        };
        self.restore_owners(restore);
    }

    fn to_proto(&self, meta: &Meta, local: Option<&crate::volstore::Local>) -> common::Volume {
        let uploaded = local.filter(|local| self.is_durable() && local.is_published);
        common::Volume {
            is_durable: uploaded.is_some(),
            uploaded_at_unix_ms: uploaded.map_or(0, |local| local.manifest.uploaded_at_ms),
            name: meta.name.clone(),
            // Stamped by the orchestrator from its own view of the fleet, like
            // a snapshot's.
            node_id: String::new(),
            size_mib: meta.size_mib,
            created_at_unix_ms: meta.created_at_ms,
            attached_to: self.holder(&meta.name).unwrap_or_default(),
            labels: meta.labels.clone(),
        }
    }
}

/// Keeping volumes in the object store, and taking them over.
impl VolumeStore {
    fn upload_lock(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            self.uploads
                .lock()
                .unwrap()
                .entry(name.to_string())
                .or_default(),
        )
    }

    /// Held across a capture and its upload; taken before a guest is frozen
    /// for one, so the freeze never waits on an upload still running.
    pub async fn lock_upload(&self, name: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.upload_lock(name).lock_owned().await
    }

    /// The upload lock if nothing holds it.
    pub fn try_lock_upload(&self, name: &str) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        self.upload_lock(name).try_lock_owned().ok()
    }

    /// Whether this node holds the volume, as opposed to reading a copy of it.
    pub fn is_local(&self, name: &str) -> bool {
        self.dir(name).join(META).exists()
    }

    /// A read-only copy of a durable volume another node holds, for a sandbox
    /// here mounting it read-only: `generation`, or the latest uploaded one.
    /// Every reader here of one generation shares the copy, and the store
    /// pins the generation for `sandbox_id` until [`Self::unpin`].
    pub async fn reader_copy(
        &self,
        name: &str,
        generation: Option<u64>,
        sandbox_id: &str,
    ) -> Result<(PathBuf, u64), Status> {
        validate_name(name)?;
        let store = self
            .object_store
            .as_ref()
            .ok_or_else(|| Status::not_found(format!("no volume {name} on this node")))?;
        let held = crate::volstore::read(store, name)
            .await?
            .filter(|held| held.manifest.state != crate::volstore::STATE_DELETING)
            .ok_or_else(|| Status::not_found(format!("no volume {name}")))?;
        let generation = generation.unwrap_or(held.manifest.generation);
        let dir = self
            .root
            .join(READERS)
            .join(name)
            .join(generation.to_string());
        let image = dir.join(IMAGE);
        let _fetching = self.lock_upload(&format!("{READERS}/{name}")).await;
        if !tokio::fs::try_exists(&image).await.unwrap_or(false) {
            tokio::fs::create_dir_all(&dir)
                .await
                .map_err(|err| Status::internal(format!("volume copy dir: {err}")))?;
            let building = dir.join(format!("{IMAGE}.building"));
            crate::volstore::fetch_generation(store, name, generation, &building).await?;
            if ondisk::is_needed(&building, &held.manifest.guest_os).await {
                ondisk::run(&building).await.map_err(|err| {
                    Status::failed_precondition(format!(
                        "volume {name}'s generation {generation} has a journal its writer left, \
                         and replaying it failed ({err})"
                    ))
                })?;
            }
            {
                use std::os::unix::fs::PermissionsExt as _;
                tokio::fs::set_permissions(&building, std::fs::Permissions::from_mode(0o444))
                    .await
                    .map_err(|err| Status::internal(format!("volume copy: {err}")))?;
            }
            tokio::fs::rename(&building, &image)
                .await
                .map_err(|err| Status::internal(format!("volume copy: {err}")))?;
            tracing::info!(
                volume = name,
                generation,
                "fetched a read-only copy of the volume"
            );
        }
        crate::volstore::pin(store, name, sandbox_id, generation).await?;
        Ok((image, generation))
    }

    /// Lets go of the generation a deleted sandbox read from a copy.
    pub async fn unpin(&self, name: &str, sandbox_id: &str) {
        if let Some(store) = &self.object_store
            && let Err(err) = crate::volstore::unpin(store, name, sandbox_id).await
        {
            tracing::warn!(volume = name, sandbox = sandbox_id, %err, "could not unpin a volume");
        }
    }

    /// The sandbox writing a volume now, if any.
    pub fn writer(&self, name: &str) -> Option<String> {
        self.claims
            .lock()
            .unwrap()
            .get(name)
            .and_then(|claim| claim.writer.clone())
    }

    /// Whether the image may differ from what the store holds. A freeze and
    /// thaw rewrite the superblock alone, so an image whose file changed is
    /// compared with the clone of its last upload before it counts.
    pub async fn is_changed(&self, name: &str) -> bool {
        let Some(local) = crate::volstore::load_local(&self.dir(name))
            .await
            .filter(|local| local.is_published)
        else {
            return true;
        };
        let image = self.image(name);
        if crate::durable::Stamp::of(&image).is_ok_and(|now| now == local.stamp) {
            return false;
        }
        let base = self.dir(name).join(crate::volstore::BASE);
        tokio::task::spawn_blocking(move || {
            crate::rootdisk::changed_since(&image, &base).unwrap_or(true)
        })
        .await
        .unwrap_or(true)
    }

    /// The generation of the volume this node last uploaded or adopted.
    pub async fn generation(&self, name: &str) -> Option<u64> {
        crate::volstore::load_local(&self.dir(name))
            .await
            .filter(|local| local.is_published)
            .map(|local| local.manifest.generation)
    }

    /// A reflink clone of the image for an upload to read, with the image's
    /// stamp as it was taken. The caller holds the image still.
    pub async fn capture(&self, name: &str) -> Result<(PathBuf, crate::durable::Stamp), Status> {
        let image = self.image(name);
        let stamp = crate::durable::Stamp::of(&image)
            .map_err(|err| Status::internal(format!("reading volume {name}: {err}")))?;
        let capture = self.dir(name).join(crate::volstore::CAPTURE);
        crate::rootdisk::clone(&image, &capture)
            .await
            .map_err(|err| Status::internal(format!("capturing volume {name}: {err}")))?;
        Ok((capture, stamp))
    }

    /// Uploads a capture taken under the volume's upload lock.
    pub async fn upload_capture(
        &self,
        name: &str,
        capture: &Path,
        stamp: crate::durable::Stamp,
    ) -> Result<(), Status> {
        let Some(store) = &self.object_store else {
            return Ok(());
        };
        let node_id = self.node_id();
        if node_id.is_empty() {
            let _ = tokio::fs::remove_file(capture).await;
            return Err(Status::unavailable(
                "this node has no id until it registers, and a volume's manifest names its holder",
            ));
        }
        let meta = self.meta(name).await?;
        let dir = self.dir(name);
        let previous = crate::volstore::load_local(&dir).await;
        let draft = crate::volstore::Manifest {
            format: 0,
            name: name.to_string(),
            generation: 0,
            node_id,
            state: String::new(),
            size_mib: meta.size_mib,
            created_at_ms: meta.created_at_ms,
            labels: meta.labels.clone(),
            guest_os: meta.guest_os.clone(),
            uploaded_at_ms: 0,
        };
        let uploaded =
            crate::volstore::upload(store, &dir, capture, stamp, draft, previous.as_ref()).await;
        let _ = tokio::fs::remove_file(capture).await;
        if let Err(err) = &uploaded
            && err.code() == tonic::Code::Aborted
        {
            self.mark_lost(name).await;
        }
        uploaded.map(drop)
    }

    /// Uploads a volume no running guest writes, if it changed since its last
    /// upload.
    pub async fn sync(&self, name: &str) -> Result<(), Status> {
        if !self.is_durable() {
            return Ok(());
        }
        let _uploading = self.lock_upload(name).await;
        if self.meta(name).await?.is_lost
            || self.writer(name).is_some()
            || !self.is_changed(name).await
        {
            return Ok(());
        }
        let (capture, stamp) = self.capture(name).await?;
        self.upload_capture(name, &capture, stamp).await
    }

    async fn sync_logged(&self, name: &str) {
        if let Err(err) = self.sync(name).await {
            tracing::warn!(
                volume = name,
                err = err.message(),
                "could not upload the volume; it is tried again when its writer next lets go"
            );
        }
    }

    async fn mark_lost(&self, name: &str) {
        let Ok(mut meta) = self.meta(name).await else {
            return;
        };
        tracing::error!(
            volume = name,
            "another node holds this volume in the object store; this copy is no longer the \
             volume and is not served from here"
        );
        meta.is_lost = true;
        let _ = self.write_meta(&meta).await;
    }

    /// Takes a durable volume onto this node from the object store. `from` is
    /// the holder the orchestrator wrote off, empty for a released volume. A
    /// volume already held here is returned as it is.
    pub async fn adopt(&self, name: &str, from: &str) -> Result<common::Volume, Status> {
        validate_name(name)?;
        let store = self.object_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("this node has no object store to adopt volumes from")
        })?;
        let node_id = self.node_id();
        if node_id.is_empty() {
            return Err(Status::unavailable("this node has not registered yet"));
        }
        let _uploading = self.lock_upload(name).await;
        let dir = self.dir(name);
        match self.meta(name).await {
            Ok(meta) if !meta.is_lost => return self.get(name).await,
            Ok(_) => {
                if let Some(holder) = self.holder(name) {
                    return Err(Status::failed_precondition(format!(
                        "this node's stale copy of volume {name} is still attached to sandbox \
                         {holder}"
                    )));
                }
                let _ = tokio::fs::remove_dir_all(&dir).await;
            }
            Err(_) => {}
        }
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|err| Status::internal(format!("volume dir: {err}")))?;
        let building = dir.join(format!("{IMAGE}.building"));
        let local = match crate::volstore::adopt(store, name, &node_id, from, &building).await {
            Ok(local) => local,
            Err(err) => {
                let _ = tokio::fs::remove_dir_all(&dir).await;
                return Err(err);
            }
        };
        let meta = Meta {
            name: name.to_string(),
            size_mib: local.manifest.size_mib,
            created_at_ms: local.manifest.created_at_ms,
            labels: local.manifest.labels.clone(),
            guest_os: local.manifest.guest_os.clone(),
            is_lost: false,
        };
        self.write_meta(&meta).await?;
        tokio::fs::rename(&building, self.image(name))
            .await
            .map_err(|err| Status::internal(format!("publishing volume {name}: {err}")))?;
        let local = crate::volstore::settle_adopted(&dir, &self.image(name), local).await?;
        Ok(self.to_proto(&meta, Some(&local)))
    }

    /// Uploads a volume a sandbox moving off this node mounts, lets go of it
    /// in the store, and removes the copy here.
    pub async fn release(&self, name: &str) -> Result<(), Status> {
        let store = self
            .object_store
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("this node has no object store"))?;
        if let Some(holder) = self.holder(name) {
            return Err(Status::failed_precondition(format!(
                "volume {name} is attached to sandbox {holder}"
            )));
        }
        self.sync(name).await?;
        let _uploading = self.lock_upload(name).await;
        let dir = self.dir(name);
        let local = crate::volstore::load_local(&dir)
            .await
            .filter(|local| local.is_published)
            .ok_or_else(|| {
                Status::failed_precondition(format!("volume {name} is not in the object store"))
            })?;
        crate::volstore::release(store, &self.node_id(), &local).await?;
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|err| Status::internal(format!("removing volume {name}: {err}")))?;
        tracing::info!(volume = name, "volume released to the object store");
        Ok(())
    }

    /// Volumes in the object store, each naming the node its manifest says
    /// holds it.
    pub async fn list_remote(&self) -> Result<Vec<common::Volume>, Status> {
        let store = self
            .object_store
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("this node has no object store"))?;
        Ok(crate::volstore::list(store)
            .await?
            .into_iter()
            .map(|manifest| common::Volume {
                name: manifest.name,
                node_id: manifest.node_id,
                size_mib: manifest.size_mib,
                attached_to: String::new(),
                labels: manifest.labels,
                created_at_unix_ms: manifest.created_at_ms,
                is_durable: true,
                uploaded_at_unix_ms: manifest.uploaded_at_ms,
            })
            .collect())
    }

    /// Deletes a stored volume whose holder is gone.
    pub async fn purge_remote(&self, name: &str) -> Result<(), Status> {
        validate_name(name)?;
        let store = self
            .object_store
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("this node has no object store"))?;
        crate::volstore::purge(store, name, None).await
    }

    /// Marks lost every copy here whose manifest names another holder, and
    /// removes the lost copies nothing holds. Run once the node knows its id.
    pub async fn reconcile_ownership(&self) {
        let Some(store) = &self.object_store else {
            return;
        };
        let node_id = self.node_id();
        if node_id.is_empty() {
            return;
        }
        let Ok(mut entries) = tokio::fs::read_dir(&self.root).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(meta) = self.meta(&name).await else {
                continue;
            };
            if !meta.is_lost
                && crate::volstore::load_local(&self.dir(&name))
                    .await
                    .is_some_and(|local| local.is_published)
            {
                match crate::volstore::read(store, &name).await {
                    Ok(Some(held))
                        if held.manifest.node_id == node_id
                            && held.manifest.state == crate::volstore::STATE_HELD => {}
                    Ok(_) => self.mark_lost(&name).await,
                    Err(err) => {
                        tracing::warn!(volume = name, %err, "could not check who holds the volume");
                    }
                }
            }
            if self.meta(&name).await.is_ok_and(|meta| meta.is_lost) && self.holder(&name).is_none()
            {
                let _ = tokio::fs::remove_dir_all(self.dir(&name)).await;
            }
        }
    }
}

/// What a guest OS formats a volume with, for messages.
fn filesystem(guest_os: &str) -> &'static str {
    match guest_os {
        "windows" => "NTFS",
        "macos" => "HFS+",
        _ => "ext4",
    }
}

/// What a guest left on an image, read by the node, and journals replayed
/// with the filesystem's own userland checker rather than by mounting the
/// image in the node's kernel: the image is whatever a guest wrote, and a
/// crafted one is a parser bug away from the host.
mod ondisk {
    use std::path::Path;

    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    async fn read_at(path: &Path, offset: u64, len: usize) -> Option<Vec<u8>> {
        let mut file = tokio::fs::File::open(path).await.ok()?;
        file.seek(std::io::SeekFrom::Start(offset)).await.ok()?;
        let mut buf = vec![0; len];
        file.read_exact(&mut buf).await.ok()?;
        Some(buf)
    }

    /// Whether the image holds a journal a reader would have to replay.
    ///
    /// NTFS is never replayed here: no tool replays its log outside
    /// Windows, so a Windows reader relies on the writer's guest having
    /// flushed it.
    /// A volume with no OS recorded predates the record, and is the node's
    /// own kind.
    pub async fn is_needed(image: &Path, guest_os: &str) -> bool {
        let is_hfs = match guest_os {
            "windows" => return false,
            "macos" => true,
            "linux" => false,
            _ => cfg!(target_os = "macos"),
        };
        if !is_hfs {
            return read_at(image, 1024, 1024)
                .await
                .is_some_and(|superblock| is_ext4_dirty(&superblock));
        }
        let Some(start) = read_at(image, 0, GPT_BYTES)
            .await
            .and_then(|gpt| hfs_partition_offset(&gpt))
        else {
            return false;
        };
        read_at(image, start + 1024, 512)
            .await
            .is_some_and(|header| is_hfs_dirty(&header))
    }

    /// The guest OS whose filesystem an image holds, for a volume that
    /// predates the record of it: an ext4 that has been mounted, or HFS+.
    /// What a node makes at create is an ext4 nobody has mounted, which any
    /// guest may take.
    pub async fn made_by(image: &Path) -> Option<&'static str> {
        if read_at(image, 1024, 1024)
            .await
            .is_some_and(|superblock| is_used_ext4(&superblock))
        {
            return Some("linux");
        }
        let start = hfs_partition_offset(&read_at(image, 0, GPT_BYTES).await?)?;
        let header = read_at(image, start + 1024, 2).await?;
        matches!(&header[..], b"H+" | b"HX").then_some("macos")
    }

    fn is_ext4(superblock: &[u8]) -> bool {
        superblock.len() >= 0x64
            && u16::from_le_bytes([superblock[0x38], superblock[0x39]]) == 0xef53
    }

    /// An ext4 with a last-mount time.
    pub fn is_used_ext4(superblock: &[u8]) -> bool {
        is_ext4(superblock) && superblock[0x2c..0x30] != [0; 4]
    }

    /// ext4 sets `needs_recovery` in its superblock while mounted and clears
    /// it on a clean unmount.
    pub fn is_ext4_dirty(superblock: &[u8]) -> bool {
        const INCOMPAT_RECOVER: u32 = 0x4;
        is_ext4(superblock)
            && u32::from_le_bytes(superblock[0x60..0x64].try_into().unwrap()) & INCOMPAT_RECOVER
                != 0
    }

    /// The protective MBR, the GPT header and the first 128 entries.
    pub const GPT_BYTES: usize = 512 * 34;

    /// Where the HFS+ partition starts in a disk the macOS guest formatted
    /// (`diskutil eraseDisk JHFS+ ... GPT`), which puts an EFI partition
    /// before it on a large disk and none on a small one.
    pub fn hfs_partition_offset(disk: &[u8]) -> Option<u64> {
        // 48465300-0000-11AA-AA11-00306543ECAC, as GPT stores it.
        const HFS: [u8; 16] = [
            0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xaa, 0x11, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43,
            0xec, 0xac,
        ];
        let header = disk.get(512..512 + 92)?;
        if &header[..8] != b"EFI PART" {
            return None;
        }
        let entries = u64::from_le_bytes(header[72..80].try_into().ok()?);
        let count = u32::from_le_bytes(header[80..84].try_into().ok()?) as usize;
        let size = u32::from_le_bytes(header[84..88].try_into().ok()?) as usize;
        let base = usize::try_from(entries).ok()?.checked_mul(512)?;
        (0..count).find_map(|index| {
            let entry = disk.get(base + index * size..base + index * size + 40)?;
            (entry[..16] == HFS)
                .then(|| u64::from_le_bytes(entry[32..40].try_into().unwrap()) * 512)
        })
    }

    /// HFS+ clears `kHFSVolumeUnmountedBit` in its volume header while
    /// mounted and sets it again on a clean unmount.
    pub fn is_hfs_dirty(header: &[u8]) -> bool {
        const UNMOUNTED: u32 = 1 << 8;
        header.len() >= 8
            && matches!(&header[..2], b"H+" | b"HX")
            && u32::from_be_bytes(header[4..8].try_into().unwrap()) & UNMOUNTED == 0
    }

    /// `e2fsck -E journal_only`: replays the journal and checks nothing
    /// else. Exit 1 is "corrected", which a replay is.
    #[cfg(not(target_os = "macos"))]
    pub async fn run(image: &Path) -> Result<(), String> {
        let output = tokio::process::Command::new("e2fsck")
            .args(["-p", "-E", "journal_only"])
            .arg(image)
            .output()
            .await
            .map_err(|err| format!("e2fsck: {err}"))?;
        match output.status.code() {
            Some(0 | 1) => Ok(()),
            _ => Err(format!(
                "e2fsck {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )),
        }
    }

    /// `fsck_hfs -p`, which on a journaled volume replays the journal and
    /// checks nothing else, on the image attached without mounting it.
    #[cfg(target_os = "macos")]
    pub async fn run(image: &Path) -> Result<(), String> {
        let output = tokio::process::Command::new("/usr/bin/hdiutil")
            .args([
                "attach",
                "-imagekey",
                "diskimage-class=CRawDiskImage",
                "-nomount",
                "-noverify",
            ])
            .arg(image)
            .output()
            .await
            .map_err(|err| format!("hdiutil: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "hdiutil attach {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let listing = String::from_utf8_lossy(&output.stdout);
        let Some(disk) = listing.split_whitespace().next().map(str::to_string) else {
            return Err("hdiutil attach named no disk".into());
        };
        let checked = match attached_hfs(&listing) {
            Some(partition) => {
                let raw = partition.replacen("/dev/disk", "/dev/rdisk", 1);
                let output = tokio::process::Command::new("/sbin/fsck_hfs")
                    .args(["-p", &raw])
                    .output()
                    .await
                    .map_err(|err| format!("fsck_hfs: {err}"))?;
                match output.status.success() {
                    true => Ok(()),
                    false => Err(format!(
                        "fsck_hfs {}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout).trim()
                    )),
                }
            }
            None => Err(format!("{disk} has no HFS+ partition")),
        };
        let _ = tokio::process::Command::new("/usr/bin/hdiutil")
            .args(["detach", &disk])
            .output()
            .await;
        checked
    }

    /// The HFS+ partition in what `hdiutil attach` printed.
    #[cfg(target_os = "macos")]
    fn attached_hfs(listing: &str) -> Option<String> {
        listing
            .lines()
            .find(|line| line.contains("Apple_HFS") || line.contains("48465300-0000-11AA"))
            .and_then(|line| line.split_whitespace().next())
            .map(str::to_string)
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
///
/// A tmpfs entry names no volume and takes no device, so the cap on block
/// devices does not count it; it shares the path rules, since it lands in
/// the same guest tree.
pub fn validate_mounts(mounts: &[common::VolumeMount]) -> Result<(), Status> {
    let block = block_mounts(mounts).count();
    if block > MAX_MOUNTS {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_MOUNTS} volume mounts, got {block}"
        )));
    }
    let mut paths: Vec<&String> = Vec::new();
    let mut names: Vec<&String> = Vec::new();
    for mount in mounts {
        if mount.is_tmpfs {
            if !mount.volume.is_empty() {
                return Err(Status::invalid_argument(format!(
                    "tmpfs mount at {} names volume {}; a tmpfs has no volume behind it",
                    mount.path, mount.volume
                )));
            }
        } else {
            validate_name(&mount.volume)?;
            if mount.size_mib != 0 {
                return Err(Status::invalid_argument(format!(
                    "volume {} has its size already; size_mib is for tmpfs mounts",
                    mount.volume
                )));
            }
        }
        validate_path(&mount.path)?;
        validate_mode(&mount.mode)?;
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
        if !mount.is_tmpfs && names.contains(&&mount.volume) {
            return Err(Status::invalid_argument(format!(
                "volume {} mounted twice",
                mount.volume
            )));
        }
        paths.push(&mount.path);
        if !mount.is_tmpfs {
            names.push(&mount.volume);
        }
    }
    Ok(())
}

/// Checks a mount root's mode: octal as a caller would type it to chmod, with
/// or without the leading setuid/setgid/sticky digit.
fn validate_mode(mode: &str) -> Result<(), Status> {
    let ok = mode.is_empty()
        || ((3..=4).contains(&mode.len()) && mode.bytes().all(|b| (b'0'..=b'7').contains(&b)));
    if !ok {
        return Err(Status::invalid_argument(format!(
            "mount mode {mode:?} must be 3 or 4 octal digits"
        )));
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
    const RESERVED: [&str; 8] = [
        "/proc", "/sys", "/dev", "/tmp", "/run", "/etc", "/usr", "/bin",
    ];
    let trimmed = path.trim_end_matches('/');
    if RESERVED
        .iter()
        .any(|reserved| trimmed == *reserved || trimmed.starts_with(&format!("{reserved}/")))
    {
        return Err(Status::invalid_argument(format!(
            "mount path {path:?} is inside a reserved directory"
        )));
    }
    Ok(())
}

/// Guest device a mount lands on, in the order the drives were attached.
pub fn device_for(index: usize, layout: crate::rootdisk::DiskLayout) -> String {
    format!(
        "/dev/vd{}",
        (layout.first_volume_device() + index as u8) as char
    )
}

/// The mounts that are block devices, each with its drive index.
///
/// Every place that links an image, attaches a drive or names a guest device
/// counts through this, so a tmpfs anywhere in the list does not shift the
/// device names of the volumes after it.
pub fn block_mounts(
    mounts: &[common::VolumeMount],
) -> impl Iterator<Item = (usize, &common::VolumeMount)> {
    mounts.iter().filter(|mount| !mount.is_tmpfs).enumerate()
}

/// The drive id of a macOS or Windows guest's volume, which becomes its
/// disk's identifier on a Mac (`burrow_vmm::vz::VOLUME_DISK_PREFIX`) and its
/// virtio serial number under Cloud Hypervisor.
pub fn disk_id(index: usize) -> String {
    format!("burrow-volume{index}")
}

/// Whether a drive is a volume's rather than the sandbox's own disk.
pub fn is_volume_drive(id: &str) -> bool {
    id.starts_with("volume") || id.starts_with("burrow-volume")
}

/// The drive id a volume is attached under. A Linux guest finds its volumes
/// by device name, so its drives keep the ids its snapshots were taken with.
pub fn drive_id(index: usize, guest_os: burrow_vmm::GuestOs) -> String {
    match guest_os {
        burrow_vmm::GuestOs::Linux => format!("volume{index}"),
        _ => disk_id(index),
    }
}

/// What the guest is told: devices rather than volume names, since the name is
/// a host-side handle and the guest only has the block device. A macOS or
/// Windows guest is told the disk's identifier instead, since it names disks
/// in the order it finds them.
///
/// The order here must be the order the drives were attached, which is why
/// both come from the same slice.
pub fn agent_mounts(
    mounts: &[common::VolumeMount],
    guest_os: burrow_vmm::GuestOs,
    layout: crate::rootdisk::DiskLayout,
) -> Vec<burrow_proto::guest::v1::VolumeMount> {
    let mut block = 0;
    mounts
        .iter()
        .map(|mount| {
            let device = if mount.is_tmpfs {
                String::new()
            } else {
                block += 1;
                match guest_os {
                    burrow_vmm::GuestOs::Linux => device_for(block - 1, layout),
                    _ => disk_id(block - 1),
                }
            };
            burrow_proto::guest::v1::VolumeMount {
                device,
                path: mount.path.clone(),
                is_read_only: mount.is_read_only,
                is_tmpfs: mount.is_tmpfs,
                size_mib: mount.size_mib,
                mode: mount.mode.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rootdisk::DiskLayout;

    fn mount(volume: &str, path: &str, read_only: bool) -> common::VolumeMount {
        common::VolumeMount {
            volume: volume.into(),
            path: path.into(),
            is_read_only: read_only,
            ..Default::default()
        }
    }

    fn tmpfs(path: &str, size_mib: u64, mode: &str) -> common::VolumeMount {
        common::VolumeMount {
            path: path.into(),
            is_tmpfs: true,
            size_mib,
            mode: mode.into(),
            ..Default::default()
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
        assert!(
            validate_mounts(&[mount("a", "/data", false), mount("b", "/data", false)]).is_err()
        );
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

    #[test]
    fn a_tmpfs_is_a_mount_without_a_volume() {
        assert!(validate_mounts(&[tmpfs("/scratch", 0, "")]).is_ok());
        assert!(validate_mounts(&[tmpfs("/scratch", 512, "1777")]).is_ok());
        assert!(validate_mounts(&[tmpfs("/scratch", 0, "755")]).is_ok());
        // Two tmpfs mounts share no name, so only their paths can clash.
        assert!(validate_mounts(&[tmpfs("/a", 0, ""), tmpfs("/b", 0, "")]).is_ok());
        assert!(validate_mounts(&[tmpfs("/a", 0, ""), tmpfs("/a", 0, "")]).is_err());
        assert!(validate_mounts(&[mount("v", "/data", false), tmpfs("/data/tmp", 0, "")]).is_err());
        // It obeys the same path rules as a volume.
        assert!(validate_mounts(&[tmpfs("/tmp/x", 0, "")]).is_err());

        let mut named = tmpfs("/scratch", 0, "");
        named.volume = "v".into();
        assert!(validate_mounts(&[named]).is_err());
        for bad in ["17777", "77", "1778", "rwx"] {
            assert!(
                validate_mounts(&[tmpfs("/scratch", 0, bad)]).is_err(),
                "{bad:?} should be refused"
            );
        }
        let mut sized = mount("v", "/data", false);
        sized.size_mib = 64;
        assert!(validate_mounts(&[sized]).is_err());
    }

    /// A Mac's volume is an image as large as asked for that takes no disk
    /// until the guest writes to it.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_mac_volume_is_a_sparse_image_of_its_size() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = std::env::temp_dir().join(format!("burrow-volume-{}", std::process::id()));
        let store = VolumeStore::new(&dir);
        store.create("v", 64, HashMap::new()).await.unwrap();
        let meta = std::fs::metadata(store.image("v")).unwrap();
        assert_eq!(meta.len(), 64 << 20);
        assert!(meta.blocks() * 512 < 1 << 20);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A tmpfs takes no drive, so the volumes around it keep the devices they
    /// would have had without it.
    #[test]
    fn a_tmpfs_does_not_shift_device_names() {
        let mounts = [
            mount("a", "/a", false),
            tmpfs("/scratch", 256, "1777"),
            mount("b", "/b", true),
        ];
        let agent = agent_mounts(&mounts, burrow_vmm::GuestOs::Linux, DiskLayout::Root);
        assert_eq!(agent[0].device, "/dev/vdb");
        assert_eq!(agent[1].device, "");
        assert!(agent[1].is_tmpfs);
        assert_eq!(agent[1].size_mib, 256);
        assert_eq!(agent[1].mode, "1777");
        assert_eq!(agent[2].device, "/dev/vdc");
        assert!(agent[2].is_read_only);
        // An overlay sandbox's scratch disk is the second drive.
        let overlay = agent_mounts(&mounts, burrow_vmm::GuestOs::Linux, DiskLayout::Overlay);
        assert_eq!(overlay[0].device, "/dev/vdc");
        assert_eq!(overlay[2].device, "/dev/vdd");

        // A Windows or macOS guest is told which of the disks after its own
        // it is.
        let mac = agent_mounts(&mounts, burrow_vmm::GuestOs::Windows, DiskLayout::Root);
        assert_eq!(mac[0].device, disk_id(0));
        assert_eq!(mac[1].device, "");
        assert_eq!(mac[2].device, "burrow-volume1");

        let block: Vec<(usize, &str)> = block_mounts(&mounts)
            .map(|(index, mount)| (index, mount.volume.as_str()))
            .collect();
        assert_eq!(block, [(0, "a"), (1, "b")]);

        // Nor does it take a claim: there is nothing to hold.
        let store = VolumeStore::new(Path::new("/tmp/burrow-volume-test"));
        assert!(store.claim("sbx_a", &[tmpfs("/scratch", 0, "")]).is_ok());
        assert!(store.claim("sbx_b", &[tmpfs("/scratch", 0, "")]).is_ok());
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
        assert!(
            store
                .claim("sbx_d", &[mount("taken", "/t", false)])
                .is_err()
        );
    }

    #[test]
    fn a_mounted_ext4_or_hfs_is_seen_to_need_its_journal_replayed() {
        let mut superblock = vec![0u8; 1024];
        superblock[0x38..0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
        superblock[0x60..0x64].copy_from_slice(&0x2c2u32.to_le_bytes());
        assert!(!ondisk::is_ext4_dirty(&superblock));
        superblock[0x60..0x64].copy_from_slice(&0x2c6u32.to_le_bytes());
        assert!(ondisk::is_ext4_dirty(&superblock));
        // A blank image is not a filesystem with a journal.
        assert!(!ondisk::is_ext4_dirty(&[0u8; 1024]));
        // Made by the node, and never mounted: anyone's to take.
        assert!(!ondisk::is_used_ext4(&superblock));
        superblock[0x2c..0x30].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        assert!(ondisk::is_used_ext4(&superblock));

        // Attributes as read off a volume while mounted and after unmounting.
        let mut header = vec![0u8; 512];
        header[..2].copy_from_slice(b"H+");
        header[4..8].copy_from_slice(&0x8000_2000u32.to_be_bytes());
        assert!(ondisk::is_hfs_dirty(&header));
        header[4..8].copy_from_slice(&0x8000_2100u32.to_be_bytes());
        assert!(!ondisk::is_hfs_dirty(&header));
        assert!(!ondisk::is_hfs_dirty(&[0u8; 512]));
    }

    /// As `diskutil eraseDisk JHFS+ burrow-volume GPT` lays out a large disk:
    /// an EFI partition, then HFS+.
    #[test]
    fn the_hfs_partition_is_found_in_the_gpt() {
        let mut disk = vec![0u8; ondisk::GPT_BYTES];
        disk[512..520].copy_from_slice(b"EFI PART");
        disk[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes());
        disk[512 + 80..512 + 84].copy_from_slice(&128u32.to_le_bytes());
        disk[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());
        let efi = 1024;
        disk[efi..efi + 4].copy_from_slice(&[0x28, 0x73, 0x2a, 0xc1]);
        disk[efi + 32..efi + 40].copy_from_slice(&40u64.to_le_bytes());
        assert_eq!(ondisk::hfs_partition_offset(&disk), None);
        let hfs = efi + 128;
        disk[hfs..hfs + 16].copy_from_slice(&[
            0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xaa, 0x11, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43,
            0xec, 0xac,
        ]);
        disk[hfs + 32..hfs + 40].copy_from_slice(&409_640u64.to_le_bytes());
        assert_eq!(ondisk::hfs_partition_offset(&disk), Some(409_640 * 512));
        assert_eq!(
            ondisk::hfs_partition_offset(&[0u8; ondisk::GPT_BYTES]),
            None
        );
    }

    fn store_with(name: &str, image: &[u8]) -> (VolumeStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("burrow-volume-{}-{name}", std::process::id()));
        let store = VolumeStore::new(&dir);
        std::fs::create_dir_all(store.dir(name)).unwrap();
        std::fs::write(store.image(name), image).unwrap();
        let meta = Meta {
            name: name.into(),
            size_mib: 1,
            created_at_ms: 0,
            labels: HashMap::new(),
            guest_os: String::new(),
            is_lost: false,
        };
        std::fs::write(
            store.dir(name).join(META),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        (store, dir)
    }

    /// A volume uploaded from one node is taken over by another once the
    /// first is written off, and the first, back again, finds it lost and
    /// stops serving its copy.
    #[tokio::test]
    async fn a_durable_volume_moves_to_another_node_and_the_old_copy_is_lost() {
        let objects = crate::objstore::fake::store(true).await;
        let (a, dir_a) = store_with("data", &[7u8; 8192]);
        let a = a.with_object_store(Some(objects.clone()));
        a.bind_node_id(Arc::new(Mutex::new("node-a".into())));
        a.sync("data").await.unwrap();
        let listed = a.get("data").await.unwrap();
        assert!(listed.is_durable);
        assert!(listed.uploaded_at_unix_ms > 0);
        assert!(!a.is_changed("data").await);

        let dir_b = std::env::temp_dir().join(format!("burrow-volume-{}-b", std::process::id()));
        let b = VolumeStore::new(&dir_b).with_object_store(Some(objects.clone()));
        b.bind_node_id(Arc::new(Mutex::new("node-b".into())));
        let refused = b.adopt("data", "node-c").await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Aborted);
        let adopted = b.adopt("data", "node-a").await.unwrap();
        assert!(adopted.is_durable);
        assert_eq!(
            std::fs::read(b.image("data")).unwrap(),
            std::fs::read(a.image("data")).unwrap()
        );
        assert_eq!(b.list_remote().await.unwrap()[0].node_id, "node-b");

        a.reconcile_ownership().await;
        assert!(a.list().await.is_empty());
        assert!(!a.dir("data").exists());
        std::fs::remove_dir_all(&dir_a).unwrap();
        std::fs::remove_dir_all(&dir_b).unwrap();
    }

    /// A sandbox on another node reads a copy of the latest upload, pinned to
    /// that generation while the writer goes on on the holding node, and the
    /// copy goes once the last reader there lets go.
    #[tokio::test]
    async fn a_remote_reader_reads_a_pinned_copy_of_the_last_upload() {
        use std::os::unix::fs::FileExt as _;
        let objects = crate::objstore::fake::store(true).await;
        let (a, dir_a) = store_with("remote", &[5u8; 8192]);
        let a = a.with_object_store(Some(objects.clone()));
        a.bind_node_id(Arc::new(Mutex::new("node-a".into())));
        a.sync("remote").await.unwrap();
        let first = a.generation("remote").await.unwrap();

        let dir_b = std::env::temp_dir().join(format!("burrow-volume-{}-rb", std::process::id()));
        let b = VolumeStore::new(&dir_b).with_object_store(Some(objects.clone()));
        b.bind_node_id(Arc::new(Mutex::new("node-b".into())));
        assert!(!b.is_local("remote"));
        b.claim("sbx_r1", &[mount("remote", "/data", true)])
            .unwrap();
        let (copy, generation) = b.reader_copy("remote", None, "sbx_r1").await.unwrap();
        assert_eq!(generation, first);
        assert_eq!(std::fs::read(&copy).unwrap(), vec![5u8; 8192]);
        assert!(std::fs::metadata(&copy).unwrap().permissions().readonly());
        b.prepare(
            &[mount("remote", "/data", true)],
            "linux",
            &Default::default(),
        )
        .await
        .unwrap();
        assert!(
            b.list().await.is_empty(),
            "a copy is not a volume this node holds"
        );

        // The writer moves on and uploads; the reader keeps its generation, and
        // a new mount gets the new one.
        std::fs::OpenOptions::new()
            .write(true)
            .open(a.image("remote"))
            .unwrap()
            .write_all_at(&[6u8; 4096], 0)
            .unwrap();
        a.sync("remote").await.unwrap();
        let second = a.generation("remote").await.unwrap();
        assert!(second > first);
        assert_eq!(std::fs::read(&copy).unwrap(), vec![5u8; 8192]);
        b.claim("sbx_r2", &[mount("remote", "/data", true)])
            .unwrap();
        let (newer, generation) = b.reader_copy("remote", None, "sbx_r2").await.unwrap();
        assert_eq!(generation, second);
        assert_eq!(std::fs::read(&newer).unwrap()[..4096], [6u8; 4096]);
        let (pinned, generation) = b
            .reader_copy("remote", Some(first), "sbx_r3")
            .await
            .unwrap();
        assert_eq!((pinned, generation), (copy.clone(), first));

        b.release_all("sbx_r1");
        assert!(copy.exists(), "another reader here still has the volume");
        b.release_all("sbx_r2");
        assert!(!copy.exists() && !newer.exists());
        b.unpin("remote", "sbx_r1").await;
        std::fs::remove_dir_all(&dir_a).unwrap();
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    /// The first writer decides what filesystem the volume holds, and a guest
    /// that cannot mount it is refused before it boots.
    #[tokio::test]
    async fn a_volume_belongs_to_the_os_that_first_wrote_it() {
        let (store, dir) = store_with("shared", &[0u8; 4096]);
        let none = std::collections::HashSet::new();
        let reader = [mount("shared", "/data", true)];
        let writer = [mount("shared", "/data", false)];
        // Reading binds nothing: a blank volume read by the wrong guest is
        // refused in the guest, and stays usable by the right one.
        store.prepare(&reader, "windows", &none).await.unwrap();
        assert_eq!(store.meta("shared").await.unwrap().guest_os, "");
        store.prepare(&writer, "linux", &none).await.unwrap();
        assert_eq!(store.meta("shared").await.unwrap().guest_os, "linux");
        store.prepare(&reader, "linux", &none).await.unwrap();
        let err = store.prepare(&writer, "windows", &none).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("ext4"), "{}", err.message());
        assert!(store.prepare(&reader, "windows", &none).await.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A suspended writer still has the filesystem mounted, so its journal is
    /// left alone, and so is it for every reader that joins one already
    /// reading past it.
    #[tokio::test]
    async fn a_journal_a_suspended_writer_holds_is_not_replayed() {
        let mut image = vec![0u8; 4096];
        image[1024 + 0x38..1024 + 0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
        image[1024 + 0x60..1024 + 0x64].copy_from_slice(&0x2c6u32.to_le_bytes());
        let (store, dir) = store_with("held", &image);
        let mut meta = store.meta("held").await.unwrap();
        meta.guest_os = "linux".into();
        store.write_meta(&meta).await.unwrap();
        let reader = [mount("held", "/data", true)];
        let dormant: std::collections::HashSet<String> = ["held".to_string()].into();

        store.claim("sbx_a", &reader).unwrap();
        store.prepare(&reader, "linux", &dormant).await.unwrap();
        // The writer has gone since, but a reader is attached past its
        // journal; the next one joins it rather than moving the disk.
        store.claim("sbx_b", &reader).unwrap();
        store
            .prepare(&reader, "linux", &std::collections::HashSet::new())
            .await
            .unwrap();
        assert!(ondisk::is_needed(&store.image("held"), "linux").await);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
