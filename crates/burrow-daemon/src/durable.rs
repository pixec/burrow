//! Suspended sandboxes kept in the object store, so they outlive their node.
//!
//! After every suspend a node uploads the sandbox's state: its memory chain
//! flattened into one chunked image, its scratch disk, its vmstate, and its
//! kernel and rootfs as blobs. A manifest written last names the generation
//! that is complete. Another node can then adopt the sandbox: fetch the small
//! parts, start the VM, and take memory as the guest faults on it.
//!
//! The manifest also carries who holds the sandbox and whether it is running.
//! A node marks it running *before* it resumes the guest, so a node adopting
//! it after this one was written off reads `running` and refuses: the state in
//! the store is from the last suspend, and the guest has moved on since.
//! Together with the lease a node holds through its heartbeats, that is what
//! keeps one sandbox from running in two places.
//!
//! Layout, under the store's prefix:
//!
//! ```text
//! sandboxes/<id>/manifest.json
//! sandboxes/<id>/<generation>/snapshot.vmstate
//! sandboxes/<id>/<generation>/snapshot.mem.index.json
//! sandboxes/<id>/<generation>/scratch.ext4.index.json
//! chunks/<sha256>
//! blobs/<digest>
//! ```

#![allow(clippy::result_large_err)]

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tonic::Status;

use crate::chunks::{Hydrator, ImageIndex, LayerId, Reuse};
use crate::objstore::ObjectStore;

const FORMAT: u32 = 1;
const MANIFEST: &str = "manifest.json";
/// The last upload, as this node made or adopted it, in the working directory.
const LOCAL: &str = "durable.json";
const SCRATCH_IMAGE: &str = "scratch.ext4";
const TEMPLATE_KERNEL: &str = "vmlinux";
const TEMPLATE_ROOTFS: &str = "rootfs.ext4";

/// The guest-memory offsets a VM faulted on while it ran, recorded by the
/// page-fault handler as it exits. Uploaded with the state, so a node adopting
/// the sandbox fetches what the guest was using before the guest asks for it.
pub const WORKING_SET: &str = "workingset.bin";

pub const STATE_SUSPENDED: &str = "suspended";
pub const STATE_RUNNING: &str = "running";

/// How old an object must be before the collector may take it. Far longer than
/// any upload, which puts its chunks before the manifest that names them.
const GARBAGE_GRACE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub id: String,
    /// Names the directory this upload's objects are under. Unix milliseconds,
    /// raised past the previous one if the clock disagrees.
    pub generation: u64,
    /// The node that last held the sandbox.
    pub node_id: String,
    pub state: String,
    pub template: String,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub scratch_disk_mib: u32,
    pub is_systemd: bool,
    pub arch: String,
    pub firecracker_version: String,
    pub kernel_digest: String,
    pub rootfs_digest: String,
    pub cpu_usage_usec: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// The sandbox's brokered credentials, sealed under the fleet's store key
    /// and keyed by where each sits in its record. The orchestrator only ever
    /// sees them redacted, so this is the one place an adopting node can get
    /// them back from.
    #[serde(default)]
    pub secrets: std::collections::BTreeMap<String, String>,
}

fn sandbox_prefix(id: &str) -> String {
    format!("sandboxes/{id}/")
}

fn manifest_key(id: &str) -> String {
    format!("sandboxes/{id}/{MANIFEST}")
}

fn generation_key(id: &str, generation: u64, file: &str) -> String {
    format!("sandboxes/{id}/{generation}/{file}")
}

fn index_key(id: &str, generation: u64, file: &str) -> String {
    generation_key(id, generation, &format!("{file}.index.json"))
}

/// Which version of a file this is, cheaply. Firecracker writes a fresh
/// vmstate on every suspend and the guest writes its disk while it runs, so a
/// file whose stamp is unchanged is the file that was uploaded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stamp {
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i128,
}

impl Stamp {
    fn of(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            ino: meta.ino(),
            size: meta.len(),
            mtime_ns: meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128,
        })
    }
}

/// What this node knows about a sandbox's stored state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalState {
    pub manifest: Manifest,
    /// Whether the manifest above reached the store. Saved before the
    /// manifest is written as well as after, so a crash between the two still
    /// leaves the node knowing there may be stored state to mark running.
    pub is_published: bool,
    pub layers: Vec<LayerId>,
    pub vmstate: Stamp,
    pub scratch: Stamp,
    pub kernel: Stamp,
    pub rootfs: Stamp,
    pub memory: ImageIndex,
    pub scratch_index: ImageIndex,
}

impl LocalState {
    /// Whether the stored state is the sandbox as it sits on disk now.
    pub fn is_current(&self, workdir: &Path, chain: &[String]) -> bool {
        self.is_published
            && self.manifest.state == STATE_SUSPENDED
            && self.layers.len() == chain.len()
            && self
                .layers
                .iter()
                .zip(chain)
                .all(|(layer, name)| LayerId::of(workdir, name).is_ok_and(|now| now == *layer))
            && Stamp::of(&workdir.join(burrow_firecracker::SNAPSHOT_FILE))
                .is_ok_and(|now| now == self.vmstate)
            && Stamp::of(&workdir.join(SCRATCH_IMAGE)).is_ok_and(|now| now == self.scratch)
    }

    fn digests(&self) -> HashSet<String> {
        self.memory
            .digests()
            .chain(self.scratch_index.digests())
            .map(str::to_string)
            .collect()
    }
}

pub async fn load_local(workdir: &Path) -> Option<LocalState> {
    let bytes = tokio::fs::read(workdir.join(LOCAL)).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn save_local(workdir: &Path, local: &LocalState) -> Result<(), Status> {
    let json = serde_json::to_vec(local)
        .map_err(|err| Status::internal(format!("encoding the durable state: {err}")))?;
    let temp = workdir.join(format!(".{LOCAL}.tmp"));
    tokio::fs::write(&temp, json)
        .await
        .map_err(|err| Status::internal(format!("writing the durable state: {err}")))?;
    tokio::fs::rename(&temp, workdir.join(LOCAL))
        .await
        .map_err(|err| Status::internal(format!("writing the durable state: {err}")))
}

pub async fn remove_local(workdir: &Path) {
    let _ = tokio::fs::remove_file(workdir.join(LOCAL)).await;
}

/// A sandbox's standing with the object store, held on the sandbox.
#[derive(Default)]
pub struct Durability {
    /// Held across an upload, and taken by a resume once it has cancelled
    /// one, so the guest never starts writing a disk that is being read.
    pub upload: tokio::sync::Mutex<()>,
    pub cancel: std::sync::Mutex<tokio_util::sync::CancellationToken>,
    pub stored: std::sync::Mutex<Option<LocalState>>,
    /// The stored state is the sandbox as it is now. Only ever true while
    /// suspended.
    pub is_current: AtomicBool,
    /// Not to be resumed until the orchestrator confirms it still lives here.
    pub is_fenced: AtomicBool,
    /// The base memory image, while it is still arriving from the store.
    pub hydration: std::sync::Mutex<Option<Arc<Hydrator>>>,
}

impl Durability {
    pub fn is_current(&self) -> bool {
        self.is_current.load(Ordering::Relaxed)
    }

    pub fn is_fenced(&self) -> bool {
        self.is_fenced.load(Ordering::Relaxed)
    }

    pub fn set_fenced(&self, fenced: bool) {
        self.is_fenced.store(fenced, Ordering::Relaxed);
    }

    pub fn invalidate(&self) {
        self.is_current.store(false, Ordering::Relaxed);
    }

    /// Whether the store may hold state for this sandbox.
    pub fn has_stored(&self) -> bool {
        self.stored.lock().unwrap().is_some()
    }

    /// The memory image still arriving, if there is one.
    pub fn arriving(&self) -> Option<Arc<Hydrator>> {
        let mut hydration = self.hydration.lock().unwrap();
        if hydration.as_ref().is_some_and(|h| h.is_complete()) {
            *hydration = None;
        }
        hydration.clone()
    }

    /// Waits for the memory image to finish arriving. Anything that reads the
    /// layer files directly, rather than through the page-fault handler, has
    /// to wait here first: until then the base has holes that are not zeroes.
    pub async fn settle_memory(&self) {
        let arriving = self.arriving();
        if let Some(hydrator) = arriving {
            hydrator.wait().await;
            *self.hydration.lock().unwrap() = None;
        }
    }

    /// Cancels an upload in flight and holds off any other until dropped.
    pub async fn stop_uploading(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.cancel.lock().unwrap().cancel();
        let guard = self.upload.lock().await;
        *self.cancel.lock().unwrap() = tokio_util::sync::CancellationToken::new();
        guard
    }
}

/// Uploads a suspended sandbox's state, returning what was stored.
///
/// `draft` carries what the manifest says about the sandbox; the generation,
/// digests and state are filled in here. `previous` is the last upload, whose
/// chunks are reused where the layers they came from are unchanged.
pub async fn upload(
    store: &ObjectStore,
    workdir: &Path,
    chain: &[String],
    draft: Manifest,
    previous: Option<&LocalState>,
) -> Result<LocalState, Status> {
    let io = |what: &str, err: std::io::Error| Status::internal(format!("{what}: {err}"));
    let started = std::time::Instant::now();
    let id = draft.id.clone();
    let layers = chain
        .iter()
        .map(|name| LayerId::of(workdir, name))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|err| io("reading the memory chain", err))?;
    let stamp = |file: &str| Stamp::of(&workdir.join(file)).map_err(|err| io(file, err));
    let vmstate = stamp(burrow_firecracker::SNAPSHOT_FILE)?;
    let scratch = stamp(SCRATCH_IMAGE)?;
    let kernel = stamp(TEMPLATE_KERNEL)?;
    let rootfs = stamp(TEMPLATE_ROOTFS)?;
    let known = previous.map(LocalState::digests).unwrap_or_default();

    let blob = |file: &'static str, stamp: &Stamp, held: Option<(&Stamp, &String)>| {
        let path = workdir.join(file);
        let reused = held
            .filter(|(was, _)| *was == stamp)
            .map(|(_, digest)| digest.clone());
        async move {
            match reused {
                Some(digest) => Ok(digest),
                None => crate::snapshot::put_blob(store, &path).await,
            }
        }
    };
    let kernel_digest = blob(
        TEMPLATE_KERNEL,
        &kernel,
        previous.map(|p| (&p.kernel, &p.manifest.kernel_digest)),
    )
    .await?;
    let rootfs_digest = blob(
        TEMPLATE_ROOTFS,
        &rootfs,
        previous.map(|p| (&p.rootfs, &p.manifest.rootfs_digest)),
    )
    .await?;

    let reuse = previous
        .filter(|p| layers.starts_with(&p.layers))
        .map(|p| Reuse {
            index: &p.memory,
            covered: p.layers.len(),
        });
    let memory = crate::chunks::put_image(store, workdir, chain, reuse, &known).await?;
    let scratch_index = match previous.filter(|p| p.scratch == scratch) {
        Some(previous) => previous.scratch_index.clone(),
        None => {
            crate::chunks::put_image(store, workdir, &[SCRATCH_IMAGE.to_string()], None, &known)
                .await?
        }
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let generation = now_ms.max(previous.map_or(0, |p| p.manifest.generation + 1));
    store
        .put_file(
            &generation_key(&id, generation, burrow_firecracker::SNAPSHOT_FILE),
            &workdir.join(burrow_firecracker::SNAPSHOT_FILE),
        )
        .await?;
    if tokio::fs::try_exists(workdir.join(WORKING_SET))
        .await
        .unwrap_or(false)
    {
        store
            .put_file(
                &generation_key(&id, generation, WORKING_SET),
                &workdir.join(WORKING_SET),
            )
            .await?;
    }
    for (file, index) in [
        (burrow_firecracker::SNAPSHOT_MEM_FILE, &memory),
        (SCRATCH_IMAGE, &scratch_index),
    ] {
        let json = serde_json::to_vec(index)
            .map_err(|err| Status::internal(format!("encoding an index: {err}")))?;
        store
            .put_bytes(&index_key(&id, generation, file), json)
            .await?;
    }

    // The sandbox's files were read without holding them still. A resume
    // cancels the upload before it starts the guest, so a change here is a
    // bug rather than a race, and is refused rather than published.
    if stamp(burrow_firecracker::SNAPSHOT_FILE)? != vmstate || stamp(SCRATCH_IMAGE)? != scratch {
        return Err(Status::aborted(
            "the sandbox changed while it was being uploaded",
        ));
    }

    let mut local = LocalState {
        manifest: Manifest {
            format: FORMAT,
            generation,
            state: STATE_SUSPENDED.to_string(),
            kernel_digest,
            rootfs_digest,
            ..draft
        },
        is_published: false,
        layers,
        vmstate,
        scratch,
        kernel,
        rootfs,
        memory,
        scratch_index,
    };
    save_local(workdir, &local).await?;
    write_manifest(store, &local.manifest).await?;
    local.is_published = true;
    save_local(workdir, &local).await?;

    if let Some(previous) = previous
        && previous.manifest.generation != generation
    {
        delete_generation(store, &id, previous.manifest.generation).await;
    }
    tracing::info!(
        sandbox = id,
        generation,
        memory_bytes = local.memory.stored_bytes(),
        scratch_bytes = local.scratch_index.stored_bytes(),
        took_ms = started.elapsed().as_millis() as u64,
        "sandbox state is in the object store"
    );
    Ok(local)
}

/// Records in the store that the sandbox is about to run on `node_id`, which
/// a node must do before it starts the guest.
pub async fn mark_running(
    store: &ObjectStore,
    workdir: &Path,
    local: &mut LocalState,
    node_id: &str,
) -> Result<(), Status> {
    let mut manifest = local.manifest.clone();
    manifest.state = STATE_RUNNING.to_string();
    manifest.node_id = node_id.to_string();
    write_manifest(store, &manifest).await?;
    local.manifest = manifest;
    save_local(workdir, local).await
}

pub async fn read_manifest(store: &ObjectStore, id: &str) -> Result<Option<Manifest>, Status> {
    let Some(bytes) = store.get_bytes(&manifest_key(id)).await? else {
        return Ok(None);
    };
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|err| Status::data_loss(format!("sandbox {id}'s stored manifest: {err}")))?;
    if manifest.format != FORMAT {
        return Err(Status::failed_precondition(format!(
            "sandbox {id} was stored by another build of burrowd"
        )));
    }
    Ok(Some(manifest))
}

pub async fn write_manifest(store: &ObjectStore, manifest: &Manifest) -> Result<(), Status> {
    let json = serde_json::to_vec_pretty(manifest)
        .map_err(|err| Status::internal(format!("encoding the manifest: {err}")))?;
    store.put_bytes(&manifest_key(&manifest.id), json).await
}

async fn delete_generation(store: &ObjectStore, id: &str, generation: u64) {
    let prefix = format!("sandboxes/{id}/{generation}/");
    match store.list(&prefix).await {
        Ok(keys) => {
            for key in keys {
                let _ = store.delete(&key).await;
            }
        }
        Err(err) => tracing::debug!(sandbox = id, %err, "could not remove an old generation"),
    }
}

/// Removes everything stored for a sandbox. The manifest goes first, so a node
/// reading it mid-purge finds nothing rather than a generation half deleted.
/// Chunks are left to the collector, since other images may share them.
pub async fn purge(store: &ObjectStore, id: &str) -> Result<(), Status> {
    store.delete(&manifest_key(id)).await?;
    for key in store.list(&sandbox_prefix(id)).await? {
        store.delete(&key).await?;
    }
    Ok(())
}

/// Brings a stored sandbox's state into `dest` for a restore: everything but
/// memory up front, memory as it is asked for.
pub async fn stage(
    store: &ObjectStore,
    snapshots: &crate::snapshot::SnapshotStore,
    manifest: &Manifest,
    dest: &Path,
) -> Result<(Vec<String>, Option<Arc<Hydrator>>), Status> {
    let id = &manifest.id;
    let generation = manifest.generation;
    let missing =
        |file: &str| Status::not_found(format!("sandbox {id}'s stored state is missing {file}"));
    let started = std::time::Instant::now();
    let vmstate = burrow_firecracker::SNAPSHOT_FILE;
    let memory_file = burrow_firecracker::SNAPSHOT_MEM_FILE;
    // Everything small at once: each is a round trip, and none depends on
    // another.
    let (kernel_path, rootfs_path) = (dest.join(TEMPLATE_KERNEL), dest.join(TEMPLATE_ROOTFS));
    let (vmstate_path, working_set_path) = (dest.join(vmstate), dest.join(WORKING_SET));
    let vmstate_key = generation_key(id, generation, vmstate);
    let working_set_key = generation_key(id, generation, WORKING_SET);
    let scratch_key = index_key(id, generation, SCRATCH_IMAGE);
    let memory_key = index_key(id, generation, memory_file);
    let (kernel, rootfs, vmstate_fetched, working_set, scratch_index, memory) = tokio::join!(
        snapshots.fetch_blob(store, &manifest.kernel_digest, &kernel_path),
        snapshots.fetch_blob(store, &manifest.rootfs_digest, &rootfs_path),
        store.get_to_file(&vmstate_key, &vmstate_path),
        store.get_to_file(&working_set_key, &working_set_path),
        crate::snapshot::read_index(store, &scratch_key),
        crate::snapshot::read_index(store, &memory_key),
    );
    kernel?;
    rootfs?;
    vmstate_fetched?.ok_or_else(|| missing(vmstate))?;
    let scratch_index = scratch_index?.ok_or_else(|| missing(SCRATCH_IMAGE))?;
    let memory = memory?.ok_or_else(|| missing(memory_file))?;
    let working_set = match working_set? {
        Some(()) => read_offsets(&working_set_path).await,
        None => Vec::new(),
    };
    let fetched_small = started.elapsed();

    let hydrator = Hydrator::begin(store.clone(), memory.clone(), &dest.join(memory_file))
        .map_err(|err| Status::internal(format!("preparing guest memory: {err}")))?;
    // The pages the guest was using, fetched alongside the scratch disk
    // rather than one fault at a time once it runs. A failure here costs
    // only faults later, which fetch for themselves. The rest of the image
    // waits until both are in: it is what the guest does not need yet, and
    // fetching it alongside them only makes the restore wait longer.
    let warming = {
        let hydrator = Arc::clone(&hydrator);
        tokio::task::spawn_blocking(move || {
            use burrow_firecracker::PageSource as _;
            hydrator.ensure_all(&working_set, PAGE)
        })
    };
    let scratch_path = dest.join(SCRATCH_IMAGE);
    let (scratch, warmed) = tokio::join!(
        crate::chunks::get_image(store, &scratch_index, &scratch_path),
        warming
    );
    scratch?;
    if let Ok(Err(err)) = warmed {
        tracing::warn!(sandbox = %id, %err, "could not fetch the working set ahead of the guest");
    }
    hydrator.start();
    let fetched_scratch = started.elapsed();

    let io = |what: &str, err: std::io::Error| Status::internal(format!("{what}: {err}"));
    let stamp = |file: &str| Stamp::of(&dest.join(file)).map_err(|err| io(file, err));
    let local = LocalState {
        manifest: manifest.clone(),
        is_published: true,
        layers: vec![LayerId::of(dest, memory_file).map_err(|err| io(memory_file, err))?],
        vmstate: stamp(vmstate)?,
        scratch: stamp(SCRATCH_IMAGE)?,
        kernel: stamp(TEMPLATE_KERNEL)?,
        rootfs: stamp(TEMPLATE_ROOTFS)?,
        memory,
        scratch_index,
    };
    save_local(dest, &local).await?;
    tracing::info!(
        sandbox = %id,
        small_ms = fetched_small.as_millis() as u64,
        scratch_and_working_set_ms = (fetched_scratch - fetched_small).as_millis() as u64,
        scratch_bytes = local.scratch_index.stored_bytes(),
        rest_ms = (started.elapsed() - fetched_scratch).as_millis() as u64,
        "staged stored state"
    );
    Ok((vec![memory_file.to_string()], Some(hydrator)))
}

const PAGE: u64 = 4096;

/// A plan file's offsets: little-endian `u64`s, the page-fault handler's
/// format. One that cannot be read is empty, since a plan only saves faults.
async fn read_offsets(path: &Path) -> Vec<u64> {
    tokio::fs::read(path)
        .await
        .unwrap_or_default()
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8 bytes")))
        .collect()
}

/// Folds an adopted sandbox's working set into its prefetch plan, so the
/// restore populates both before the guest runs. Written by rename, because
/// the plan may be a link to the template's.
pub async fn merge_working_set(workdir: &Path, plan: &str) -> std::io::Result<bool> {
    let mut offsets = read_offsets(&workdir.join(WORKING_SET)).await;
    if offsets.is_empty() {
        return Ok(false);
    }
    offsets.extend(read_offsets(&workdir.join(plan)).await);
    offsets.sort_unstable();
    offsets.dedup();
    let bytes: Vec<u8> = offsets.iter().flat_map(|o| o.to_le_bytes()).collect();
    let temp = workdir.join(format!(".{plan}.merging"));
    tokio::fs::write(&temp, bytes).await?;
    tokio::fs::rename(&temp, workdir.join(plan)).await?;
    Ok(true)
}

/// Deletes chunks and old generations nothing references any more.
///
/// Run by every node with the store, unsynchronised: deletes are idempotent,
/// and everything younger than [`GARBAGE_GRACE`] is left whatever it looks
/// like, which covers an upload that has put its chunks but not yet the
/// manifest that names them.
pub async fn collect_garbage(
    store: &ObjectStore,
    snapshots: &crate::snapshot::SnapshotStore,
) -> Result<(), Status> {
    let mut referenced = HashSet::new();
    snapshots.remote_chunk_refs(&mut referenced).await?;

    let objects = store.list_aged("sandboxes/").await?;
    let mut current: HashMap<String, u64> = HashMap::new();
    for (key, _) in &objects {
        let Some(id) = key
            .strip_prefix("sandboxes/")
            .and_then(|rest| rest.strip_suffix(&format!("/{MANIFEST}")))
        else {
            continue;
        };
        let Ok(Some(manifest)) = read_manifest(store, id).await else {
            continue;
        };
        for file in [burrow_firecracker::SNAPSHOT_MEM_FILE, SCRATCH_IMAGE] {
            if let Some(index) =
                crate::snapshot::read_index(store, &index_key(id, manifest.generation, file))
                    .await?
            {
                referenced.extend(index.digests().map(str::to_string));
            }
        }
        current.insert(id.to_string(), manifest.generation);
    }

    let cutoff = std::time::SystemTime::now() - GARBAGE_GRACE;
    let mut stale = 0;
    for (key, modified) in &objects {
        let Some((id, rest)) = key
            .strip_prefix("sandboxes/")
            .and_then(|rest| rest.split_once('/'))
        else {
            continue;
        };
        if rest == MANIFEST || modified.is_none_or(|at| at > cutoff) {
            continue;
        }
        let generation = rest
            .split_once('/')
            .and_then(|(g, _)| g.parse::<u64>().ok());
        if generation.is_some() && generation == current.get(id).copied() {
            continue;
        }
        if store.delete(key).await.is_ok() {
            stale += 1;
        }
    }

    let removed = crate::chunks::collect_garbage(store, &referenced, GARBAGE_GRACE).await?;
    if removed > 0 || stale > 0 {
        tracing::info!(
            chunks = removed,
            objects = stale,
            "collected unreferenced stored state"
        );
    }
    Ok(())
}
