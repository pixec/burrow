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
//!
//! Every write that hands the sandbox to a node is conditional on the version
//! of the manifest it was decided on (`If-Match` on its ETag, `If-None-Match`
//! for the first), so two nodes that both read it suspended cannot both take
//! it: one write lands and the other is refused before anything starts. A
//! node writing as the holder checks the manifest still names it, so one the
//! sandbox moved off cannot write over the node running it now. Together with
//! the lease a node holds through its heartbeats, that is what keeps one
//! sandbox from running in two places.
//!
//! Layout, under the store's prefix:
//!
//! ```text
//! sandboxes/<id>/manifest.json
//! sandboxes/<id>/<generation>/<state>
//! sandboxes/<id>/<generation>/<memory>.index.json
//! sandboxes/<id>/<generation>/scratch.ext4.index.json
//! sandboxes/<id>/<generation>/command-logs.json
//! chunks/<sha256>
//! blobs/<digest>
//! ```
//!
//! `<state>` and `<memory>` are the sandbox's hypervisor's [`burrow_vmm::Layout`].

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
/// The sandbox's command logs, by file name, as chunked images.
const COMMAND_LOGS: &str = "command-logs.json";

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
    /// The version of `hypervisor` that wrote the state.
    pub firecracker_version: String,
    /// The sandbox's hypervisor, the only one its state restores under. Empty
    /// in a manifest from before there was a choice, which was Firecracker.
    #[serde(default)]
    pub hypervisor: String,
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

impl Manifest {
    pub fn hypervisor(&self) -> Result<burrow_vmm::Hypervisor, Status> {
        burrow_vmm::Hypervisor::from_record(&self.hypervisor).ok_or_else(|| {
            Status::failed_precondition(format!(
                "sandbox {} was stored under {:?}, which this build does not know",
                self.id, self.hypervisor
            ))
        })
    }

    fn layout(&self) -> Result<burrow_vmm::Layout, Status> {
        self.hypervisor().map(burrow_vmm::Hypervisor::layout)
    }
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
    #[serde(default)]
    pub logs: std::collections::BTreeMap<String, LogImage>,
}

/// One command log file as uploaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogImage {
    pub stamp: Stamp,
    pub index: ImageIndex,
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
            && self.manifest.layout().is_ok_and(|layout| {
                Stamp::of(&workdir.join(layout.state)).is_ok_and(|now| now == self.vmstate)
            })
            && Stamp::of(&workdir.join(SCRATCH_IMAGE)).is_ok_and(|now| now == self.scratch)
    }

    fn digests(&self) -> HashSet<String> {
        self.memory
            .digests()
            .chain(self.scratch_index.digests())
            .chain(self.logs.values().flat_map(|log| log.index.digests()))
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

/// The memory image a stored sandbox is made of. A backend whose memory lives
/// inside a host-bound state file has none to chunk or rehydrate elsewhere,
/// so its state cannot be stored.
fn memory_file(layout: burrow_vmm::Layout) -> Result<&'static str, Status> {
    layout.memory.ok_or_else(|| {
        Status::failed_precondition(
            "this hypervisor keeps guest memory inside its saved state, which cannot be stored",
        )
    })
}

/// Uploads a suspended sandbox's state, returning what was stored.
///
/// `draft` carries what the manifest says about the sandbox; the generation,
/// digests and state are filled in here. `previous` is the last upload, whose
/// chunks are reused where the layers they came from are unchanged.
pub async fn upload(
    store: &ObjectStore,
    workdir: &Path,
    logs_dir: &Path,
    chain: &[String],
    draft: Manifest,
    previous: Option<&LocalState>,
) -> Result<LocalState, Status> {
    let io = |what: &str, err: std::io::Error| Status::internal(format!("{what}: {err}"));
    let started = std::time::Instant::now();
    let id = draft.id.clone();
    let layout = draft.layout()?;
    let memory_file = memory_file(layout)?;
    let layers = chain
        .iter()
        .map(|name| LayerId::of(workdir, name))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|err| io("reading the memory chain", err))?;
    let stamp = |file: &str| Stamp::of(&workdir.join(file)).map_err(|err| io(file, err));
    let vmstate = stamp(layout.state)?;
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

    let logs = upload_logs(store, logs_dir, previous, &known).await?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let generation = now_ms.max(previous.map_or(0, |p| p.manifest.generation + 1));
    store
        .put_file(
            &generation_key(&id, generation, layout.state),
            &workdir.join(layout.state),
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
    for (file, index) in [(memory_file, &memory), (SCRATCH_IMAGE, &scratch_index)] {
        let json = serde_json::to_vec(index)
            .map_err(|err| Status::internal(format!("encoding an index: {err}")))?;
        store
            .put_bytes(&index_key(&id, generation, file), json)
            .await?;
    }
    let indexes: std::collections::BTreeMap<&String, &ImageIndex> =
        logs.iter().map(|(name, log)| (name, &log.index)).collect();
    let json = serde_json::to_vec(&indexes)
        .map_err(|err| Status::internal(format!("encoding an index: {err}")))?;
    store
        .put_bytes(&generation_key(&id, generation, COMMAND_LOGS), json)
        .await?;

    // The sandbox's files were read without holding them still. A resume
    // cancels the upload before it starts the guest, so a change here is a
    // bug rather than a race, and is refused rather than published.
    if stamp(layout.state)? != vmstate || stamp(SCRATCH_IMAGE)? != scratch {
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
        logs,
    };
    save_local(workdir, &local).await?;
    // A previous upload that never heard back may or may not have landed.
    let may_create = previous.is_none_or(|previous| !previous.is_published);
    write_held(store, &local.manifest.node_id, &local.manifest, may_create).await?;
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
/// a node must do before it starts the guest. Refused when the store says
/// another node holds it now.
pub async fn mark_running(
    store: &ObjectStore,
    workdir: &Path,
    local: &mut LocalState,
    node_id: &str,
) -> Result<(), Status> {
    let mut manifest = local.manifest.clone();
    manifest.state = STATE_RUNNING.to_string();
    manifest.node_id = node_id.to_string();
    write_held(store, node_id, &manifest, false).await?;
    local.manifest = manifest;
    save_local(workdir, local).await
}

/// A sandbox's manifest as the store holds it, with the ETag it was read at.
#[derive(Debug)]
pub struct Held {
    pub manifest: Manifest,
    etag: String,
}

pub async fn read_manifest(store: &ObjectStore, id: &str) -> Result<Option<Held>, Status> {
    let Some((bytes, etag)) = store.get_bytes_versioned(&manifest_key(id)).await? else {
        return Ok(None);
    };
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|err| Status::data_loss(format!("sandbox {id}'s stored manifest: {err}")))?;
    if manifest.format != FORMAT {
        return Err(Status::failed_precondition(format!(
            "sandbox {id} was stored by another build of burrowd"
        )));
    }
    Ok(Some(Held { manifest, etag }))
}

/// Writes `next` over the manifest `held` was read as, or as the sandbox's
/// first when `held` is `None`.
///
/// This is the lease. The write is conditional on the version read, so of
/// two nodes that read the same manifest and both try to take the sandbox,
/// one lands and the other is refused here, naming the holder, before it has
/// started anything.
pub async fn replace_manifest(
    store: &ObjectStore,
    held: Option<&Held>,
    next: &Manifest,
) -> Result<Held, Status> {
    let json = serde_json::to_vec_pretty(next)
        .map_err(|err| Status::internal(format!("encoding the manifest: {err}")))?;
    let key = manifest_key(&next.id);
    match store
        .put_bytes_if(&key, json, held.map(|held| held.etag.as_str()))
        .await?
    {
        Some(etag) => Ok(Held {
            manifest: next.clone(),
            etag,
        }),
        None => {
            let current = read_manifest(store, &next.id).await?;
            Err(lost(&next.id, current.as_ref()))
        }
    }
}

/// Writes `next` for a sandbox the store must record as held by `holder`, or,
/// when `may_create`, have nothing for yet.
///
/// Only a node writes its own name in, and a failed adopt hands back exactly
/// what it read, so while the manifest names `holder` no other node runs the
/// sandbox, whatever else changed.
pub async fn write_held(
    store: &ObjectStore,
    holder: &str,
    next: &Manifest,
    may_create: bool,
) -> Result<Held, Status> {
    let current = read_manifest(store, &next.id).await?;
    match &current {
        Some(held) if held.manifest.node_id == holder => {
            replace_manifest(store, Some(held), next).await
        }
        None if may_create => replace_manifest(store, None, next).await,
        _ => Err(lost(&next.id, current.as_ref())),
    }
}

fn lost(id: &str, current: Option<&Held>) -> Status {
    match current {
        Some(held) => Status::aborted(format!(
            "sandbox {id} is held by node {} in the object store ({}, generation {}); this node \
             lost it and does not run it",
            held.manifest.node_id, held.manifest.state, held.manifest.generation
        )),
        None => Status::aborted(format!(
            "sandbox {id} is no longer in the object store; this node does not run it"
        )),
    }
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
    logs_dir: &Path,
) -> Result<(Vec<String>, Option<Arc<Hydrator>>), Status> {
    let id = &manifest.id;
    let generation = manifest.generation;
    let missing =
        |file: &str| Status::not_found(format!("sandbox {id}'s stored state is missing {file}"));
    let started = std::time::Instant::now();
    let layout = manifest.layout()?;
    let vmstate = layout.state;
    let memory_file = memory_file(layout)?;
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
            use burrow_vmm::PageSource as _;
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
    let logs = stage_logs(store, id, generation, logs_dir).await?;

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
        logs,
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

/// Uploads the sandbox's command logs, each a chunked image so what an
/// earlier upload put is not put again: a log only grows.
async fn upload_logs(
    store: &ObjectStore,
    dir: &Path,
    previous: Option<&LocalState>,
    known: &HashSet<String>,
) -> Result<std::collections::BTreeMap<String, LogImage>, Status> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".log"))
        .collect();
    names.sort();
    let mut logs = std::collections::BTreeMap::new();
    for name in names {
        let Ok(stamp) = Stamp::of(&dir.join(&name)) else {
            continue;
        };
        let held = previous
            .and_then(|p| p.logs.get(&name))
            .filter(|log| log.stamp == stamp);
        let index = match held {
            Some(log) => log.index.clone(),
            None => {
                crate::chunks::put_image(store, dir, std::slice::from_ref(&name), None, known)
                    .await?
            }
        };
        logs.insert(name, LogImage { stamp, index });
    }
    Ok(logs)
}

/// Brings a stored sandbox's command logs into `dir`. A generation uploaded
/// before logs were kept on the node has none.
async fn stage_logs(
    store: &ObjectStore,
    id: &str,
    generation: u64,
    dir: &Path,
) -> Result<std::collections::BTreeMap<String, LogImage>, Status> {
    let key = generation_key(id, generation, COMMAND_LOGS);
    let Some(bytes) = store.get_bytes(&key).await? else {
        return Ok(Default::default());
    };
    let indexes: std::collections::BTreeMap<String, ImageIndex> = serde_json::from_slice(&bytes)
        .map_err(|err| Status::data_loss(format!("index {key} is unreadable: {err}")))?;
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|err| Status::internal(format!("creating {}: {err}", dir.display())))?;
    }
    let mut logs = std::collections::BTreeMap::new();
    for (name, index) in indexes {
        if name.contains('/') || !name.ends_with(".log") {
            continue;
        }
        let path = dir.join(&name);
        crate::chunks::get_image(store, &index, &path).await?;
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|err| Status::internal(format!("{}: {err}", path.display())))?;
        }
        let stamp = Stamp::of(&path)
            .map_err(|err| Status::internal(format!("{}: {err}", path.display())))?;
        logs.insert(name, LogImage { stamp, index });
    }
    Ok(logs)
}

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
        let Ok(Some(Held { manifest, .. })) = read_manifest(store, id).await else {
            continue;
        };
        // Refused rather than skipped: skipping would leave this sandbox's
        // chunks unreferenced, and the sweep below would take them.
        let layout = manifest.layout()?;
        for file in layout.memory.into_iter().chain([SCRATCH_IMAGE]) {
            if let Some(index) =
                crate::snapshot::read_index(store, &index_key(id, manifest.generation, file))
                    .await?
            {
                referenced.extend(index.digests().map(str::to_string));
            }
        }
        if let Some(bytes) = store
            .get_bytes(&generation_key(id, manifest.generation, COMMAND_LOGS))
            .await?
        {
            let logs: std::collections::BTreeMap<String, ImageIndex> =
                serde_json::from_slice(&bytes).map_err(|err| {
                    Status::data_loss(format!(
                        "sandbox {id}'s command log index is unreadable: {err}"
                    ))
                })?;
            referenced.extend(
                logs.values()
                    .flat_map(ImageIndex::digests)
                    .map(str::to_string),
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(node_id: &str, state: &str) -> Manifest {
        Manifest {
            format: FORMAT,
            id: "sbx_1".into(),
            generation: 1,
            node_id: node_id.into(),
            state: state.into(),
            template: "alpine".into(),
            vcpus: 1,
            mem_mib: 512,
            scratch_disk_mib: 1024,
            is_systemd: false,
            arch: "aarch64".into(),
            firecracker_version: "1".into(),
            hypervisor: "firecracker".into(),
            kernel_digest: String::new(),
            rootfs_digest: String::new(),
            cpu_usage_usec: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            secrets: Default::default(),
        }
    }

    /// A move racing a start, or two orchestrators placing one sandbox: both
    /// nodes read it suspended and both claim it. Only one may run it.
    #[tokio::test]
    async fn of_two_nodes_claiming_one_sandbox_only_one_takes_it() {
        let store = crate::objstore::fake::store(true).await;
        replace_manifest(&store, None, &manifest("node-a", STATE_SUSPENDED))
            .await
            .unwrap();
        let held = read_manifest(&store, "sbx_1").await.unwrap().unwrap();
        let (claim_b, claim_c) = (
            manifest("node-b", STATE_RUNNING),
            manifest("node-c", STATE_RUNNING),
        );
        let (b, c) = tokio::join!(
            replace_manifest(&store, Some(&held), &claim_b),
            replace_manifest(&store, Some(&held), &claim_c),
        );
        let (winner, lost) = match (b, c) {
            (Ok(_), Err(lost)) => ("node-b", lost),
            (Err(lost), Ok(_)) => ("node-c", lost),
            (b, c) => panic!(
                "exactly one claim should land: {:?} {:?}",
                b.is_ok(),
                c.is_ok()
            ),
        };
        assert_eq!(lost.code(), tonic::Code::Aborted);
        assert!(lost.message().contains(winner), "{}", lost.message());
        let now = read_manifest(&store, "sbx_1").await.unwrap().unwrap();
        assert_eq!(now.manifest.node_id, winner);
        assert_eq!(now.manifest.state, STATE_RUNNING);
    }

    /// The node the sandbox moved off still has its copy. Neither a resume
    /// nor an upload from it may land over the node that runs it now.
    #[tokio::test]
    async fn a_node_that_lost_the_sandbox_cannot_write_over_its_holder() {
        let store = crate::objstore::fake::store(true).await;
        let suspended = manifest("node-a", STATE_SUSPENDED);
        let held = replace_manifest(&store, None, &suspended).await.unwrap();
        replace_manifest(&store, Some(&held), &manifest("node-b", STATE_RUNNING))
            .await
            .unwrap();

        let stale = write_held(&store, "node-a", &manifest("node-a", STATE_RUNNING), true)
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::Aborted);
        assert!(stale.message().contains("node-b"), "{}", stale.message());
        let first = replace_manifest(&store, None, &suspended)
            .await
            .unwrap_err();
        assert_eq!(first.code(), tonic::Code::Aborted);
        assert_eq!(
            read_manifest(&store, "sbx_1")
                .await
                .unwrap()
                .unwrap()
                .manifest
                .node_id,
            "node-b"
        );

        // A failed adopt hands back exactly what it read, after which the
        // node it came from holds it again.
        write_held(&store, "node-b", &suspended, false)
            .await
            .unwrap();
        write_held(&store, "node-a", &manifest("node-a", STATE_RUNNING), false)
            .await
            .unwrap();
    }
}
