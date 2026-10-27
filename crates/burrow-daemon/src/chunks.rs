//! Disk and memory images in the object store, as content-addressed chunks.
//!
//! An image is cut into fixed chunks, each stored once under its digest at
//! `chunks/<sha256>`, and described by an index naming the digest of every
//! chunk that holds data. Two things follow:
//!
//! - **Uploads cost what changed.** A sandbox suspended a second time shares
//!   almost every chunk with its first suspend, and a snapshot shares most of
//!   its chunks with the sandbox it came from, so only new digests are sent.
//! - **A restore can start before the image has arrived.** A chunk is a unit
//!   that can be fetched on its own, so guest memory is served lazily: the
//!   page-fault handler asks a [`Hydrator`] for the chunk under a fault, while
//!   the rest is filled in behind the running guest.
//!
//! A memory image is always uploaded flattened, the newest layer of a chain
//! winning page by page, so the index describes one file and a restore never
//! has a chain to rebuild remotely.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tonic::Status;

use crate::objstore::ObjectStore;

/// Large enough that a restore is not thousands of requests, small enough that
/// the fault waiting on one is not stalled for long.
pub const CHUNK_SIZE: u64 = 1 << 20;

/// Requests in flight per image, for uploads and background fills alike.
const PARALLELISM: usize = 8;

/// The granularity zeroes are left as holes at. A guest page.
const PAGE: usize = 4096;

/// Beside a file being filled in, holding its index. Its presence is what says
/// the file is incomplete, so a restart that finds one fills the file again
/// rather than trusting it.
const MARKER_SUFFIX: &str = "hydrating";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageIndex {
    pub size: u64,
    pub chunk_size: u64,
    /// Chunk number to digest, for every chunk that holds data. A chunk absent
    /// here is zeroes.
    pub chunks: BTreeMap<u64, String>,
}

impl ImageIndex {
    fn range(&self, chunk: u64) -> (u64, u64) {
        let start = chunk * self.chunk_size;
        (start, (start + self.chunk_size).min(self.size))
    }

    pub fn digests(&self) -> impl Iterator<Item = &str> {
        self.chunks.values().map(String::as_str)
    }

    pub fn stored_bytes(&self) -> u64 {
        self.chunks
            .keys()
            .map(|&n| {
                let (start, end) = self.range(n);
                end - start
            })
            .sum()
    }
}

pub fn chunk_key(digest: &str) -> String {
    format!("chunks/{digest}")
}

/// Which file a layer is, without reading it. A memory layer is never written
/// again once it exists, so the same inode at the same size is the same bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerId {
    pub name: String,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
}

impl LayerId {
    pub fn of(dir: &Path, name: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(dir.join(name))?;
        Ok(Self {
            name: name.to_string(),
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
        })
    }
}

/// What an earlier upload of the same chain already established.
pub struct Reuse<'a> {
    pub index: &'a ImageIndex,
    /// How many of the current layers that upload covered. Only chunks the
    /// layers past these touch can have changed.
    pub covered: usize,
}

#[cfg(target_os = "linux")]
fn extents(file: &std::fs::File) -> std::io::Result<Vec<(u64, u64)>> {
    burrow_firecracker::data_extents(file)
}

#[cfg(not(target_os = "linux"))]
fn extents(file: &std::fs::File) -> std::io::Result<Vec<(u64, u64)>> {
    let size = file.metadata()?.len();
    Ok(if size == 0 {
        Vec::new()
    } else {
        vec![(0, size)]
    })
}

struct OpenLayer {
    file: std::fs::File,
    extents: Vec<(u64, u64)>,
}

impl OpenLayer {
    fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let first = self.extents.partition_point(|&(_, e)| e <= start);
        self.extents[first..]
            .iter()
            .take_while(move |&&(s, _)| s < end)
            .map(move |&(s, e)| (s.max(start), e.min(end)))
    }

    fn chunks(&self, chunk_size: u64) -> impl Iterator<Item = u64> + '_ {
        self.extents
            .iter()
            .flat_map(move |&(s, e)| (s / chunk_size)..e.div_ceil(chunk_size))
    }
}

/// Reads one chunk of the chain as the guest sees it: oldest layer first, each
/// newer one written over it where it holds data.
fn read_merged(layers: &[OpenLayer], start: u64, end: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; (end - start) as usize];
    for layer in layers {
        for (s, e) in layer.overlapping(start, end) {
            layer
                .file
                .read_exact_at(&mut buf[(s - start) as usize..(e - start) as usize], s)?;
        }
    }
    Ok(buf)
}

fn digest_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Uploads a chain of layers, oldest first, as one flattened image.
///
/// `known` holds digests the store is already relied on to have, because the
/// manifest this upload replaces references them. Anything else is put even
/// if it may be there: a chunk only another, deleted, image referenced could
/// be collected between a check and its reuse, and a put refreshes the age
/// the collector judges by.
pub async fn put_image(
    store: &ObjectStore,
    dir: &Path,
    layers: &[String],
    reuse: Option<Reuse<'_>>,
    known: &HashSet<String>,
) -> Result<ImageIndex, Status> {
    let io = |err: std::io::Error| Status::internal(format!("reading an image to upload: {err}"));
    let opened: Vec<OpenLayer> = {
        let paths: Vec<PathBuf> = layers.iter().map(|name| dir.join(name)).collect();
        tokio::task::spawn_blocking(move || {
            paths
                .iter()
                .map(|path| {
                    let file = std::fs::File::open(path)?;
                    let extents = extents(&file)?;
                    Ok(OpenLayer { file, extents })
                })
                .collect::<std::io::Result<Vec<_>>>()
        })
        .await
        .map_err(|err| Status::internal(format!("opening layers: {err}")))?
        .map_err(io)?
    };
    let size = opened
        .iter()
        .map(|layer| layer.file.metadata().map(|m| m.len()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(io)?
        .into_iter()
        .max()
        .unwrap_or(0);

    let mut index = ImageIndex {
        size,
        chunk_size: CHUNK_SIZE,
        chunks: BTreeMap::new(),
    };
    // Chunks a covered layer left alone keep the digest the earlier upload
    // gave them; only what a newer layer touched is read again.
    let (candidates, carried): (Vec<u64>, BTreeMap<u64, String>) = match &reuse {
        Some(reuse) if reuse.index.size == size && reuse.index.chunk_size == CHUNK_SIZE => {
            let dirty: std::collections::BTreeSet<u64> = opened[reuse.covered.min(opened.len())..]
                .iter()
                .flat_map(|layer| layer.chunks(CHUNK_SIZE))
                .collect();
            let carried = reuse
                .index
                .chunks
                .iter()
                .filter(|(n, _)| !dirty.contains(n))
                .map(|(n, d)| (*n, d.clone()))
                .collect();
            (dirty.into_iter().collect(), carried)
        }
        _ => {
            let all: std::collections::BTreeSet<u64> = opened
                .iter()
                .flat_map(|layer| layer.chunks(CHUNK_SIZE))
                .collect();
            (all.into_iter().collect(), BTreeMap::new())
        }
    };
    index.chunks = carried;

    let opened = Arc::new(opened);
    let known = Arc::new(known.clone());
    let read = candidates.len();
    let mut sent = 0usize;
    let mut results = futures::stream::iter(candidates)
        .map(|n| {
            let opened = Arc::clone(&opened);
            let known = Arc::clone(&known);
            let store = store.clone();
            let start = n * CHUNK_SIZE;
            let end = (start + CHUNK_SIZE).min(size);
            async move {
                let bytes = tokio::task::spawn_blocking(move || read_merged(&opened, start, end))
                    .await
                    .map_err(|err| Status::internal(format!("reading a chunk: {err}")))?
                    .map_err(io)?;
                if bytes.iter().all(|&b| b == 0) {
                    return Ok::<_, Status>((n, None, false));
                }
                let digest = digest_of(&bytes);
                if known.contains(&digest) {
                    return Ok((n, Some(digest), false));
                }
                store.put_bytes(&chunk_key(&digest), bytes).await?;
                Ok((n, Some(digest), true))
            }
        })
        .buffer_unordered(PARALLELISM);
    while let Some(result) = results.next().await {
        let (n, digest, put) = result?;
        sent += put as usize;
        match digest {
            Some(digest) => index.chunks.insert(n, digest),
            None => index.chunks.remove(&n),
        };
    }
    tracing::debug!(chunks = index.chunks.len(), read, sent, "image uploaded");
    Ok(index)
}

/// Fetches one chunk and checks it is what its digest says.
async fn fetch_chunk(store: &ObjectStore, digest: &str) -> Result<Vec<u8>, Status> {
    let mut delay = std::time::Duration::from_millis(100);
    let mut attempt = 0;
    loop {
        attempt += 1;
        match store.get_bytes(&chunk_key(digest)).await {
            Ok(Some(bytes)) if digest_of(&bytes) == digest => return Ok(bytes),
            Ok(Some(_)) => {
                return Err(Status::data_loss(format!(
                    "chunk {digest} from the object store does not match its digest"
                )));
            }
            Ok(None) => {
                return Err(Status::data_loss(format!(
                    "chunk {digest} is missing from the object store"
                )));
            }
            Err(err) if attempt < 6 => {
                tracing::debug!(digest, %err, attempt, "chunk fetch failed; retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Writes a chunk at its offset, leaving its zero pages as holes so a filled
/// file is as sparse as the one that was uploaded.
fn write_chunk(file: &std::fs::File, start: u64, bytes: &[u8]) -> std::io::Result<()> {
    let mut run: Option<usize> = None;
    let pages = bytes.len().div_ceil(PAGE);
    for page in 0..=pages {
        let is_data = page < pages && {
            let from = page * PAGE;
            bytes[from..(from + PAGE).min(bytes.len())]
                .iter()
                .any(|&b| b != 0)
        };
        match (is_data, run) {
            (true, None) => run = Some(page * PAGE),
            (false, Some(from)) => {
                let to = (page * PAGE).min(bytes.len());
                file.write_all_at(&bytes[from..to], start + from as u64)?;
                run = None;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Fetches a whole image into `path` before anything uses it.
pub async fn get_image(store: &ObjectStore, index: &ImageIndex, path: &Path) -> Result<(), Status> {
    let file = create_sized(path, index.size)
        .map_err(|err| Status::internal(format!("creating {}: {err}", path.display())))?;
    let file = Arc::new(file);
    let chunks: Vec<(u64, String)> = index
        .chunks
        .iter()
        .map(|(&n, digest)| (index.range(n).0, digest.clone()))
        .collect();
    let mut results = futures::stream::iter(chunks)
        .map(|(start, digest)| {
            let file = Arc::clone(&file);
            let store = store.clone();
            async move {
                let bytes = fetch_chunk(&store, &digest).await?;
                tokio::task::spawn_blocking(move || write_chunk(&file, start, &bytes))
                    .await
                    .map_err(|err| Status::internal(format!("writing a chunk: {err}")))?
                    .map_err(|err| Status::internal(format!("writing a chunk: {err}")))
            }
        })
        .buffer_unordered(PARALLELISM);
    while let Some(result) = results.next().await {
        result?;
    }
    file.sync_data()
        .map_err(|err| Status::internal(format!("flushing {}: {err}", path.display())))
}

fn create_sized(path: &Path, size: u64) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(size)?;
    Ok(file)
}

pub fn marker_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(MARKER_SUFFIX);
    path.with_file_name(name)
}

fn write_marker(path: &Path, index: &ImageIndex) -> std::io::Result<()> {
    let marker = marker_path(path);
    let temp = marker.with_extension("tmp");
    std::fs::write(
        &temp,
        serde_json::to_vec(index).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&temp, &marker)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Missing,
    Fetching,
    Present,
}

struct State {
    slots: HashMap<u64, Slot>,
    remaining: usize,
    /// Every name the file is reachable by that carries a marker, removed
    /// together once it is complete.
    markers: Vec<PathBuf>,
}

/// A memory file being filled in from the object store while a guest runs on
/// it.
///
/// Faults and the background fill both go through [`Self::claim`], so a chunk
/// is fetched once whoever wants it first, and a fault for a chunk the fill is
/// already fetching waits for that fetch rather than starting another.
pub struct Hydrator {
    path: PathBuf,
    file: std::fs::File,
    index: ImageIndex,
    store: ObjectStore,
    runtime: tokio::runtime::Handle,
    state: Mutex<State>,
    arrived: Condvar,
    done: tokio::sync::watch::Sender<bool>,
    cancelled: std::sync::atomic::AtomicBool,
}

impl Hydrator {
    /// Starts filling a new file at `path` from `index`.
    pub fn begin(store: ObjectStore, index: ImageIndex, path: &Path) -> std::io::Result<Arc<Self>> {
        let file = create_sized(path, index.size)?;
        write_marker(path, &index)?;
        Ok(Self::new(store, index, path, file))
    }

    /// Picks up a fill a restart interrupted, if `path` has one. Nothing
    /// written before the restart is trusted: a chunk may have been half way
    /// through its write.
    pub fn resume(store: ObjectStore, path: &Path) -> Option<std::io::Result<Arc<Self>>> {
        let bytes = std::fs::read(marker_path(path)).ok()?;
        Some((|| {
            let index: ImageIndex =
                serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?;
            file.set_len(index.size)?;
            Ok(Self::new(store, index, path, file))
        })())
    }

    fn new(store: ObjectStore, index: ImageIndex, path: &Path, file: std::fs::File) -> Arc<Self> {
        let slots: HashMap<u64, Slot> = index.chunks.keys().map(|&n| (n, Slot::Missing)).collect();
        let remaining = slots.len();
        let hydrator = Arc::new(Self {
            path: path.to_path_buf(),
            file,
            store,
            runtime: tokio::runtime::Handle::current(),
            state: Mutex::new(State {
                slots,
                remaining,
                markers: vec![marker_path(path)],
            }),
            arrived: Condvar::new(),
            done: tokio::sync::watch::channel(false).0,
            cancelled: std::sync::atomic::AtomicBool::new(false),
            index,
        });
        if remaining == 0 {
            hydrator.complete(&mut hydrator.state.lock().unwrap());
        }
        hydrator
    }

    /// Fills in every chunk no fault has asked for yet, behind the guest.
    pub fn start(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move { this.fill().await });
    }

    /// Forgets one name of the file, for one reader that is gone. A snapshot
    /// and the sandboxes restored from it share a fill, so it stops only once
    /// no name is left that anything will read.
    pub fn detach(&self, path: &Path) {
        let marker = marker_path(path);
        let mut state = self.state.lock().unwrap();
        state.markers.retain(|held| *held != marker);
        let _ = std::fs::remove_file(&marker);
        if state.markers.is_empty() {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn is_complete(&self) -> bool {
        *self.done.borrow()
    }

    /// Waits for the whole file to be present.
    pub async fn wait(&self) {
        let mut done = self.done.subscribe();
        let _ = done.wait_for(|done| *done).await;
    }

    /// Gives the file a second name, marked as incomplete for as long as it
    /// is. Returns whether it still is.
    pub fn link_to(&self, dest: &Path) -> std::io::Result<bool> {
        let mut state = self.state.lock().unwrap();
        std::fs::hard_link(&self.path, dest)?;
        if state.remaining == 0 {
            return Ok(false);
        }
        write_marker(dest, &self.index)?;
        state.markers.push(marker_path(dest));
        Ok(true)
    }

    /// Takes a chunk to fetch, or waits out someone else's fetch of it.
    /// `None` means it is already present.
    fn claim(&self, n: u64, wait: bool) -> Option<()> {
        let mut state = self.state.lock().unwrap();
        loop {
            match state.slots.get(&n).copied() {
                None | Some(Slot::Present) => return None,
                Some(Slot::Fetching) if wait => state = self.arrived.wait(state).unwrap(),
                Some(Slot::Fetching) => return None,
                Some(Slot::Missing) => {
                    state.slots.insert(n, Slot::Fetching);
                    return Some(());
                }
            }
        }
    }

    fn settle(&self, n: u64, result: &Result<(), Status>) {
        let mut state = self.state.lock().unwrap();
        if result.is_ok() {
            state.slots.insert(n, Slot::Present);
            state.remaining -= 1;
            if state.remaining == 0 {
                self.complete(&mut state);
            }
        } else {
            state.slots.insert(n, Slot::Missing);
        }
        drop(state);
        self.arrived.notify_all();
    }

    fn complete(&self, state: &mut State) {
        if let Err(err) = self.file.sync_data() {
            tracing::warn!(path = %self.path.display(), %err, "could not flush a filled image");
            return;
        }
        for marker in state.markers.drain(..) {
            let _ = std::fs::remove_file(marker);
        }
        self.done.send_replace(true);
        tracing::info!(
            path = %self.path.display(),
            bytes = self.index.stored_bytes(),
            "image fully arrived from the object store"
        );
    }

    async fn fetch(&self, n: u64) -> Result<Vec<u8>, Status> {
        fetch_chunk(&self.store, &self.index.chunks[&n]).await
    }

    fn write(&self, n: u64, bytes: &[u8]) -> Result<(), Status> {
        write_chunk(&self.file, self.index.range(n).0, bytes)
            .map_err(|err| Status::internal(format!("writing {}: {err}", self.path.display())))
    }

    async fn fill(self: Arc<Self>) {
        let started = std::time::Instant::now();
        let mut backoff = std::time::Duration::from_secs(1);
        loop {
            if self.is_complete() || self.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let wanted: Vec<u64> = {
                let state = self.state.lock().unwrap();
                let mut wanted: Vec<u64> = state
                    .slots
                    .iter()
                    .filter(|(_, slot)| **slot == Slot::Missing)
                    .map(|(n, _)| *n)
                    .collect();
                wanted.sort_unstable();
                wanted
            };
            let failed = std::sync::atomic::AtomicUsize::new(0);
            futures::stream::iter(wanted)
                .for_each_concurrent(PARALLELISM, |n| {
                    let this = Arc::clone(&self);
                    let failed = &failed;
                    async move {
                        if this.cancelled.load(std::sync::atomic::Ordering::Relaxed)
                            || this.claim(n, false).is_none()
                        {
                            return;
                        }
                        let result = match this.fetch(n).await {
                            Ok(bytes) => {
                                let writer = Arc::clone(&this);
                                tokio::task::spawn_blocking(move || writer.write(n, &bytes))
                                    .await
                                    .unwrap_or_else(|err| {
                                        Err(Status::internal(format!("writing a chunk: {err}")))
                                    })
                            }
                            Err(err) => Err(err),
                        };
                        if let Err(err) = &result {
                            failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::warn!(path = %this.path.display(), chunk = n, %err, "could not fill a chunk");
                        }
                        this.settle(n, &result);
                    }
                })
                .await;
            if failed.into_inner() > 0 {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
            } else {
                // Whatever is left is a fault's fetch still in flight.
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        tracing::debug!(
            path = %self.path.display(),
            took_ms = started.elapsed().as_millis() as u64,
            "background fill finished"
        );
    }

    /// Fetches the chunks `numbers` names that nobody has yet, in parallel,
    /// from a thread outside the runtime.
    fn ensure_chunks(&self, numbers: impl IntoIterator<Item = u64>) -> std::io::Result<()> {
        let mut claimed = Vec::new();
        let mut waited = Vec::new();
        for n in numbers {
            match self.claim(n, false) {
                Some(()) => claimed.push(n),
                None => waited.push(n),
            }
        }
        let fetched: Vec<(u64, Result<Vec<u8>, Status>)> = self.runtime.block_on(
            futures::stream::iter(claimed)
                .map(|n| async move { (n, self.fetch(n).await) })
                .buffer_unordered(PARALLELISM * 2)
                .collect(),
        );
        let mut first_error = None;
        for (n, bytes) in fetched {
            let result = bytes.and_then(|bytes| self.write(n, &bytes));
            self.settle(n, &result);
            if let Err(err) = result {
                first_error.get_or_insert(err);
            }
        }
        if let Some(err) = first_error {
            return Err(std::io::Error::other(err.message().to_string()));
        }
        // Chunks someone else was fetching: wait for theirs, and fetch any
        // whose fetch failed.
        for n in waited {
            while self.claim(n, true).is_some() {
                let result = self
                    .runtime
                    .block_on(self.fetch(n))
                    .and_then(|bytes| self.write(n, &bytes));
                self.settle(n, &result);
                result.map_err(|err| std::io::Error::other(err.message().to_string()))?;
            }
        }
        Ok(())
    }
}

impl burrow_firecracker::PageSource for Hydrator {
    fn extents(&self) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = Vec::new();
        for &n in self.index.chunks.keys() {
            let (start, end) = self.index.range(n);
            match out.last_mut() {
                Some(last) if last.1 == start => last.1 = end,
                _ => out.push((start, end)),
            }
        }
        out
    }

    fn ensure(&self, offset: u64, len: u64) -> std::io::Result<()> {
        let chunk = self.index.chunk_size;
        self.ensure_chunks((offset / chunk)..(offset + len).div_ceil(chunk))
    }

    fn ensure_all(&self, offsets: &[u64], page_size: u64) -> std::io::Result<()> {
        let chunk = self.index.chunk_size;
        let numbers: std::collections::BTreeSet<u64> = offsets
            .iter()
            .flat_map(|&offset| (offset / chunk)..(offset + page_size).div_ceil(chunk))
            .collect();
        self.ensure_chunks(numbers)
    }
}

/// Collects chunks no index references any more.
///
/// `referenced` must be gathered before the chunk listing is read, and a chunk
/// younger than `grace` is kept whether referenced or not: an upload puts its
/// chunks before the manifest naming them, and that window must not look like
/// garbage.
pub async fn collect_garbage(
    store: &ObjectStore,
    referenced: &HashSet<String>,
    grace: std::time::Duration,
) -> Result<usize, Status> {
    let cutoff = std::time::SystemTime::now() - grace;
    let mut removed = 0;
    for (key, modified) in store.list_aged("chunks/").await? {
        let Some(digest) = key.strip_prefix("chunks/") else {
            continue;
        };
        if referenced.contains(digest) || modified.is_none_or(|at| at > cutoff) {
            continue;
        }
        store.delete(&key).await?;
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_pages_are_left_as_holes() {
        let dir = std::env::temp_dir().join(format!("burrow-chunks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image");
        let file = create_sized(&path, 4 * PAGE as u64).unwrap();
        let mut bytes = vec![0u8; 3 * PAGE];
        bytes[PAGE + 7] = 1;
        bytes[3 * PAGE - 1] = 2;
        write_chunk(&file, PAGE as u64, &bytes).unwrap();
        let read = std::fs::read(&path).unwrap();
        assert_eq!(read.len(), 4 * PAGE);
        assert_eq!(read[2 * PAGE + 7], 1);
        assert_eq!(read[4 * PAGE - 1], 2);
        assert_eq!(read.iter().filter(|&&b| b != 0).count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_layer_wins_where_it_holds_data() {
        let dir = std::env::temp_dir().join(format!("burrow-merge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("base"), vec![1u8; 8]).unwrap();
        std::fs::write(dir.join("diff"), [0, 0, 9, 9]).unwrap();
        let layers = vec![
            OpenLayer {
                file: std::fs::File::open(dir.join("base")).unwrap(),
                extents: vec![(0, 8)],
            },
            OpenLayer {
                file: std::fs::File::open(dir.join("diff")).unwrap(),
                extents: vec![(2, 4)],
            },
        ];
        assert_eq!(
            read_merged(&layers, 0, 8).unwrap(),
            [1, 1, 9, 9, 1, 1, 1, 1]
        );
        assert_eq!(read_merged(&layers, 3, 6).unwrap(), [9, 1, 1]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extents_map_to_the_chunks_they_touch() {
        let layer = OpenLayer {
            file: std::fs::File::open("/dev/null").unwrap(),
            extents: vec![(0, 10), (CHUNK_SIZE * 3 - 1, CHUNK_SIZE * 3 + 1)],
        };
        assert_eq!(layer.chunks(CHUNK_SIZE).collect::<Vec<_>>(), vec![0, 2, 3]);
    }
}
