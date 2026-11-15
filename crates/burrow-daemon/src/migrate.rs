//! Exists only to carry object stores written in the format before casync
//! chunks across one release. The release after removes this module, its
//! start and fleet report in `serve`, its call in [`crate::chunks`], the
//! legacy keys in [`crate::snapshot`]'s delete and collector and in
//! [`crate::rootdisk`]'s collector, and its command.
//!
//! That format kept each chunk uncompressed at `chunks/<sha256>` and each
//! index as JSON at `<name>.index.json`. Chunk ids are the same SHA-256 in
//! both, so migrating is rewriting objects: each chunk compressed to its
//! casync path, each index encoded as `<name>.caibx` beside its JSON.
//!
//! A node on the old build may share the store for a while, and its
//! collector deletes every `chunks/` object no `.index.json` names. So until
//! the orchestrator reports every node upgraded, nothing old is deleted:
//!
//! - A restore that meets an object only the old format has reads it from
//!   there ([`on_demand`]). A chunk is copied to its new path on the way; an
//!   index is decoded but not written, since a `.caibx` is only ever written
//!   once every chunk it names is in `chunks.castr/`.
//! - A background pass copies every live old index's chunks and then writes
//!   its `.caibx`, so new uploads and the new collector never depend on an
//!   old object.
//!
//! Once every node is upgraded the pass also retires the old objects: each old
//! chunk is put again in the new format, which refreshes its age for the
//! collector, read back, and only then deleted; old indexes go last, after
//! every chunk. Any number of nodes may run passes at once: a chunk's object
//! is named by its content and an index's encoding is a function of its JSON,
//! so two nodes write the same thing, and a delete another node got to first
//! is not an error.

#![allow(clippy::result_large_err)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt as _;
use sha2::{Digest as _, Sha256};
use tonic::Status;

use crate::chunks::{ImageIndex, chunk_key};
use crate::objstore::ObjectStore;

const LEGACY_CHUNKS: &str = "chunks/";
const LEGACY_INDEX: &str = ".index.json";
/// Where the old format kept indexes.
const OWNERS: [&str; 4] = ["images/", "snapshots/", "sandboxes/", "volumes/"];
/// Long enough that a node's restores after a restart are not queued behind
/// the pass.
const START_AFTER: Duration = Duration::from_secs(60);
const RETRY_AFTER: Duration = Duration::from_secs(600);
const PROGRESS_EVERY: Duration = Duration::from_secs(30);
/// Chunks migrated at once, each a core's worth of compression at most, so a
/// pass leaves the node's CPU and upload slots to its sandboxes.
const PARALLELISM: usize = 2;

/// What the orchestrator last said about the fleet: every registered node is
/// on a build that keeps chunks as casync does.
static FLEET_UPGRADED: AtomicBool = AtomicBool::new(false);

pub fn set_fleet_upgraded(is_upgraded: bool) {
    FLEET_UPGRADED.store(is_upgraded, Ordering::Relaxed);
}

/// Runs passes behind the node's start until the store holds nothing in the
/// old format.
pub fn start(store: ObjectStore) {
    tokio::spawn(async move {
        tokio::time::sleep(START_AFTER).await;
        let mut waiting_said = false;
        loop {
            let may_delete = FLEET_UPGRADED.load(Ordering::Relaxed);
            if !may_delete && !waiting_said {
                tracing::info!(
                    "old-format objects in the object store are copied but kept until every node \
                     runs a build that keeps chunks as casync does"
                );
                waiting_said = true;
            }
            match run(&store, may_delete).await {
                Ok(true) => {
                    tracing::info!(
                        "the background migration from the format before casync is finished; \
                         anything an old build writes from now on is found only by \
                         `burrowd migrate-chunks --check`"
                    );
                    return;
                }
                Ok(false) => {}
                Err(err) => tracing::warn!(
                    err = err.message(),
                    "migrating the object store from the format before casync; trying again later"
                ),
            }
            tokio::time::sleep(RETRY_AFTER).await;
        }
    });
}

/// The object the current format keeps at `key`, read from the old format
/// when only that has it, or `None` when neither has it.
pub async fn on_demand(store: &ObjectStore, key: &str) -> Result<Option<Vec<u8>>, Status> {
    let Some(legacy) = crate::chunks::legacy_key(key) else {
        return Ok(None);
    };
    let migrated = match legacy.strip_prefix(LEGACY_CHUNKS) {
        Some(digest) => copy_chunk(store, digest).await?,
        None => match read_legacy_index(store, &legacy).await? {
            Some(index) => {
                tracing::info!(key, "read an index from the format before casync");
                Some(encode(&legacy, &index)?)
            }
            None => None,
        },
    };
    match migrated {
        Some(bytes) => Ok(Some(bytes)),
        // Another node may have migrated it, and removed the old object,
        // since the first read.
        None => store.get_bytes(key).await,
    }
}

/// Puts an old chunk at its new path, checked against its digest first.
/// Returns what was put, or `None` when the old chunk is gone.
async fn copy_chunk(store: &ObjectStore, digest: &str) -> Result<Option<Vec<u8>>, Status> {
    let legacy = format!("{LEGACY_CHUNKS}{digest}");
    let Some(bytes) = store.get_bytes(&legacy).await? else {
        return Ok(None);
    };
    let digest = digest.to_string();
    let packed = tokio::task::spawn_blocking(move || {
        if hex::encode(Sha256::digest(&bytes)) != digest {
            return Err(Status::data_loss(format!(
                "{legacy} does not match its digest, so it cannot be migrated"
            )));
        }
        crate::chunks::compress(&bytes)
            .map(|packed| (digest, packed))
            .map_err(|err| Status::internal(format!("compressing {legacy}: {err}")))
    })
    .await
    .map_err(|err| Status::internal(format!("migrating a chunk: {err}")))?;
    let (digest, packed) = packed?;
    store.put_bytes(&chunk_key(&digest), packed.clone()).await?;
    tracing::debug!(digest, "copied a chunk from the format before casync");
    Ok(Some(packed))
}

async fn read_legacy_index(
    store: &ObjectStore,
    legacy: &str,
) -> Result<Option<ImageIndex>, Status> {
    let Some(json) = store.get_bytes(legacy).await? else {
        return Ok(None);
    };
    serde_json::from_slice(&json).map(Some).map_err(|err| {
        Status::failed_precondition(format!(
            "{legacy} is in no format this build knows, so it cannot be migrated: {err}"
        ))
    })
}

fn encode(legacy: &str, index: &ImageIndex) -> Result<Vec<u8>, Status> {
    crate::caibx::encode(index)
        .map_err(|err| Status::failed_precondition(format!("{legacy} cannot be migrated: {err}")))
}

fn current_key(legacy: &str) -> Option<String> {
    legacy
        .strip_suffix(LEGACY_INDEX)
        .map(|stem| format!("{stem}.caibx"))
}

async fn legacy_indexes(store: &ObjectStore) -> Result<Vec<String>, Status> {
    let mut out = Vec::new();
    for owner in OWNERS {
        out.extend(
            store
                .list(owner)
                .await?
                .into_iter()
                .filter(|key| key.ends_with(LEGACY_INDEX)),
        );
    }
    Ok(out)
}

/// Whether anything still reads the old index at `legacy`: an image's always,
/// a snapshot's or volume's while it has a manifest, a stored sandbox's for
/// its current generation. The rest is left to the collector, and deleted
/// with the other old objects.
async fn is_live(store: &ObjectStore, legacy: &str) -> Result<bool, Status> {
    let mut parts = legacy.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("snapshots"), Some(id), _) => {
            store.exists(&format!("snapshots/{id}/manifest.json")).await
        }
        (Some("volumes"), Some(name), _) => {
            store.exists(&format!("volumes/{name}/manifest.json")).await
        }
        (Some("sandboxes"), Some(id), Some(generation)) => {
            Ok(crate::durable::read_manifest(store, id)
                .await?
                .is_some_and(|held| held.manifest.generation.to_string() == generation))
        }
        _ => Ok(true),
    }
}

/// Gives a live old index its `.caibx`, once every chunk it names is in the
/// new format.
async fn convert_index(store: &ObjectStore, legacy: &str) -> Result<(), Status> {
    let key = current_key(legacy).expect("listed by its suffix");
    if store.exists(&key).await? || !is_live(store, legacy).await? {
        return Ok(());
    }
    let Some(index) = read_legacy_index(store, legacy).await? else {
        return Ok(());
    };
    let bytes = encode(legacy, &index)?;
    let digests: std::collections::BTreeSet<String> = index.chunks.values().cloned().collect();
    let mut copies = futures::stream::iter(digests)
        .map(|digest| async move {
            if store.exists(&chunk_key(&digest)).await? {
                return Ok(());
            }
            match copy_chunk(store, &digest).await? {
                Some(_) => Ok(()),
                None => Err(Status::data_loss(format!(
                    "chunk {digest} of {legacy} is in neither format"
                ))),
            }
        })
        .buffer_unordered(PARALLELISM);
    while let Some(result) = copies.next().await {
        result?;
    }
    drop(copies);
    crate::chunks::put_zeroes(store, &index).await?;
    store.put_bytes(&key, bytes).await
}

/// Removes an old index once nothing needs it: its `.caibx` reads back as the
/// same index, or nothing reads it.
async fn retire_index(store: &ObjectStore, legacy: &str) -> Result<(), Status> {
    if !is_live(store, legacy).await? {
        return delete_legacy(store, legacy).await;
    }
    let key = current_key(legacy).expect("listed by its suffix");
    let (Some(old), Some(new)) = (
        read_legacy_index(store, legacy).await?,
        store.get_bytes(&key).await?,
    ) else {
        return Ok(());
    };
    match crate::caibx::decode(&new) {
        Ok(new) if new.size == old.size && new.chunks == old.chunks => {
            delete_legacy(store, legacy).await
        }
        _ => Err(Status::data_loss(format!(
            "{key} does not read back as the index in {legacy}"
        ))),
    }
}

/// Puts an old chunk in the new format again, which also refreshes its age
/// for the collector, checks it reads back, and removes the old one.
async fn retire_chunk(store: &ObjectStore, digest: &str) -> Result<(), Status> {
    if copy_chunk(store, digest).await?.is_none() {
        return Ok(());
    }
    let key = chunk_key(digest);
    if !reads_back(store, &key, digest).await? {
        return Err(Status::data_loss(format!(
            "{key} does not read back as chunk {digest}"
        )));
    }
    delete_legacy(store, &format!("{LEGACY_CHUNKS}{digest}")).await
}

/// Another node retiring the same object may delete it first, which some
/// stores report as an error.
async fn delete_legacy(store: &ObjectStore, key: &str) -> Result<(), Status> {
    match store.delete(key).await {
        Err(_) if !store.exists(key).await? => Ok(()),
        result => result,
    }
}

async fn reads_back(store: &ObjectStore, key: &str, digest: &str) -> Result<bool, Status> {
    let Some(packed) = store.get_bytes(key).await? else {
        return Ok(false);
    };
    Ok(crate::chunks::decompress(digest, &packed)
        .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == digest))
}

/// One pass over the store: every live old index converted, and with
/// `may_delete`, every old object retired, chunks before indexes. Returns
/// whether nothing old is left.
pub async fn run(store: &ObjectStore, may_delete: bool) -> Result<bool, Status> {
    let started = std::time::Instant::now();
    let indexes = legacy_indexes(store).await?;
    let mut failed = 0;
    for legacy in &indexes {
        if let Err(err) = convert_index(store, legacy).await {
            tracing::warn!(
                index = legacy,
                err = err.message(),
                "could not migrate an index"
            );
            failed += 1;
        }
    }
    if failed > 0 {
        return Err(Status::unavailable(format!(
            "{failed} of {} indexes could not be migrated",
            indexes.len()
        )));
    }
    if !may_delete {
        return Ok(false);
    }

    let mut digests: Vec<String> = store
        .list(LEGACY_CHUNKS)
        .await?
        .into_iter()
        .filter_map(|key| key.strip_prefix(LEGACY_CHUNKS).map(str::to_string))
        .filter(|digest| digest.len() == 64 && !digest.contains('/'))
        .collect();
    let total = digests.len();
    if total > 0 || !indexes.is_empty() {
        tracing::info!(
            indexes = indexes.len(),
            chunks = total,
            "retiring the object store's objects in the format before casync"
        );
    }
    // From a random point, so nodes running passes together mostly retire
    // different chunks.
    if total > 0 {
        digests.rotate_left((uuid::Uuid::new_v4().as_u128() % total as u128) as usize);
    }
    let (done, failed) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let mut reported = std::time::Instant::now();
    let mut results = futures::stream::iter(digests)
        .map(|digest| async move {
            let result = retire_chunk(store, &digest).await;
            (digest, result)
        })
        .buffer_unordered(PARALLELISM);
    while let Some((digest, result)) = results.next().await {
        match result {
            Ok(()) => done.fetch_add(1, Ordering::Relaxed),
            Err(err) => {
                tracing::warn!(
                    chunk = digest,
                    err = err.message(),
                    "could not migrate a chunk"
                );
                failed.fetch_add(1, Ordering::Relaxed)
            }
        };
        if reported.elapsed() >= PROGRESS_EVERY {
            reported = std::time::Instant::now();
            tracing::info!(
                done = done.load(Ordering::Relaxed),
                total,
                "migrating chunks from the format before casync"
            );
        }
    }
    drop(results);
    let failed = failed.into_inner();
    if failed > 0 {
        return Err(Status::unavailable(format!(
            "{failed} of {total} chunks could not be migrated"
        )));
    }
    // Last, so an old build's collector that is still running after all
    // still finds every chunk named until the chunks are gone too.
    for legacy in &indexes {
        retire_index(store, legacy).await?;
    }
    tracing::info!(
        indexes = indexes.len(),
        chunks = total,
        took_ms = started.elapsed().as_millis() as u64,
        "the object store holds nothing in the format before casync"
    );
    Ok(true)
}

#[derive(clap::Args)]
pub struct Args {
    #[arg(long, env = "BURROW_OBJECT_STORE")]
    object_store: String,
    #[arg(long, env = "BURROW_OBJECT_STORE_ENDPOINT")]
    object_store_endpoint: String,
    #[arg(long, default_value = "us-east-1", env = "BURROW_OBJECT_STORE_REGION")]
    object_store_region: String,
    /// Only count what is still in the old format, and fail if anything is.
    #[arg(long)]
    check: bool,
    /// Also delete the old objects once their new ones are verified. Nodes
    /// do this on their own once the orchestrator reports every node
    /// upgraded; a node still on the old build loses data if it runs first.
    #[arg(long)]
    delete_old: bool,
    /// Confirm every node sharing the store runs a build that keeps chunks as
    /// casync does, which --delete-old requires.
    #[arg(long)]
    force: bool,
}

/// `burrowd migrate-chunks`: a pass in the foreground, or with `--check` a
/// count of what is left.
pub async fn command(args: Args) -> anyhow::Result<()> {
    if args.delete_old && !args.force {
        anyhow::bail!(
            "--delete-old deletes what the format before casync wrote, which a node still on an \
             older build reads and collects by: pass --force once every node sharing the store \
             is upgraded, or let the nodes do it, which they do once the orchestrator reports \
             them all upgraded"
        );
    }
    let store = ObjectStore::open(&crate::objstore::Options {
        url: args.object_store,
        endpoint: args.object_store_endpoint,
        region: args.object_store_region,
        attempts: 10,
        uploads: 8,
        uploads_per_sandbox: 8,
    })?;
    if !args.check {
        run(&store, args.delete_old)
            .await
            .map_err(|err| anyhow::anyhow!("{}", err.message()))?;
    }
    let indexes = legacy_indexes(&store).await?.len();
    let chunks = store.list(LEGACY_CHUNKS).await?.len();
    println!("{indexes} indexes and {chunks} chunks are in the format before casync");
    if args.check && indexes + chunks > 0 {
        anyhow::bail!("the object store has not finished migrating");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunks::CHUNK_SIZE;

    const SNAPSHOT_INDEX: &str = "snapshots/snap_1/snapshot.mem.index.json";

    async fn legacy_chunk(store: &ObjectStore, fill: u8) -> String {
        let bytes = vec![fill; CHUNK_SIZE as usize];
        let digest = hex::encode(Sha256::digest(&bytes));
        store
            .put_bytes(&format!("{LEGACY_CHUNKS}{digest}"), bytes)
            .await
            .unwrap();
        digest
    }

    async fn legacy_store() -> (ObjectStore, ImageIndex) {
        let store = crate::objstore::fake::store(true).await;
        let index = ImageIndex {
            size: 3 * CHUNK_SIZE,
            chunk_size: CHUNK_SIZE,
            chunks: [
                (0, legacy_chunk(&store, 1).await),
                (2, legacy_chunk(&store, 2).await),
            ]
            .into(),
        };
        store
            .put_bytes(SNAPSHOT_INDEX, serde_json::to_vec(&index).unwrap())
            .await
            .unwrap();
        store
            .put_bytes("snapshots/snap_1/manifest.json", b"{}".to_vec())
            .await
            .unwrap();
        (store, index)
    }

    /// What the old build's collector deletes: every old chunk no old index
    /// names.
    async fn old_collector(store: &ObjectStore) {
        let mut named = std::collections::HashSet::new();
        for key in legacy_indexes(store).await.unwrap() {
            let index = read_legacy_index(store, &key).await.unwrap().unwrap();
            named.extend(index.chunks.into_values());
        }
        for key in store.list(LEGACY_CHUNKS).await.unwrap() {
            if !named.contains(key.strip_prefix(LEGACY_CHUNKS).unwrap()) {
                store.delete(&key).await.unwrap();
            }
        }
    }

    async fn new_chunks_present(store: &ObjectStore, key: &str) {
        let index = crate::chunks::read_index(store, key)
            .await
            .unwrap()
            .unwrap();
        for digest in index.digests() {
            assert!(
                store.exists(&chunk_key(&digest)).await.unwrap(),
                "{key} names {digest}, which chunks.castr/ lacks"
            );
        }
    }

    /// A restore reading an index and a chunk only the old format has gets
    /// them, copies the chunk to its new path and deletes nothing.
    #[tokio::test]
    async fn a_restore_reads_the_old_format_and_deletes_nothing() {
        let (store, index) = legacy_store().await;
        let key = "snapshots/snap_1/snapshot.mem.caibx";
        let read = crate::chunks::read_index(&store, key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.chunks, index.chunks);
        assert!(
            !store.exists(key).await.unwrap(),
            "no .caibx before its chunks"
        );

        let dir = std::env::temp_dir().join(format!("burrow-migrate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::chunks::get_image(&store, &read, &dir.join("image"))
            .await
            .unwrap();
        let image = std::fs::read(dir.join("image")).unwrap();
        assert_eq!(image.len() as u64, 3 * CHUNK_SIZE);
        assert!(image[..CHUNK_SIZE as usize].iter().all(|&b| b == 1));
        assert!(
            image[CHUNK_SIZE as usize..2 * CHUNK_SIZE as usize]
                .iter()
                .all(|&b| b == 0)
        );
        assert!(store.exists(&chunk_key(&index.chunks[&0])).await.unwrap());
        assert!(store.exists(SNAPSHOT_INDEX).await.unwrap());
        assert_eq!(store.list(LEGACY_CHUNKS).await.unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// While an old build may share the store its collector runs beside new
    /// nodes: a pass converts without deleting, so the old collector still
    /// finds every chunk it needs, and nothing new depends on an old chunk.
    #[tokio::test]
    async fn an_old_collector_beside_a_pass_loses_nothing() {
        let (store, index) = legacy_store().await;
        assert!(!run(&store, false).await.unwrap());
        old_collector(&store).await;
        assert!(store.exists(SNAPSHOT_INDEX).await.unwrap());
        for digest in index.chunks.values() {
            assert!(
                store
                    .exists(&format!("{LEGACY_CHUNKS}{digest}"))
                    .await
                    .unwrap()
            );
        }
        // Even an old collector that deleted every old chunk leaves what
        // the new format names whole.
        for key in store.list(LEGACY_CHUNKS).await.unwrap() {
            store.delete(&key).await.unwrap();
        }
        new_chunks_present(&store, "snapshots/snap_1/snapshot.mem.caibx").await;
    }

    /// Once every node is upgraded, a pass leaves only the current format,
    /// and a second finds nothing.
    #[tokio::test]
    async fn a_pass_of_an_upgraded_fleet_retires_every_old_object() {
        let (store, index) = legacy_store().await;
        let garbage = legacy_chunk(&store, 3).await;
        assert!(run(&store, true).await.unwrap());
        assert!(legacy_indexes(&store).await.unwrap().is_empty());
        assert!(store.list(LEGACY_CHUNKS).await.unwrap().is_empty());
        for digest in index.digests().chain([garbage]) {
            assert!(
                reads_back(&store, &chunk_key(&digest), &digest)
                    .await
                    .unwrap()
            );
        }
        assert!(run(&store, true).await.unwrap());
    }

    /// A new copy already there is put again before its old one goes: it may
    /// be old enough for the collector, or not what it should be.
    #[tokio::test]
    async fn retiring_a_chunk_puts_its_new_copy_again() {
        let (store, index) = legacy_store().await;
        let digest = &index.chunks[&0];
        store
            .put_bytes(&chunk_key(digest), b"stale".to_vec())
            .await
            .unwrap();
        retire_chunk(&store, digest).await.unwrap();
        assert!(
            reads_back(&store, &chunk_key(digest), digest)
                .await
                .unwrap()
        );
        assert!(
            !store
                .exists(&format!("{LEGACY_CHUNKS}{digest}"))
                .await
                .unwrap()
        );
    }

    /// The old index of a snapshot deleted before it was converted is not
    /// turned into a `.caibx` the collector would count, and goes with the
    /// other old objects.
    #[tokio::test]
    async fn an_old_index_with_no_manifest_is_not_converted() {
        let (store, _) = legacy_store().await;
        store
            .delete("snapshots/snap_1/manifest.json")
            .await
            .unwrap();
        assert!(!run(&store, false).await.unwrap());
        assert!(
            !store
                .exists("snapshots/snap_1/snapshot.mem.caibx")
                .await
                .unwrap()
        );
        assert!(run(&store, true).await.unwrap());
        assert!(!store.exists(SNAPSHOT_INDEX).await.unwrap());
    }

    /// An old index in no format this build knows, or with chunks of another
    /// size, is refused, not guessed at, and kept.
    #[tokio::test]
    async fn an_unreadable_old_index_is_refused() {
        let store = crate::objstore::fake::store(true).await;
        store
            .put_bytes("volumes/data/manifest.json", b"{}".to_vec())
            .await
            .unwrap();
        store
            .put_bytes("volumes/data/7.index.json", b"not an index".to_vec())
            .await
            .unwrap();
        let refused = crate::chunks::read_index(&store, "volumes/data/7.caibx")
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(
            refused.message().contains("cannot be migrated"),
            "{}",
            refused.message()
        );
        assert!(run(&store, true).await.is_err());
        assert!(store.exists("volumes/data/7.index.json").await.unwrap());

        let odd = ImageIndex {
            size: 8 << 30,
            chunk_size: 1 << 30,
            chunks: [(0, "ab".repeat(32))].into(),
        };
        store
            .put_bytes(
                "volumes/data/7.index.json",
                serde_json::to_vec(&odd).unwrap(),
            )
            .await
            .unwrap();
        let refused = crate::chunks::read_index(&store, "volumes/data/7.caibx")
            .await
            .unwrap_err();
        assert!(
            refused.message().contains("chunk size"),
            "{}",
            refused.message()
        );
    }

    /// An old chunk that does not hash to its name is kept, the pass fails,
    /// and a restore needing it is refused rather than given bad bytes.
    #[tokio::test]
    async fn a_corrupt_old_chunk_is_refused_and_kept() {
        let (store, index) = legacy_store().await;
        let digest = &index.chunks[&2];
        store
            .put_bytes(&format!("{LEGACY_CHUNKS}{digest}"), vec![9; 16])
            .await
            .unwrap();
        assert!(run(&store, true).await.is_err());
        assert!(
            store
                .exists(&format!("{LEGACY_CHUNKS}{digest}"))
                .await
                .unwrap()
        );
        let path = std::env::temp_dir().join(format!("burrow-corrupt-{}", uuid::Uuid::new_v4()));
        let refused = crate::chunks::get_image(&store, &index, &path)
            .await
            .unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert_eq!(refused.code(), tonic::Code::DataLoss);
        assert!(
            refused.message().contains("cannot be migrated"),
            "{}",
            refused.message()
        );
    }
}
