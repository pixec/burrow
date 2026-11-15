//! Exists only to carry object stores written in the format before casync
//! chunks across one release. The release after removes this module, its
//! start in `serve`, its call in [`crate::chunks`] and its command.
//!
//! That format kept each chunk uncompressed at `chunks/<sha256>` and each
//! index as JSON at `<name>.index.json`. Chunk ids are the same SHA-256 in
//! both, so a sandbox's, snapshot's or volume's own records stay valid and
//! migrating is rewriting objects: each index encoded as `<name>.caibx` beside
//! its JSON, each chunk compressed to its casync path.
//!
//! Every node with a store runs a pass in the background from its start, and
//! a restore that meets an object only the old format has migrates it first
//! ([`on_demand`]). Any number of nodes may do either at once: a chunk's new
//! object is named by its content and an index's encoding is a function of
//! the JSON, so two nodes migrating one object write the same thing. Old
//! objects go only once their new ones read back the same: an index right
//! after its `.caibx` is written, a chunk only once a pass has found no old
//! index left, so every chunk is named by an index the collector counts
//! before its old copy is gone.

#![allow(clippy::result_large_err)]

use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Runs passes behind the node's start until the store holds nothing in the
/// old format.
pub fn start(store: ObjectStore) {
    tokio::spawn(async move {
        tokio::time::sleep(START_AFTER).await;
        loop {
            match run(&store).await {
                Ok(()) => return,
                Err(err) => tracing::warn!(
                    err = err.message(),
                    "migrating the object store from the format before casync; trying again later"
                ),
            }
            tokio::time::sleep(RETRY_AFTER).await;
        }
    });
}

/// The object the current format keeps at `key`, migrated from the old
/// format, or `None` when neither has it.
pub async fn on_demand(store: &ObjectStore, key: &str) -> Result<Option<Vec<u8>>, Status> {
    let Some(legacy) = crate::chunks::legacy_key(key) else {
        return Ok(None);
    };
    let migrated = match legacy.strip_prefix(LEGACY_CHUNKS) {
        Some(digest) => migrate_chunk(store, digest).await?,
        None => migrate_index(store, &legacy, key).await?,
    };
    match migrated {
        Some(bytes) => {
            match legacy.starts_with(LEGACY_CHUNKS) {
                true => tracing::debug!(key, "migrated a chunk from the format before casync"),
                false => tracing::info!(
                    key,
                    "migrated an index from the format before casync before reading it"
                ),
            }
            Ok(Some(bytes))
        }
        // Another node may have migrated it, and removed the old object,
        // since the first read.
        None => store.get_bytes(key).await,
    }
}

async fn migrate_chunk(store: &ObjectStore, digest: &str) -> Result<Option<Vec<u8>>, Status> {
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
    Ok(Some(packed))
}

async fn migrate_index(
    store: &ObjectStore,
    legacy: &str,
    key: &str,
) -> Result<Option<Vec<u8>>, Status> {
    let Some(index) = read_legacy_index(store, legacy).await? else {
        return Ok(None);
    };
    let bytes = crate::caibx::encode(&index).map_err(|err| {
        Status::failed_precondition(format!("{legacy} cannot be migrated: {err}"))
    })?;
    crate::chunks::put_zeroes(store, &index).await?;
    store.put_bytes(key, bytes.clone()).await?;
    Ok(Some(bytes))
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

/// Gives an old index its `.caibx`, unless it has one, and removes the old
/// one once the new one reads back as the same index.
async fn retire_index(store: &ObjectStore, legacy: &str) -> Result<(), Status> {
    let key = current_key(legacy).expect("listed by its suffix");
    if !store.exists(&key).await? {
        migrate_index(store, legacy, &key).await?;
    }
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

/// Gives an old chunk a verified new copy and removes it.
async fn retire_chunk(store: &ObjectStore, digest: &str) -> Result<(), Status> {
    let legacy = format!("{LEGACY_CHUNKS}{digest}");
    if !store.exists(&legacy).await? {
        return Ok(());
    }
    let key = chunk_key(digest);
    if !reads_back(store, &key, digest).await? {
        if migrate_chunk(store, digest).await?.is_none() {
            return Ok(());
        }
        if !reads_back(store, &key, digest).await? {
            return Err(Status::data_loss(format!(
                "{key} does not read back as chunk {digest}"
            )));
        }
    }
    delete_legacy(store, &legacy).await
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

/// One pass over the store. Old chunks are touched only once every old
/// index has been retired.
pub async fn run(store: &ObjectStore) -> Result<(), Status> {
    let started = std::time::Instant::now();
    let indexes = legacy_indexes(store).await?;
    let mut failed = 0;
    for legacy in &indexes {
        if let Err(err) = retire_index(store, legacy).await {
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

    let mut digests: Vec<String> = store
        .list(LEGACY_CHUNKS)
        .await?
        .into_iter()
        .filter_map(|key| key.strip_prefix(LEGACY_CHUNKS).map(str::to_string))
        .filter(|digest| digest.len() == 64 && !digest.contains('/'))
        .collect();
    let total = digests.len();
    // From a random point, so nodes running passes together mostly retire
    // different chunks.
    if total > 0 {
        digests.rotate_left((uuid::Uuid::new_v4().as_u128() % total as u128) as usize);
    }
    if total > 0 || !indexes.is_empty() {
        tracing::info!(
            indexes = indexes.len(),
            chunks = total,
            "migrating the object store from the format before casync"
        );
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
    let failed = failed.into_inner();
    if failed > 0 {
        return Err(Status::unavailable(format!(
            "{failed} of {total} chunks could not be migrated"
        )));
    }
    tracing::info!(
        indexes = indexes.len(),
        chunks = total,
        took_ms = started.elapsed().as_millis() as u64,
        "the object store holds nothing in the format before casync"
    );
    Ok(())
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
}

/// `burrowd migrate-chunks`: a pass in the foreground, which nodes also run
/// on their own, or with `--check` a count of what is left.
pub async fn command(args: Args) -> anyhow::Result<()> {
    let store = ObjectStore::open(&crate::objstore::Options {
        url: args.object_store,
        endpoint: args.object_store_endpoint,
        region: args.object_store_region,
        attempts: 10,
        uploads: 8,
        uploads_per_sandbox: 8,
    })?;
    if !args.check {
        return run(&store)
            .await
            .map_err(|err| anyhow::anyhow!("{}", err.message()));
    }
    let indexes = legacy_indexes(&store).await?.len();
    let chunks = store.list(LEGACY_CHUNKS).await?.len();
    println!("{indexes} indexes and {chunks} chunks are in the format before casync");
    if indexes + chunks > 0 {
        anyhow::bail!("the object store has not finished migrating");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunks::CHUNK_SIZE;

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
            .put_bytes(
                "snapshots/snap_1/snapshot.mem.index.json",
                serde_json::to_vec(&index).unwrap(),
            )
            .await
            .unwrap();
        (store, index)
    }

    /// A restore reading an index and a chunk only the old format has gets
    /// them migrated, and the old objects stay for the pass to retire.
    #[tokio::test]
    async fn a_restore_migrates_what_it_reads() {
        let (store, index) = legacy_store().await;
        let read = crate::chunks::read_index(&store, "snapshots/snap_1/snapshot.mem.caibx")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.chunks, index.chunks);
        assert!(
            store
                .exists("snapshots/snap_1/snapshot.mem.index.json")
                .await
                .unwrap()
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
        assert!(
            store
                .exists(&chunk_key(&crate::caibx::zero_id(CHUNK_SIZE)))
                .await
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pass leaves only the current format, and a second finds nothing.
    #[tokio::test]
    async fn a_pass_retires_every_old_object() {
        let (store, index) = legacy_store().await;
        let garbage = legacy_chunk(&store, 3).await;
        run(&store).await.unwrap();
        assert!(legacy_indexes(&store).await.unwrap().is_empty());
        assert!(store.list(LEGACY_CHUNKS).await.unwrap().is_empty());
        for digest in index.digests().chain([garbage]) {
            assert!(
                reads_back(&store, &chunk_key(&digest), &digest)
                    .await
                    .unwrap()
            );
        }
        run(&store).await.unwrap();
    }

    /// An old index in no format this build knows is refused, not guessed at.
    #[tokio::test]
    async fn an_unreadable_old_index_is_refused() {
        let store = crate::objstore::fake::store(true).await;
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
        assert!(run(&store).await.is_err());
        assert!(store.exists("volumes/data/7.index.json").await.unwrap());
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
        assert!(run(&store).await.is_err());
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
