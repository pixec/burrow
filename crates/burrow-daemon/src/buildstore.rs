//! Builds in the object store, the one place nodes get them from.
//!
//! A node that finishes a build uploads it before it reports it: every file
//! the manifest names as chunks and an index under `images/`, keyed by the
//! file's digest as a suspended sandbox's image is, then the manifest itself,
//! byte for byte, at `builds/<hex>.json`. The orchestrator tags a build only
//! on that report, so a tag never names a build the store does not hold.
//!
//! A node that needs a build it does not hold fetches it: the manifest,
//! verified against the digest, then each file assembled from the chunks of
//! builds it already holds where it can and from the store otherwise, and
//! checked whole against the manifest. The build is published with one
//! rename, so a create sees either nothing or all of it, and a node that dies
//! part way leaves a staging directory its next start sweeps. Concurrent
//! creates of one build share one fetch.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tonic::Status;

use burrow_common::build::{Digest, Manifest};

use crate::blobs::BlobStore;
use crate::chunks::LocalChunk;
use crate::objstore::ObjectStore;

const BUILDS: &str = "builds/";

/// How long a build's manifest is in the store before the orchestrator may
/// collect it: longer than any upload takes to be reported.
pub const GRACE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Where a build's manifest is kept in the store.
pub fn manifest_key(key: &str) -> String {
    format!("{BUILDS}{key}.json")
}

/// The files of a build with their digests: its disk, its kernel and the
/// other files it names.
pub(crate) fn artifacts(manifest: &Manifest) -> Result<Vec<(String, String)>, Status> {
    let mut files = vec![(manifest.rootfs.file.clone(), manifest.rootfs.digest.clone())];
    if !manifest.kernel.is_empty() {
        files.push((crate::boot::KERNEL.to_string(), manifest.kernel.clone()));
    }
    files.extend(
        manifest
            .files
            .iter()
            .map(|(file, digest)| (file.clone(), digest.clone())),
    );
    for (file, digest) in &files {
        crate::template::validate_name(file)?;
        if crate::blobs::Digest::parse(digest).is_none() {
            return Err(Status::data_loss(format!("{file}: not a sha-256 digest")));
        }
    }
    Ok(files)
}

/// Refuses a build this node must not fetch: an installed macOS machine
/// anywhere but on a Mac.
pub(crate) fn may_fetch(manifest: &Manifest, is_mac_node: bool) -> Result<(), Status> {
    if manifest.guest_os == burrow_vmm::GuestOs::MacOs.as_str() && !is_mac_node {
        return Err(Status::failed_precondition(
            "the build is an installed macOS machine, which only a Mac node fetches",
        ));
    }
    Ok(())
}

/// Uploads the build in `key`, then its manifest. A file the store already
/// holds is not sent again, and one shared with `parent`, a build on this
/// node it was made from, is uploaded as what changed.
pub async fn upload(
    store: &ObjectStore,
    data_dir: &Path,
    key: &str,
    parent: &str,
) -> Result<(), Status> {
    let started = std::time::Instant::now();
    let bytes = crate::template::manifest_bytes(data_dir, key)
        .await
        .ok_or_else(|| {
            Status::not_found(format!("no build {}", crate::template::digest_of(key)))
        })?;
    let manifest: Manifest = serde_json::from_str(&bytes)
        .map_err(|err| Status::internal(format!("build {key}'s manifest: {err}")))?;
    let blobs = BlobStore::new(data_dir);
    let builds = crate::template::builds_dir(data_dir);
    let base = match parent.is_empty() {
        true => None,
        false => crate::template::read_manifest(data_dir, parent)
            .await
            .map(|manifest| (builds.join(parent).join(&manifest.rootfs.file), manifest)),
    };
    for (file, digest) in artifacts(&manifest)? {
        let base = match &base {
            Some((path, base)) if file == base.rootfs.file => {
                crate::rootdisk::remembered(&blobs, &base.rootfs.digest)
                    .await
                    .map(|index| (path.clone(), index))
            }
            _ => None,
        };
        upload_file(store, &blobs, &builds.join(key).join(&file), &digest, base).await?;
    }
    store
        .put_bytes(&manifest_key(key), bytes.into_bytes())
        .await?;
    tracing::info!(
        build = crate::template::digest_of(key),
        took_ms = started.elapsed().as_millis() as u64,
        "build uploaded to the object store"
    );
    Ok(())
}

/// Puts one file of a build as chunks and an index, unless the store holds
/// its index already, which it then puts again: the collector takes an index
/// no build names once it is past its grace, and this build's manifest is
/// still to come.
async fn upload_file(
    store: &ObjectStore,
    blobs: &BlobStore,
    path: &Path,
    digest: &str,
    base: Option<(PathBuf, crate::chunks::ImageIndex)>,
) -> Result<(), Status> {
    let key = crate::rootdisk::remote_index_key(digest);
    let index = match store.get_bytes(&key).await? {
        Some(bytes) => {
            let index = crate::caibx::decode(&bytes)
                .map_err(|err| Status::data_loss(format!("index {key} is unreadable: {err}")))?;
            store.put_bytes(&key, bytes).await?;
            index
        }
        None => {
            let index = crate::chunks::put_disk_since(
                store,
                path,
                base.as_ref().map(|(path, index)| (path.as_path(), index)),
                &Default::default(),
            )
            .await?;
            crate::chunks::put_index(store, &key, &index).await?;
            index
        }
    };
    if let Err(err) = crate::rootdisk::remember(blobs, path, digest, &index).await {
        tracing::debug!(file = %path.display(), %err, "could not record a build file's index");
    }
    Ok(())
}

/// Fetches in progress, by build, so concurrent creates share one.
static FETCHES: Mutex<std::collections::BTreeMap<String, Arc<tokio::sync::Mutex<()>>>> =
    Mutex::new(std::collections::BTreeMap::new());

/// Fetches the build in `key` from the store unless this node holds it, once
/// `accept` has passed its manifest. Says whether it fetched.
pub async fn fetch(
    store: &ObjectStore,
    data_dir: &Path,
    key: &str,
    accept: impl FnOnce(&Manifest) -> Result<(), Status>,
) -> Result<bool, Status> {
    if crate::template::read_manifest(data_dir, key)
        .await
        .is_some()
    {
        return Ok(false);
    }
    let lock = Arc::clone(FETCHES.lock().unwrap().entry(key.to_string()).or_default());
    let fetched = {
        let _held = lock.lock().await;
        match crate::template::read_manifest(data_dir, key).await {
            Some(_) => Ok(false),
            None => fetch_held(store, data_dir, key, accept)
                .await
                .map(|()| true),
        }
    };
    let mut fetches = FETCHES.lock().unwrap();
    if Arc::strong_count(&lock) == 2 {
        fetches.remove(key);
    }
    fetched
}

async fn fetch_held(
    store: &ObjectStore,
    data_dir: &Path,
    key: &str,
    accept: impl FnOnce(&Manifest) -> Result<(), Status>,
) -> Result<(), Status> {
    let started = std::time::Instant::now();
    let digest = Digest::parse(key)
        .ok_or_else(|| Status::invalid_argument(format!("{key:?} is not a build digest")))?;
    let bytes = store
        .get_bytes(&manifest_key(key))
        .await?
        .ok_or_else(|| Status::not_found(format!("build {digest} is not in the object store")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| Status::data_loss(format!("build {digest}'s manifest is not UTF-8")))?;
    let manifest = Manifest::verified(&text, &digest).map_err(Status::data_loss)?;
    accept(&manifest)?;
    let files = artifacts(&manifest)?;
    let blobs = BlobStore::new(data_dir);
    let local = local_chunks(data_dir, &blobs).await;
    let staging = crate::template::staging_dir(data_dir, key).await?;
    let assembled = async {
        let mut indexes = Vec::new();
        let mut total = crate::chunks::Assembled::default();
        for (file, digest) in &files {
            let index_key = crate::rootdisk::remote_index_key(digest);
            let index = crate::chunks::read_index(store, &index_key)
                .await?
                .ok_or_else(|| {
                    Status::data_loss(format!(
                        "{file} of build sha256:{key} is not in the object store"
                    ))
                })?;
            let done =
                crate::chunks::assemble(store, &index, &local, &staging.join(file), digest).await?;
            total.fetched_bytes += done.fetched_bytes;
            total.reused_bytes += done.reused_bytes;
            indexes.push((file, digest, index));
        }
        crate::template::publish_bytes(data_dir, &staging, text.as_bytes()).await?;
        Ok::<_, Status>((indexes, total))
    }
    .await;
    let (indexes, total) = match assembled {
        Ok(assembled) => assembled,
        Err(err) => {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(err);
        }
    };
    let dir = crate::template::builds_dir(data_dir).join(key);
    for (file, digest, index) in indexes {
        if let Err(err) = crate::rootdisk::remember(&blobs, &dir.join(file), digest, &index).await {
            tracing::debug!(file, %err, "could not record a build file's index");
        }
    }
    tracing::info!(
        build = %digest,
        fetched_bytes = total.fetched_bytes,
        reused_bytes = total.reused_bytes,
        took_ms = started.elapsed().as_millis() as u64,
        "build fetched from the object store"
    );
    Ok(())
}

/// Every chunk of the builds on this node whose index is recorded, by
/// digest.
async fn local_chunks(data_dir: &Path, blobs: &BlobStore) -> HashMap<String, LocalChunk> {
    let mut chunks = HashMap::new();
    let builds = crate::template::builds_dir(data_dir);
    let Ok(mut entries) = tokio::fs::read_dir(&builds).await else {
        return chunks;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let key = entry.file_name().to_string_lossy().into_owned();
        if key.starts_with('.') {
            continue;
        }
        let Some(manifest) = crate::template::read_manifest(data_dir, &key).await else {
            continue;
        };
        let Ok(files) = artifacts(&manifest) else {
            continue;
        };
        for (file, digest) in files {
            let Some(index) = crate::rootdisk::remembered(blobs, &digest).await else {
                continue;
            };
            let path = Arc::new(entry.path().join(file));
            for (&n, chunk) in &index.chunks {
                chunks
                    .entry(chunk.clone())
                    .or_insert_with(|| (Arc::clone(&path), index.range(n).0));
            }
        }
    }
    chunks
}

/// The builds whose manifests the store has held for longer than `grace`,
/// for the orchestrator to collect those no row keeps.
pub async fn stored(
    store: &ObjectStore,
    grace: std::time::Duration,
) -> Result<Vec<String>, Status> {
    let cutoff = std::time::SystemTime::now() - grace;
    Ok(store
        .list_aged(BUILDS)
        .await?
        .into_iter()
        .filter(|(_, modified)| modified.is_some_and(|at| at <= cutoff))
        .filter_map(|(key, _)| {
            let hex = key.strip_prefix(BUILDS)?.strip_suffix(".json")?;
            Digest::parse(hex).map(|digest| digest.to_string())
        })
        .collect())
}

/// Deletes a build's manifest from the store, unless it was put again
/// within `grace`: a node uploading the same build again is about to report
/// it. Its files go with the collector's next pass once no build names them.
pub async fn purge(
    store: &ObjectStore,
    digest: &str,
    grace: std::time::Duration,
) -> Result<bool, Status> {
    let key = crate::template::key_of(digest)?;
    let object = manifest_key(&key);
    let cutoff = std::time::SystemTime::now() - grace;
    match store.modified(&object).await? {
        Some(at) if at <= cutoff => {
            store.delete(&object).await?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// The digests of every file the builds in the store name, for the
/// collector: their indexes and chunks are kept while a build names them.
pub async fn remote_refs(
    store: &ObjectStore,
    images: &mut std::collections::HashSet<String>,
) -> Result<(), Status> {
    for key in store.list(BUILDS).await? {
        let Some(hex) = key
            .strip_prefix(BUILDS)
            .and_then(|rest| rest.strip_suffix(".json"))
        else {
            continue;
        };
        let Some(digest) = Digest::parse(hex) else {
            continue;
        };
        let Some(bytes) = store.get_bytes(&key).await? else {
            continue;
        };
        // A manifest that cannot be read stops the pass rather than leaving
        // its files unreferenced.
        let text = String::from_utf8(bytes)
            .map_err(|_| Status::data_loss(format!("build {digest}'s manifest is not UTF-8")))?;
        let manifest = Manifest::verified(&text, &digest).map_err(Status::data_loss)?;
        images.extend(artifacts(&manifest)?.into_iter().map(|(_, digest)| digest));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::chunks::CHUNK_SIZE;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("burrow-buildstore-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A disk of chunks of `fill` bytes, a hole in the second and a short
    /// last chunk.
    fn disk(fill: &[u8]) -> Vec<u8> {
        let chunk = CHUNK_SIZE as usize;
        let mut bytes = vec![0u8; chunk * (fill.len() + 1) + 4096];
        for (n, &byte) in fill.iter().enumerate() {
            let at = if n == 0 { 0 } else { (n + 1) * chunk };
            bytes[at..at + chunk].fill(byte);
        }
        let tail = bytes.len() - 4096;
        bytes[tail..].fill(0xee);
        bytes
    }

    async fn build(data_dir: &Path, rootfs: &[u8], guest_os: &str) -> String {
        let staging = crate::template::staging_dir(data_dir, "test")
            .await
            .unwrap();
        tokio::fs::write(staging.join(crate::rootdisk::IMAGE), rootfs)
            .await
            .unwrap();
        tokio::fs::write(staging.join(crate::boot::KERNEL), b"kernel")
            .await
            .unwrap();
        let config = crate::oci::ImageEnvironment {
            guest_os: guest_os.into(),
            ..Default::default()
        };
        let manifest = crate::template::manifest_for(&staging, &config, String::new())
            .await
            .unwrap();
        crate::template::publish(data_dir, &staging, &manifest)
            .await
            .unwrap()
    }

    fn rootfs(data_dir: &Path, key: &str) -> Vec<u8> {
        std::fs::read(
            crate::template::builds_dir(data_dir)
                .join(key)
                .join(crate::rootdisk::IMAGE),
        )
        .unwrap()
    }

    fn any(_: &Manifest) -> Result<(), Status> {
        Ok(())
    }

    /// A build uploaded on one node is fetched whole on another, with the
    /// manifest it was published with, and only the chunks the other node
    /// lacks come from the store: a rebuild that changed one chunk fetches
    /// that chunk alone.
    #[tokio::test]
    async fn a_node_fetches_only_the_chunks_it_lacks() {
        let (store, faults, _) = crate::objstore::fake::controlled().await;
        let (a, b) = (scratch("lacks-a"), scratch("lacks-b"));
        let first = build(&a, &disk(&[1, 2, 3]), "").await;
        upload(&store, &a, &first, "").await.unwrap();
        assert!(fetch(&store, &b, &first, any).await.unwrap());
        assert_eq!(rootfs(&b, &first), rootfs(&a, &first));
        assert_eq!(
            crate::template::manifest_bytes(&b, &first).await,
            crate::template::manifest_bytes(&a, &first).await
        );
        // Three chunks of data, the short tail and the kernel.
        assert_eq!(faults.chunk_gets.swap(0, Ordering::Relaxed), 5);
        assert!(!fetch(&store, &b, &first, any).await.unwrap());
        assert_eq!(faults.chunk_gets.load(Ordering::Relaxed), 0);

        let second = build(&a, &disk(&[1, 9, 3]), "").await;
        upload(&store, &a, &second, &first).await.unwrap();
        assert!(fetch(&store, &b, &second, any).await.unwrap());
        assert_eq!(rootfs(&b, &second), rootfs(&a, &second));
        assert_eq!(faults.chunk_gets.load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// A chunk whose bytes do not match its digest stops the fetch, and
    /// nothing of the build is published or left staged.
    #[tokio::test]
    async fn a_corrupt_chunk_is_refused() {
        let (store, _, objects) = crate::objstore::fake::controlled().await;
        let (a, b) = (scratch("corrupt-a"), scratch("corrupt-b"));
        let key = build(&a, &disk(&[4, 5]), "").await;
        upload(&store, &a, &key, "").await.unwrap();
        let first = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(vec![4u8; CHUNK_SIZE as usize]))
        };
        objects.lock().unwrap().overwrite(
            &crate::chunks::chunk_key(&first),
            crate::chunks::compress(b"not this").unwrap(),
        );
        let err = fetch(&store, &b, &key, any).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::DataLoss, "{err:?}");
        let builds: Vec<_> = std::fs::read_dir(crate::template::builds_dir(&b))
            .unwrap()
            .collect();
        assert!(builds.is_empty(), "{builds:?}");
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// Two creates of a build this node lacks share one fetch: each chunk
    /// is read from the store once.
    #[tokio::test]
    async fn concurrent_fetches_of_a_build_share_one() {
        let (store, faults, _) = crate::objstore::fake::controlled().await;
        let (a, b) = (scratch("shared-a"), scratch("shared-b"));
        let key = build(&a, &disk(&[6, 7, 8]), "").await;
        upload(&store, &a, &key, "").await.unwrap();
        let (one, two) = tokio::join!(fetch(&store, &b, &key, any), fetch(&store, &b, &key, any));
        let mut fetched = [one.unwrap(), two.unwrap()];
        fetched.sort();
        assert_eq!(fetched, [false, true]);
        assert_eq!(faults.chunk_gets.load(Ordering::Relaxed), 5);
        assert!(!FETCHES.lock().unwrap().contains_key(&key));
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// An installed macOS machine is fetched by a Mac node and refused by
    /// any other before a chunk is read.
    #[tokio::test]
    async fn a_macos_build_is_fetched_only_by_a_mac_node() {
        let (store, faults, _) = crate::objstore::fake::controlled().await;
        let (a, b) = (scratch("mac-a"), scratch("mac-b"));
        let key = build(&a, &disk(&[3]), "macos").await;
        upload(&store, &a, &key, "").await.unwrap();
        let err = fetch(&store, &b, &key, |manifest| may_fetch(manifest, false))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(faults.chunk_gets.load(Ordering::Relaxed), 0);
        assert!(
            fetch(&store, &b, &key, |manifest| may_fetch(manifest, true))
                .await
                .unwrap()
        );
        assert!(may_fetch(&Manifest::default(), false).is_ok());
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// A build is listed for collection once its manifest is past the
    /// grace, purged only then, and its files go with the next chunk
    /// collection once no build names them.
    #[tokio::test]
    async fn a_purged_build_leaves_its_files_to_the_collector() {
        let (store, _, objects) = crate::objstore::fake::controlled().await;
        let a = scratch("purge");
        let key = build(&a, &disk(&[2]), "").await;
        upload(&store, &a, &key, "").await.unwrap();
        let digest = crate::template::digest_of(&key);
        let grace = std::time::Duration::from_secs(3600);
        assert!(stored(&store, grace).await.unwrap().is_empty());
        assert!(!purge(&store, &digest, grace).await.unwrap());

        let collector = crate::snapshot::SnapshotStore::new(
            &a.join("collector"),
            Some(store.clone()),
            HashMap::new(),
        );
        objects
            .lock()
            .unwrap()
            .age("", std::time::Duration::from_secs(3 * 24 * 3600));
        crate::durable::collect_garbage(&store, &collector)
            .await
            .unwrap();
        assert!(!objects.lock().unwrap().keys("chunks.castr/").is_empty());
        assert!(!objects.lock().unwrap().keys("images/").is_empty());

        assert_eq!(stored(&store, grace).await.unwrap(), vec![digest.clone()]);
        assert!(purge(&store, &digest, grace).await.unwrap());
        // The first pass takes the indexes, the next the chunks they named.
        for _ in 0..2 {
            crate::durable::collect_garbage(&store, &collector)
                .await
                .unwrap();
        }
        let objects = objects.lock().unwrap();
        assert!(objects.keys("builds/").is_empty());
        assert!(objects.keys("images/").is_empty());
        assert!(objects.keys("chunks.castr/").is_empty());
        drop(objects);
        let _ = std::fs::remove_dir_all(&a);
    }
}
