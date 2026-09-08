//! Content-addressed store for template artifacts.
//!
//! Templates are node-local, so moving one between nodes needs a name for an
//! artifact that does not depend on where it came from, and a way to accept one
//! from a peer without trusting it. Both fall out of storing artifacts under
//! their SHA-256 digest: identical artifacts dedupe, "does this node have it"
//! is answerable without a transfer, and a received blob is hashed as it
//! arrives and adopted only if the digest matches, so a peer that serves the
//! wrong bytes poisons nothing.
//!
//! Warm snapshots are deliberately not distributable: they encode host CPU
//! features and the exact Firecracker version, so a receiving node builds its
//! own from the kernel and rootfs it pulled.

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt;

/// A SHA-256 digest, lowercase hex.
///
/// Parsed rather than passed as a bare string because it names a path: an
/// unchecked digest with a `/` or `..` in it would let a peer address any file
/// on the node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(String);

impl Digest {
    pub fn parse(text: &str) -> Option<Self> {
        let valid = text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit());
        // Uppercase hex would name a different file on a case-sensitive
        // filesystem and the same one elsewhere; refuse rather than normalise.
        let lowercase = !text.bytes().any(|b| b.is_ascii_uppercase());
        (valid && lowercase).then(|| Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Bytes read per hashing/transfer step. Large enough that a 512 MiB rootfs is
/// not thousands of round trips, small enough to stay off the stack.
const CHUNK: usize = 1024 * 1024;

/// Most a single blob transfer may write before it is abandoned.
///
/// A byte cap, not a time limit: digest verification only happens once the
/// stream ends, so a peer (or a node impersonating one) that never ends it
/// would otherwise fill the disk. What bounds how *long* one may run is the
/// per-chunk deadline in `template::distribute::fetch_blob`; a peer that
/// trickles bytes slowly enough is stopped by that rather than by this.
///
/// Matches the OCI pull path's own [`crate::oci`] layer cap, since a
/// peer-distributed template's rootfs and kernel are exactly what an OCI pull
/// would fetch instead.
const MAX_BLOB_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("blobs"),
        }
    }

    pub fn path(&self, digest: &Digest) -> PathBuf {
        self.root.join(digest.as_str())
    }

    pub async fn has(&self, digest: &Digest) -> bool {
        tokio::fs::try_exists(self.path(digest))
            .await
            .unwrap_or(false)
    }

    /// Adopts a file that is already on this node, returning its digest.
    ///
    /// Hard-linked rather than copied where possible: a template's rootfs is
    /// hundreds of megabytes and the store is on the same filesystem.
    pub async fn insert(&self, source: &Path) -> io::Result<Digest> {
        let digest = hash_file(source).await?;
        let dest = self.path(&digest);
        if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            return Ok(digest);
        }
        tokio::fs::create_dir_all(&self.root).await?;
        match tokio::fs::hard_link(source, &dest).await {
            Ok(()) => Ok(digest),
            // Across filesystems, or where the source is already linked
            // elsewhere in a way the kernel refuses; a copy is always correct.
            Err(_) => {
                tokio::fs::copy(source, &dest).await?;
                Ok(digest)
            }
        }
    }

    /// Places a stored blob where a template expects to find it.
    pub async fn materialise(&self, digest: &Digest, dest: &Path) -> io::Result<()> {
        let source = self.path(digest);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let _ = tokio::fs::remove_file(dest).await;
        match tokio::fs::hard_link(&source, dest).await {
            Ok(()) => Ok(()),
            Err(_) => tokio::fs::copy(&source, dest).await.map(|_| ()),
        }
    }

    /// Removes blobs nothing refers to any more.
    ///
    /// Deliberately timid, because a blob wrongly collected is a template that
    /// no longer boots. Three things have to be true before one goes:
    ///
    /// - **Nothing links to it.** A template's `vmlinux` and `rootfs.ext4` are
    ///   hard links to their blob ([`Self::insert`] links rather than copies),
    ///   so a link count above one means the bytes are in use as an artifact
    ///   somewhere on this node and the blob is only the second name for them.
    /// - **No layer index entry names it.** Those are the build cache's own
    ///   references, and they outlive the sandbox the layer came from.
    /// - **It is older than `min_age`.** The window between a blob being
    ///   adopted and whatever is fetching it linking it into a template is
    ///   exactly when it has neither a link nor an index entry, and a pull of a
    ///   multi-gigabyte rootfs can sit in it for a while.
    ///
    /// Returns how many were removed and the bytes they occupied.
    pub async fn collect_garbage(
        &self,
        referenced: &std::collections::HashSet<String>,
        min_age: std::time::Duration,
    ) -> (usize, u64) {
        use std::os::unix::fs::MetadataExt as _;

        let Ok(mut entries) = tokio::fs::read_dir(&self.root).await else {
            return (0, 0);
        };
        let (mut removed, mut freed) = (0usize, 0u64);
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            // A transfer in progress owns its temporary and removes it itself;
            // one left by a process that died is collected on age alone, since
            // no digest ever names it.
            let incoming = name.starts_with(".incoming-");
            if !incoming && Digest::parse(&name).is_none() {
                continue;
            }
            if !incoming && referenced.contains(&name) {
                continue;
            }
            let Ok(meta) = tokio::fs::metadata(entry.path()).await else {
                continue;
            };
            if !incoming && meta.nlink() > 1 {
                continue;
            }
            // Unreadable timestamps read as "recent", so nothing is collected
            // on the strength of a failed stat.
            let old_enough = meta
                .modified()
                .ok()
                .and_then(|at| at.elapsed().ok())
                .is_some_and(|elapsed| elapsed > min_age);
            if !old_enough {
                continue;
            }
            if tokio::fs::remove_file(entry.path()).await.is_ok() {
                removed += 1;
                freed += meta.len();
            }
        }
        (removed, freed)
    }

    /// Begins receiving a blob whose digest is known in advance.
    pub async fn receive(&self, expected: Digest) -> io::Result<BlobWriter> {
        tokio::fs::create_dir_all(&self.root).await?;
        // Unique per transfer, not merely per digest: two concurrent pulls of
        // the *same* blob sharing one temporary would interleave their writes
        // while each hashed only its own stream, and both would then "verify"
        // a file neither of them wrote.
        let serial = TRANSFER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temp = self.root.join(format!(
            ".incoming-{expected}.{}.{serial}",
            std::process::id()
        ));
        let file = tokio::fs::File::create(&temp).await?;
        Ok(BlobWriter {
            file,
            temp,
            dest: self.path(&expected),
            expected,
            hasher: Sha256::new(),
            written: 0,
            cap: MAX_BLOB_BYTES,
            finished: false,
        })
    }
}

/// Distinguishes concurrent transfers within this process; the pid
/// distinguishes them between processes sharing a store.
static TRANSFER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A blob being written, verified as it arrives.
///
/// Nothing is visible under its final name until [`finish`](BlobWriter::finish)
/// confirms the digest, so a transfer that is truncated, corrupted, or
/// deliberately wrong leaves only a temporary file behind.
pub struct BlobWriter {
    file: tokio::fs::File,
    temp: PathBuf,
    dest: PathBuf,
    expected: Digest,
    hasher: Sha256,
    /// Bytes accepted so far, checked against `cap` on every write.
    written: u64,
    /// [`MAX_BLOB_BYTES`] in production; shrunk in tests so the limit can be
    /// hit without actually transferring gigabytes.
    cap: u64,
    /// Set once the temporary has been renamed into place, so the drop guard
    /// does not remove a blob that was adopted.
    finished: bool,
}

impl BlobWriter {
    pub async fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.written += chunk.len() as u64;
        if self.written > self.cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("blob exceeds the {} byte limit", self.cap),
            ));
        }
        self.hasher.update(chunk);
        self.file.write_all(chunk).await
    }

    /// Verifies the digest and adopts the blob, or discards it.
    pub async fn finish(mut self) -> io::Result<Digest> {
        self.file.flush().await?;
        self.file.sync_all().await?;

        let actual = hex(&self.hasher.clone().finalize());
        if actual != self.expected.0 {
            let _ = tokio::fs::remove_file(&self.temp).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "blob does not match its digest: asked for {}, received {actual}",
                    self.expected
                ),
            ));
        }
        // Rename is atomic within a filesystem, so a concurrent reader sees
        // either no blob or a complete one.
        tokio::fs::rename(&self.temp, &self.dest).await?;
        self.finished = true;
        Ok(self.expected.clone())
    }
}

/// A dropped transfer takes its temporary with it; without this an aborted
/// pull leaves an `.incoming-*` file behind for every attempt.
impl Drop for BlobWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

/// Digest of a file on disk, read in chunks so a rootfs is never held in
/// memory.
pub async fn hash_file(path: &Path) -> io::Result<Digest> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Digest(hex(&hasher.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow-blobs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_file_is_stored_under_its_digest_and_found_again() {
        let dir = scratch("roundtrip");
        let store = BlobStore::new(&dir);
        let source = dir.join("rootfs.ext4");
        tokio::fs::write(&source, b"template contents")
            .await
            .unwrap();

        let digest = store.insert(&source).await.unwrap();
        assert!(store.has(&digest).await);

        let dest = dir.join("restored/rootfs.ext4");
        store.materialise(&digest, &dest).await.unwrap();
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), b"template contents");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_same_bytes_are_stored_once() {
        let dir = scratch("dedup");
        let store = BlobStore::new(&dir);
        tokio::fs::write(dir.join("a"), b"shared kernel")
            .await
            .unwrap();
        tokio::fs::write(dir.join("b"), b"shared kernel")
            .await
            .unwrap();

        let first = store.insert(&dir.join("a")).await.unwrap();
        let second = store.insert(&dir.join("b")).await.unwrap();
        assert_eq!(first, second);

        let stored = std::fs::read_dir(dir.join("blobs")).unwrap().count();
        assert_eq!(stored, 1, "two identical artifacts should share one blob");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The point of content addressing: a peer that serves the wrong bytes
    /// must not be able to install them as the template everyone else runs.
    #[tokio::test]
    async fn a_blob_that_does_not_match_its_digest_is_rejected() {
        let dir = scratch("mismatch");
        let store = BlobStore::new(&dir);
        tokio::fs::write(dir.join("honest"), b"the real rootfs")
            .await
            .unwrap();
        let digest = store.insert(&dir.join("honest")).await.unwrap();
        tokio::fs::remove_file(store.path(&digest)).await.unwrap();

        let mut writer = store.receive(digest.clone()).await.unwrap();
        writer.write(b"malicious rootfs").await.unwrap();
        let err = writer.finish().await.unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!store.has(&digest).await, "a bad blob was adopted");
        // Nor is anything left lying around under a temporary name.
        let leftovers: Vec<_> = std::fs::read_dir(dir.join("blobs")).unwrap().collect();
        assert!(
            leftovers.is_empty(),
            "a rejected transfer left files behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_verified_blob_is_adopted() {
        let dir = scratch("verified");
        let store = BlobStore::new(&dir);
        tokio::fs::write(dir.join("src"), b"kernel bytes")
            .await
            .unwrap();
        let digest = store.insert(&dir.join("src")).await.unwrap();
        tokio::fs::remove_file(store.path(&digest)).await.unwrap();

        let mut writer = store.receive(digest.clone()).await.unwrap();
        // Arriving in pieces, as it would over a stream.
        writer.write(b"kernel ").await.unwrap();
        writer.write(b"bytes").await.unwrap();
        assert_eq!(writer.finish().await.unwrap(), digest);
        assert!(store.has(&digest).await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A peer (or a node impersonating one) that never sends the chunk which
    /// would complete or fail the digest check must not be able to stream
    /// forever and fill the disk. The cap is shrunk here rather than
    /// transferring gigabytes to prove it.
    #[tokio::test]
    async fn a_transfer_past_the_cap_is_abandoned_and_cleaned_up() {
        let dir = scratch("oversized");
        let store = BlobStore::new(&dir);
        let digest = Digest::parse(&"b".repeat(64)).unwrap();

        let mut writer = store.receive(digest.clone()).await.unwrap();
        writer.cap = 10;
        writer.write(b"0123456789").await.unwrap();
        let err = writer.write(b"one byte too many").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        drop(writer);

        assert!(!store.has(&digest).await);
        let leftovers: Vec<_> = std::fs::read_dir(dir.join("blobs")).unwrap().collect();
        assert!(
            leftovers.is_empty(),
            "an abandoned transfer left files behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What may be collected is narrow, and this is the shape of it.
    #[tokio::test]
    async fn only_an_old_unlinked_unreferenced_blob_is_collected() {
        let dir = scratch("gc");
        let store = BlobStore::new(&dir);
        let ancient = std::time::Duration::from_secs(0);

        // Linked into a template, the way a real artifact is.
        tokio::fs::write(dir.join("rootfs"), b"a template's rootfs")
            .await
            .unwrap();
        let linked = store.insert(&dir.join("rootfs")).await.unwrap();

        // Named by a layer index entry, though nothing links to it.
        tokio::fs::write(dir.join("layer"), b"a cached build layer")
            .await
            .unwrap();
        let referenced = store.insert(&dir.join("layer")).await.unwrap();
        tokio::fs::remove_file(dir.join("layer")).await.unwrap();

        // Neither: a template that was deleted, or a pull nobody finished.
        tokio::fs::write(dir.join("orphan"), b"nothing refers to this")
            .await
            .unwrap();
        let orphan = store.insert(&dir.join("orphan")).await.unwrap();
        tokio::fs::remove_file(dir.join("orphan")).await.unwrap();

        let keep: std::collections::HashSet<String> = [referenced.to_string()].into();
        let (removed, freed) = store.collect_garbage(&keep, ancient).await;

        assert_eq!(removed, 1);
        assert_eq!(freed, b"nothing refers to this".len() as u64);
        assert!(
            store.has(&linked).await,
            "a template's rootfs was collected"
        );
        assert!(store.has(&referenced).await, "a cached layer was collected");
        assert!(!store.has(&orphan).await, "an orphan was kept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The window between a blob being adopted and whatever fetched it linking
    /// it into a template is exactly when it looks like an orphan.
    #[tokio::test]
    async fn a_blob_younger_than_the_retention_is_left_alone() {
        let dir = scratch("gc-young");
        let store = BlobStore::new(&dir);
        tokio::fs::write(dir.join("fresh"), b"just arrived")
            .await
            .unwrap();
        let digest = store.insert(&dir.join("fresh")).await.unwrap();
        tokio::fs::remove_file(dir.join("fresh")).await.unwrap();

        let (removed, _) = store
            .collect_garbage(
                &std::collections::HashSet::new(),
                std::time::Duration::from_secs(3600),
            )
            .await;
        assert_eq!(removed, 0);
        assert!(store.has(&digest).await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A digest names a path, so anything that is not one must be refused
    /// before it gets near the filesystem.
    #[test]
    fn only_a_real_digest_parses() {
        let valid = "a".repeat(64);
        assert!(Digest::parse(&valid).is_some());

        for bad in [
            "",
            "short",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64),
            "../../etc/shadow",
            &format!("{}/x", "a".repeat(62)),
            &"g".repeat(64),
        ] {
            assert!(Digest::parse(bad).is_none(), "{bad:?} should not parse");
        }
    }

    #[tokio::test]
    async fn a_digest_matches_the_reference_value() {
        let dir = scratch("known");
        let file = dir.join("abc");
        tokio::fs::write(&file, b"abc").await.unwrap();
        assert_eq!(
            hash_file(&file).await.unwrap().as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
