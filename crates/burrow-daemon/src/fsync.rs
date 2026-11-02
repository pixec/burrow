//! Getting what the daemon writes onto the disk, not just into the page cache.
//!
//! A suspend or a snapshot is reported done once its files are on the node's
//! disk. Until something `fsync`s them they are only in the host page cache,
//! and a power cut leaves a torn state that restores into a corrupt guest, or a
//! manifest naming files that never reached the disk. The rule everywhere is
//! the same: each file first, then the directory that names it, and only then
//! report it done. A rename that publishes a directory is followed by a sync of
//! the directory it was renamed into, or the rename itself can be lost.

use std::io;
use std::path::{Path, PathBuf};

/// Flushes `path`'s data and metadata to the disk.
///
/// Read-only is enough: `fsync` acts on the file, not on the descriptor's
/// mode, and a VMM may still hold the file open for writing. On macOS
/// `sync_all` is `F_FULLFSYNC`, which also empties the drive's own cache.
fn sync_file_blocking(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(test)]
    record::note(Synced::File(path.to_path_buf()));
    Ok(())
}

/// Flushes a directory's entries, which is what makes a create, an unlink or
/// a rename inside it durable.
fn sync_dir_blocking(dir: &Path) -> io::Result<()> {
    let handle = std::fs::File::open(dir)?;
    match handle.sync_all() {
        Ok(()) => {}
        // A filesystem that cannot sync a directory (some FUSE and network
        // ones) has nothing more to give; the files themselves are synced.
        Err(err) if matches!(err.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP)) => {
            tracing::debug!(dir = %dir.display(), %err, "directory sync not supported here");
        }
        Err(err) => return Err(err),
    }
    #[cfg(test)]
    record::note(Synced::Dir(dir.to_path_buf()));
    Ok(())
}

/// Syncs `names` inside `dir`, in the order given, then `dir` itself.
pub async fn files_then_dir(dir: &Path, names: Vec<String>) -> io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        for name in &names {
            sync_file_blocking(&dir.join(name))
                .map_err(|err| io::Error::new(err.kind(), format!("syncing {name}: {err}")))?;
        }
        sync_dir_blocking(&dir)
    })
    .await
    .map_err(io::Error::other)?
}

/// Syncs every regular file directly in `dir`, then `dir`.
///
/// For a directory that is published whole, such as a snapshot, where every
/// file in it is part of what is being made durable.
pub async fn tree(dir: &Path) -> io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut names: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                names.push(entry.path());
            }
        }
        // Sorted only so the order is the same every time.
        names.sort();
        for path in &names {
            sync_file_blocking(path)?;
        }
        sync_dir_blocking(&dir)
    })
    .await
    .map_err(io::Error::other)?
}

/// Syncs one directory, after a rename into it or an unlink from it.
pub async fn dir(dir: &Path) -> io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || sync_dir_blocking(&dir))
        .await
        .map_err(io::Error::other)?
}

/// Syncs one file.
pub async fn file(path: &Path) -> io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || sync_file_blocking(&path))
        .await
        .map_err(io::Error::other)?
}

/// Replaces `path` with `bytes` so that either the old or the new contents
/// survive a power cut, never a truncated file: written to a temporary beside
/// it, synced, renamed over it, and the directory synced.
pub async fn replace(path: &Path, temp: &Path, bytes: Vec<u8>) -> io::Result<()> {
    tokio::fs::write(temp, bytes).await?;
    if let Err(err) = file(temp).await {
        let _ = tokio::fs::remove_file(temp).await;
        return Err(err);
    }
    if let Err(err) = tokio::fs::rename(temp, path).await {
        let _ = tokio::fs::remove_file(temp).await;
        return Err(err);
    }
    match path.parent() {
        Some(parent) => dir(parent).await,
        None => Ok(()),
    }
}

/// One sync, as the test recorder sees it.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Synced {
    File(PathBuf),
    Dir(PathBuf),
}

/// Every sync made by this process's tests, in order.
///
/// Process-wide because syncs run on blocking threads; tests read back only
/// the entries under their own temporary directory, so tests running in
/// parallel do not see each other's.
#[cfg(test)]
pub mod record {
    use super::Synced;
    use std::path::Path;
    use std::sync::Mutex;

    static SYNCS: Mutex<Vec<Synced>> = Mutex::new(Vec::new());

    pub(super) fn note(synced: Synced) {
        SYNCS.lock().unwrap().push(synced);
    }

    /// The syncs of paths under `root`, in the order they were made.
    pub fn under(root: &Path) -> Vec<Synced> {
        SYNCS
            .lock()
            .unwrap()
            .iter()
            .filter(|synced| match synced {
                Synced::File(path) | Synced::Dir(path) => path.starts_with(root),
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "burrow-fsync-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn files_are_synced_in_order_and_the_directory_last() {
        let dir = scratch("order");
        for name in ["snapshot.vmstate", "snapshot.mem", "scratch.ext4"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        files_then_dir(
            &dir,
            vec![
                "snapshot.vmstate".into(),
                "snapshot.mem".into(),
                "scratch.ext4".into(),
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            record::under(&dir),
            vec![
                Synced::File(dir.join("snapshot.vmstate")),
                Synced::File(dir.join("snapshot.mem")),
                Synced::File(dir.join("scratch.ext4")),
                Synced::Dir(dir.clone()),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file that is not there is an error, not a skipped sync: a suspend
    /// that cannot sync what it wrote must not report itself done.
    #[tokio::test]
    async fn a_missing_file_fails_and_the_directory_is_not_synced() {
        let dir = scratch("missing");
        let err = files_then_dir(&dir, vec!["snapshot.mem".into()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("snapshot.mem"), "{err}");
        assert!(record::under(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_tree_syncs_every_file_then_itself() {
        let dir = scratch("tree");
        std::fs::write(dir.join("b"), b"x").unwrap();
        std::fs::write(dir.join("a"), b"x").unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        tree(&dir).await.unwrap();
        assert_eq!(
            record::under(&dir),
            vec![
                Synced::File(dir.join("a")),
                Synced::File(dir.join("b")),
                Synced::Dir(dir.clone()),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_replacement_is_synced_before_and_after_its_rename() {
        let dir = scratch("replace");
        let path = dir.join("manifest.json");
        let temp = dir.join(".manifest.json.tmp");
        replace(&path, &temp, b"{}".to_vec()).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        assert!(!temp.exists());
        assert_eq!(
            record::under(&dir),
            vec![Synced::File(temp), Synced::Dir(dir.clone())]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
