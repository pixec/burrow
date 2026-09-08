//! File transfer in and out of the sandbox.

#![allow(clippy::result_large_err)]

use std::os::unix::fs::PermissionsExt;

use nix::fcntl::{AT_FDCWD, OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::Mode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::{Status, Streaming};

use burrow_proto::agent::v1 as agentpb;

/// Opens `path` like [`std::fs::File::open`]/[`std::fs::File::create`] would,
/// except a symlink anywhere along it (not just the final component) is
/// refused instead of followed.
///
/// The host checks `path_scopes` by matching `path`'s string components
/// against a configured prefix before an upload or download reaches the
/// guest. That says nothing about a symlink planted inside the scope: a
/// caller confined to `/work` who plants `/work/leak -> /etc/shadow` and
/// names `/work/leak` passes the string check fine. `openat2`'s
/// `RESOLVE_NO_SYMLINKS` resolves the whole path in one kernel call, so
/// there's no gap between checking a component and opening it for a link to
/// exploit.
fn open_no_symlinks(path: &str, flags: OFlag, mode: Mode) -> std::io::Result<std::fs::File> {
    let how = OpenHow::new()
        .flags(flags | OFlag::O_CLOEXEC)
        .mode(mode)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    let fd = openat2(AT_FDCWD, path, how).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

/// Opens one component *inside* a directory already held open.
///
/// `RESOLVE_BENEATH` on top of `RESOLVE_NO_SYMLINKS` because the walks below
/// take names straight from a directory listing: neither a link nor a `..`
/// can lead anywhere outside `dir`, whatever the tree does between the listing
/// and this open.
fn openat_no_symlinks(
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
    flags: OFlag,
) -> std::io::Result<std::fs::File> {
    let how = OpenHow::new()
        .flags(flags | OFlag::O_CLOEXEC)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    let fd = openat2(dir, name, how).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

/// Opens a directory, refusing a symlink anywhere along the path.
fn open_dir_no_symlinks(path: &str) -> std::io::Result<std::fs::File> {
    open_no_symlinks(path, OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty())
}

/// The `/proc` name of an open descriptor.
///
/// Listing a directory needs a path, and there is no `readdir` that takes a
/// descriptor here. This is the one path that cannot be redirected: the kernel
/// resolves it to the inode the descriptor is already open on, whatever a
/// caller renames or relinks underneath. The descriptor has to stay open
/// across the read.
fn proc_path(dir: &std::fs::File) -> std::path::PathBuf {
    use std::os::fd::AsRawFd as _;
    std::path::PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

/// Creates every missing directory in `path`, one component at a time, without
/// walking through a symlink.
///
/// `create_dir_all` resolves the whole path by the ordinary rules, so a caller
/// confined to `/work` who plants `/work/out -> /etc` and uploads to
/// `/work/out/passwd` gets the parent "created" as `/etc` and the file written
/// there; the host's `path_scopes` check saw only the string `/work/out/...`
/// and passed it. Each component is instead made and reopened relative to the
/// one before it under `RESOLVE_NO_SYMLINKS`, which is the same guarantee the
/// final open already gives.
fn create_dir_all_no_symlinks(path: &std::path::Path) -> std::io::Result<()> {
    use std::path::Component;

    let mut components = path.components().peekable();
    let mut dir = match components.peek() {
        Some(Component::RootDir) => {
            components.next();
            open_dir_no_symlinks("/")?
        }
        _ => open_dir_no_symlinks(".")?,
    };

    for component in components {
        let name = match component {
            Component::Normal(name) => name,
            Component::CurDir => continue,
            // `..` inside an upload path is an escape attempt whichever
            // directory it is evaluated in, and RESOLVE_BENEATH would refuse
            // it anyway; saying so is clearer than an EXDEV from the kernel.
            Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "`..` is not allowed in an upload path",
                ));
            }
            Component::RootDir | Component::Prefix(_) => continue,
        };
        // EEXIST is the common case: only the tail of the path is usually
        // new. An existing *symlink* also reports EEXIST, and is caught by the
        // open below refusing it.
        match nix::sys::stat::mkdirat(&dir, name, Mode::from_bits_truncate(0o755)) {
            Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
            Err(err) => return Err(std::io::Error::from(err)),
        }
        dir = openat_no_symlinks(&dir, name, OFlag::O_RDONLY | OFlag::O_DIRECTORY)?;
    }
    Ok(())
}

/// Bytes per streamed chunk.
///
/// Matches HTTP/2's default flow-control window. 256 KiB was tried and showed
/// no measurable gain: a message larger than the window cannot be sent in one
/// go and stalls for WINDOW_UPDATE round trips instead of pipelining.
const CHUNK_SIZE: usize = 64 * 1024;
const CHANNEL_CAPACITY: usize = 16;

fn io_status(action: &str, path: &str, err: std::io::Error) -> Status {
    let message = format!("{action} {path}: {err}");
    match err.kind() {
        std::io::ErrorKind::NotFound => Status::not_found(message),
        std::io::ErrorKind::PermissionDenied => Status::permission_denied(message),
        _ => Status::internal(message),
    }
}

/// Streams an uploaded file to disk. The first chunk carries the path and
/// mode; every chunk including the first may carry data.
pub async fn upload(
    mut inbound: Streaming<agentpb::FileChunk>,
) -> Result<agentpb::UploadResult, Status> {
    let first = inbound
        .next()
        .await
        .transpose()?
        .ok_or_else(|| Status::invalid_argument("upload stream was empty"))?;
    if first.path.is_empty() {
        return Err(Status::invalid_argument("first chunk must set path"));
    }
    let path = first.path.clone();
    let mode = if first.mode == 0 { 0o644 } else { first.mode };

    if let Some(parent) = std::path::Path::new(&path).parent()
        && !parent.as_os_str().is_empty()
    {
        let parent = parent.to_path_buf();
        tokio::task::spawn_blocking(move || create_dir_all_no_symlinks(&parent))
            .await
            .map_err(|err| Status::internal(format!("mkdir did not run: {err}")))?
            .map_err(|err| io_status("create parent of", &path, err))?;
    }

    let open_path = path.clone();
    let std_file = tokio::task::spawn_blocking(move || {
        open_no_symlinks(
            &open_path,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC,
            Mode::from_bits_truncate(0o644),
        )
    })
    .await
    .map_err(|err| Status::internal(format!("open did not run: {err}")))?
    .map_err(|err| io_status("create", &path, err))?;
    let mut file = tokio::fs::File::from_std(std_file);

    let mut written = 0u64;
    let mut chunk = Some(first);
    while let Some(data) = chunk {
        if !data.data.is_empty() {
            file.write_all(&data.data)
                .await
                .map_err(|err| io_status("write", &path, err))?;
            written += data.data.len() as u64;
        }
        chunk = inbound.next().await.transpose()?;
    }
    file.flush()
        .await
        .map_err(|err| io_status("flush", &path, err))?;

    // Applied after the content is written, so a file destined to be
    // executable is never briefly executable while still partial. Uses
    // fchmod on the descriptor already open, not set_permissions(&path, ..),
    // which would re-resolve the path and could follow a symlink this
    // upload's own open just refused.
    let file = file.into_std().await;
    tokio::task::spawn_blocking(move || {
        nix::sys::stat::fchmod(&file, Mode::from_bits_truncate(mode))
    })
    .await
    .map_err(|err| Status::internal(format!("chmod did not run: {err}")))?
    .map_err(|err| io_status("chmod", &path, std::io::Error::from(err)))?;

    Ok(agentpb::UploadResult {
        bytes_written: written,
    })
}

/// Streams a file out of the sandbox.
pub async fn download(
    path: String,
) -> Result<mpsc::Receiver<Result<agentpb::FileChunk, Status>>, Status> {
    let open_path = path.clone();
    let std_file = tokio::task::spawn_blocking(move || {
        open_no_symlinks(&open_path, OFlag::O_RDONLY, Mode::empty())
    })
    .await
    .map_err(|err| Status::internal(format!("open did not run: {err}")))?
    .map_err(|err| io_status("open", &path, err))?;
    let mut file = tokio::fs::File::from_std(std_file);

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            match file.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = agentpb::FileChunk {
                        path: String::new(),
                        mode: 0,
                        data: buf[..n].to_vec(),
                    };
                    if tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    let _ = tx.send(Err(io_status("read", &path, err))).await;
                    break;
                }
            }
        }
    });
    Ok(rx)
}

/// Lists a directory, refusing to follow a symlink to get to it.
///
/// `read_dir(path)` resolves the path the ordinary way, so a caller confined to
/// `/work` who plants `/work/peek -> /` and lists `/work/peek` gets the root of
/// the guest: the host's `path_scopes` check only saw the string. The directory
/// is opened under `RESOLVE_NO_SYMLINKS` first and listed through its own
/// descriptor instead.
///
/// Entries are described by `lstat`, which `DirEntry::metadata` already uses,
/// so a symlink inside the directory is reported as the link it is.
pub async fn list_dir(path: &str) -> Result<agentpb::ListDirResponse, Status> {
    let owned = path.to_string();
    let dir = tokio::task::spawn_blocking(move || open_dir_no_symlinks(&owned))
        .await
        .map_err(|err| Status::internal(format!("open did not run: {err}")))?
        .map_err(|err| io_status("read_dir", path, err))?;

    let mut entries = tokio::fs::read_dir(proc_path(&dir))
        .await
        .map_err(|err| io_status("read_dir", path, err))?;

    let mut out = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|err| io_status("read_dir", path, err))?
    {
        let meta = match entry.metadata().await {
            Ok(meta) => meta,
            // A file can vanish between listing and stat; skip it rather than
            // failing the whole listing.
            Err(_) => continue,
        };
        out.push(agentpb::DirEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir: meta.is_dir(),
            size: meta.len(),
            mode: meta.permissions().mode(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    // Held until here: the listing above is only of the checked directory for
    // as long as this descriptor is open.
    drop(dir);
    Ok(agentpb::ListDirResponse { entries: out })
}

/// Watches a directory for changes.
///
/// Implemented by polling and diffing snapshots of the tree rather than with
/// inotify. Polling cannot see a create-then-delete that happens entirely
/// between two scans, but it needs no watch descriptors: inotify's per-user
/// limits are easy to exhaust from inside a sandbox, and exceeding them fails
/// in ways that are hard to diagnose from the outside. The interval is the
/// caller's to choose.
pub async fn watch(
    path: String,
    recursive: bool,
    interval: std::time::Duration,
) -> Result<mpsc::Receiver<Result<agentpb::WatchEvent, Status>>, Status> {
    // Opened rather than `try_exists`, which follows symlinks: a watch on
    // `/work/peek -> /` would otherwise scan the whole guest and stream every
    // change in it out to the caller.
    {
        let probe = path.clone();
        tokio::task::spawn_blocking(move || open_dir_no_symlinks(&probe))
            .await
            .map_err(|err| Status::internal(format!("open did not run: {err}")))?
            .map_err(|err| io_status("watch", &path, err))?;
    }

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let mut previous = scan(&path, recursive).await;
        loop {
            tokio::time::sleep(interval).await;
            // The receiver going away is how a client cancels a watch.
            if tx.is_closed() {
                return;
            }
            let current = scan(&path, recursive).await;

            for (entry, meta) in &current {
                let event = match previous.get(entry) {
                    None => "created",
                    Some(before) if before != meta => "modified",
                    Some(_) => continue,
                };
                if tx
                    .send(Ok(agentpb::WatchEvent {
                        r#type: event.into(),
                        path: entry.clone(),
                        is_dir: meta.is_dir,
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            for (entry, meta) in &previous {
                if !current.contains_key(entry)
                    && tx
                        .send(Ok(agentpb::WatchEvent {
                            r#type: "deleted".into(),
                            path: entry.clone(),
                            is_dir: meta.is_dir,
                        }))
                        .await
                        .is_err()
                {
                    return;
                }
            }
            previous = current;
        }
    });
    Ok(rx)
}

/// What a watch compares between polls: enough to notice a write without
/// reading file contents.
#[derive(PartialEq, Eq)]
struct Fingerprint {
    is_dir: bool,
    len: u64,
    mtime: Option<std::time::SystemTime>,
}

async fn scan(root: &str, recursive: bool) -> std::collections::HashMap<String, Fingerprint> {
    let root = root.to_string();
    tokio::task::spawn_blocking(move || scan_blocking(&root, recursive))
        .await
        .unwrap_or_default()
}

/// Walks the tree by descriptor rather than by path.
///
/// Every directory is entered with [`openat_no_symlinks`] relative to the one
/// that listed it, so a symlink cannot pull the walk out of the subtree the
/// caller asked to watch, neither the root nor a subdirectory that becomes a
/// link between one poll and the next. Names are still reported as the paths a
/// caller would use; only the resolution is fd-relative.
///
/// Blocking because a descriptor-relative walk has no async equivalent here.
fn scan_blocking(root: &str, recursive: bool) -> std::collections::HashMap<String, Fingerprint> {
    let mut out = std::collections::HashMap::new();
    let Ok(root_dir) = open_dir_no_symlinks(root) else {
        return out;
    };
    let mut stack = vec![(root_dir, std::path::PathBuf::from(root))];

    while let Some((dir, prefix)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(proc_path(&dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            // `DirEntry::metadata` is an lstat, so a symlink fingerprints as
            // itself and never reads as a directory to descend into.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let name = entry.file_name();
            let path = prefix.join(&name);
            if meta.is_dir()
                && recursive
                && let Ok(child) =
                    openat_no_symlinks(&dir, &name, OFlag::O_RDONLY | OFlag::O_DIRECTORY)
            {
                stack.push((child, path.clone()));
            }
            out.insert(
                path.to_string_lossy().into_owned(),
                Fingerprint {
                    is_dir: meta.is_dir(),
                    len: meta.len(),
                    mtime: meta.modified().ok(),
                },
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch tree, removed when the guard drops.
    struct Tmp(std::path::PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("burrow-files-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self, rest: &str) -> String {
            self.0.join(rest).to_string_lossy().into_owned()
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The host checks an upload's path as a string against `path_scopes`. A
    /// symlink planted inside the scope passes that check, so creating the
    /// parent must not walk through one, or the upload lands wherever the link
    /// points, outside the scope entirely.
    #[test]
    fn a_parent_is_not_created_through_a_symlink() {
        let tmp = Tmp::new("mkdir");
        std::fs::create_dir_all(tmp.path("scope")).unwrap();
        std::fs::create_dir_all(tmp.path("elsewhere")).unwrap();
        std::os::unix::fs::symlink(tmp.path("elsewhere"), tmp.path("scope/escape")).unwrap();

        let err = create_dir_all_no_symlinks(std::path::Path::new(&tmp.path("scope/escape/sub")))
            .expect_err("the link must be refused");
        // ELOOP is what openat2 reports for a RESOLVE_NO_SYMLINKS violation.
        assert_eq!(err.raw_os_error(), Some(nix::libc::ELOOP), "{err:?}");
        assert!(!std::path::Path::new(&tmp.path("elsewhere/sub")).exists());
    }

    #[test]
    fn a_missing_parent_is_still_created() {
        let tmp = Tmp::new("mkdir-ok");
        create_dir_all_no_symlinks(std::path::Path::new(&tmp.path("a/b/c"))).unwrap();
        assert!(std::path::Path::new(&tmp.path("a/b/c")).is_dir());
        // Idempotent, which is what `create_dir_all` callers rely on.
        create_dir_all_no_symlinks(std::path::Path::new(&tmp.path("a/b/c"))).unwrap();
    }

    /// `..` is an escape however it is resolved, so it is refused outright
    /// rather than left to the kernel.
    #[test]
    fn a_parent_reference_is_refused() {
        let tmp = Tmp::new("mkdir-dotdot");
        let err = create_dir_all_no_symlinks(std::path::Path::new(&tmp.path("a/../b")))
            .expect_err("`..` must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// `/work/peek -> /` would otherwise list the root of the guest, with the
    /// host's scope check having seen only the string `/work/peek`.
    #[tokio::test]
    async fn listing_through_a_symlink_is_refused() {
        let tmp = Tmp::new("ls");
        std::fs::create_dir_all(tmp.path("real")).unwrap();
        std::fs::write(tmp.path("real/secret"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.path("real"), tmp.path("peek")).unwrap();

        assert!(list_dir(&tmp.path("peek")).await.is_err());
        // The directory itself still lists.
        let listed = list_dir(&tmp.path("real")).await.unwrap();
        assert_eq!(listed.entries.len(), 1);
        assert_eq!(listed.entries[0].name, "secret");
    }

    /// A watch is a stream of everything under a directory, so a symlinked
    /// subdirectory would stream a tree the caller was never scoped to.
    #[test]
    fn a_scan_does_not_descend_through_a_symlink() {
        let tmp = Tmp::new("scan");
        std::fs::create_dir_all(tmp.path("scope/inside")).unwrap();
        std::fs::write(tmp.path("scope/inside/here"), b"x").unwrap();
        std::fs::create_dir_all(tmp.path("outside")).unwrap();
        std::fs::write(tmp.path("outside/secret"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.path("outside"), tmp.path("scope/escape")).unwrap();

        let seen = scan_blocking(&tmp.path("scope"), true);

        assert!(seen.contains_key(&tmp.path("scope/inside/here")));
        // The link itself is listed, it is really there, but nothing behind it.
        assert!(seen.contains_key(&tmp.path("scope/escape")));
        assert!(
            !seen.contains_key(&tmp.path("scope/escape/secret")),
            "the walk followed a symlink out of the watched tree"
        );
    }

    /// A root that is itself a link is refused rather than walked.
    #[test]
    fn a_scan_of_a_symlinked_root_finds_nothing() {
        let tmp = Tmp::new("scan-root");
        std::fs::create_dir_all(tmp.path("real")).unwrap();
        std::fs::write(tmp.path("real/secret"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.path("real"), tmp.path("peek")).unwrap();

        assert!(scan_blocking(&tmp.path("peek"), true).is_empty());
    }
}
