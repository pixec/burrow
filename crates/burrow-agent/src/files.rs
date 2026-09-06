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
        tokio::fs::create_dir_all(parent)
            .await
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
    tokio::task::spawn_blocking(move || nix::sys::stat::fchmod(&file, Mode::from_bits_truncate(mode)))
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

pub async fn list_dir(path: &str) -> Result<agentpb::ListDirResponse, Status> {
    let mut entries = tokio::fs::read_dir(path)
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
    if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return Err(Status::not_found(format!("no such directory: {path}")));
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
    let mut out = std::collections::HashMap::new();
    let mut stack = vec![std::path::PathBuf::from(root)];

    while let Some(dir) = stack.pop() {
        let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Ok(meta) = entry.metadata().await else {
                continue;
            };
            let path = entry.path();
            if meta.is_dir() && recursive {
                stack.push(path.clone());
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
