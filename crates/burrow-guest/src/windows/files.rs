//! File transfer in and out of a Windows sandbox.
//!
//! The Linux agent refuses a symlink anywhere along an upload's or
//! download's path, because the host checked `path_scopes` against the path
//! as a string and a link inside the scope would lead out of it. Windows has
//! no `RESOLVE_NO_SYMLINKS`, so the equivalent is a check after the open: the
//! final component is opened as itself (`FILE_FLAG_OPEN_REPARSE_POINT`) and
//! must not be a reparse point, and the path Windows resolved the handle to
//! must be the path asked for. A symlink or junction anywhere earlier makes
//! the two differ. So does an 8.3 short name, which is refused the same way.

#![allow(clippy::result_large_err)]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::{Status, Streaming};

use burrow_proto::guest::v1 as guestpb;

use crate::windows::{mode, nt, token, users, win};

/// What `files-as-user` in the health response promises.
pub const FEATURE_FILES_AS_USER: &str = "files-as-user";

const CHUNK_SIZE: usize = 64 * 1024;
const CHANNEL_CAPACITY: usize = 16;
/// ERROR_CANT_RESOLVE_FILENAME, what a path through a link is refused with:
/// ELOOP, as `RESOLVE_NO_SYMLINKS` gives on Linux.
const THROUGH_A_LINK: i32 = 1921;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const CREATE_NEW: u32 = 1;
const ERROR_ALREADY_EXISTS: i32 = 183;

fn io_status(action: &str, path: &str, err: std::io::Error) -> Status {
    let message = format!("{action} {path}: {err}");
    match err.kind() {
        std::io::ErrorKind::NotFound => Status::not_found(message),
        std::io::ErrorKind::PermissionDenied => Status::permission_denied(message),
        _ => Status::internal(message),
    }
}

fn mapped(path: &str) -> Result<String, Status> {
    win::map_path(path)
        .map_err(|_| Status::invalid_argument(format!("{path:?} is not a local path")))
}

/// Opens a mapped path, refusing it if any part of it is a link.
pub fn open_no_links(path: &str, access: u32, disposition: u32) -> std::io::Result<File> {
    open_no_links_reporting(path, access, disposition).map(|(file, _)| file)
}

/// [`open_no_links`], saying whether something was already there.
fn open_no_links_reporting(
    path: &str,
    access: u32,
    disposition: u32,
) -> std::io::Result<(File, bool)> {
    let (file, existed) =
        nt::open_path(path, access | nt::FILE_READ_ATTRIBUTES, disposition, true)?;
    let info = nt::info(&file)?;
    if info.attributes & mode::FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !nt::final_path(&file)?.eq_ignore_ascii_case(path)
    {
        return Err(std::io::Error::from_raw_os_error(THROUGH_A_LINK));
    }
    Ok((file, existed))
}

/// Runs file work off the runtime, as `user` when one is named.
///
/// A user's work gets a thread of its own, impersonating them, that exits
/// afterwards, never a pool thread: the identity stays with the thread.
pub async fn blocking<T: Send + 'static>(
    user: &str,
    work: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<std::io::Result<T>, Status> {
    if users::is_agent(user) {
        return tokio::task::spawn_blocking(work)
            .await
            .map_err(|err| Status::internal(format!("file work did not run: {err}")));
    }
    let user = user.to_string();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("burrow-as-user".into())
        .spawn(move || {
            let result = token::logon(&user).map(|token| {
                token.impersonate().and_then(|()| {
                    let out = work();
                    token::revert();
                    out
                })
            });
            let _ = tx.send(result);
        })
        .map_err(|err| Status::internal(format!("starting file work: {err}")))?;
    rx.await
        .map_err(|_| Status::internal("file work ended without a result"))?
}

/// Creates every missing directory of `path` (mapped), each checked to be a
/// real directory where it was asked for, and gives the ones it creates to
/// `owner`.
fn create_dir_all_no_links(path: &str, owner: Option<&[u8]>) -> std::io::Result<()> {
    let mut prefix = path[..3].to_string();
    for part in path[3..].split('\\').filter(|part| !part.is_empty()) {
        prefix = crate::paths::windows::join(&prefix, part);
        let long = win::wide(&crate::paths::windows::long(&prefix));
        // SAFETY: `long` is NUL-terminated.
        let created = unsafe {
            windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(
                long.as_ptr(),
                std::ptr::null(),
            )
        } != 0;
        if !created && win::last_error() as i32 != ERROR_ALREADY_EXISTS {
            return Err(win::last_io_error());
        }
        let access = if created && owner.is_some() {
            nt::WRITE_OWNER | nt::READ_CONTROL | nt::WRITE_DAC
        } else {
            0
        };
        let dir = open_no_links(&prefix, access, OPEN_EXISTING)?;
        if !nt::info(&dir)?.is_dir() {
            return Err(std::io::Error::from_raw_os_error(267));
        }
        if created && let Some(sid) = owner {
            give_to(&dir, sid, true)?;
        }
    }
    Ok(())
}

/// Makes `sid` the owner of what the handle holds and grants it full
/// control, inherited below for a directory. Ownership alone on Windows
/// grants only the right to change the ACL, not to read or write, so the
/// grant is what makes an owned file the owner's.
fn give_to(file: &File, sid: &[u8], is_dir: bool) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, SE_FILE_OBJECT, SetEntriesInAclW,
        SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, NO_INHERITANCE, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION,
    };
    let sid_ptr: *mut std::ffi::c_void = sid.as_ptr().cast_mut().cast();
    let mut old = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: the handle is open with READ_CONTROL; `descriptor` is freed below.
    let rc = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0x1F_01FF,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: if is_dir {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            NO_INHERITANCE
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid_ptr.cast(),
        },
    };
    let mut new = std::ptr::null_mut();
    // SAFETY: `old` lives in `descriptor`; `new` is LocalFree'd below.
    let rc = unsafe { SetEntriesInAclW(1, &access, old, &mut new) };
    let result = if rc != 0 {
        Err(std::io::Error::from_raw_os_error(rc as i32))
    } else {
        // SAFETY: the handle is open with WRITE_OWNER and WRITE_DAC.
        let rc = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                sid_ptr,
                std::ptr::null_mut(),
                new,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            Err(std::io::Error::from_raw_os_error(rc as i32))
        } else {
            Ok(())
        }
    };
    // SAFETY: both were allocated by the calls above.
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(new.cast());
        windows_sys::Win32::Foundation::LocalFree(descriptor);
    }
    result
}

/// Streams an uploaded file to disk, as burrow-guest does on Linux: the
/// first chunk carries the path, mode, owner and whether to leave an existing
/// file alone.
///
/// A mode has one bit Windows can keep: without the owner's write bit the
/// file is made read-only. An owner is a local account, made the file's
/// owner and given full control of it.
pub async fn upload(
    mut inbound: Streaming<guestpb::FileChunk>,
) -> Result<guestpb::UploadResult, Status> {
    let mut first = inbound
        .next()
        .await
        .transpose()?
        .ok_or_else(|| Status::invalid_argument("upload stream was empty"))?;
    if first.path.is_empty() {
        return Err(Status::invalid_argument("first chunk must set path"));
    }
    let path = std::mem::take(&mut first.path);
    let target = mapped(&path)?;
    let mode = if first.mode == 0 { 0o644 } else { first.mode };
    let is_as_user = !users::is_agent(&first.user);
    if is_as_user && !first.owner.is_empty() {
        return Err(Status::invalid_argument(
            "an upload made as a user is that user's; it takes no owner",
        ));
    }
    // Resolved before anything is created, so an owner who does not exist
    // fails the upload as a request.
    let owner = if first.owner.is_empty() || users::is_agent(&first.owner) {
        None
    } else {
        users::lookup_user(&first.owner)?;
        Some(Arc::new(users::sid(&first.owner)?))
    };

    if let Some((parent, _)) = crate::paths::windows::split(&target) {
        let parent = parent.to_string();
        let owner = owner.clone();
        blocking(&first.user, move || {
            create_dir_all_no_links(&parent, owner.as_deref().map(Vec::as_slice))
        })
        .await?
        .map_err(|err| io_status("create parent of", &path, err))?;
    }

    let is_skipping = first.is_existing_skipped;
    let open_target = target.clone();
    let owner_access = if owner.is_some() {
        nt::WRITE_OWNER | nt::READ_CONTROL | nt::WRITE_DAC
    } else {
        0
    };
    let opened = blocking(&first.user, move || {
        let access = nt::GENERIC_WRITE | nt::FILE_WRITE_ATTRIBUTES | owner_access;
        if is_skipping {
            return open_no_links(&open_target, access, CREATE_NEW).map(|file| (file, true));
        }
        // Opened, checked, then emptied, so nothing unchecked is truncated.
        let (file, existed) = open_no_links_reporting(&open_target, access, OPEN_ALWAYS)?;
        let is_created = !existed;
        if nt::info(&file)?.is_dir() {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        file.set_len(0)?;
        Ok((file, is_created))
    })
    .await?;
    let (mut file, is_created) = match opened {
        Err(err) if is_skipping && matches!(err.raw_os_error(), Some(80 | 183)) => {
            return Ok(guestpb::UploadResult { bytes_written: 0 });
        }
        other => other.map_err(|err| io_status("create", &path, err))?,
    };

    let mut written = 0u64;
    let mut chunk = Some(first);
    while let Some(data) = chunk {
        if !data.data.is_empty() {
            let bytes = data.data;
            let len = bytes.len() as u64;
            file = tokio::task::spawn_blocking(move || file.write_all(&bytes).map(|()| file))
                .await
                .map_err(|err| Status::internal(format!("write did not run: {err}")))?
                .map_err(|err| io_status("write", &path, err))?;
            written += len;
        }
        chunk = inbound.next().await.transpose()?;
    }

    // Applied after the content, through the handle already open, as on
    // Linux: a read-only bit set first would refuse the content's own write.
    tokio::task::spawn_blocking(move || {
        if is_created && mode & 0o200 == 0 {
            let attributes = nt::info(&file)?.attributes;
            nt::set_basic(
                &file,
                None,
                None,
                Some(mode::attributes_for_chmod(attributes, mode)),
            )?;
        }
        match owner {
            Some(sid) => give_to(&file, &sid, false),
            None => Ok(()),
        }
    })
    .await
    .map_err(|err| Status::internal(format!("chmod did not run: {err}")))?
    .map_err(|err| io_status("chmod", &path, err))?;

    Ok(guestpb::UploadResult {
        bytes_written: written,
    })
}

/// Streams a file out of the sandbox.
pub async fn download(
    path: String,
    user: &str,
) -> Result<mpsc::Receiver<Result<guestpb::FileChunk, Status>>, Status> {
    let target = mapped(&path)?;
    let file = blocking(user, move || {
        let file = open_no_links(&target, nt::GENERIC_READ, OPEN_EXISTING)?;
        if nt::info(&file)?.is_dir() {
            return Err(std::io::Error::from_raw_os_error(1));
        }
        Ok(file)
    })
    .await?
    .map_err(|err| io_status("open", &path, err))?;

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let _ = std::thread::Builder::new()
        .name("download".into())
        .spawn(move || {
            let mut file = file;
            let mut buf = vec![0u8; CHUNK_SIZE];
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = guestpb::FileChunk {
                            data: buf[..n].to_vec(),
                            ..Default::default()
                        };
                        if tx.blocking_send(Ok(chunk)).is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = tx.blocking_send(Err(io_status("read", &path, err)));
                        break;
                    }
                }
            }
        });
    Ok(rx)
}

/// Lists a directory, refusing to reach it through a link, by its handle.
pub async fn list_dir(path: &str, user: &str) -> Result<guestpb::ListDirResponse, Status> {
    let target = mapped(path)?;
    let entries = blocking(user, move || {
        let dir = open_no_links(&target, nt::FILE_LIST_DIRECTORY, OPEN_EXISTING)?;
        let mut out: Vec<guestpb::DirEntry> = nt::entries(&dir)?
            .into_iter()
            .map(|entry| guestpb::DirEntry {
                is_dir: entry.attributes & mode::FILE_ATTRIBUTE_DIRECTORY != 0
                    && !mode::is_link(entry.attributes, entry.reparse_tag),
                size: entry.size,
                mode: mode::mode(entry.attributes, entry.reparse_tag, &entry.name),
                name: entry.name,
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    })
    .await?
    .map_err(|err| io_status("read_dir", path, err))?;
    Ok(guestpb::ListDirResponse { entries })
}

/// Watches a directory with `ReadDirectoryChangesW`.
///
/// The Linux agent polls, because inotify's per-user limits are easy to
/// exhaust from inside a sandbox. Windows has no such limit on directory
/// change notifications, so this watches instead, and `interval` is not used:
/// changes are reported as they happen. When more change at once than the
/// buffer holds, Windows says only that something did, and the events in
/// between are lost; the watch goes on.
///
/// Events name the path in drive form, the watched directory's path joined
/// with the entry's.
pub async fn watch(
    path: String,
    recursive: bool,
    _interval: std::time::Duration,
    user: &str,
) -> Result<mpsc::Receiver<Result<guestpb::WatchEvent, Status>>, Status> {
    let target = mapped(&path)?;
    {
        let probe = target.clone();
        blocking(user, move || {
            open_no_links(&probe, nt::FILE_LIST_DIRECTORY, OPEN_EXISTING)
        })
        .await?
        .map_err(|err| io_status("watch", &path, err))?;
    }
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let user = user.to_string();
    tokio::spawn(async move {
        let result = blocking(&user, move || watch_blocking(&target, recursive, &tx)).await;
        if let Ok(Err(err)) | Err(err) =
            result.map_err(|status| std::io::Error::other(status.message().to_string()))
        {
            tracing::debug!(%err, "watch ended");
        }
    });
    Ok(rx)
}

fn watch_blocking(
    root: &str,
    recursive: bool,
    tx: &mpsc::Sender<Result<guestpb::WatchEvent, Status>>,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME,
        FILE_ACTION_RENAMED_OLD_NAME, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
        FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
        FILE_NOTIFY_CHANGE_SIZE, FILE_NOTIFY_INFORMATION, ReadDirectoryChangesW,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED};
    use windows_sys::Win32::System::Threading::CreateEventW;

    // Overlapped, so the wait can time out and notice the caller has gone.
    let long = win::wide(&crate::paths::windows::long(root));
    // SAFETY: `long` is NUL-terminated; the handle is owned below.
    let dir = win::owned(unsafe {
        windows_sys::Win32::Storage::FileSystem::CreateFileW(
            long.as_ptr(),
            nt::FILE_LIST_DIRECTORY,
            nt::SHARE_ALL,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    })?;
    // SAFETY: an unnamed manual-reset event, owned below.
    let event = win::owned(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })?;

    // Which paths are directories, for a deletion, which cannot be asked of
    // what is gone. Seeded from what exists when the watch starts.
    let mut dirs = std::collections::HashSet::new();
    seed_dirs(root, recursive, &mut dirs);

    let filter = FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE;
    let mut buf = vec![0u64; 8 * 1024];
    loop {
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.as_raw_handle();
        // SAFETY: `buf` and `overlapped` outlive the operation, which is
        // waited for or cancelled below before either is touched again.
        win::check(unsafe {
            ReadDirectoryChangesW(
                dir.as_raw_handle(),
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                i32::from(recursive),
                filter,
                std::ptr::null_mut(),
                &mut overlapped,
                None,
            )
        })?;
        let mut returned = 0u32;
        loop {
            // SAFETY: waits on the operation started above.
            let ok = unsafe {
                GetOverlappedResultEx(dir.as_raw_handle(), &overlapped, &mut returned, 1000, 0)
            };
            if ok != 0 {
                break;
            }
            // WAIT_TIMEOUT: nothing yet; a caller that went away ends it.
            if win::last_error() == 258 {
                if tx.is_closed() {
                    // SAFETY: cancels the operation this thread started, then
                    // waits for it to stop using `buf`.
                    unsafe {
                        CancelIoEx(dir.as_raw_handle(), &overlapped);
                        GetOverlappedResultEx(
                            dir.as_raw_handle(),
                            &overlapped,
                            &mut returned,
                            u32::MAX,
                            0,
                        );
                    }
                    return Ok(());
                }
                continue;
            }
            return Err(win::last_io_error());
        }
        if returned == 0 {
            tracing::debug!(root, "watch buffer overflowed; changes were missed");
            continue;
        }
        let base = buf.as_ptr().cast::<u8>();
        let mut offset = 0usize;
        loop {
            // SAFETY: the system wrote a chain of records into `buf`.
            let record = unsafe { &*base.add(offset).cast::<FILE_NOTIFY_INFORMATION>() };
            let name = unsafe {
                std::slice::from_raw_parts(
                    record.FileName.as_ptr(),
                    record.FileNameLength as usize / 2,
                )
            };
            let path = crate::paths::windows::join(root, &String::from_utf16_lossy(name));
            let kind = match record.Action {
                FILE_ACTION_ADDED | FILE_ACTION_RENAMED_NEW_NAME => "created",
                FILE_ACTION_REMOVED | FILE_ACTION_RENAMED_OLD_NAME => "deleted",
                FILE_ACTION_MODIFIED => "modified",
                _ => "",
            };
            if !kind.is_empty() {
                let is_dir = if kind == "deleted" {
                    dirs.remove(&path.to_lowercase())
                } else {
                    let is_dir = std::path::Path::new(&crate::paths::windows::long(&path)).is_dir();
                    if is_dir {
                        dirs.insert(path.to_lowercase());
                    }
                    is_dir
                };
                // A directory's own write time changes with every entry made
                // in it; Linux's poll reports that as a modification too.
                let event = guestpb::WatchEvent {
                    r#type: kind.into(),
                    path,
                    is_dir,
                };
                if tx.blocking_send(Ok(event)).is_err() {
                    return Ok(());
                }
            }
            if record.NextEntryOffset == 0 {
                break;
            }
            offset += record.NextEntryOffset as usize;
        }
    }
}

fn seed_dirs(root: &str, recursive: bool, dirs: &mut std::collections::HashSet<String>) {
    let mut stack = vec![root.to_string()];
    while let Some(dir) = stack.pop() {
        let Ok(handle) = open_no_links(&dir, nt::FILE_LIST_DIRECTORY, OPEN_EXISTING) else {
            continue;
        };
        let Ok(entries) = nt::entries(&handle) else {
            continue;
        };
        for entry in entries {
            if entry.attributes & mode::FILE_ATTRIBUTE_DIRECTORY != 0
                && !mode::is_link(entry.attributes, entry.reparse_tag)
            {
                let path = crate::paths::windows::join(&dir, &entry.name);
                dirs.insert(path.to_lowercase());
                if recursive {
                    stack.push(path);
                }
            }
        }
    }
}
