//! One POSIX file operation per call, on Windows.
//!
//! The same contract as the Linux agent's: each call acts on the object a
//! language's own file API would, errors come back as the errno an SDK
//! raises (see [`crate::errno`]), and the request's path scopes and write
//! ceiling are held to the object the call acts on. The scope is checked on
//! the path Windows resolved the opened handle to (`GetFinalPathNameByHandleW`),
//! and the call then acts through that handle, or through a handle opened
//! relative to a checked directory's, so nothing swapped in between can
//! redirect it.
//!
//! What POSIX has and Windows does not:
//!
//! - Modes: only the owner's write bit, as the read-only attribute; see
//!   [`super::mode`] for what stat reports.
//! - Owners: chown succeeds and changes nothing, as it does in Node on
//!   Windows; uid and gid read as 0.
//! - `pread`/`pwrite`: Windows moves the file position on a positioned read
//!   or write, so the position is put back afterwards. Two calls on one
//!   handle at once can see each other's position.
//! - Open handles do not survive an agent upgrade: a new process cannot take
//!   over the old one's handles, so they read as closed (EBADF) after one.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::windows::fs::FileExt as _;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use tonic::Status;

use burrow_proto::guest::v1 as guestpb;
use guestpb::fs_request::Op;
use guestpb::fs_response::Result as Outcome;

use crate::errno::{self, Errno};
use crate::paths::windows as wpaths;
use crate::windows::nt::{self, FILE_CREATE, FILE_OPEN, FILE_OPEN_IF};
use crate::windows::{files, mode, win};

/// What `fs-scoped` in the health response promises.
pub const FEATURE_FS: &str = "fs-scoped";

const MAX_IO: usize = 4 << 20;
const MAX_HANDLES: usize = 1024;
const IDLE: Duration = Duration::from_secs(600);

const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;
const ACCESS_MODE: u32 = O_WRONLY | O_RDWR;
const OPEN_FLAGS: u32 = ACCESS_MODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND;

const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_EXECUTE: u32 = 0x20;
/// Win32 dispositions.
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const CREATE_NEW: u32 = 1;

type R<T> = Result<T, Errno>;

fn io(err: std::io::Error) -> Errno {
    errno::from_io(&err)
}

pub async fn handle(req: guestpb::FsRequest) -> Result<guestpb::FsResponse, Status> {
    let op = req
        .op
        .ok_or_else(|| Status::invalid_argument("FsRequest names no op"))?;
    let (syscall, path, dest) = op.describe();
    let (path, dest) = (path.to_string(), dest.to_string());
    // A call on a handle runs as the agent: the handle already carries what
    // its open was allowed.
    let as_user = match op {
        Op::Read(_)
        | Op::Write(_)
        | Op::Fstat(_)
        | Op::Ftruncate(_)
        | Op::Fsync(_)
        | Op::Close(_) => String::new(),
        _ => req.user.clone(),
    };
    let user = req.user;
    let limits = Limits {
        scopes: req
            .path_scopes
            .iter()
            .filter_map(|scope| win::map_path(scope).ok())
            .collect(),
        is_scoped: !req.path_scopes.is_empty(),
        max_write_bytes: req.max_write_bytes,
    };
    let outcome = files::blocking(&as_user, move || Ok(run(op, user, &limits)))
        .await?
        .unwrap_or_else(|err| Err(io(err)));
    let result = outcome.unwrap_or_else(|errno| {
        Outcome::Error(guestpb::FsError {
            code: errno.name(),
            errno: errno.number(),
            syscall: syscall.into(),
            path,
            dest,
        })
    });
    Ok(guestpb::FsResponse {
        result: Some(result),
    })
}

fn run(op: Op, user: String, limits: &Limits) -> R<Outcome> {
    let done = Outcome::IsDone(true);
    Ok(match op {
        Op::Stat(stat) if stat.is_nofollow => {
            let (dir, name) = limits.parent(&stat.path)?;
            let file = entry(&dir, &name, nt::FILE_READ_ATTRIBUTES)?;
            Outcome::Stat(stat_of(&file)?)
        }
        Op::Stat(stat) => Outcome::Stat(stat_of(
            &limits.object(&stat.path, nt::FILE_READ_ATTRIBUTES)?,
        )?),
        Op::ReadDir(dir) => {
            let dir = limits.object(&dir.path, nt::FILE_LIST_DIRECTORY)?;
            if !nt::info(&dir).map_err(io)?.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            Outcome::Entries(guestpb::FsDirEntries {
                entries: nt::entries(&dir)
                    .map_err(io)?
                    .into_iter()
                    .map(|entry| guestpb::FsDirEntry {
                        r#type: mode::entry_type(entry.attributes, entry.reparse_tag).into(),
                        name: entry.name,
                    })
                    .collect(),
            })
        }
        Op::Mkdir(mkdir) if mkdir.is_recursive => Outcome::Path(mkdir_all(&mkdir.path, limits)?),
        Op::Mkdir(mkdir) => {
            let (dir, name) = limits.parent(&mkdir.path)?;
            make_dir(&dir, &name)?;
            done
        }
        Op::Remove(rm) => {
            remove(&rm, limits)?;
            done
        }
        Op::Rename(rename) => {
            let (from, from_name) = limits.parent(&rename.src)?;
            let (to, to_name) = limits.parent(&rename.dst)?;
            let file = entry(&from, &from_name, nt::DELETE | nt::FILE_READ_ATTRIBUTES)?;
            nt::rename(&file, &to, named(&to_name)?).map_err(io)?;
            done
        }
        Op::Copy(copy) => {
            copy_path(&copy, limits)?;
            done
        }
        Op::Chmod(chmod) => {
            let file = limits.object(
                &chmod.path,
                nt::FILE_READ_ATTRIBUTES | nt::FILE_WRITE_ATTRIBUTES,
            )?;
            let attributes = nt::info(&file).map_err(io)?.attributes;
            nt::set_basic(
                &file,
                None,
                None,
                Some(mode::attributes_for_chmod(attributes, chmod.mode)),
            )
            .map_err(io)?;
            done
        }
        Op::Chown(chown) => {
            // Checked to exist and to be in scope, then left as it is.
            if chown.is_nofollow {
                let (dir, name) = limits.parent(&chown.path)?;
                entry(&dir, &name, nt::FILE_READ_ATTRIBUTES)?;
            } else {
                limits.object(&chown.path, nt::FILE_READ_ATTRIBUTES)?;
            }
            done
        }
        Op::Utimes(utimes) => {
            let access = nt::FILE_READ_ATTRIBUTES | nt::FILE_WRITE_ATTRIBUTES;
            let file = if utimes.is_nofollow {
                let (dir, name) = limits.parent(&utimes.path)?;
                entry(&dir, &name, access)?
            } else {
                limits.object(&utimes.path, access)?
            };
            nt::set_basic(
                &file,
                Some(mode::unix_ns_to_filetime(utimes.atime_ns)),
                Some(mode::unix_ns_to_filetime(utimes.mtime_ns)),
                None,
            )
            .map_err(io)?;
            done
        }
        Op::Truncate(truncate) => {
            let file = limits.object(
                &truncate.path,
                FILE_GENERIC_WRITE | nt::FILE_READ_ATTRIBUTES,
            )?;
            if nt::info(&file).map_err(io)?.is_dir() {
                return Err(Errno::EISDIR);
            }
            limits.grow(&file, truncate.length)?;
            file.set_len(truncate.length).map_err(io)?;
            done
        }
        Op::Symlink(symlink) => {
            let (dir, name) = limits.parent(&symlink.path)?;
            make_symlink(&dir, &name, &symlink.target)?;
            done
        }
        Op::Link(link) => {
            let (from, from_name) = limits.parent(&link.existing)?;
            let (to, to_name) = limits.parent(&link.path)?;
            let file = entry(
                &from,
                &from_name,
                nt::FILE_READ_ATTRIBUTES | nt::FILE_WRITE_ATTRIBUTES,
            )?;
            // As on Linux: a directory cannot be hard-linked.
            if nt::info(&file).map_err(io)?.is_dir() {
                return Err(Errno::EPERM);
            }
            nt::link(&file, &to, named(&to_name)?).map_err(io)?;
            done
        }
        Op::Readlink(readlink) => {
            let (dir, name) = limits.parent(&readlink.path)?;
            let file = entry(&dir, &name, nt::FILE_READ_ATTRIBUTES)?;
            if !nt::info(&file).map_err(io)?.is_link() {
                return Err(Errno::EINVAL);
            }
            Outcome::Path(nt::read_link(&file).map_err(io)?)
        }
        Op::Realpath(realpath) => {
            let file = limits.object(&realpath.path, nt::FILE_READ_ATTRIBUTES)?;
            Outcome::Path(nt::final_path(&file).map_err(io)?)
        }
        Op::Access(access) => {
            check_access(&access.path, access.mode, limits)?;
            done
        }
        Op::Mkdtemp(mkdtemp) => Outcome::Path(make_temp_dir(&mkdtemp.prefix, limits)?),
        Op::Open(open) => {
            if open.flags & !OPEN_FLAGS != 0 || open.flags & ACCESS_MODE == ACCESS_MODE {
                return Err(Errno::EINVAL);
            }
            let file = open_checked(&open.path, open.flags, open.mode, limits)?;
            Outcome::Handle(table().insert(file, user, open.flags)?)
        }
        Op::Read(read) => {
            let len = read.length as usize;
            if len > MAX_IO {
                return Err(Errno::EINVAL);
            }
            let (file, _) = table().get(read.handle, &user)?;
            let mut data = vec![0; len];
            let n = match u64::try_from(read.position) {
                Ok(position) => positioned(&file, |file| file.seek_read(&mut data, position))?,
                Err(_) => (&*file).read(&mut data).map_err(io)?,
            };
            data.truncate(n);
            Outcome::Data(data)
        }
        Op::Write(write) => {
            if write.data.len() > MAX_IO {
                return Err(Errno::EINVAL);
            }
            let (file, flags) = table().get(write.handle, &user)?;
            let appends = flags & O_APPEND != 0;
            if limits.max_write_bytes != 0 {
                let start = match u64::try_from(write.position) {
                    _ if appends => nt::info(&file).map_err(io)?.size,
                    Ok(position) => position,
                    Err(_) => (&*file).stream_position().map_err(io)?,
                };
                limits.grow(&file, start.saturating_add(write.data.len() as u64))?;
            }
            // An append handle writes at the end wherever it is told to, as
            // O_APPEND does with pwrite.
            let n = match u64::try_from(write.position) {
                Ok(position) if !appends => {
                    positioned(&file, |file| file.seek_write(&write.data, position))?
                }
                _ => (&*file).write(&write.data).map_err(io)?,
            };
            Outcome::Written(n as u64)
        }
        Op::Fstat(handle) => Outcome::Stat(stat_of(&table().get(handle.handle, &user)?.0)?),
        Op::Ftruncate(truncate) => {
            let (file, _) = table().get(truncate.handle, &user)?;
            limits.grow(&file, truncate.length)?;
            file.set_len(truncate.length).map_err(io)?;
            done
        }
        Op::Fsync(fsync) => {
            let (file, _) = table().get(fsync.handle, &user)?;
            // Both are FlushFileBuffers on Windows.
            if fsync.is_data_only {
                file.sync_data()
            } else {
                file.sync_all()
            }
            .map_err(io)?;
            done
        }
        Op::Close(handle) => {
            table().close(handle.handle, &user)?;
            done
        }
    })
}

/// A positioned read or write with the handle's own position put back.
fn positioned(file: &File, op: impl FnOnce(&File) -> std::io::Result<usize>) -> R<usize> {
    let mut held = file;
    let before = held.stream_position().map_err(io)?;
    let result = op(file);
    held.seek(SeekFrom::Start(before)).map_err(io)?;
    result.map_err(io)
}

/// A name a handle-relative call may take: one component.
fn named(name: &str) -> R<&str> {
    if name == "." {
        Err(Errno::EBUSY)
    } else {
        Ok(name)
    }
}

/// What a call may touch, as the sandbox's policy on the host sets it.
struct Limits {
    /// Mapped to drive form. A scope that maps to nothing admits nothing.
    scopes: Vec<String>,
    is_scoped: bool,
    max_write_bytes: u64,
}

impl Limits {
    fn admits(&self, path: &str) -> bool {
        !self.is_scoped || wpaths::within(&self.scopes, path)
    }

    /// Refuses an object outside the scopes, by the path its handle is open on.
    fn check(&self, file: &File) -> R<()> {
        if !self.is_scoped {
            return Ok(());
        }
        if !self.admits(&nt::final_path(file).map_err(io)?) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Opens `path`, following links as the guest's programs would, and
    /// checks what it reached.
    fn object(&self, path: &str, access: u32) -> R<File> {
        let path = win::map_path(path)?;
        let (file, _) = nt::open_path(&path, access, OPEN_EXISTING, false).map_err(io)?;
        self.check(&file)?;
        Ok(file)
    }

    /// The directory holding `path`'s last component, checked with the name
    /// joined on, and that name; "." when the path is a drive root.
    fn parent(&self, path: &str) -> R<(File, String)> {
        let mapped = win::map_path(path)?;
        let dir_access = nt::FILE_LIST_DIRECTORY | nt::FILE_READ_ATTRIBUTES;
        let Some((parent, name)) = wpaths::split(&mapped) else {
            let (dir, _) = nt::open_path(&mapped, dir_access, OPEN_EXISTING, false).map_err(io)?;
            self.check(&dir)?;
            return Ok((dir, ".".into()));
        };
        let (dir, _) = nt::open_path(parent, dir_access, OPEN_EXISTING, false).map_err(io)?;
        if !nt::info(&dir).map_err(io)?.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if self.is_scoped {
            let joined = wpaths::join(&nt::final_path(&dir).map_err(io)?, name);
            if !self.admits(&joined) {
                return Err(Errno::EACCES);
            }
        }
        Ok((dir, name.to_string()))
    }

    /// Refuses growing `file` to `size` past the cap. A file already past it
    /// may still be rewritten or shrunk within the size it has.
    fn grow(&self, file: &File, size: u64) -> R<()> {
        if self.max_write_bytes == 0 || size <= self.max_write_bytes {
            return Ok(());
        }
        if size > nt::info(file).map_err(io)?.size {
            return Err(Errno::EFBIG);
        }
        Ok(())
    }
}

/// Opens an entry of a checked directory as itself, a link not followed.
fn entry(dir: &File, name: &str, access: u32) -> R<File> {
    if name == "." {
        return dir.try_clone().map_err(io);
    }
    nt::open_at(dir, name, access, FILE_OPEN, nt::FILE_OPEN_REPARSE_POINT, 0)
        .map(|(file, _)| file)
        .map_err(io)
}

fn make_dir(dir: &File, name: &str) -> R<File> {
    nt::open_at(
        dir,
        named(name)?,
        nt::FILE_LIST_DIRECTORY | nt::FILE_READ_ATTRIBUTES,
        FILE_CREATE,
        nt::FILE_DIRECTORY_FILE,
        0,
    )
    .map(|(file, _)| file)
    .map_err(io)
}

fn stat_of(file: &File) -> R<guestpb::FsStatResult> {
    let info = nt::info(file).map_err(io)?;
    let name = nt::final_path(file).unwrap_or_default();
    Ok(guestpb::FsStatResult {
        dev: u64::from(info.volume),
        ino: info.index,
        mode: mode::mode(info.attributes, info.reparse_tag, &name),
        nlink: u64::from(info.nlink),
        uid: 0,
        gid: 0,
        rdev: 0,
        size: info.size,
        blksize: 4096,
        blocks: info.allocated.div_ceil(512),
        atime_ns: mode::filetime_to_unix_ns(info.accessed),
        mtime_ns: mode::filetime_to_unix_ns(info.written),
        ctime_ns: mode::filetime_to_unix_ns(info.changed),
        birthtime_ns: mode::filetime_to_unix_ns(info.created),
    })
}

/// mkdir -p, returning the first directory it created, empty when every one
/// was there already.
fn mkdir_all(path: &str, limits: &Limits) -> R<String> {
    let mapped = win::map_path(path)?;
    let parts: Vec<&str> = mapped[3..]
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    let mut prefix = mapped[..3].to_string();
    let mut first = String::new();
    for (i, part) in parts.iter().enumerate() {
        prefix = wpaths::join(&prefix, part);
        match nt::open_path(&prefix, nt::FILE_READ_ATTRIBUTES, OPEN_EXISTING, false) {
            Ok((file, _)) => {
                if nt::info(&file).map_err(io)?.is_dir() {
                    continue;
                }
                return Err(if i + 1 == parts.len() {
                    Errno::EEXIST
                } else {
                    Errno::ENOTDIR
                });
            }
            Err(err) if errno::from_io(&err) == Errno::ENOENT => {}
            Err(err) => return Err(io(err)),
        }
        let (dir, name) = limits.parent(&prefix)?;
        match make_dir(&dir, &name) {
            Ok(_) if first.is_empty() => first.clone_from(&prefix),
            Ok(_) | Err(Errno::EEXIST) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(first)
}

fn remove(rm: &guestpb::FsRemove, limits: &Limits) -> R<()> {
    let removed = limits.parent(&rm.path).and_then(|(dir, name)| {
        let name = named(&name)?;
        let file = entry(&dir, name, nt::DELETE | nt::FILE_READ_ATTRIBUTES)?;
        let info = nt::info(&file).map_err(io)?;
        let is_dir = info.is_dir() && !info.is_link();
        match (is_dir, rm.is_recursive, rm.is_dir_only) {
            (true, true, _) => {
                drop(file);
                remove_tree(&dir, name, limits)
            }
            (true, false, false) => Err(Errno::EISDIR),
            (false, _, true) => Err(Errno::ENOTDIR),
            _ => nt::delete(&file).map_err(io),
        }
    });
    match removed {
        Err(Errno::ENOENT) if rm.is_force => Ok(()),
        other => other,
    }
}

/// rm -r by handle: each directory is entered relative to the one that
/// listed it and never through a link, so a link inside the tree is removed
/// as itself and nothing it points at goes with it.
fn remove_tree(parent: &File, name: &str, limits: &Limits) -> R<()> {
    let (dir, _) = nt::open_at(
        parent,
        name,
        nt::FILE_LIST_DIRECTORY | nt::DELETE | nt::FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        nt::FILE_DIRECTORY_FILE | nt::FILE_OPEN_REPARSE_POINT,
        0,
    )
    .map_err(io)?;
    limits.check(&dir)?;
    for child in nt::entries(&dir).map_err(io)? {
        if child.attributes & mode::FILE_ATTRIBUTE_DIRECTORY != 0
            && !mode::is_link(child.attributes, child.reparse_tag)
        {
            remove_tree(&dir, &child.name, limits)?;
        } else {
            let file = entry(&dir, &child.name, nt::DELETE | nt::FILE_READ_ATTRIBUTES)?;
            nt::delete(&file).map_err(io)?;
        }
    }
    nt::delete(&dir).map_err(io)
}

/// Open flags in their Linux values, as access rights and whether to create.
fn access_for(flags: u32) -> u32 {
    let mut access = nt::FILE_READ_ATTRIBUTES;
    let write = if flags & O_APPEND != 0 {
        // Append data without write data: Windows then writes every byte at
        // the end, atomically, as O_APPEND does.
        FILE_GENERIC_WRITE & !FILE_WRITE_DATA
    } else {
        FILE_GENERIC_WRITE
    };
    match flags & ACCESS_MODE {
        O_WRONLY => access |= write,
        O_RDWR => access |= FILE_GENERIC_READ | write,
        _ => access |= FILE_GENERIC_READ,
    }
    // A truncate needs write data whatever the access mode, as O_TRUNC
    // truncates an O_RDONLY open on Linux too.
    if flags & O_TRUNC != 0 {
        access |= FILE_WRITE_DATA;
    }
    if flags & O_CREAT != 0 {
        access |= nt::FILE_WRITE_ATTRIBUTES;
    }
    access
}

/// open(2), with nothing created or truncated before what it would happen to
/// has been checked.
fn open_checked(path: &str, flags: u32, create_mode: u32, limits: &Limits) -> R<File> {
    let access = access_for(flags);
    let exclusive = flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL;
    let file = 'opened: {
        if !limits.is_scoped {
            let disposition = if exclusive {
                CREATE_NEW
            } else if flags & O_CREAT != 0 {
                OPEN_ALWAYS
            } else {
                OPEN_EXISTING
            };
            let (file, existed) =
                nt::open_path(&win::map_path(path)?, access, disposition, false).map_err(io)?;
            break 'opened (file, disposition != OPEN_EXISTING && !existed);
        }
        if !exclusive {
            match limits.object(path, access) {
                Ok(file) => break 'opened (file, false),
                Err(Errno::ENOENT) if flags & O_CREAT != 0 => {}
                Err(err) => return Err(err),
            }
        }
        // Created as a name in a checked directory. A link at that name is
        // refused rather than followed to wherever it would create the file.
        let (dir, name) = limits.parent(path)?;
        let disposition = if exclusive { FILE_CREATE } else { FILE_OPEN_IF };
        let (file, created) = nt::open_at(
            &dir,
            named(&name)?,
            access,
            disposition,
            nt::FILE_NON_DIRECTORY_FILE | nt::FILE_OPEN_REPARSE_POINT,
            0,
        )
        .map_err(io)?;
        if nt::info(&file).map_err(io)?.is_link() {
            return Err(Errno::ELOOP);
        }
        (file, created)
    };
    let (file, created) = file;
    let info = nt::info(&file).map_err(io)?;
    if info.is_dir() && flags & ACCESS_MODE != 0 {
        return Err(Errno::EISDIR);
    }
    if flags & O_TRUNC != 0 && !info.is_dir() {
        file.set_len(0).map_err(io)?;
    }
    if created && create_mode != 0 && create_mode & 0o200 == 0 {
        nt::set_basic(
            &file,
            None,
            None,
            Some(mode::attributes_for_chmod(info.attributes, create_mode)),
        )
        .map_err(io)?;
    }
    Ok(file)
}

fn check_access(path: &str, wanted: u32, limits: &Limits) -> R<()> {
    let mut access = nt::FILE_READ_ATTRIBUTES;
    if wanted & 4 != 0 {
        access |= FILE_GENERIC_READ;
    }
    if wanted & 2 != 0 {
        access |= FILE_GENERIC_WRITE;
    }
    if wanted & 1 != 0 {
        access |= FILE_EXECUTE;
    }
    // Opening with the rights asked for is the access check, made against
    // the file's ACL as the caller.
    let file = limits.object(path, access)?;
    let info = nt::info(&file).map_err(io)?;
    // The read-only attribute refuses writes whatever the ACL says.
    if wanted & 2 != 0 && !info.is_dir() && info.attributes & mode::FILE_ATTRIBUTE_READONLY != 0 {
        return Err(Errno::EACCES);
    }
    Ok(())
}

/// Makes `name` in `dir` a symlink to `target`, a file or a directory link
/// as the target is one when it is made, which Windows has to be told.
fn make_symlink(dir: &File, name: &str, target: &str) -> R<()> {
    let name = named(name)?;
    let is_absolute = target.starts_with(['/', '\\']) || target.as_bytes().get(1) == Some(&b':');
    let absolute = is_absolute.then(|| win::map_path(target)).transpose()?;
    let resolved = match &absolute {
        Some(mapped) => mapped.clone(),
        None => win::map_path(&wpaths::join(
            &nt::final_path(dir).map_err(io)?,
            &target.replace('/', "\\"),
        ))?,
    };
    let is_dir = std::path::Path::new(&wpaths::long(&resolved)).is_dir();
    let kind = if is_dir {
        nt::FILE_DIRECTORY_FILE
    } else {
        nt::FILE_NON_DIRECTORY_FILE
    };
    let (link, _) = nt::open_at(
        dir,
        name,
        nt::GENERIC_WRITE | nt::DELETE | nt::FILE_READ_ATTRIBUTES,
        FILE_CREATE,
        kind | nt::FILE_OPEN_REPARSE_POINT,
        0,
    )
    .map_err(io)?;
    if let Err(err) = nt::set_symlink(&link, target, absolute.as_deref()) {
        let _ = nt::delete(&link);
        return Err(io(err));
    }
    Ok(())
}

fn copy_path(copy: &guestpb::FsCopy, limits: &Limits) -> R<()> {
    let src = limits.object(&copy.src, FILE_GENERIC_READ)?;
    let info = nt::info(&src).map_err(io)?;
    if info.is_dir() {
        if !copy.is_recursive {
            return Err(Errno::EISDIR);
        }
        let (parent, name) = limits.parent(&copy.dst)?;
        return copy_tree(&src, &info, &parent, named(&name)?, copy, limits, None);
    }
    let mut flags = O_WRONLY | O_CREAT;
    if copy.is_exclusive {
        flags |= O_EXCL;
    }
    let dst = open_checked(&copy.dst, flags, 0, limits)?;
    copy_file(&src, &info, &dst, copy.is_preserving, limits)
}

fn copy_file(
    src: &File,
    info: &nt::Info,
    dst: &File,
    is_preserving: bool,
    limits: &Limits,
) -> R<()> {
    // Emptied only once it is known not to be the source: a file copied onto
    // itself would otherwise come out empty.
    if nt::info(dst).map_err(io)?.is_same(info) {
        return Err(Errno::EINVAL);
    }
    limits.grow(dst, info.size)?;
    dst.set_len(0).map_err(io)?;
    std::io::copy(&mut &*src, &mut &*dst).map_err(io)?;
    if is_preserving {
        preserve(dst, info)?;
    }
    Ok(())
}

/// Carries times and the read-only bit over, which is what Windows has of
/// `cp -p`.
fn preserve(dst: &File, info: &nt::Info) -> R<()> {
    let readonly = info.attributes & mode::FILE_ATTRIBUTE_READONLY;
    let attributes =
        (nt::info(dst).map_err(io)?.attributes & !mode::FILE_ATTRIBUTE_READONLY) | readonly;
    nt::set_basic(
        dst,
        Some(info.accessed),
        Some(info.written),
        Some(attributes),
    )
    .map_err(io)
}

/// cp -r, as the Linux agent does it: links inside the tree are copied as
/// links, each directory on either side is checked as it is entered, and a
/// destination inside the source is not copied into itself.
fn copy_tree(
    src: &File,
    info: &nt::Info,
    parent: &File,
    name: &str,
    copy: &guestpb::FsCopy,
    limits: &Limits,
    top: Option<(u32, u64)>,
) -> R<()> {
    let (dst, _) = nt::open_at(
        parent,
        name,
        nt::FILE_LIST_DIRECTORY | nt::FILE_READ_ATTRIBUTES | nt::FILE_WRITE_ATTRIBUTES,
        if copy.is_exclusive {
            FILE_CREATE
        } else {
            FILE_OPEN_IF
        },
        nt::FILE_DIRECTORY_FILE | nt::FILE_OPEN_REPARSE_POINT,
        0,
    )
    .map_err(io)?;
    limits.check(&dst)?;
    let dst_info = nt::info(&dst).map_err(io)?;
    if dst_info.is_link() {
        return Err(Errno::ELOOP);
    }
    let top = top.unwrap_or((dst_info.volume, dst_info.index));
    let file_disposition = if copy.is_exclusive {
        FILE_CREATE
    } else {
        FILE_OPEN_IF
    };
    for child in nt::entries(src).map_err(io)? {
        if mode::is_link(child.attributes, child.reparse_tag) {
            let link = entry(src, &child.name, nt::FILE_READ_ATTRIBUTES)?;
            let target = nt::read_link(&link).map_err(io)?;
            if !copy.is_exclusive
                && let Ok(existing) =
                    entry(&dst, &child.name, nt::DELETE | nt::FILE_READ_ATTRIBUTES)
            {
                nt::delete(&existing).map_err(io)?;
            }
            make_symlink(&dst, &child.name, &target)?;
        } else if child.attributes & mode::FILE_ATTRIBUTE_DIRECTORY != 0 {
            let (from, _) = nt::open_at(
                src,
                &child.name,
                nt::FILE_LIST_DIRECTORY | nt::FILE_READ_ATTRIBUTES,
                FILE_OPEN,
                nt::FILE_DIRECTORY_FILE | nt::FILE_OPEN_REPARSE_POINT,
                0,
            )
            .map_err(io)?;
            let from_info = nt::info(&from).map_err(io)?;
            if (from_info.volume, from_info.index) == top {
                continue;
            }
            limits.check(&from)?;
            copy_tree(
                &from,
                &from_info,
                &dst,
                &child.name,
                copy,
                limits,
                Some(top),
            )?;
        } else {
            let (from, _) = nt::open_at(
                src,
                &child.name,
                FILE_GENERIC_READ,
                FILE_OPEN,
                nt::FILE_NON_DIRECTORY_FILE | nt::FILE_OPEN_REPARSE_POINT,
                0,
            )
            .map_err(io)?;
            let from_info = nt::info(&from).map_err(io)?;
            let (to, _) = nt::open_at(
                &dst,
                &child.name,
                FILE_GENERIC_WRITE | nt::FILE_READ_ATTRIBUTES,
                file_disposition,
                nt::FILE_NON_DIRECTORY_FILE | nt::FILE_OPEN_REPARSE_POINT,
                0,
            )
            .map_err(io)?;
            copy_file(&from, &from_info, &to, copy.is_preserving, limits)?;
        }
    }
    if copy.is_preserving {
        preserve(&dst, info)?;
    }
    Ok(())
}

fn make_temp_dir(prefix: &str, limits: &Limits) -> R<String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for _ in 0..100 {
        let suffix: String = win::random::<6>()
            .iter()
            .map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()]))
            .collect();
        let path = win::map_path(&format!("{prefix}{suffix}"))?;
        let (dir, name) = limits.parent(&path)?;
        match make_dir(&dir, &name) {
            Ok(_) => return Ok(path),
            Err(Errno::EEXIST) => continue,
            Err(err) => return Err(err),
        }
    }
    Err(Errno::EEXIST)
}

/// A file opened by FsOpen.
struct Open {
    file: Arc<File>,
    /// Who opened it, and so who may use it.
    user: String,
    flags: u32,
    used: Instant,
}

#[derive(Default)]
struct Table {
    open: Mutex<HashMap<u64, Open>>,
}

fn table() -> &'static Table {
    static TABLE: LazyLock<Table> = LazyLock::new(Table::default);
    &TABLE
}

impl Table {
    fn insert(&self, file: File, user: String, flags: u32) -> R<u64> {
        let mut open = self.open.lock().unwrap();
        if open.len() >= MAX_HANDLES {
            return Err(Errno::EMFILE);
        }
        // Random rather than counted, so one caller cannot guess at another's,
        // and within 53 bits, so a JavaScript number carries it exactly.
        let handle = loop {
            let handle = u64::from_ne_bytes(win::random()) & ((1 << 53) - 1);
            if handle != 0 && !open.contains_key(&handle) {
                break handle;
            }
        };
        open.insert(
            handle,
            Open {
                file: Arc::new(file),
                user,
                flags,
                used: Instant::now(),
            },
        );
        Ok(handle)
    }

    fn get(&self, handle: u64, user: &str) -> R<(Arc<File>, u32)> {
        let mut open = self.open.lock().unwrap();
        let entry = open
            .get_mut(&handle)
            .filter(|entry| entry.user == user)
            .ok_or(Errno::EBADF)?;
        entry.used = Instant::now();
        Ok((Arc::clone(&entry.file), entry.flags))
    }

    fn close(&self, handle: u64, user: &str) -> R<()> {
        let mut open = self.open.lock().unwrap();
        match open.get(&handle) {
            Some(entry) if entry.user == user => {
                open.remove(&handle);
                Ok(())
            }
            _ => Err(Errno::EBADF),
        }
    }
}

/// Closes handles left unused for [`IDLE`], for as long as the agent runs.
pub async fn close_idle() {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        table()
            .open
            .lock()
            .unwrap()
            .retain(|_, entry| entry.used.elapsed() < IDLE);
    }
}
