//! One POSIX file operation per call, which SDKs mirror a language's own file
//! API on without an exec per call.
//!
//! Paths resolve the way the guest's own processes see them: inside
//! [`files::guest_root`], following symlinks as the kernel would. Upload and
//! download refuse every symlink so that the host's string check on a path
//! holds; here a caller is asking for POSIX, so the sandbox's path scopes come
//! with the request and are held here, to the object each call acts on.
//!
//! Kernel errors are the response's own `FsError`, by errno name, so an SDK
//! can raise exactly what the language would. Only a request this agent cannot
//! serve at all is a gRPC error.
//!
//! Linux holds every object by descriptor: `O_PATH` opens anything without
//! needing access to it, and `/proc/self/fd` names it. macOS has neither, so
//! where Linux checks an `O_PATH` descriptor macOS resolves the path itself
//! to a name with no link in it, checks that name, and acts on it with a
//! call that refuses any link (`AT_SYMLINK_NOFOLLOW_ANY`). The README says
//! what that does and does not change.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::ffi::OsStringExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::fs::{FileExt as _, FileTypeExt as _, MetadataExt as _};
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, FcntlArg, FdFlag, OFlag, fcntl};
#[cfg(target_os = "linux")]
use nix::fcntl::{OpenHow, ResolveFlag, openat2};
use nix::libc;
use nix::sys::stat::{Mode, UtimensatFlags};
use nix::sys::time::TimeSpec;
use nix::unistd::UnlinkatFlags;
use tonic::Status;

use burrow_proto::guest::v1 as guestpb;
use guestpb::fs_request::Op;
use guestpb::fs_response::Result as Outcome;

use crate::unix::files;

/// What `fs-scoped` in the health response promises: Fs, with the request's
/// path scopes and write cap enforced.
pub const FEATURE_FS: &str = "fs-scoped";

/// The most one read or write carries, so a call is one bounded message.
const MAX_IO: usize = 4 << 20;
/// Open handles across every caller. Each is a descriptor the agent holds, out
/// of the same limit everything else it does draws on.
const MAX_HANDLES: usize = 1024;
/// How long a handle may go unused before the agent closes it: a client that
/// went away without closing would otherwise hold it for the guest's life.
const IDLE: Duration = Duration::from_secs(600);
/// The access mode bits. Not `O_ACCMODE`, which musl widens with `O_PATH`.
const ACCESS_MODE: OFlag = OFlag::O_WRONLY.union(OFlag::O_RDWR);
/// The open flags a caller may pass, all of them in their Linux values.
#[cfg(target_os = "linux")]
const OPEN_FLAGS: OFlag = ACCESS_MODE
    .union(OFlag::O_CREAT)
    .union(OFlag::O_EXCL)
    .union(OFlag::O_TRUNC)
    .union(OFlag::O_APPEND);
/// The same flags as the request carries them, in Linux's numbers, and what
/// each is here.
#[cfg(target_os = "macos")]
const OPEN_FLAGS: [(u32, OFlag); 6] = [
    (0o1, OFlag::O_WRONLY),
    (0o2, OFlag::O_RDWR),
    (0o100, OFlag::O_CREAT),
    (0o200, OFlag::O_EXCL),
    (0o1000, OFlag::O_TRUNC),
    (0o2000, OFlag::O_APPEND),
];
/// How a directory is held for the calls that act on a name in it: by
/// `O_PATH` on Linux, which needs no access to the directory at all; for
/// search on macOS, which needs the search permission every one of those
/// calls needs anyway.
#[cfg(target_os = "linux")]
const DIR_HANDLE: OFlag = OFlag::O_PATH.union(OFlag::O_DIRECTORY);
#[cfg(target_os = "macos")]
const DIR_HANDLE: OFlag = OFlag::O_SEARCH;
/// What realpath(3) allows before ELOOP, as the kernel's own resolution does.
const MAX_SYMLINKS: u32 = 40;
const NS: i64 = 1_000_000_000;

pub async fn handle(req: guestpb::FsRequest) -> Result<guestpb::FsResponse, Status> {
    let op = req
        .op
        .ok_or_else(|| Status::invalid_argument("FsRequest names no op"))?;
    let (syscall, path, dest) = op.describe();
    let (path, dest) = (path.to_string(), dest.to_string());
    // A call on a handle runs on the pool: the descriptor already carries what
    // its open was allowed, and a thread of its own per read would cost more
    // than the read.
    let as_user = match op {
        Op::Read(_)
        | Op::Write(_)
        | Op::Fstat(_)
        | Op::Ftruncate(_)
        | Op::Fsync(_)
        | Op::Close(_) => None,
        _ => files::fs_user(&req.user)?,
    };
    let user = req.user;
    // On macOS a scope under `/tmp`, `/var` or `/etc` is read as the kernel
    // names what is in it, under `/private`.
    #[cfg(target_os = "macos")]
    let scopes = req
        .path_scopes
        .iter()
        .map(|scope| crate::paths::macos_unaliased(scope).into_owned())
        .collect();
    #[cfg(target_os = "linux")]
    let scopes = req.path_scopes;
    let limits = Limits {
        scopes,
        max_write_bytes: req.max_write_bytes,
    };
    let outcome = files::blocking(as_user, move || Ok(run(op, user, &limits)))
        .await?
        .unwrap_or_else(|err| Err(errno(err)));
    let result = outcome.unwrap_or_else(|errno| {
        let (code, errno) = wire_errno(errno);
        Outcome::Error(guestpb::FsError {
            code,
            errno,
            syscall: syscall.into(),
            path,
            dest,
        })
    });
    Ok(guestpb::FsResponse {
        result: Some(result),
    })
}

/// An errno as `FsError` carries it: by name, with Linux's number.
#[cfg(target_os = "linux")]
fn wire_errno(errno: Errno) -> (String, i32) {
    (format!("{errno:?}"), errno as i32)
}

/// macOS numbers most errnos past 34 differently, and reports a resolution
/// that would leave its directory as `ENOTCAPABLE` where Linux reports
/// `EXDEV`; both are given as Linux would.
#[cfg(target_os = "macos")]
fn wire_errno(errno: Errno) -> (String, i32) {
    let name = match errno as i32 {
        libc::ENOTCAPABLE => "EXDEV".to_string(),
        _ => format!("{errno:?}"),
    };
    match crate::errno::linux_number(&name) {
        Some(number) => (name, number),
        None => ("EIO".to_string(), libc::EIO),
    }
}

fn run(op: Op, user: String, limits: &Limits) -> nix::Result<Outcome> {
    let done = Outcome::IsDone(true);
    Ok(match op {
        Op::Stat(stat) if stat.is_nofollow => Outcome::Stat(lstat(&stat.path, limits)?),
        #[cfg(target_os = "linux")]
        Op::Stat(stat) => Outcome::Stat(stat_of(&limits.object(&stat.path, OFlag::O_PATH)?)?),
        #[cfg(target_os = "macos")]
        Op::Stat(stat) => {
            let path = limits.resolved(&stat.path)?;
            Outcome::Stat(stat_raw(&nix::sys::stat::fstatat(
                nix::fcntl::AT_FDCWD,
                path.as_c_str(),
                no_links(),
            )?))
        }
        Op::ReadDir(dir) => Outcome::Entries(read_dir(
            &limits.object(&dir.path, OFlag::O_RDONLY | OFlag::O_DIRECTORY)?,
        )?),
        Op::Mkdir(mkdir) if mkdir.is_recursive => {
            Outcome::Path(mkdir_all(&mkdir.path, mode_or(mkdir.mode, 0o777), limits)?)
        }
        Op::Mkdir(mkdir) => {
            let (dir, name) = limits.parent(&mkdir.path)?;
            nix::sys::stat::mkdirat(&dir, name.as_os_str(), mode_or(mkdir.mode, 0o777))?;
            done
        }
        Op::Remove(rm) => {
            remove(&rm, limits)?;
            done
        }
        Op::Rename(rename) => {
            let (from, from_name) = limits.parent(&rename.src)?;
            let (to, to_name) = limits.parent(&rename.dst)?;
            nix::fcntl::renameat(&from, from_name.as_os_str(), &to, to_name.as_os_str())?;
            done
        }
        Op::Copy(copy) => {
            copy_path(&copy, limits)?;
            done
        }
        #[cfg(target_os = "linux")]
        Op::Chmod(chmod) => {
            // chmod through the descriptor's `/proc` name, which follows to the
            // inode it is open on: fchmod refuses an O_PATH descriptor.
            let file = limits.object(&chmod.path, OFlag::O_PATH)?;
            std::fs::set_permissions(
                files::proc_path(&file),
                std::fs::Permissions::from_mode(chmod.mode),
            )
            .map_err(errno)?;
            done
        }
        #[cfg(target_os = "macos")]
        Op::Chmod(chmod) => {
            let path = limits.resolved(&chmod.path)?;
            // SAFETY: `path` outlives the call.
            Errno::result(unsafe {
                libc::fchmodat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    mode(chmod.mode).bits(),
                    crate::unix::darwin::AT_SYMLINK_NOFOLLOW_ANY,
                )
            })?;
            done
        }
        Op::Chown(chown) => {
            change_owner(&chown, limits)?;
            done
        }
        Op::Utimes(utimes) => {
            let atime = timespec(utimes.atime_ns);
            let mtime = timespec(utimes.mtime_ns);
            if utimes.is_nofollow {
                let (dir, name) = limits.parent(&utimes.path)?;
                nix::sys::stat::utimensat(
                    &dir,
                    name.as_os_str(),
                    &atime,
                    &mtime,
                    UtimensatFlags::NoFollowSymlink,
                )?;
            } else {
                utimes_following(&utimes.path, &atime, &mtime, limits)?;
            }
            done
        }
        #[cfg(target_os = "linux")]
        Op::Truncate(truncate) => {
            // Opened for writing through the checked descriptor's `/proc`
            // name, which reopens that inode and no other.
            let checked = limits.object(&truncate.path, OFlag::O_PATH)?;
            let file = File::options()
                .write(true)
                .open(files::proc_path(&checked))
                .map_err(errno)?;
            limits.grow(&file, truncate.length)?;
            file.set_len(truncate.length).map_err(errno)?;
            done
        }
        #[cfg(target_os = "macos")]
        Op::Truncate(truncate) => {
            let path = limits.resolved(&truncate.path)?;
            let flags =
                OFlag::O_WRONLY | OFlag::O_CLOEXEC | OFlag::from_bits_retain(libc::O_NOFOLLOW_ANY);
            let file = File::from(nix::fcntl::open(path.as_c_str(), flags, Mode::empty())?);
            limits.grow(&file, truncate.length)?;
            file.set_len(truncate.length).map_err(errno)?;
            done
        }
        Op::Symlink(symlink) => {
            let (dir, name) = limits.parent(&symlink.path)?;
            nix::unistd::symlinkat(symlink.target.as_str(), &dir, name.as_os_str())?;
            done
        }
        Op::Link(link) => {
            let (from, from_name) = limits.parent(&link.existing)?;
            let (to, to_name) = limits.parent(&link.path)?;
            nix::unistd::linkat(
                &from,
                from_name.as_os_str(),
                &to,
                to_name.as_os_str(),
                AtFlags::empty(),
            )?;
            done
        }
        Op::Readlink(readlink) => {
            let (dir, name) = limits.parent(&readlink.path)?;
            let target = nix::fcntl::readlinkat(&dir, name.as_os_str())?;
            Outcome::Path(target.to_string_lossy().into_owned())
        }
        #[cfg(target_os = "linux")]
        Op::Realpath(realpath) => {
            limits.object(&realpath.path, OFlag::O_PATH)?;
            Outcome::Path(resolve(&realpath.path)?)
        }
        #[cfg(target_os = "macos")]
        Op::Realpath(realpath) => Outcome::Path(
            limits
                .resolved(&realpath.path)?
                .into_string()
                .map_err(|_| Errno::EINVAL)?,
        ),
        #[cfg(target_os = "linux")]
        Op::Access(access) => {
            check_access(&limits.object(&access.path, OFlag::O_PATH)?, access.mode)?;
            done
        }
        #[cfg(target_os = "macos")]
        Op::Access(access) => {
            check_access(&limits.resolved(&access.path)?, access.mode)?;
            done
        }
        Op::Mkdtemp(mkdtemp) => Outcome::Path(make_temp_dir(&mkdtemp.prefix, limits)?),
        Op::Open(open) => {
            let flags = open_flags(open.flags)?;
            let mode = if flags.contains(OFlag::O_CREAT) {
                mode_or(open.mode, 0o666)
            } else {
                Mode::empty()
            };
            let file = open_checked(&open.path, flags, mode, limits)?;
            Outcome::Handle(table().insert(file, user, flags)?)
        }
        Op::Read(read) => {
            let len = read.length as usize;
            if len > MAX_IO {
                return Err(Errno::EINVAL);
            }
            let file = table().get(read.handle, &user)?;
            let mut data = vec![0; len];
            let n = match u64::try_from(read.position) {
                Ok(position) => file.read_at(&mut data, position),
                Err(_) => (&*file).read(&mut data),
            }
            .map_err(errno)?;
            data.truncate(n);
            Outcome::Data(data)
        }
        Op::Write(write) => {
            if write.data.len() > MAX_IO {
                return Err(Errno::EINVAL);
            }
            let file = table().get(write.handle, &user)?;
            if limits.max_write_bytes != 0 {
                let appends = fcntl(file.as_fd(), FcntlArg::F_GETFL)
                    .map(|flags| OFlag::from_bits_truncate(flags).contains(OFlag::O_APPEND))?;
                // An O_APPEND handle writes at the end wherever it is told to,
                // pwrite included.
                let start = match u64::try_from(write.position) {
                    _ if appends => file.metadata().map_err(errno)?.len(),
                    Ok(position) => position,
                    Err(_) => (&*file).stream_position().map_err(errno)?,
                };
                limits.grow(&file, start.saturating_add(write.data.len() as u64))?;
            }
            let n = match u64::try_from(write.position) {
                Ok(position) => file.write_at(&write.data, position),
                Err(_) => (&*file).write(&write.data),
            }
            .map_err(errno)?;
            Outcome::Written(n as u64)
        }
        Op::Fstat(handle) => Outcome::Stat(stat_of(&*table().get(handle.handle, &user)?)?),
        Op::Ftruncate(truncate) => {
            let file = table().get(truncate.handle, &user)?;
            limits.grow(&file, truncate.length)?;
            file.set_len(truncate.length).map_err(errno)?;
            done
        }
        Op::Fsync(fsync) => {
            let file = table().get(fsync.handle, &user)?;
            if fsync.is_data_only {
                file.sync_data()
            } else {
                file.sync_all()
            }
            .map_err(errno)?;
            done
        }
        Op::Close(handle) => {
            table().close(handle.handle, &user)?;
            done
        }
    })
}

fn errno(err: std::io::Error) -> Errno {
    Errno::from_raw(err.raw_os_error().unwrap_or(libc::EIO))
}

/// The flags of an FsOpen, as this system numbers them.
#[cfg(target_os = "linux")]
fn open_flags(wire: u32) -> nix::Result<OFlag> {
    OFlag::from_bits(i32::try_from(wire).map_err(|_| Errno::EINVAL)?)
        .filter(|flags| OPEN_FLAGS.contains(*flags) && (*flags & ACCESS_MODE) != ACCESS_MODE)
        .ok_or(Errno::EINVAL)
}

#[cfg(target_os = "macos")]
fn open_flags(wire: u32) -> nix::Result<OFlag> {
    let mut flags = OFlag::empty();
    let mut left = wire;
    for (linux, native) in OPEN_FLAGS {
        if wire & linux != 0 {
            flags |= native;
            left &= !linux;
        }
    }
    if left != 0 || (flags & ACCESS_MODE) == ACCESS_MODE {
        return Err(Errno::EINVAL);
    }
    Ok(flags)
}

/// Permission bits as a `Mode`, which is 16 bits wide on macOS.
pub fn mode(bits: u32) -> Mode {
    Mode::from_bits_truncate(bits as libc::mode_t)
}

fn mode_or(bits: u32, default: u32) -> Mode {
    mode(if bits == 0 { default } else { bits })
}

fn timespec(ns: i64) -> TimeSpec {
    TimeSpec::new(ns.div_euclid(NS), ns.rem_euclid(NS))
}

/// What a call may touch, as the sandbox's policy on the host sets it.
struct Limits {
    scopes: Vec<String>,
    max_write_bytes: u64,
}

impl Limits {
    /// Refuses an object outside the scopes.
    ///
    /// Checked through the descriptor the call then acts through, so what was
    /// checked is what is touched, whatever is renamed or relinked in between.
    fn check(&self, file: &File) -> nix::Result<()> {
        if self.scopes.is_empty() {
            return Ok(());
        }
        if !crate::paths::within_posix(&self.scopes, &guest_name(file)?) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Opens `path` the way the call will act on it, and checks it.
    fn object(&self, path: &str, flags: OFlag) -> nix::Result<File> {
        let file = open_in(path, flags, Mode::empty())?;
        self.check(&file)?;
        Ok(file)
    }

    /// [`resolve`]s `path` and refuses the name it comes to outside the
    /// scopes: macOS's stand-in for an `O_PATH` [`object`](Self::object).
    ///
    /// The name has no link in it, and every call made with it refuses one
    /// anywhere along it, so what the call acts on is whatever sits at that
    /// name, inside the scope, when it acts. A link planted or swapped in
    /// after the check fails the call with `ELOOP` instead of being followed.
    #[cfg(target_os = "macos")]
    fn resolved(&self, path: &str) -> nix::Result<CString> {
        let name = resolve(path)?;
        if !self.scopes.is_empty() && !crate::paths::within_posix(&self.scopes, &name) {
            return Err(Errno::EACCES);
        }
        CString::new(name).map_err(|_| Errno::EINVAL)
    }

    /// [`at`], with the name checked where it sits: a call on the name itself
    /// acts in that directory, so the directory's own name and the entry make
    /// the path judged, and the scope's root can itself be created or removed.
    fn parent(&self, path: &str) -> nix::Result<(File, OsString)> {
        let (dir, name) = at(path)?;
        if self.scopes.is_empty() {
            return Ok((dir, name));
        }
        let entry = name.to_str().ok_or(Errno::EACCES)?;
        // [`at`] gives "." when the path names the directory itself.
        if entry == "." {
            self.check(&dir)?;
            return Ok((dir, name));
        }
        let joined = format!("{}/{entry}", guest_name(&dir)?.trim_end_matches('/'));
        if !crate::paths::within_posix(&self.scopes, &joined) {
            return Err(Errno::EACCES);
        }
        Ok((dir, name))
    }

    /// Refuses growing `file` to `size` past the cap. A file already past it
    /// may still be rewritten or shrunk within the size it has.
    fn grow(&self, file: &File, size: u64) -> nix::Result<()> {
        if self.max_write_bytes == 0 || size <= self.max_write_bytes {
            return Ok(());
        }
        if size > file.metadata().map_err(errno)?.len() {
            return Err(Errno::EFBIG);
        }
        Ok(())
    }
}

/// The guest's name for what `file` is.
///
/// The `/proc` name is the path as this agent's mount namespace sees it.
/// Resolved again inside the guest root, following nothing, it must reach the
/// same inode, or it is not the guest's name for the object and says nothing
/// about where the object is.
#[cfg(target_os = "linux")]
fn guest_name(file: &File) -> nix::Result<String> {
    let name = std::fs::read_link(files::proc_path(file)).map_err(errno)?;
    let name = name.to_str().ok_or(Errno::EACCES)?.to_string();
    let how = OpenHow::new()
        .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
        .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_SYMLINKS);
    let root = files::guest_root().map_err(errno)?;
    let named = openat2(&root, name.as_str(), how)
        .map(File::from)
        .map_err(|_| Errno::EACCES)?;
    let (held, named) = (
        file.metadata().map_err(errno)?,
        named.metadata().map_err(errno)?,
    );
    if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
        return Err(Errno::EACCES);
    }
    Ok(name)
}

/// The same check on macOS: `F_GETPATH` is the kernel's name for what the
/// descriptor is open on, and it must reach the same inode again with no link
/// anywhere along it.
#[cfg(target_os = "macos")]
fn guest_name(file: &File) -> nix::Result<String> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes, NUL included.
    Errno::result(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) })?;
    let name = std::ffi::CStr::from_bytes_until_nul(&buf).map_err(|_| Errno::EACCES)?;
    let named = nix::sys::stat::fstatat(nix::fcntl::AT_FDCWD, name, no_links())
        .map_err(|_| Errno::EACCES)?;
    let held = nix::sys::stat::fstat(file)?;
    if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) {
        return Err(Errno::EACCES);
    }
    name.to_str().map(str::to_string).map_err(|_| Errno::EACCES)
}

/// `AT_SYMLINK_NOFOLLOW_ANY`: a link anywhere in the path, the last
/// component included, fails the call with `ELOOP`.
#[cfg(target_os = "macos")]
fn no_links() -> AtFlags {
    AtFlags::from_bits_retain(crate::unix::darwin::AT_SYMLINK_NOFOLLOW_ANY)
}

/// open(2), with nothing created or truncated before what it would happen to
/// has been checked.
fn open_checked(path: &str, flags: OFlag, mode: Mode, limits: &Limits) -> nix::Result<File> {
    if limits.scopes.is_empty() {
        return open_in(path, flags, mode);
    }
    if !flags.contains(OFlag::O_CREAT | OFlag::O_EXCL) {
        match limits.object(
            path,
            flags - (OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_TRUNC),
        ) {
            Ok(file) => {
                if flags.contains(OFlag::O_TRUNC) {
                    file.set_len(0).map_err(errno)?;
                }
                return Ok(file);
            }
            Err(Errno::ENOENT) if flags.contains(OFlag::O_CREAT) => {}
            Err(err) => return Err(err),
        }
    }
    // Created as a name in a checked directory. A link at that name is
    // refused rather than followed to wherever it would create the file.
    let (dir, name) = limits.parent(path)?;
    create_beneath(&dir, &name, flags, mode)
}

/// Opens `path` inside the guest root, following symlinks there as the guest's
/// own processes would: an absolute link target means the guest's `/`.
#[cfg(target_os = "linux")]
fn open_in<P: ?Sized + nix::NixPath>(path: &P, flags: OFlag, mode: Mode) -> nix::Result<File> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let how = OpenHow::new()
        .flags(flags | OFlag::O_CLOEXEC)
        .mode(mode)
        .resolve(ResolveFlag::RESOLVE_IN_ROOT);
    let root = files::guest_root().map_err(errno)?;
    Ok(File::from(openat2(&root, path, how)?))
}

/// The guest root is `/` on macOS, so this is openat(2) from it.
#[cfg(target_os = "macos")]
fn open_in<P: ?Sized + nix::NixPath>(path: &P, flags: OFlag, mode: Mode) -> nix::Result<File> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let root = files::guest_root().map_err(errno)?;
    Ok(File::from(nix::fcntl::openat(
        &root,
        path,
        flags | OFlag::O_CLOEXEC,
        mode,
    )?))
}

/// The directory holding `path`'s last component, and that component, for the
/// calls that act on a name rather than on what it resolves to.
fn at(path: &str) -> nix::Result<(File, OsString)> {
    let path = Path::new(path);
    let dir_flags = DIR_HANDLE;
    let Some(name) = path.file_name() else {
        // `/`, or a path ending in `..`: the name is the directory itself.
        return Ok((open_in(path, dir_flags, Mode::empty())?, ".".into()));
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((open_in(parent, dir_flags, Mode::empty())?, name.to_owned()))
}

/// Opens a name inside a directory already held, refusing a symlink, with the
/// mode a created file gets. The walks of a copy take their names from a
/// listing, so nothing they open can lead out of the tree they are walking.
#[cfg(target_os = "linux")]
fn create_beneath(dir: &File, name: &OsStr, flags: OFlag, mode: Mode) -> nix::Result<File> {
    let how = OpenHow::new()
        .flags(flags | OFlag::O_CLOEXEC)
        .mode(mode)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    Ok(File::from(openat2(dir, name, how)?))
}

#[cfg(target_os = "macos")]
fn create_beneath(dir: &File, name: &OsStr, flags: OFlag, mode: Mode) -> nix::Result<File> {
    let flags = flags | OFlag::O_CLOEXEC | files::beneath_no_symlinks();
    Ok(File::from(nix::fcntl::openat(dir, name, flags, mode)?))
}

#[cfg(target_os = "linux")]
fn stat_of(file: &File) -> nix::Result<guestpb::FsStatResult> {
    let meta = file.metadata().map_err(errno)?;
    Ok(stat_result(
        &meta,
        birthtime(file, OsStr::new(""), libc::AT_EMPTY_PATH),
    ))
}

#[cfg(target_os = "macos")]
fn stat_of(file: &File) -> nix::Result<guestpb::FsStatResult> {
    Ok(stat_raw(&nix::sys::stat::fstat(file)?))
}

#[cfg(target_os = "linux")]
fn lstat(path: &str, limits: &Limits) -> nix::Result<guestpb::FsStatResult> {
    let (dir, name) = limits.parent(path)?;
    let meta = std::fs::symlink_metadata(files::proc_path(&dir).join(&name)).map_err(errno)?;
    Ok(stat_result(
        &meta,
        birthtime(&dir, &name, libc::AT_SYMLINK_NOFOLLOW),
    ))
}

#[cfg(target_os = "macos")]
fn lstat(path: &str, limits: &Limits) -> nix::Result<guestpb::FsStatResult> {
    let (dir, name) = limits.parent(path)?;
    Ok(stat_raw(&nix::sys::stat::fstatat(
        &dir,
        name.as_os_str(),
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )?))
}

/// A stat as macOS's kernel returns it, which carries the birth time itself.
#[cfg(target_os = "macos")]
fn stat_raw(stat: &libc::stat) -> guestpb::FsStatResult {
    guestpb::FsStatResult {
        dev: stat.st_dev as u64,
        ino: stat.st_ino,
        mode: u32::from(stat.st_mode),
        nlink: u64::from(stat.st_nlink),
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat.st_rdev as u64,
        size: stat.st_size as u64,
        blksize: stat.st_blksize as u64,
        blocks: stat.st_blocks as u64,
        atime_ns: stat.st_atime * NS + stat.st_atime_nsec,
        mtime_ns: stat.st_mtime * NS + stat.st_mtime_nsec,
        ctime_ns: stat.st_ctime * NS + stat.st_ctime_nsec,
        birthtime_ns: stat.st_birthtime * NS + stat.st_birthtime_nsec,
    }
}

#[cfg(target_os = "linux")]
fn stat_result(meta: &Metadata, birthtime_ns: i64) -> guestpb::FsStatResult {
    guestpb::FsStatResult {
        dev: meta.dev(),
        ino: meta.ino(),
        mode: meta.mode(),
        nlink: meta.nlink(),
        uid: meta.uid(),
        gid: meta.gid(),
        rdev: meta.rdev(),
        size: meta.size(),
        blksize: meta.blksize(),
        blocks: meta.blocks(),
        atime_ns: meta.atime() * NS + meta.atime_nsec(),
        mtime_ns: meta.mtime() * NS + meta.mtime_nsec(),
        ctime_ns: meta.ctime() * NS + meta.ctime_nsec(),
        birthtime_ns,
    }
}

/// statx(2)'s layout as far as `stx_btime`, padded to the kernel's 256 bytes.
/// libc binds statx for musl only from 1.2.3, which this target is not built
/// against, so the syscall is made by hand for the one field `stat` lacks.
#[cfg(target_os = "linux")]
#[repr(C)]
struct Statx {
    mask: u32,
    _head: [u32; 19],
    btime_sec: i64,
    btime_nsec: u32,
    _tail: [u32; 41],
}

#[cfg(target_os = "linux")]
const STATX_BTIME: u32 = 0x800;

/// When the file was created, 0 where the filesystem does not record it.
#[cfg(target_os = "linux")]
fn birthtime(dir: &File, name: &OsStr, flags: libc::c_int) -> i64 {
    let Ok(name) = CString::new(name.as_bytes()) else {
        return 0;
    };
    // SAFETY: all zeroes is a valid value of a struct of integers.
    let mut buf: Statx = unsafe { std::mem::zeroed() };
    // SAFETY: `buf` is the size the kernel writes, and `name` outlives the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            dir.as_raw_fd(),
            name.as_ptr(),
            flags,
            STATX_BTIME,
            &mut buf as *mut Statx,
        )
    };
    if rc != 0 || buf.mask & STATX_BTIME == 0 {
        return 0;
    }
    buf.btime_sec * NS + i64::from(buf.btime_nsec)
}

/// Lists through the descriptor, held open across the read, so the listing is
/// of the directory that was checked.
fn read_dir(dir: &File) -> nix::Result<guestpb::FsDirEntries> {
    let mut entries = Vec::new();
    for entry in files::read_dir(dir).map_err(errno)? {
        let entry = entry.map_err(errno)?;
        let kind = entry.file_type().map_or("unknown", |kind| {
            if kind.is_file() {
                "file"
            } else if kind.is_dir() {
                "dir"
            } else if kind.is_symlink() {
                "symlink"
            } else if kind.is_fifo() {
                "fifo"
            } else if kind.is_socket() {
                "socket"
            } else if kind.is_char_device() {
                "char"
            } else if kind.is_block_device() {
                "block"
            } else {
                "unknown"
            }
        });
        entries.push(guestpb::FsDirEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            r#type: kind.into(),
        });
    }
    Ok(guestpb::FsDirEntries { entries })
}

/// mkdir -p, returning the first directory it created as Node's `recursive`
/// does, empty when every one was there already.
fn mkdir_all(path: &str, mode: Mode, limits: &Limits) -> nix::Result<String> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let mut prefix = if path.starts_with('/') {
        String::from("/")
    } else {
        String::new()
    };
    let mut first = String::new();
    for (i, part) in parts.iter().enumerate() {
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        prefix.push_str(part);
        // A directory already there is passed through unchecked: nothing is
        // made in it but its child, whose own parent check is the one that
        // places it.
        match open_in(prefix.as_str(), DIR_HANDLE, Mode::empty()) {
            Ok(_) => continue,
            Err(Errno::ENOTDIR) if i + 1 == parts.len() => return Err(Errno::EEXIST),
            Err(Errno::ENOENT) => {}
            Err(err) => return Err(err),
        }
        let (dir, name) = limits.parent(&prefix)?;
        match nix::sys::stat::mkdirat(&dir, name.as_os_str(), mode) {
            Ok(()) if first.is_empty() => first.clone_from(&prefix),
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(first)
}

fn remove(rm: &guestpb::FsRemove, limits: &Limits) -> nix::Result<()> {
    let removed = limits.parent(&rm.path).and_then(|(dir, name)| {
        if rm.is_recursive {
            let stat =
                nix::sys::stat::fstatat(&dir, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)?;
            if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                return remove_tree(&dir, &name, limits);
            }
        }
        let flag = if rm.is_dir_only {
            UnlinkatFlags::RemoveDir
        } else {
            UnlinkatFlags::NoRemoveDir
        };
        let unlinked = nix::unistd::unlinkat(&dir, name.as_os_str(), flag);
        // macOS's unlink(2) of a directory is EPERM, which POSIX allows;
        // Linux's EISDIR is what the SDKs were written against, and says why.
        #[cfg(target_os = "macos")]
        if unlinked == Err(Errno::EPERM)
            && !rm.is_dir_only
            && nix::sys::stat::fstatat(&dir, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFDIR)
        {
            return Err(Errno::EISDIR);
        }
        unlinked
    });
    match removed {
        Err(Errno::ENOENT) if rm.is_force => Ok(()),
        other => other,
    }
}

/// rm -r by descriptor: each directory is entered relative to the one that
/// listed it, never through a link, so a symlink inside the tree is removed as
/// itself and nothing it points at goes with it. Each directory is checked as
/// it is entered; what is unlinked is a name in a checked directory.
fn remove_tree(parent: &File, name: &OsStr, limits: &Limits) -> nix::Result<()> {
    let dir = files::openat_no_symlinks(parent, name, OFlag::O_RDONLY | OFlag::O_DIRECTORY)
        .map_err(errno)?;
    limits.check(&dir)?;
    for entry in files::read_dir(&dir).map_err(errno)? {
        let entry = entry.map_err(errno)?;
        let child = entry.file_name();
        if entry.file_type().map_err(errno)?.is_dir() {
            remove_tree(&dir, &child, limits)?;
        } else {
            nix::unistd::unlinkat(&dir, child.as_os_str(), UnlinkatFlags::NoRemoveDir)?;
        }
    }
    nix::unistd::unlinkat(parent, name, UnlinkatFlags::RemoveDir)
}

fn copy_path(copy: &guestpb::FsCopy, limits: &Limits) -> nix::Result<()> {
    // Nonblocking so a FIFO at `src` is refused below rather than waited on
    // for a writer.
    let src = limits.object(&copy.src, OFlag::O_RDONLY | OFlag::O_NONBLOCK)?;
    let meta = src.metadata().map_err(errno)?;
    if meta.is_dir() {
        if !copy.is_recursive {
            return Err(Errno::EISDIR);
        }
        let (parent, name) = limits.parent(&copy.dst)?;
        return copy_tree(&src, &meta, &parent, &name, copy, limits, None);
    }
    if !meta.is_file() {
        return Err(Errno::EINVAL);
    }
    let mut flags = OFlag::O_WRONLY | OFlag::O_CREAT;
    if copy.is_exclusive {
        flags |= OFlag::O_EXCL;
    }
    let dst = open_checked(&copy.dst, flags, mode(meta.mode()), limits)?;
    copy_file(&src, &meta, &dst, copy.is_preserving, limits)
}

fn copy_file(
    src: &File,
    meta: &Metadata,
    dst: &File,
    is_preserving: bool,
    limits: &Limits,
) -> nix::Result<()> {
    // Truncated only once it is known not to be the source: a file copied
    // onto itself would otherwise come out empty.
    let existing = dst.metadata().map_err(errno)?;
    if (existing.dev(), existing.ino()) == (meta.dev(), meta.ino()) {
        return Err(Errno::EINVAL);
    }
    limits.grow(dst, meta.len())?;
    dst.set_len(0).map_err(errno)?;
    std::io::copy(&mut &*src, &mut &*dst).map_err(errno)?;
    if is_preserving {
        preserve(dst, meta)?;
    }
    Ok(())
}

fn preserve(dst: &File, meta: &Metadata) -> nix::Result<()> {
    nix::sys::stat::fchmod(dst, mode(meta.mode()))?;
    nix::sys::stat::futimens(
        dst,
        &TimeSpec::new(meta.atime(), meta.atime_nsec()),
        &TimeSpec::new(meta.mtime(), meta.mtime_nsec()),
    )
}

/// cp -r. Symlinks inside the tree are copied as links, as Node's `cp` does,
/// and sockets, FIFOs and devices are left out. Each directory on either side
/// is checked as it is entered, and every file is a name in one. `top` is the
/// destination directory the copy began at, which a destination inside the
/// source would otherwise find in its own listing and copy into itself without
/// end.
fn copy_tree(
    src: &File,
    meta: &Metadata,
    parent: &File,
    name: &OsStr,
    copy: &guestpb::FsCopy,
    limits: &Limits,
    top: Option<(u64, u64)>,
) -> nix::Result<()> {
    // Writable by its owner until it is filled, whatever the source's mode: a
    // read-only source directory would otherwise refuse its own contents.
    match nix::sys::stat::mkdirat(parent, name, mode(meta.mode() | 0o700)) {
        Ok(()) => {}
        Err(Errno::EEXIST) if !copy.is_exclusive => {}
        Err(err) => return Err(err),
    }
    let dst = files::openat_no_symlinks(parent, name, OFlag::O_RDONLY | OFlag::O_DIRECTORY)
        .map_err(errno)?;
    limits.check(&dst)?;
    let top = match top {
        Some(top) => top,
        None => {
            let at = dst.metadata().map_err(errno)?;
            (at.dev(), at.ino())
        }
    };
    let mut flags = OFlag::O_WRONLY | OFlag::O_CREAT;
    flags |= if copy.is_exclusive {
        OFlag::O_EXCL
    } else {
        OFlag::O_TRUNC
    };
    for entry in files::read_dir(src).map_err(errno)? {
        let entry = entry.map_err(errno)?;
        let child = entry.file_name();
        let kind = entry.file_type().map_err(errno)?;
        if kind.is_dir() {
            let from = files::openat_no_symlinks(src, &child, OFlag::O_RDONLY | OFlag::O_DIRECTORY)
                .map_err(errno)?;
            let from_meta = from.metadata().map_err(errno)?;
            if (from_meta.dev(), from_meta.ino()) == top {
                continue;
            }
            limits.check(&from)?;
            copy_tree(&from, &from_meta, &dst, &child, copy, limits, Some(top))?;
        } else if kind.is_symlink() {
            let target = nix::fcntl::readlinkat(src, child.as_os_str())?;
            match nix::unistd::symlinkat(target.as_os_str(), &dst, child.as_os_str()) {
                Err(Errno::EEXIST) if !copy.is_exclusive => {
                    nix::unistd::unlinkat(&dst, child.as_os_str(), UnlinkatFlags::NoRemoveDir)?;
                    nix::unistd::symlinkat(target.as_os_str(), &dst, child.as_os_str())?;
                }
                other => other?,
            }
        } else if kind.is_file() {
            let from = files::openat_no_symlinks(src, &child, OFlag::O_RDONLY).map_err(errno)?;
            let from_meta = from.metadata().map_err(errno)?;
            let to = create_beneath(&dst, &child, flags, mode(from_meta.mode()))?;
            copy_file(&from, &from_meta, &to, copy.is_preserving, limits)?;
        }
    }
    if copy.is_preserving {
        preserve(&dst, meta)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn change_owner(chown: &guestpb::FsChown, limits: &Limits) -> nix::Result<()> {
    // -1 is chown(2)'s own "leave it", which as a uid_t is its largest value.
    let id = |id: i64| match id {
        -1 => Ok(u32::MAX),
        id => u32::try_from(id).map_err(|_| Errno::EINVAL),
    };
    let (uid, gid) = (id(chown.uid)?, id(chown.gid)?);
    let (fd, name, flags) = if chown.is_nofollow {
        let (dir, name) = limits.parent(&chown.path)?;
        (dir, name, libc::AT_SYMLINK_NOFOLLOW)
    } else {
        let file = limits.object(&chown.path, OFlag::O_PATH)?;
        (file, OsString::new(), libc::AT_EMPTY_PATH)
    };
    let name = CString::new(name.into_vec()).map_err(|_| Errno::EINVAL)?;
    // `libc` directly, as `files::fchown` is: nix gates its wrapper behind a
    // feature this workspace does not enable.
    // SAFETY: `fd` and `name` outlive the call.
    Errno::result(unsafe { libc::fchownat(fd.as_raw_fd(), name.as_ptr(), uid, gid, flags) })
        .map(drop)
}

/// As on Linux, with a followed path [`resolved`](Limits::resolved) rather
/// than held.
#[cfg(target_os = "macos")]
fn change_owner(chown: &guestpb::FsChown, limits: &Limits) -> nix::Result<()> {
    let id = |id: i64| match id {
        -1 => Ok(u32::MAX),
        id => u32::try_from(id).map_err(|_| Errno::EINVAL),
    };
    let (uid, gid) = (id(chown.uid)?, id(chown.gid)?);
    let (dir, name, flags) = if chown.is_nofollow {
        let (dir, name) = limits.parent(&chown.path)?;
        let name = CString::new(name.into_vec()).map_err(|_| Errno::EINVAL)?;
        (Some(dir), name, libc::AT_SYMLINK_NOFOLLOW)
    } else {
        let name = limits.resolved(&chown.path)?;
        (None, name, crate::unix::darwin::AT_SYMLINK_NOFOLLOW_ANY)
    };
    let fd = dir.as_ref().map_or(libc::AT_FDCWD, |dir| dir.as_raw_fd());
    // SAFETY: `dir` and `name` outlive the call.
    Errno::result(unsafe { libc::fchownat(fd, name.as_ptr(), uid, gid, flags) }).map(drop)
}

/// utimes(2) on what `path` leads to.
#[cfg(target_os = "linux")]
fn utimes_following(
    path: &str,
    atime: &TimeSpec,
    mtime: &TimeSpec,
    limits: &Limits,
) -> nix::Result<()> {
    let file = limits.object(path, OFlag::O_PATH)?;
    nix::sys::stat::utimensat(
        nix::fcntl::AT_FDCWD,
        &files::proc_path(&file),
        atime,
        mtime,
        UtimensatFlags::FollowSymlink,
    )
}

#[cfg(target_os = "macos")]
fn utimes_following(
    path: &str,
    atime: &TimeSpec,
    mtime: &TimeSpec,
    limits: &Limits,
) -> nix::Result<()> {
    let path = limits.resolved(path)?;
    let times = [*atime.as_ref(), *mtime.as_ref()];
    // SAFETY: `path` and `times` outlive the call.
    Errno::result(unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            crate::unix::darwin::AT_SYMLINK_NOFOLLOW_ANY,
        )
    })
    .map(drop)
}

#[cfg(target_os = "linux")]
fn check_access(file: &File, mode: u32) -> nix::Result<()> {
    // faccessat2 with AT_EACCESS, made by hand: plain access(2) checks the
    // real uid, which is root's even on a thread working as a user, and musl
    // drops AT_EACCESS whenever the real and effective ids agree.
    // SAFETY: the descriptor and the empty path outlive the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            file.as_raw_fd(),
            c"".as_ptr(),
            mode,
            libc::AT_EACCESS | libc::AT_EMPTY_PATH,
        )
    };
    Errno::result(rc).map(drop)
}

/// faccessat(2) with `AT_EACCESS`, which on macOS checks the calling
/// thread's own credentials, a user's when the thread has taken them on.
#[cfg(target_os = "macos")]
fn check_access(path: &CString, mode: u32) -> nix::Result<()> {
    let mode = libc::c_int::try_from(mode).map_err(|_| Errno::EINVAL)?;
    // SAFETY: `path` outlives the call.
    Errno::result(unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            path.as_ptr(),
            mode,
            libc::AT_EACCESS | crate::unix::darwin::AT_SYMLINK_NOFOLLOW_ANY,
        )
    })
    .map(drop)
}

/// realpath(3) inside the guest root, resolved a component at a time. The
/// kernel's own answer, a descriptor's `/proc` name, is the path as the
/// agent's mount namespace sees it, which under systemd is not the guest's.
fn resolve(path: &str) -> nix::Result<String> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let root = files::guest_root().map_err(errno)?;
    let mut resolved: Vec<String> = Vec::new();
    let mut pending: Vec<String> = path.split('/').rev().map(str::to_owned).collect();
    let mut links = 0;
    while let Some(part) = pending.pop() {
        match part.as_str() {
            "" | "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => resolved.push(part),
        }
        // Relative to the root, through components already resolved, so
        // nothing but this last one can be a link.
        let here = resolved.join("/");
        let stat = nix::sys::stat::fstatat(&root, here.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
            continue;
        }
        links += 1;
        if links > MAX_SYMLINKS {
            return Err(Errno::ELOOP);
        }
        let target = nix::fcntl::readlinkat(&root, here.as_str())?;
        let target = target.to_string_lossy();
        resolved.pop();
        if target.starts_with('/') {
            resolved.clear();
        }
        pending.extend(target.split('/').rev().map(str::to_owned));
    }
    Ok(format!("/{}", resolved.join("/")))
}

fn make_temp_dir(prefix: &str, limits: &Limits) -> nix::Result<String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for _ in 0..100 {
        let suffix: String = random::<6>()
            .iter()
            .map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()]))
            .collect();
        let path = format!("{prefix}{suffix}");
        let (dir, name) = limits.parent(&path)?;
        match nix::sys::stat::mkdirat(&dir, name.as_os_str(), Mode::from_bits_truncate(0o700)) {
            Ok(()) => return Ok(path),
            Err(Errno::EEXIST) => continue,
            Err(err) => return Err(err),
        }
    }
    Err(Errno::EEXIST)
}

#[cfg(target_os = "linux")]
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // SAFETY: writes at most N bytes into `bytes`.
    unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), N, 0) };
    bytes
}

/// getentropy(2), macOS's getrandom; N is never above its 256.
#[cfg(target_os = "macos")]
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // SAFETY: writes exactly N bytes into `bytes`.
    unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), N) };
    bytes
}

/// A file opened by FsOpen.
struct Open {
    file: Arc<File>,
    /// Who opened it, and so who may use it: the descriptor carries what that
    /// user was allowed, which another user has no claim to.
    user: String,
    flags: OFlag,
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

/// One handle as the agent replacing this one finds it.
#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    handle: u64,
    fd: RawFd,
    user: String,
    flags: i32,
    idle: Duration,
}

impl Table {
    fn insert(&self, file: File, user: String, flags: OFlag) -> nix::Result<u64> {
        let mut open = self.open.lock().unwrap();
        if open.len() >= MAX_HANDLES {
            return Err(Errno::EMFILE);
        }
        // Random rather than counted, so one caller cannot guess at another's,
        // and within 53 bits, so a JavaScript number carries it exactly.
        let handle = loop {
            let handle = u64::from_ne_bytes(random()) & ((1 << 53) - 1);
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

    fn get(&self, handle: u64, user: &str) -> nix::Result<Arc<File>> {
        let mut open = self.open.lock().unwrap();
        let entry = open
            .get_mut(&handle)
            .filter(|entry| entry.user == user)
            .ok_or(Errno::EBADF)?;
        entry.used = Instant::now();
        Ok(Arc::clone(&entry.file))
    }

    fn close(&self, handle: u64, user: &str) -> nix::Result<()> {
        let mut open = self.open.lock().unwrap();
        match open.get(&handle) {
            Some(entry) if entry.user == user => {
                open.remove(&handle);
                Ok(())
            }
            _ => Err(Errno::EBADF),
        }
    }

    fn close_idle(&self) {
        self.open
            .lock()
            .unwrap()
            .retain(|_, entry| entry.used.elapsed() < IDLE);
    }

    fn save(&self, path: &str) -> std::io::Result<()> {
        let open = self.open.lock().unwrap();
        let mut saved = Vec::with_capacity(open.len());
        for (&handle, entry) in open.iter() {
            fcntl(entry.file.as_fd(), FcntlArg::F_SETFD(FdFlag::empty()))?;
            saved.push(Saved {
                handle,
                fd: entry.file.as_raw_fd(),
                user: entry.user.clone(),
                flags: entry.flags.bits(),
                idle: entry.used.elapsed(),
            });
        }
        let bytes = serde_json::to_vec(&saved).map_err(std::io::Error::other)?;
        std::fs::write(path, bytes)
    }

    fn restore(&self, path: &str) {
        let saved = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<Saved>>(&bytes).ok());
        let _ = std::fs::remove_file(path);
        let mut open = self.open.lock().unwrap();
        let kept = ACCESS_MODE | OFlag::O_APPEND;
        for saved in saved.into_iter().flatten() {
            // Read back off the descriptor: a number that did not survive the
            // exec, or that something since reused, is not the handle any more.
            // SAFETY: F_GETFL only reads the flags of whatever the number is.
            let flags = unsafe { libc::fcntl(saved.fd, libc::F_GETFL) };
            if flags < 0
                || OFlag::from_bits_truncate(flags) & kept
                    != OFlag::from_bits_truncate(saved.flags) & kept
            {
                continue;
            }
            // SAFETY: the descriptor was this handle's in the agent before, left
            // open across the exec for it, and nothing else here owns it.
            let file = unsafe { File::from_raw_fd(saved.fd) };
            if fcntl(file.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).is_err() {
                continue;
            }
            open.insert(
                saved.handle,
                Open {
                    file: Arc::new(file),
                    user: saved.user,
                    flags: OFlag::from_bits_truncate(saved.flags),
                    used: Instant::now()
                        .checked_sub(saved.idle)
                        .unwrap_or_else(Instant::now),
                },
            );
        }
    }
}

/// Closes handles left unused for [`IDLE`], for as long as the agent runs.
pub async fn close_idle() {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        table().close_idle();
    }
}

/// Leaves every open handle's descriptor open across the exec of an upgrade,
/// and writes down which handle each one is for the next agent to read back.
/// Run as the last thing before the exec, so nothing started in between
/// inherits them.
pub fn save(path: &str) -> std::io::Result<()> {
    table().save(path)
}

/// Reads what [`save`] wrote and removes the file. Best effort, as for
/// commands: a handle that did not come through reads as EBADF, as if closed.
pub fn restore(path: &str) {
    table().restore(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(std::path::PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("burrow-fs-{tag}-{}-{n}", std::process::id()));
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

    async fn call(user: &str, op: Op) -> Outcome {
        request(user, &[], 0, op).await
    }

    async fn limited(scopes: &[&str], max_write_bytes: u64, op: Op) -> Outcome {
        request("", scopes, max_write_bytes, op).await
    }

    async fn request(user: &str, scopes: &[&str], max_write_bytes: u64, op: Op) -> Outcome {
        handle(guestpb::FsRequest {
            user: user.into(),
            path_scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            max_write_bytes,
            op: Some(op),
        })
        .await
        .unwrap()
        .result
        .unwrap()
    }

    fn opening(path: String, flags: u32) -> Op {
        Op::Open(guestpb::FsOpen {
            path,
            flags,
            mode: 0,
        })
    }

    fn code(outcome: Outcome) -> String {
        match outcome {
            Outcome::Error(err) => err.code,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    async fn open(path: &str, flags: u32) -> u64 {
        match call(
            "",
            Op::Open(guestpb::FsOpen {
                path: path.into(),
                flags,
                mode: 0,
            }),
        )
        .await
        {
            Outcome::Handle(handle) => handle,
            other => panic!("open: {other:?}"),
        }
    }

    async fn read(user: &str, handle: u64, position: i64, length: u32) -> Outcome {
        call(
            user,
            Op::Read(guestpb::FsRead {
                handle,
                position,
                length,
            }),
        )
        .await
    }

    #[tokio::test]
    async fn a_kernel_error_comes_back_by_name() {
        let tmp = Tmp::new("errno");
        let missing = tmp.path("missing");
        let outcome = call(
            "",
            Op::Stat(guestpb::FsStat {
                path: missing.clone(),
                is_nofollow: false,
            }),
        )
        .await;
        let Outcome::Error(err) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(err.code, "ENOENT");
        assert_eq!(err.errno, libc::ENOENT);
        assert_eq!(err.syscall, "stat");
        assert_eq!(err.path, missing);
    }

    #[tokio::test]
    async fn a_handle_reads_and_writes_by_position_and_closes() {
        let tmp = Tmp::new("handle");
        let path = tmp.path("f");
        let handle = open(&path, 0o102).await;

        let write = |position, data: &[u8]| {
            call(
                "",
                Op::Write(guestpb::FsWrite {
                    handle,
                    position,
                    data: data.to_vec(),
                }),
            )
        };
        assert_eq!(write(-1, b"hello").await, Outcome::Written(5));
        assert_eq!(write(0, b"J").await, Outcome::Written(1));
        // A positional write leaves the handle's own position where it was.
        assert_eq!(write(-1, b"!").await, Outcome::Written(1));
        assert_eq!(std::fs::read(&path).unwrap(), b"Jello!");

        assert_eq!(
            read("", handle, 1, 4).await,
            Outcome::Data(b"ello".to_vec())
        );
        assert_eq!(read("", handle, 6, 4).await, Outcome::Data(Vec::new()));
        let Outcome::Stat(stat) = call("", Op::Fstat(guestpb::FsHandle { handle })).await else {
            panic!("fstat");
        };
        assert_eq!(stat.size, 6);

        assert_eq!(
            call("", Op::Close(guestpb::FsHandle { handle })).await,
            Outcome::IsDone(true)
        );
        assert_eq!(code(read("", handle, 0, 1).await), "EBADF");
    }

    #[tokio::test]
    async fn a_read_from_the_handle_position_moves_it() {
        let tmp = Tmp::new("cursor");
        let path = tmp.path("f");
        std::fs::write(&path, b"abcdef").unwrap();
        let handle = open(&path, 0).await;
        assert_eq!(read("", handle, -1, 2).await, Outcome::Data(b"ab".to_vec()));
        assert_eq!(read("", handle, 0, 1).await, Outcome::Data(b"a".to_vec()));
        assert_eq!(read("", handle, -1, 2).await, Outcome::Data(b"cd".to_vec()));
    }

    #[tokio::test]
    async fn a_handle_is_its_opener_s_alone() {
        let tmp = Tmp::new("owner");
        let path = tmp.path("f");
        std::fs::write(&path, b"secret").unwrap();
        let handle = open(&path, 0).await;
        // The handle op does not look the user up, so any name will do.
        assert_eq!(code(read("nobody", handle, 0, 6).await), "EBADF");
        assert_eq!(
            code(call("nobody", Op::Close(guestpb::FsHandle { handle })).await),
            "EBADF"
        );
        assert_eq!(
            read("", handle, 0, 6).await,
            Outcome::Data(b"secret".to_vec())
        );
    }

    #[tokio::test]
    async fn oversized_io_and_unknown_flags_are_einval() {
        let tmp = Tmp::new("limits");
        let path = tmp.path("f");
        std::fs::write(&path, b"x").unwrap();
        let handle = open(&path, 0).await;
        assert_eq!(
            code(read("", handle, 0, (MAX_IO + 1) as u32).await),
            "EINVAL"
        );
        // O_PATH, then an access mode of 3.
        for flags in [0o10000000, 3] {
            let outcome = call(
                "",
                Op::Open(guestpb::FsOpen {
                    path: path.clone(),
                    flags,
                    mode: 0,
                }),
            )
            .await;
            assert_eq!(code(outcome), "EINVAL", "flags {flags:o}");
        }
    }

    #[tokio::test]
    async fn a_recursive_mkdir_reports_the_first_directory_it_made() {
        let tmp = Tmp::new("mkdir");
        let mkdir = |path: String| {
            call(
                "",
                Op::Mkdir(guestpb::FsMkdir {
                    path,
                    mode: 0,
                    is_recursive: true,
                }),
            )
        };
        assert_eq!(mkdir(tmp.path("a/b/c")).await, Outcome::Path(tmp.path("a")));
        assert!(Path::new(&tmp.path("a/b/c")).is_dir());
        assert_eq!(mkdir(tmp.path("a/b/c")).await, Outcome::Path(String::new()));
        assert_eq!(
            mkdir(tmp.path("a/b/d")).await,
            Outcome::Path(tmp.path("a/b/d"))
        );
        std::fs::write(tmp.path("file"), b"").unwrap();
        assert_eq!(code(mkdir(tmp.path("file")).await), "EEXIST");
    }

    #[tokio::test]
    async fn an_exclusive_copy_does_not_replace() {
        let tmp = Tmp::new("copy");
        std::fs::write(tmp.path("src"), b"new").unwrap();
        std::fs::write(tmp.path("dst"), b"old").unwrap();
        let copy = |is_exclusive| {
            call(
                "",
                Op::Copy(guestpb::FsCopy {
                    src: tmp.path("src"),
                    dst: tmp.path("dst"),
                    is_exclusive,
                    is_recursive: false,
                    is_preserving: false,
                }),
            )
        };
        assert_eq!(code(copy(true).await), "EEXIST");
        assert_eq!(std::fs::read(tmp.path("dst")).unwrap(), b"old");
        assert_eq!(copy(false).await, Outcome::IsDone(true));
        assert_eq!(std::fs::read(tmp.path("dst")).unwrap(), b"new");
    }

    #[tokio::test]
    async fn a_recursive_copy_keeps_links_as_links_and_times_when_asked() {
        let tmp = Tmp::new("cp-r");
        std::fs::create_dir_all(tmp.path("src/sub")).unwrap();
        std::fs::write(tmp.path("src/sub/f"), b"data").unwrap();
        std::os::unix::fs::symlink("sub/f", tmp.path("src/link")).unwrap();
        let old = TimeSpec::new(1_000_000, 0);
        nix::sys::stat::utimensat(
            nix::fcntl::AT_FDCWD,
            tmp.path("src/sub/f").as_str(),
            &old,
            &old,
            UtimensatFlags::FollowSymlink,
        )
        .unwrap();

        let outcome = call(
            "",
            Op::Copy(guestpb::FsCopy {
                src: tmp.path("src"),
                dst: tmp.path("dst"),
                is_exclusive: true,
                is_recursive: true,
                is_preserving: true,
            }),
        )
        .await;
        assert_eq!(outcome, Outcome::IsDone(true));
        assert_eq!(std::fs::read(tmp.path("dst/sub/f")).unwrap(), b"data");
        assert_eq!(
            std::fs::read_link(tmp.path("dst/link")).unwrap(),
            Path::new("sub/f")
        );
        assert_eq!(
            std::fs::metadata(tmp.path("dst/sub/f")).unwrap().mtime(),
            1_000_000
        );
    }

    #[tokio::test]
    async fn a_directory_copies_only_recursively() {
        let tmp = Tmp::new("cp-dir");
        std::fs::create_dir_all(tmp.path("src")).unwrap();
        let outcome = call(
            "",
            Op::Copy(guestpb::FsCopy {
                src: tmp.path("src"),
                dst: tmp.path("dst"),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(code(outcome), "EISDIR");
    }

    #[tokio::test]
    async fn realpath_and_lstat_see_links_as_posix_does() {
        let tmp = Tmp::new("links");
        std::fs::create_dir_all(tmp.path("real")).unwrap();
        std::fs::write(tmp.path("real/f"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.path("real"), tmp.path("abs")).unwrap();
        std::os::unix::fs::symlink("abs/f", tmp.path("rel")).unwrap();
        let canonical = std::fs::canonicalize(tmp.path("real/f")).unwrap();

        let outcome = call(
            "",
            Op::Realpath(guestpb::FsRealpath {
                path: tmp.path("rel"),
            }),
        )
        .await;
        assert_eq!(
            outcome,
            Outcome::Path(canonical.to_string_lossy().into_owned())
        );

        let stat = |is_nofollow| {
            call(
                "",
                Op::Stat(guestpb::FsStat {
                    path: tmp.path("rel"),
                    is_nofollow,
                }),
            )
        };
        let (Outcome::Stat(followed), Outcome::Stat(link)) = (stat(false).await, stat(true).await)
        else {
            panic!("stat");
        };
        let kind = |mode: u32| mode as libc::mode_t & libc::S_IFMT;
        assert_eq!(kind(followed.mode), libc::S_IFREG);
        assert_eq!(kind(link.mode), libc::S_IFLNK);
    }

    #[tokio::test]
    async fn a_forced_recursive_remove_takes_the_tree_and_not_what_links_lead_to() {
        let tmp = Tmp::new("rm");
        std::fs::create_dir_all(tmp.path("tree/sub")).unwrap();
        std::fs::create_dir_all(tmp.path("kept")).unwrap();
        std::fs::write(tmp.path("kept/f"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.path("kept"), tmp.path("tree/sub/out")).unwrap();
        let remove = |path: String| {
            call(
                "",
                Op::Remove(guestpb::FsRemove {
                    path,
                    is_recursive: true,
                    is_force: true,
                    is_dir_only: false,
                }),
            )
        };
        assert_eq!(remove(tmp.path("tree")).await, Outcome::IsDone(true));
        assert!(!Path::new(&tmp.path("tree")).exists());
        assert!(Path::new(&tmp.path("kept/f")).exists());
        assert_eq!(remove(tmp.path("tree")).await, Outcome::IsDone(true));
    }

    #[test]
    fn a_handle_survives_save_and_restore() {
        let tmp = Tmp::new("save");
        let path = tmp.path("f");
        let state = tmp.path("state");
        std::fs::write(&path, b"0123456789").unwrap();

        let before = Table::default();
        let handle = before
            .insert(File::open(&path).unwrap(), "alice".into(), OFlag::O_RDONLY)
            .unwrap();
        let mut buf = [0u8; 4];
        (&*before.get(handle, "alice").unwrap())
            .read_exact(&mut buf)
            .unwrap();
        before.save(&state).unwrap();
        // The descriptors outlive the table, as they outlive the agent across
        // its exec.
        for (_, entry) in before.open.lock().unwrap().drain() {
            std::mem::forget(entry.file);
        }

        let after = Table::default();
        after.restore(&state);
        assert!(!Path::new(&state).exists());
        let file = after.get(handle, "alice").unwrap();
        let mut buf = [0u8; 3];
        (&*file).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"456");
        let fd_flags = fcntl(file.as_fd(), FcntlArg::F_GETFD).unwrap();
        assert!(FdFlag::from_bits_truncate(fd_flags).contains(FdFlag::FD_CLOEXEC));
        assert_eq!(after.get(handle, "bob").unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn a_handle_whose_descriptor_is_gone_is_dropped() {
        let tmp = Tmp::new("stale");
        let state = tmp.path("state");
        let saved = vec![Saved {
            handle: 7,
            fd: 1 << 20,
            user: String::new(),
            flags: 0,
            idle: Duration::ZERO,
        }];
        std::fs::write(&state, serde_json::to_vec(&saved).unwrap()).unwrap();
        let after = Table::default();
        after.restore(&state);
        assert_eq!(after.get(7, "").unwrap_err(), Errno::EBADF);
    }

    /// A link that passed as pointing inside the scope, then swapped to point
    /// outside, is refused where it now lands; the refusal reads as the
    /// kernel's would.
    #[tokio::test]
    async fn a_link_swapped_to_lead_outside_the_scope_is_refused() {
        let tmp = Tmp::new("swap");
        std::fs::create_dir_all(tmp.path("scope")).unwrap();
        std::fs::create_dir_all(tmp.path("outside")).unwrap();
        std::fs::write(tmp.path("scope/mine"), b"mine").unwrap();
        std::fs::write(tmp.path("outside/secret"), b"secret").unwrap();
        let scope = tmp.path("scope");
        let link = tmp.path("scope/link");
        std::os::unix::fs::symlink(tmp.path("scope/mine"), &link).unwrap();
        let outcome = limited(&[&scope], 0, opening(link.clone(), 0)).await;
        assert!(matches!(outcome, Outcome::Handle(_)), "{outcome:?}");

        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(tmp.path("outside/secret"), &link).unwrap();
        let Outcome::Error(err) = limited(&[&scope], 0, opening(link.clone(), 0)).await else {
            panic!("the swapped link was followed out of the scope");
        };
        assert_eq!(
            (err.code.as_str(), err.syscall.as_str()),
            ("EACCES", "open")
        );
        // Creating through it, or through a link to a directory outside, is
        // refused too, and nothing is made out there.
        std::os::unix::fs::symlink(tmp.path("outside"), tmp.path("scope/dir")).unwrap();
        let outcome = limited(&[&scope], 0, opening(tmp.path("scope/dir/new"), 0o101)).await;
        assert_eq!(code(outcome), "EACCES");
        assert!(!Path::new(&tmp.path("outside/new")).exists());
        let stat = Op::Stat(guestpb::FsStat {
            path: link,
            is_nofollow: false,
        });
        assert_eq!(code(limited(&[&scope], 0, stat).await), "EACCES");
    }

    #[tokio::test]
    async fn a_link_inside_the_scope_is_followed() {
        let tmp = Tmp::new("inside");
        std::fs::create_dir_all(tmp.path("scope/real")).unwrap();
        std::fs::write(tmp.path("scope/real/f"), b"here").unwrap();
        std::os::unix::fs::symlink(tmp.path("scope/real"), tmp.path("scope/link")).unwrap();
        let scope = tmp.path("scope");
        let Outcome::Handle(handle) =
            limited(&[&scope], 0, opening(tmp.path("scope/link/f"), 0)).await
        else {
            panic!("open through an in-scope link");
        };
        assert_eq!(
            read("", handle, 0, 4).await,
            Outcome::Data(b"here".to_vec())
        );
        // The link itself, acted on rather than followed, is placed by its
        // directory.
        let lstat = Op::Stat(guestpb::FsStat {
            path: tmp.path("scope/link"),
            is_nofollow: true,
        });
        assert!(matches!(
            limited(&[&scope], 0, lstat).await,
            Outcome::Stat(_)
        ));
    }

    /// A call as a user is checked by the kernel as that user, and what it
    /// creates is theirs. Run where the host has a `nobody`, as the node
    /// image does; skipped elsewhere.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_call_as_a_user_is_the_user_s() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let Ok(nobody) = crate::linux::users::credentials("nobody") else {
            return;
        };
        let tmp = Tmp::new("as-user");
        std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::write(tmp.path("roots"), b"root only").unwrap();
        std::fs::set_permissions(tmp.path("roots"), std::fs::Permissions::from_mode(0o600))
            .unwrap();

        let created = call("nobody", opening(tmp.path("mine"), 0o1 | 0o100)).await;
        assert!(matches!(created, Outcome::Handle(_)), "{created:?}");
        let made = Op::Mkdir(guestpb::FsMkdir {
            path: tmp.path("dir/sub"),
            is_recursive: true,
            ..Default::default()
        });
        assert!(!matches!(call("nobody", made).await, Outcome::Error(_)));
        for path in ["mine", "dir", "dir/sub"] {
            let meta = std::fs::metadata(tmp.path(path)).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (nobody.uid, nobody.gid), "{path}");
        }

        assert_eq!(
            code(call("nobody", opening(tmp.path("roots"), 0)).await),
            "EACCES"
        );
        let chown = Op::Chown(guestpb::FsChown {
            path: tmp.path("mine"),
            uid: 0,
            gid: 0,
            ..Default::default()
        });
        assert_eq!(code(call("nobody", chown).await), "EPERM");
        // The same file is root's to read.
        assert!(matches!(
            call("", opening(tmp.path("roots"), 0)).await,
            Outcome::Handle(_)
        ));
    }

    #[tokio::test]
    async fn the_scope_root_itself_can_be_made_and_removed() {
        let tmp = Tmp::new("root");
        let scope = tmp.path("scope");
        let mkdir = Op::Mkdir(guestpb::FsMkdir {
            path: scope.clone(),
            is_recursive: true,
            ..Default::default()
        });
        assert!(!matches!(
            limited(&[&scope], 0, mkdir).await,
            Outcome::Error(_)
        ));
        assert!(std::fs::metadata(&scope).unwrap().is_dir());
        // A sibling sharing the prefix is not in the scope.
        let sibling = Op::Mkdir(guestpb::FsMkdir {
            path: format!("{scope}x"),
            ..Default::default()
        });
        assert_eq!(code(limited(&[&scope], 0, sibling).await), "EACCES");
        let rmdir = Op::Remove(guestpb::FsRemove {
            path: scope.clone(),
            is_dir_only: true,
            ..Default::default()
        });
        assert!(!matches!(
            limited(&[&scope], 0, rmdir).await,
            Outcome::Error(_)
        ));
        assert!(std::fs::metadata(&scope).is_err());
    }

    #[tokio::test]
    async fn a_recursive_remove_does_not_leave_the_scope() {
        let tmp = Tmp::new("rm-scope");
        std::fs::create_dir_all(tmp.path("scope/tree")).unwrap();
        std::fs::create_dir_all(tmp.path("outside")).unwrap();
        std::fs::write(tmp.path("outside/kept"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.path("outside"), tmp.path("scope/tree/out")).unwrap();
        std::os::unix::fs::symlink(tmp.path("outside"), tmp.path("scope/via")).unwrap();
        let scope = tmp.path("scope");
        let scopes = [scope.as_str()];
        let remove = |path: String| {
            limited(
                &scopes,
                0,
                Op::Remove(guestpb::FsRemove {
                    path,
                    is_recursive: true,
                    is_force: false,
                    is_dir_only: false,
                }),
            )
        };
        assert_eq!(code(remove(tmp.path("scope/via/kept")).await), "EACCES");
        assert_eq!(remove(tmp.path("scope/tree")).await, Outcome::IsDone(true));
        assert!(!Path::new(&tmp.path("scope/tree")).exists());
        assert!(Path::new(&tmp.path("outside/kept")).exists());
    }

    #[tokio::test]
    async fn growing_a_file_past_the_cap_is_efbig() {
        let tmp = Tmp::new("cap");
        let path = tmp.path("f");
        let Outcome::Handle(handle) = limited(&[], 10, opening(path.clone(), 0o102)).await else {
            panic!("open");
        };
        let write = |position, data: &[u8]| {
            limited(
                &[],
                10,
                Op::Write(guestpb::FsWrite {
                    handle,
                    position,
                    data: data.to_vec(),
                }),
            )
        };
        assert_eq!(write(-1, b"12345678").await, Outcome::Written(8));
        assert_eq!(code(write(-1, b"abc").await), "EFBIG");
        assert_eq!(code(write(8, b"abc").await), "EFBIG");
        assert_eq!(write(0, b"rewrite").await, Outcome::Written(7));
        let ftruncate = Op::Ftruncate(guestpb::FsFtruncate { handle, length: 11 });
        assert_eq!(code(limited(&[], 10, ftruncate).await), "EFBIG");
        let truncate = Op::Truncate(guestpb::FsTruncate {
            path: path.clone(),
            length: 11,
        });
        assert_eq!(code(limited(&[], 10, truncate).await), "EFBIG");
        std::fs::write(tmp.path("big"), [0u8; 11]).unwrap();
        let copy = Op::Copy(guestpb::FsCopy {
            src: tmp.path("big"),
            dst: tmp.path("copy"),
            ..Default::default()
        });
        assert_eq!(code(limited(&[], 10, copy).await), "EFBIG");
        assert_eq!(std::fs::read(&path).unwrap(), b"rewrite8");
    }

    /// Without is_recursive, remove is unlink(2) or rmdir(2) and fails as they
    /// do, rather than picking whichever fits what is there.
    #[tokio::test]
    async fn unlink_and_rmdir_refuse_what_they_do_not_remove() {
        let tmp = Tmp::new("unlink");
        std::fs::create_dir_all(tmp.path("empty")).unwrap();
        std::fs::create_dir_all(tmp.path("full")).unwrap();
        std::fs::write(tmp.path("full/f"), b"x").unwrap();
        std::fs::write(tmp.path("file"), b"x").unwrap();
        let remove = |path: String, is_dir_only| {
            call(
                "",
                Op::Remove(guestpb::FsRemove {
                    path,
                    is_recursive: false,
                    is_force: false,
                    is_dir_only,
                }),
            )
        };
        let Outcome::Error(err) = remove(tmp.path("empty"), false).await else {
            panic!("unlink removed a directory");
        };
        assert_eq!(
            (err.code.as_str(), err.syscall.as_str()),
            ("EISDIR", "unlink")
        );
        assert!(Path::new(&tmp.path("empty")).is_dir());

        let Outcome::Error(err) = remove(tmp.path("file"), true).await else {
            panic!("rmdir removed a file");
        };
        assert_eq!(
            (err.code.as_str(), err.syscall.as_str()),
            ("ENOTDIR", "rmdir")
        );
        assert_eq!(code(remove(tmp.path("full"), true).await), "ENOTEMPTY");
        assert_eq!(remove(tmp.path("empty"), true).await, Outcome::IsDone(true));
        assert_eq!(remove(tmp.path("file"), false).await, Outcome::IsDone(true));
    }
}
