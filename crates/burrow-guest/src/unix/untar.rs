//! Unpacking a tar stream as root, metadata and all.
//!
//! Files, symlinks and hard links are unpacked by the `tar` crate with their
//! mode, owner, extended attributes and modification time. Directories are
//! made here and finished last, deepest first, so their own times and modes
//! are not disturbed by what is unpacked into them. Times are then set to
//! the nanosecond from the archive's PAX records where it has them.

use std::io::Read;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use nix::sys::stat::{UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;
use tokio_stream::StreamExt as _;
use tonic::{Status, Streaming};

use burrow_proto::guest::v1 as guestpb;

/// What `extract-tar` in the health response promises.
pub const FEATURE_EXTRACT_TAR: &str = "extract-tar";

pub async fn extract(
    mut inbound: Streaming<guestpb::TarChunk>,
) -> Result<guestpb::ExtractTarResponse, Status> {
    let first = inbound
        .next()
        .await
        .transpose()?
        .ok_or_else(|| Status::invalid_argument("the archive stream was empty"))?;
    let dest = PathBuf::from(&first.path);
    if !dest.is_absolute() || dest.components().any(|c| c == Component::ParentDir) {
        return Err(Status::invalid_argument(format!(
            "{}: an archive unpacks into an absolute path",
            first.path
        )));
    }
    let (chunks, received) = tokio::sync::mpsc::channel(16);
    let unpacking = tokio::task::spawn_blocking(move || {
        let input = Chunks {
            received,
            current: std::io::Cursor::new(Vec::new()),
        };
        unpack(&dest, input)
    });
    let mut fed = chunks.send(first.data).await.is_ok();
    while fed && let Some(chunk) = inbound.next().await {
        fed = chunks.send(chunk?.data).await.is_ok();
    }
    drop(chunks);
    let entries = unpacking
        .await
        .map_err(|err| Status::internal(err.to_string()))?
        .map_err(|err| Status::internal(format!("unpacking into {}: {err}", first.path)))?;
    Ok(guestpb::ExtractTarResponse { entries })
}

/// The stream's chunks, read in order on a blocking thread.
struct Chunks {
    received: tokio::sync::mpsc::Receiver<Vec<u8>>,
    current: std::io::Cursor<Vec<u8>>,
}

impl Read for Chunks {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let read = self.current.read(buf)?;
            if read > 0 || buf.is_empty() {
                return Ok(read);
            }
            match self.received.blocking_recv() {
                Some(chunk) => self.current = std::io::Cursor::new(chunk),
                None => return Ok(0),
            }
        }
    }
}

/// A directory to finish once everything is in it.
struct Dir {
    path: PathBuf,
    mode: u32,
    uid: u32,
    gid: u32,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    times: Option<(TimeSpec, TimeSpec)>,
}

fn unpack(dest: &Path, input: impl Read) -> std::io::Result<u64> {
    std::fs::create_dir_all(dest)?;
    let mut archive = tar::Archive::new(input);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);
    archive.set_overwrite(true);
    let mut dirs = Vec::new();
    let mut count = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.into_owned();
        if name
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(std::io::Error::other(format!(
                "{}: not a path inside the archive",
                name.display()
            )));
        }
        let target = dest.join(&name);
        let (times, xattrs) = pax(&mut entry)?;
        let header = entry.header();
        let is_dir = header.entry_type().is_dir();
        if let Ok(existing) = std::fs::symlink_metadata(&target) {
            match (existing.is_dir(), is_dir) {
                (true, false) => std::fs::remove_dir_all(&target)?,
                (false, true) => std::fs::remove_file(&target)?,
                _ => {}
            }
        }
        if is_dir {
            std::fs::create_dir_all(&target)?;
            dirs.push(Dir {
                path: target,
                mode: header.mode()?,
                uid: u32::try_from(header.uid()?).map_err(std::io::Error::other)?,
                gid: u32::try_from(header.gid()?).map_err(std::io::Error::other)?,
                xattrs,
                times,
            });
        } else {
            entry.unpack_in(dest)?;
            if let Some((atime, mtime)) = times {
                utimensat(
                    nix::fcntl::AT_FDCWD,
                    &target,
                    &atime,
                    &mtime,
                    UtimensatFlags::NoFollowSymlink,
                )?;
            }
        }
        count += 1;
    }
    for dir in dirs.iter().rev() {
        std::os::unix::fs::lchown(&dir.path, Some(dir.uid), Some(dir.gid))?;
        std::fs::set_permissions(&dir.path, std::fs::Permissions::from_mode(dir.mode))?;
        for (name, value) in &dir.xattrs {
            set_xattr(&dir.path, name, value)?;
        }
        if let Some((atime, mtime)) = dir.times {
            utimensat(
                nix::fcntl::AT_FDCWD,
                &dir.path,
                &atime,
                &mtime,
                UtimensatFlags::NoFollowSymlink,
            )?;
        }
    }
    Ok(count)
}

/// An entry's access and modification times and its extended attributes,
/// from its PAX records.
#[allow(clippy::type_complexity)]
fn pax<R: Read>(
    entry: &mut tar::Entry<R>,
) -> std::io::Result<(Option<(TimeSpec, TimeSpec)>, Vec<(Vec<u8>, Vec<u8>)>)> {
    let (mut atime, mut mtime, mut xattrs) = (None, None, Vec::new());
    if let Some(extensions) = entry.pax_extensions()? {
        for extension in extensions {
            let extension = extension?;
            match extension.key_bytes() {
                b"atime" => atime = timespec(extension.value_bytes()),
                b"mtime" => mtime = timespec(extension.value_bytes()),
                key => {
                    if let Some(name) = key.strip_prefix(b"SCHILY.xattr.") {
                        xattrs.push((name.to_vec(), extension.value_bytes().to_vec()));
                    }
                }
            }
        }
    }
    Ok((atime.zip(mtime), xattrs))
}

/// `secs.nanos`, as a PAX time record holds it.
fn timespec(value: &[u8]) -> Option<TimeSpec> {
    let value = std::str::from_utf8(value).ok()?;
    let (secs, nanos) = value.split_once('.').unwrap_or((value, "0"));
    let nanos = format!("{nanos:0<9}");
    Some(TimeSpec::new(
        secs.parse().ok()?,
        nanos.get(..9)?.parse().ok()?,
    ))
}

fn set_xattr(path: &Path, name: &[u8], value: &[u8]) -> std::io::Result<()> {
    use std::ffi::CString;
    let path = CString::new(path.as_os_str().as_bytes())?;
    let name = CString::new(name)?;
    // SAFETY: both strings are NUL-terminated and outlive the call, and the
    // value is a live slice of the length given.
    #[cfg(target_os = "linux")]
    let rc = unsafe {
        nix::libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    // SAFETY: as above.
    #[cfg(target_os = "macos")]
    let rc = unsafe {
        nix::libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            nix::libc::XATTR_NOFOLLOW,
        )
    };
    match rc {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    fn archive() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut add = |name: &str,
                       kind: tar::EntryType,
                       mode: u32,
                       link: Option<&str>,
                       body: &[u8],
                       mtime: &str| {
            builder
                .append_pax_extensions([("mtime", mtime.as_bytes()), ("atime", mtime.as_bytes())])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_size(body.len() as u64);
            match link {
                Some(link) => builder.append_link(&mut header, name, link).unwrap(),
                None => builder.append_data(&mut header, name, body).unwrap(),
            }
        };
        add("app", tar::EntryType::Directory, 0o750, None, b"", "1000.5");
        add(
            "app/data",
            tar::EntryType::Regular,
            0o640,
            None,
            b"kept",
            "2000.000000123",
        );
        add(
            "app/again",
            tar::EntryType::Link,
            0o640,
            Some("app/data"),
            b"",
            "2000.000000123",
        );
        add(
            "app/link",
            tar::EntryType::Symlink,
            0o777,
            Some("data"),
            b"",
            "3000",
        );
        builder.into_inner().unwrap()
    }

    /// A tree unpacks over what was there, with its modes, hard link,
    /// symlink and times, the directory's included, to the nanosecond.
    #[test]
    fn a_tree_unpacks_with_its_metadata_over_what_was_there() {
        let dest = std::env::temp_dir().join(format!("burrow-untar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(dest.join("app/data")).unwrap();
        std::fs::write(dest.join("app/link"), b"in the way").unwrap();
        std::fs::write(dest.join("app/other"), b"stays").unwrap();

        let count = unpack(&dest, std::io::Cursor::new(archive())).unwrap();

        assert_eq!(count, 4);
        let data = std::fs::metadata(dest.join("app/data")).unwrap();
        assert_eq!(std::fs::read(dest.join("app/data")).unwrap(), b"kept");
        assert_eq!(data.mode() & 0o7777, 0o640);
        assert_eq!((data.mtime(), data.mtime_nsec()), (2000, 123));
        assert_eq!(data.nlink(), 2);
        assert_eq!(
            std::fs::read_link(dest.join("app/link")).unwrap(),
            Path::new("data")
        );
        let dir = std::fs::metadata(dest.join("app")).unwrap();
        assert_eq!(dir.mode() & 0o7777, 0o750);
        assert_eq!((dir.mtime(), dir.mtime_nsec()), (1000, 500_000_000));
        assert_eq!(std::fs::read(dest.join("app/other")).unwrap(), b"stays");
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn a_pax_time_reads_to_the_nanosecond() {
        assert_eq!(timespec(b"12.5"), Some(TimeSpec::new(12, 500_000_000)));
        assert_eq!(timespec(b"12"), Some(TimeSpec::new(12, 0)));
        assert_eq!(timespec(b"12.000000001"), Some(TimeSpec::new(12, 1)));
        assert_eq!(timespec(b"x"), None);
    }
}
