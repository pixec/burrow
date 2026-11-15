//! An ext4 image, read in userspace.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Read as _, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use ext4_view::{Ext4, Ext4Error, FileType, Metadata};

use crate::protocol::{Entry, Kind, Stat, TarSummary, Time};

/// Reads with `pread`, which is all the confined reader may do to the image.
struct Pread(std::fs::File);

impl ext4_view::Ext4Read for Pread {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(self.0.read_exact_at(dst, start_byte)?)
    }
}

pub struct Image(Ext4);

/// What went wrong, as the caller is told it.
pub type Error = String;

fn failed(path: &str) -> impl Fn(Ext4Error) -> Error + '_ {
    move |err| match err {
        Ext4Error::NotFound => format!("{path}: no such file or directory"),
        Ext4Error::NotADirectory => format!("{path}: not a directory"),
        err => format!("{path}: {err}"),
    }
}

fn kind(file_type: FileType) -> Kind {
    if file_type.is_dir() {
        Kind::Dir
    } else if file_type.is_symlink() {
        Kind::Symlink
    } else if file_type.is_char_dev() {
        Kind::CharDevice
    } else if file_type.is_block_dev() {
        Kind::BlockDevice
    } else if file_type.is_fifo() {
        Kind::Fifo
    } else if file_type.is_socket() {
        Kind::Socket
    } else {
        Kind::File
    }
}

fn time(stamp: ext4_view::Timestamp) -> Time {
    Time {
        secs: stamp.seconds(),
        nanos: stamp.nanoseconds(),
    }
}

/// `security.*`, `trusted.*` and `user.*` go as they are stored. POSIX ACLs
/// are stored in ext4's compact form and handed to `setxattr` in the
/// kernel's, so they are converted. Anything else under `system.` is the
/// filesystem's own and stays behind.
fn portable(name: &[u8], value: Vec<u8>) -> Option<Vec<u8>> {
    match name {
        b"system.posix_acl_access" | b"system.posix_acl_default" => acl_to_xattr(&value),
        _ if name.starts_with(b"system.") => None,
        _ => Some(value),
    }
}

/// ext4's ACL (version 1, short entries for the owner, group, mask and
/// other) as `posix_acl_xattr` (version 2, every entry eight bytes).
fn acl_to_xattr(stored: &[u8]) -> Option<Vec<u8>> {
    const USER: u16 = 0x02;
    const GROUP: u16 = 0x08;
    let (version, mut rest) = stored.split_at_checked(4)?;
    if version != 1u32.to_le_bytes() {
        return None;
    }
    let mut out = 2u32.to_le_bytes().to_vec();
    while !rest.is_empty() {
        let tag = u16::from_le_bytes(rest.get(..2)?.try_into().ok()?);
        let perm = rest.get(2..4)?;
        let (id, len) = match tag {
            USER | GROUP => (rest.get(4..8)?.try_into().ok()?, 8),
            _ => (u32::MAX.to_le_bytes(), 4),
        };
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(perm);
        out.extend_from_slice(&id);
        rest = &rest[len..];
    }
    Some(out)
}

impl Image {
    /// Loads the filesystem on `file`: its superblock, group descriptors and
    /// journal, which is replayed in memory.
    pub fn open(file: std::fs::File) -> Result<Self, Error> {
        Ext4::load(Box::new(Pread(file)))
            .map(Self)
            .map_err(|err| format!("not a readable ext4 filesystem: {err}"))
    }

    pub fn list(&self, path: &str) -> Result<Vec<Entry>, Error> {
        let mut entries = Vec::new();
        for entry in self.0.read_dir(path).map_err(failed(path))? {
            let entry = entry.map_err(failed(path))?;
            let name = entry.file_name().as_ref().to_vec();
            if name == b"." || name == b".." {
                continue;
            }
            let kind = kind(entry.file_type().map_err(failed(path))?);
            entries.push(Entry { name, kind });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    pub fn stat(&self, path: &str) -> Result<Stat, Error> {
        self.stat_bytes(path.as_bytes()).map_err(failed(path))
    }

    fn stat_bytes(&self, path: &[u8]) -> Result<Stat, Ext4Error> {
        let metadata = self.0.symlink_metadata(path)?;
        let target = match metadata.is_symlink() {
            true => Some(self.0.read_link(path)?.as_ref().to_vec()),
            false => None,
        };
        let xattrs = self
            .0
            .xattrs(path)?
            .into_iter()
            .filter_map(|xattr| Some((xattr.name.clone(), portable(&xattr.name, xattr.value)?)))
            .collect();
        Ok(stat_of(&metadata, target, xattrs))
    }

    /// Hands `sink` up to `len` bytes of the regular file at `path` from
    /// `offset`.
    pub fn read(
        &self,
        path: &str,
        offset: u64,
        len: u64,
        mut sink: impl FnMut(&[u8]) -> std::io::Result<()>,
    ) -> Result<(), Error> {
        let metadata = self.0.symlink_metadata(path).map_err(failed(path))?;
        if !metadata.file_type().is_regular_file() {
            return Err(format!("{path}: not a regular file"));
        }
        let mut file = self.0.open(path).map_err(failed(path))?;
        file.seek_to(offset.min(metadata.len()))
            .map_err(failed(path))?;
        let mut left = len;
        let mut buffer = vec![0; 64 << 10];
        while left > 0 {
            let want = buffer
                .len()
                .min(usize::try_from(left).unwrap_or(usize::MAX));
            let got = file.read_bytes(&mut buffer[..want]).map_err(failed(path))?;
            if got == 0 {
                break;
            }
            sink(&buffer[..got]).map_err(|err| err.to_string())?;
            left -= got as u64;
        }
        Ok(())
    }

    /// Writes the tree at `path` to `out` as a tar archive whose entries are
    /// named from `path`'s last component. Directories, regular files,
    /// symlinks and hard links within the tree go with their mode, owner,
    /// times and extended attributes; devices, fifos and sockets are left
    /// out and counted. A sparse file is written whole, its holes as zeros,
    /// and counts against `max_bytes` at its full size: the archive has no
    /// sparse entries, so the new disk holds the file without holes.
    pub fn tar(
        &self,
        path: &str,
        max_bytes: u64,
        max_entries: u64,
        out: impl Write,
    ) -> Result<TarSummary, Error> {
        let root = path.trim_end_matches('/');
        let Some((_, name)) = root.rsplit_once('/').filter(|(_, name)| !name.is_empty()) else {
            return Err(format!("{path}: not a path below /"));
        };
        let mut builder = tar::Builder::new(out);
        let mut summary = TarSummary::default();
        let mut linked: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut pending = vec![(root.as_bytes().to_vec(), name.as_bytes().to_vec())];
        let io = |err: std::io::Error| format!("{path}: writing the archive: {err}");
        while let Some((at, named)) = pending.pop() {
            let shown = String::from_utf8_lossy(&at).into_owned();
            let stat = self.stat_bytes(&at).map_err(failed(&shown))?;
            if matches!(
                stat.kind,
                Kind::CharDevice | Kind::BlockDevice | Kind::Fifo | Kind::Socket
            ) {
                summary.skipped += 1;
                continue;
            }
            summary.entries += 1;
            if summary.entries > max_entries {
                return Err(format!(
                    "{path} holds more than {max_entries} files, the most a recreate carries"
                ));
            }
            let mut extensions: Vec<(String, Vec<u8>)> = vec![
                ("atime".into(), pax_time(stat.atime)),
                ("mtime".into(), pax_time(stat.mtime)),
            ];
            for (name, value) in &stat.xattrs {
                if let Ok(name) = std::str::from_utf8(name) {
                    extensions.push((format!("SCHILY.xattr.{name}"), value.clone()));
                }
            }
            builder
                .append_pax_extensions(
                    extensions
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_slice())),
                )
                .map_err(io)?;
            let mut header = tar::Header::new_gnu();
            header.set_mode(u32::from(stat.mode));
            header.set_uid(u64::from(stat.uid));
            header.set_gid(u64::from(stat.gid));
            header.set_mtime(u64::try_from(stat.mtime.secs).unwrap_or(0));
            header.set_size(0);
            let entry_name = Path::new(OsStr::from_bytes(&named));
            match stat.kind {
                Kind::Dir => {
                    header.set_entry_type(tar::EntryType::Directory);
                    builder
                        .append_data(&mut header, entry_name, std::io::empty())
                        .map_err(io)?;
                    let listed = self.list(&shown)?;
                    for child in listed.into_iter().rev() {
                        let mut child_at = at.clone();
                        child_at.push(b'/');
                        child_at.extend_from_slice(&child.name);
                        let mut child_named = named.clone();
                        child_named.push(b'/');
                        child_named.extend_from_slice(&child.name);
                        pending.push((child_at, child_named));
                    }
                }
                Kind::Symlink => {
                    header.set_entry_type(tar::EntryType::Symlink);
                    let target = stat.target.unwrap_or_default();
                    builder
                        .append_link(&mut header, entry_name, OsStr::from_bytes(&target))
                        .map_err(io)?;
                }
                _ if stat.links > 1 && linked.contains_key(&stat.inode) => {
                    header.set_entry_type(tar::EntryType::Link);
                    let first = &linked[&stat.inode];
                    builder
                        .append_link(&mut header, entry_name, OsStr::from_bytes(first))
                        .map_err(io)?;
                }
                _ => {
                    if stat.links > 1 {
                        linked.insert(stat.inode, named.clone());
                    }
                    summary.bytes += stat.size;
                    if summary.bytes > max_bytes {
                        return Err(format!(
                            "{path} holds more than {max_bytes} bytes, the most a recreate \
                             carries"
                        ));
                    }
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(stat.size);
                    let file = self.0.open(at.as_slice()).map_err(failed(&shown))?;
                    builder
                        .append_data(&mut header, entry_name, file.take(stat.size))
                        .map_err(io)?;
                }
            }
        }
        builder.into_inner().map_err(io)?;
        Ok(summary)
    }
}

fn stat_of(metadata: &Metadata, target: Option<Vec<u8>>, xattrs: Vec<(Vec<u8>, Vec<u8>)>) -> Stat {
    Stat {
        kind: kind(metadata.file_type()),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.len(),
        inode: metadata.inode(),
        links: metadata.links(),
        atime: time(metadata.accessed()),
        mtime: time(metadata.modified()),
        target,
        xattrs,
    }
}

fn pax_time(time: Time) -> Vec<u8> {
    format!("{}.{:09}", time.secs, time.nanos).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ext4 keeps the owner, group, mask and other entries short; the kernel
    /// takes every entry at full width with no id where there is none.
    #[test]
    fn an_ext4_acl_becomes_the_kernels() {
        let mut stored = 1u32.to_le_bytes().to_vec();
        stored.extend_from_slice(&[0x01, 0, 6, 0]);
        stored.extend_from_slice(&[0x02, 0, 4, 0, 0xe8, 0x03, 0, 0]);
        stored.extend_from_slice(&[0x20, 0, 0, 0]);
        let mut wanted = 2u32.to_le_bytes().to_vec();
        wanted.extend_from_slice(&[0x01, 0, 6, 0, 0xff, 0xff, 0xff, 0xff]);
        wanted.extend_from_slice(&[0x02, 0, 4, 0, 0xe8, 0x03, 0, 0]);
        wanted.extend_from_slice(&[0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(acl_to_xattr(&stored), Some(wanted));
        assert_eq!(acl_to_xattr(&[2, 0, 0, 0]), None);
        assert_eq!(acl_to_xattr(&[1, 0, 0, 0, 2, 0, 4]), None);
    }

    #[test]
    fn only_portable_attributes_are_carried() {
        assert_eq!(portable(b"security.capability", vec![1]), Some(vec![1]));
        assert_eq!(portable(b"user.note", vec![2]), Some(vec![2]));
        assert_eq!(portable(b"system.data", vec![3]), None);
    }
}
