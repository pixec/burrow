//! A sandbox's own root disk, made from its template's image.
//!
//! On the root layout a Linux guest boots from one writable disk, mounted as
//! `/`, which is a copy-on-write clone of the template's `rootfs.ext4`: a
//! `FICLONE` reflink where the filesystem shares extents (XFS, btrfs), APFS's
//! `clonefile` on a Mac, and a sparse copy of the image's data elsewhere. The
//! image itself stays in the sandbox's directory as `rootfs.ext4`, a hard link
//! the guest never sees, so the disk can always be compared with the image it
//! was cloned from. Sandboxes made before root disks keep the overlay layout:
//! the image read-only under an overlay on a scratch disk.
//!
//! Nothing here reads a guest's filesystem: a disk grows as a file, and the
//! guest grows its filesystem from inside. A guest controls the bytes on its
//! disk, so the host kernel never mounts one and no host tool parses one.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tonic::Status;

use burrow_common::disk::MIB;
use burrow_proto::common::v1 as common;

use crate::chunks::{CHUNK_SIZE, ImageIndex};

/// A root-layout sandbox's disk, in its working directory and its snapshots.
pub const ROOT_DISK: &str = "root.ext4";
/// The overlay layout's writable disk.
pub const SCRATCH_DISK: &str = "scratch.ext4";
/// The template's image, as a sandbox's directory and a snapshot hold it.
pub const IMAGE: &str = "rootfs.ext4";

/// What a root disk gets beyond its image when the create names no size, the
/// room an overlay sandbox's scratch disk gave it.
pub const DEFAULT_HEADROOM_MIB: u32 = 1024;

/// How a sandbox's filesystem sits on its disks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DiskLayout {
    /// The image read-only under an overlay on a scratch disk. What every
    /// record written before the field was.
    #[default]
    Overlay,
    /// One writable disk, cloned from the image, mounted as `/`.
    Root,
}

impl DiskLayout {
    pub fn from_record(name: &str) -> Self {
        match name {
            "root" => Self::Root,
            _ => Self::Overlay,
        }
    }

    pub fn from_proto(layout: i32) -> Self {
        match common::DiskLayout::try_from(layout) {
            Ok(common::DiskLayout::Root) => Self::Root,
            _ => Self::Overlay,
        }
    }

    pub fn to_proto(self) -> common::DiskLayout {
        match self {
            Self::Overlay => common::DiskLayout::Overlay,
            Self::Root => common::DiskLayout::Root,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Overlay => "overlay",
            Self::Root => "root",
        }
    }

    /// The disk the guest writes, in the sandbox's directory.
    pub fn disk(self) -> &'static str {
        match self {
            Self::Overlay => SCRATCH_DISK,
            Self::Root => ROOT_DISK,
        }
    }

    /// The kernel arguments that mount the root under this layout.
    pub fn boot_args(self) -> &'static str {
        match self {
            Self::Overlay => "root=/dev/vda ro burrow.layout=overlay",
            Self::Root => "root=/dev/vda rw",
        }
    }

    /// The drives the guest boots with, before any volume.
    pub fn drives(self) -> Vec<burrow_vmm::DriveSpec> {
        match self {
            Self::Overlay => vec![
                burrow_vmm::DriveSpec::root_ro(IMAGE),
                burrow_vmm::DriveSpec::scratch_rw(SCRATCH_DISK),
            ],
            Self::Root => vec![burrow_vmm::DriveSpec::root_rw(ROOT_DISK)],
        }
    }

    /// The first guest device a volume lands on.
    pub fn first_volume_device(self) -> u8 {
        match self {
            Self::Overlay => b'c',
            Self::Root => b'b',
        }
    }
}

/// A root disk's size for a create asking for `requested` MiB of an image of
/// `image_bytes`: the image plus [`DEFAULT_HEADROOM_MIB`] when it names none,
/// and never smaller than the image.
pub fn disk_mib(requested: u32, image_bytes: u64) -> Result<u32, Status> {
    let image_mib = u32::try_from(image_bytes.div_ceil(MIB)).unwrap_or(u32::MAX);
    match requested {
        0 => Ok(image_mib.saturating_add(DEFAULT_HEADROOM_MIB)),
        mib if mib < image_mib => Err(Status::invalid_argument(format!(
            "a {mib} MiB disk is smaller than its template's {image_mib} MiB image"
        ))),
        mib => Ok(mib),
    }
}

/// How a disk was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Made {
    /// Sharing every block with its source until either is written.
    Clone,
    /// The source's data copied, holes left as holes.
    Copy,
}

/// Directories whose filesystem was found unable to clone, so the attempt is
/// not made, and the warning not given, on every disk.
static UNCLONABLE: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

fn device_of(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(std::fs::metadata(path)?.dev())
}

/// Makes `dest` a copy of `source` that shares its blocks where the
/// filesystem can, and a sparse copy where it cannot.
pub fn clone_blocking(source: &Path, dest: &Path) -> std::io::Result<Made> {
    let _ = std::fs::remove_file(dest);
    let pair = (
        device_of(source)?,
        device_of(dest.parent().unwrap_or(Path::new(".")))?,
    );
    if !UNCLONABLE.lock().unwrap().contains(&pair) {
        match reflink(source, dest) {
            Ok(()) => return Ok(Made::Clone),
            Err(err) if is_unclonable(&err) => {
                tracing::warn!(
                    source = %source.display(),
                    dest = %dest.parent().unwrap_or(Path::new(".")).display(),
                    %err,
                    "this filesystem cannot clone disks, so every one is copied: put the data \
                     directory on XFS or btrfs, with images and sandboxes on one filesystem"
                );
                UNCLONABLE.lock().unwrap().push(pair);
                let _ = std::fs::remove_file(dest);
            }
            Err(err) => return Err(err),
        }
    }
    sparse_copy(source, dest)?;
    Ok(Made::Copy)
}

pub async fn clone(source: &Path, dest: &Path) -> std::io::Result<Made> {
    let (source, dest) = (source.to_path_buf(), dest.to_path_buf());
    tokio::task::spawn_blocking(move || clone_blocking(&source, &dest))
        .await
        .map_err(std::io::Error::other)?
}

/// Whether disks cloned from `source` into `dir` share blocks with it.
pub fn is_clonable(source: &Path, dir: &Path) -> bool {
    match (device_of(source), device_of(dir)) {
        (Ok(a), Ok(b)) => !UNCLONABLE.lock().unwrap().contains(&(a, b)),
        _ => false,
    }
}

fn is_unclonable(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EOPNOTSUPP)
            | Some(libc::EXDEV)
            | Some(libc::EINVAL)
            | Some(libc::ENOTTY)
            | Some(libc::ENOSYS)
    ) || err.kind() == std::io::ErrorKind::Unsupported
}

#[cfg(target_os = "linux")]
fn reflink(source: &Path, dest: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    /// `_IOW(0x94, 9, int)`.
    const FICLONE: libc::c_ulong = 0x4004_9409;
    let from = std::fs::File::open(source)?;
    let to = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)?;
    // SAFETY: both descriptors are open for the call.
    if unsafe { libc::ioctl(to.as_raw_fd(), FICLONE as _, from.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn reflink(source: &Path, dest: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let cstr = |path: &Path| {
        std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::other("a path holds a NUL"))
    };
    let (from, to) = (cstr(source)?, cstr(dest)?);
    // SAFETY: both are NUL-terminated paths.
    if unsafe { libc::clonefile(from.as_ptr(), to.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reflink(_source: &Path, _dest: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// The byte ranges of `file` that hold data, from `SEEK_DATA`/`SEEK_HOLE`.
pub fn data_extents(file: &std::fs::File) -> std::io::Result<Vec<(u64, u64)>> {
    use std::os::fd::AsRawFd as _;
    let fd = file.as_raw_fd();
    let size = file.metadata()?.len() as i64;
    let mut extents = Vec::new();
    let mut cursor = 0i64;
    while cursor < size {
        // SAFETY: `fd` is open; SEEK_DATA/SEEK_HOLE take plain integers.
        let start = unsafe { libc::lseek(fd, cursor as libc::off_t, libc::SEEK_DATA) };
        if start < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENXIO) => break,
                Some(libc::EINVAL) => return Ok(vec![(0, size as u64)]),
                _ => return Err(err),
            }
        }
        // SAFETY: as above.
        let end = unsafe { libc::lseek(fd, start, libc::SEEK_HOLE) };
        if end < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if end <= start {
            break;
        }
        extents.push((start as u64, end as u64));
        cursor = end as i64;
    }
    Ok(extents)
}

/// Copies `source`'s data to a new `dest` of the same size, leaving holes.
fn sparse_copy(source: &Path, dest: &Path) -> std::io::Result<()> {
    let from = std::fs::File::open(source)?;
    let to = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)?;
    let size = from.metadata()?.len();
    to.set_len(size)?;
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    for (start, end) in data_extents(&from)? {
        let mut at = start;
        while at < end {
            let len = ((end - at) as usize).min(buf.len());
            from.read_exact_at(&mut buf[..len], at)?;
            if buf[..len].iter().any(|&b| b != 0) {
                to.write_all_at(&buf[..len], at)?;
            }
            at += len as u64;
        }
    }
    to.sync_all()
}

/// The magic an Apple sparse image (ASIF), a macOS guest's disk, starts with.
const ASIF_MAGIC: &[u8; 4] = b"shdw";
/// Where an ASIF header holds the disk's size, in 512-byte sectors, big-endian.
const ASIF_SECTORS_AT: u64 = 0x30;

/// The size a disk presents to its guest: an ASIF image's from its header,
/// since its length is only the space it has allocated, and any other disk's
/// its length.
pub fn provisioned_bytes(path: &Path) -> u64 {
    let Ok(file) = std::fs::File::open(path) else {
        return 0;
    };
    let len = file.metadata().map_or(0, |meta| meta.len());
    let mut magic = [0u8; 4];
    let mut sectors = [0u8; 8];
    match file.read_exact_at(&mut magic, 0).is_ok()
        && &magic == ASIF_MAGIC
        && file.read_exact_at(&mut sectors, ASIF_SECTORS_AT).is_ok()
    {
        true => u64::from_be_bytes(sectors).saturating_mul(512),
        false => len,
    }
}

/// Grows a disk file to `mib`. Disks only grow: a smaller size is refused,
/// since the filesystem on it already reaches past it.
pub async fn grow(path: &Path, mib: u32) -> Result<bool, Status> {
    let wanted = u64::from(mib) * MIB;
    let len = tokio::fs::metadata(path)
        .await
        .map_err(|err| Status::internal(format!("reading {}: {err}", path.display())))?
        .len();
    if wanted < len {
        return Err(Status::invalid_argument(format!(
            "disks only grow: this one is {} MiB and {mib} MiB was asked for",
            len.div_ceil(MIB)
        )));
    }
    if wanted == len {
        return Ok(false);
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| Status::internal(format!("opening {}: {err}", path.display())))?;
    file.set_len(wanted)
        .and_then(|()| file.sync_all())
        .map_err(|err| Status::internal(format!("growing {}: {err}", path.display())))?;
    Ok(true)
}

/// Cuts a disk to `mib`, once its guest has shrunk the filesystem on it to
/// fit.
pub async fn cut(path: &Path, mib: u32) -> Result<(), Status> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| Status::internal(format!("opening {}: {err}", path.display())))?;
    file.set_len(u64::from(mib) * MIB)
        .and_then(|()| file.sync_all())
        .map_err(|err| Status::internal(format!("shrinking {}: {err}", path.display())))
}

/// One extent as `FIEMAP` reports it: where a run of the file sits on the
/// device, or `None` where that is not known yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mapped {
    logical: u64,
    end: u64,
    physical: Option<u64>,
}

#[cfg(target_os = "linux")]
fn fiemap(file: &std::fs::File) -> std::io::Result<Vec<Mapped>> {
    use std::os::fd::AsRawFd as _;
    /// `_IOWR('f', 11, struct fiemap)`.
    const FS_IOC_FIEMAP: libc::c_ulong = 0xC020_660B;
    const FLAG_SYNC: u32 = 0x1;
    const EXTENT_LAST: u32 = 0x1;
    const EXTENT_UNKNOWN: u32 = 0x2;
    const EXTENT_DELALLOC: u32 = 0x4;
    const EXTENT_NOT_ALIGNED: u32 = 0x100;
    const EXTENT_DATA_INLINE: u32 = 0x200;
    const COUNT: usize = 256;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Extent {
        logical: u64,
        physical: u64,
        length: u64,
        reserved64: [u64; 2],
        flags: u32,
        reserved: [u32; 3],
    }
    #[repr(C)]
    struct Request {
        start: u64,
        length: u64,
        flags: u32,
        mapped: u32,
        count: u32,
        reserved: u32,
        extents: [Extent; COUNT],
    }

    let size = file.metadata()?.len();
    let mut out = Vec::new();
    let mut start = 0u64;
    while start < size {
        let mut request = Request {
            start,
            length: u64::MAX - start,
            flags: FLAG_SYNC,
            mapped: 0,
            count: COUNT as u32,
            reserved: 0,
            extents: [Extent::default(); COUNT],
        };
        // SAFETY: the descriptor is open and `request` is laid out as the
        // kernel's `struct fiemap` with room for `count` extents after it.
        if unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_FIEMAP as _, &mut request) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if request.mapped == 0 {
            break;
        }
        let mut last = false;
        for extent in &request.extents[..request.mapped as usize] {
            let unknown =
                EXTENT_UNKNOWN | EXTENT_DELALLOC | EXTENT_NOT_ALIGNED | EXTENT_DATA_INLINE;
            out.push(Mapped {
                logical: extent.logical,
                end: extent.logical + extent.length,
                physical: (extent.flags & unknown == 0).then_some(extent.physical),
            });
            start = extent.logical + extent.length;
            last |= extent.flags & EXTENT_LAST != 0;
        }
        if last {
            break;
        }
    }
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
fn fiemap(_file: &std::fs::File) -> std::io::Result<Vec<Mapped>> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// `extents` cut to `[start, end)`, with runs that continue on the device
/// joined, so two files mapping a range to the same blocks compare equal.
fn mapping_within(extents: &[Mapped], start: u64, end: u64) -> Vec<Mapped> {
    let first = extents.partition_point(|extent| extent.end <= start);
    let mut out: Vec<Mapped> = Vec::new();
    for extent in extents[first..].iter().take_while(|e| e.logical < end) {
        let from = extent.logical.max(start);
        let to = extent.end.min(end);
        let piece = Mapped {
            logical: from,
            end: to,
            physical: extent.physical.map(|p| p + (from - extent.logical)),
        };
        match out.last_mut() {
            Some(prev)
                if prev.end == piece.logical
                    && matches!((prev.physical, piece.physical),
                        (Some(a), Some(b)) if a + (prev.end - prev.logical) == b) =>
            {
                prev.end = piece.end;
            }
            _ => out.push(piece),
        }
    }
    out
}

/// The chunks of `disk` that are still exactly `image`'s: every byte of them
/// sits on the same device blocks in both files, or in a hole in both. On a
/// filesystem that reflinks, those are the chunks the guest never wrote,
/// found without reading either file. `None` where the filesystem cannot
/// say, and then every chunk with data is read.
pub fn unchanged_chunks(
    disk: &std::fs::File,
    image: &std::fs::File,
) -> Option<std::collections::BTreeSet<u64>> {
    let (Ok(disk_map), Ok(image_map)) = (fiemap(disk), fiemap(image)) else {
        return None;
    };
    let size = disk.metadata().ok()?.len();
    let mut unchanged = std::collections::BTreeSet::new();
    for n in 0..size.div_ceil(CHUNK_SIZE) {
        let (start, end) = (n * CHUNK_SIZE, ((n + 1) * CHUNK_SIZE).min(size));
        let a = mapping_within(&disk_map, start, end);
        if a.iter().any(|m| m.physical.is_none()) {
            continue;
        }
        if a == mapping_within(&image_map, start, end) {
            unchanged.insert(n);
        }
    }
    Some(unchanged)
}

/// Disks made ahead of the creates that need them, on a filesystem that
/// cannot clone: one per template, copied in the background and replaced as
/// it is taken, so a create renames a disk into place instead of copying the
/// image on its own critical path.
#[derive(Clone)]
pub struct Spares {
    dir: PathBuf,
    held: std::sync::Arc<Mutex<HashMap<String, PathBuf>>>,
    filling: std::sync::Arc<Mutex<std::collections::HashSet<String>>>,
}

impl Spares {
    /// Spares are cheap to make again, so whatever a previous run left is
    /// dropped rather than trusted.
    pub fn new(dir: PathBuf) -> Self {
        let _ = std::fs::remove_dir_all(&dir);
        Self {
            dir,
            held: Default::default(),
            filling: Default::default(),
        }
    }

    /// Makes `dest` a root disk from `template`'s image: a clone where the
    /// filesystem makes one instantly, else the template's spare.
    pub async fn take(
        &self,
        templates_dir: &Path,
        template: &str,
        dest: &Path,
    ) -> std::io::Result<()> {
        let image = templates_dir.join(template).join(IMAGE);
        let dir = dest.parent().unwrap_or(Path::new("."));
        if is_clonable(&image, dir) && clone(&image, dest).await? == Made::Clone {
            return Ok(());
        }
        let key = spare_key(template, &image)?;
        let spare = self.held.lock().unwrap().remove(&key);
        let taken = match spare {
            Some(spare) => tokio::fs::rename(&spare, dest).await.is_ok(),
            None => false,
        };
        if !taken && !tokio::fs::try_exists(dest).await.unwrap_or(false) {
            clone(&image, dest).await?;
        }
        self.refill(key, image);
        Ok(())
    }

    /// Copies a template's image into a spare behind whatever took the last.
    fn refill(&self, key: String, image: PathBuf) {
        if !self.filling.lock().unwrap().insert(key.clone()) {
            return;
        }
        let spares = self.clone();
        tokio::spawn(async move {
            let path = spares.dir.join(format!("{key}.ext4"));
            let made = async {
                tokio::fs::create_dir_all(&spares.dir).await?;
                let temp = path.with_extension("tmp");
                clone(&image, &temp).await?;
                tokio::fs::rename(&temp, &path).await
            }
            .await;
            match made {
                Ok(()) => {
                    let stale = spares.held.lock().unwrap().insert(key.clone(), path);
                    if let Some(stale) = stale {
                        let _ = tokio::fs::remove_file(stale).await;
                    }
                }
                Err(err) => tracing::warn!(spare = key, %err, "could not make a spare disk"),
            }
            spares.filling.lock().unwrap().remove(&key);
        });
    }
}

/// A spare is of one version of a template's image, named by its inode.
fn spare_key(template: &str, image: &Path) -> std::io::Result<String> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(image)?;
    Ok(format!("{template}-{}-{}", meta.ino(), meta.mtime()))
}

/// An image a root disk was cloned from: the file, its digest, and the
/// digest of each chunk of it.
#[derive(Debug, Clone)]
pub struct Image {
    pub digest: String,
    pub path: PathBuf,
    pub index: ImageIndex,
}

/// What [`image_of`] remembers about a file so that it reads it once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Known {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    digest: String,
}

/// The image at `path`: its digest and chunk index, computed in one read the
/// first time and remembered by inode after. The file is adopted into the
/// blob store under its digest, by a hard link, so a node looking for the
/// image by digest finds it there while anything still links it.
pub async fn image_of(blobs: &crate::blobs::BlobStore, path: &Path) -> Result<Image, Status> {
    let io =
        |err: std::io::Error| Status::internal(format!("reading image {}: {err}", path.display()));
    let stamp = {
        use std::os::unix::fs::MetadataExt as _;
        let meta = tokio::fs::metadata(path).await.map_err(io)?;
        Known {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime_ns: meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128,
            digest: String::new(),
        }
    };
    let known_path = blobs.inode_record(stamp.dev, stamp.ino);
    if let Ok(bytes) = tokio::fs::read(&known_path).await
        && let Ok(known) = serde_json::from_slice::<Known>(&bytes)
        && (Known {
            digest: String::new(),
            ..known.clone()
        }) == stamp
        && let Some(digest) = crate::blobs::Digest::parse(&known.digest)
        && let Ok(bytes) = tokio::fs::read(blobs.index_path(&digest)).await
        && let Ok(index) = serde_json::from_slice::<ImageIndex>(&bytes)
    {
        return Ok(Image {
            digest: known.digest,
            path: path.to_path_buf(),
            index,
        });
    }

    let file = path.to_path_buf();
    let (digest, index) = tokio::task::spawn_blocking(move || index_file(&file))
        .await
        .map_err(|err| Status::internal(format!("indexing did not run: {err}")))?
        .map_err(io)?;
    let parsed = crate::blobs::Digest::parse(&digest).expect("a sha-256 in hex");
    blobs.adopt(path, &parsed).await.map_err(io)?;
    let json = serde_json::to_vec(&index)
        .map_err(std::io::Error::other)
        .map_err(io)?;
    let index_file = blobs.index_path(&parsed);
    crate::fsync::replace(&index_file, &index_file.with_extension("tmp"), json)
        .await
        .map_err(io)?;
    if let Some(parent) = known_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let known = Known {
        digest: digest.clone(),
        ..stamp
    };
    let _ = tokio::fs::write(&known_path, serde_json::to_vec(&known).unwrap_or_default()).await;
    Ok(Image {
        digest,
        path: path.to_path_buf(),
        index,
    })
}

/// A file's SHA-256 and its chunk index, from one sequential read.
fn index_file(path: &Path) -> std::io::Result<(String, ImageIndex)> {
    let file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    let mut whole = Sha256::new();
    let mut chunks = BTreeMap::new();
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    let mut n = 0u64;
    while n * CHUNK_SIZE < size {
        let len = (size - n * CHUNK_SIZE).min(CHUNK_SIZE) as usize;
        file.read_exact_at(&mut buf[..len], n * CHUNK_SIZE)?;
        whole.update(&buf[..len]);
        if buf[..len].iter().any(|&b| b != 0) {
            chunks.insert(n, hex::encode(Sha256::digest(&buf[..len])));
        }
        n += 1;
    }
    Ok((
        hex::encode(whole.finalize()),
        ImageIndex {
            size,
            chunk_size: CHUNK_SIZE,
            chunks,
        },
    ))
}

/// The image with `digest` on this node: in the blob store, or as one of its
/// templates' images. A template's is indexed the first time it is looked at
/// and found by inode after, so the search reads each image once.
pub async fn local_image(
    blobs: &crate::blobs::BlobStore,
    templates_dir: &Path,
    digest: &str,
) -> Option<Image> {
    let parsed = crate::blobs::Digest::parse(digest)?;
    if blobs.has(&parsed).await {
        return image_of(blobs, &blobs.path(&parsed)).await.ok();
    }
    let mut entries = tokio::fs::read_dir(templates_dir).await.ok()?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path().join(IMAGE);
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            continue;
        }
        if let Ok(image) = image_of(blobs, &path).await
            && image.digest == digest
        {
            return Some(image);
        }
    }
    None
}

/// Indexes every template's image behind the node's start, so the first
/// restore that looks for one does not read it on its own critical path.
pub async fn index_templates(blobs: &crate::blobs::BlobStore, templates_dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(templates_dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path().join(IMAGE);
        if tokio::fs::try_exists(&path).await.unwrap_or(false)
            && let Err(err) = image_of(blobs, &path).await
        {
            tracing::debug!(image = %path.display(), err = err.message(), "could not index an image");
        }
    }
}

/// Object key of an image's index in the store.
pub fn remote_index_key(digest: &str) -> String {
    format!("images/{digest}.index.json")
}

/// Puts an image into the object store once: its chunks, then the index that
/// names them. A store that already has the index has the chunks.
pub async fn upload_image(
    store: &crate::objstore::ObjectStore,
    image: &Image,
) -> Result<(), Status> {
    let key = remote_index_key(&image.digest);
    if store.exists(&key).await? {
        return Ok(());
    }
    let dir = image.path.parent().unwrap_or(Path::new("/"));
    let name = image
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let index = crate::chunks::put_image(store, dir, &[name], None, &Default::default()).await?;
    if index.chunks != image.index.chunks {
        return Err(Status::internal(format!(
            "image {} changed while it was uploaded",
            image.digest
        )));
    }
    let json = serde_json::to_vec(&index)
        .map_err(|err| Status::internal(format!("encoding an index: {err}")))?;
    store.put_bytes(&key, json).await
}

/// Brings the image with `digest` onto this node from the object store,
/// verified whole against its digest before it is adopted.
pub async fn fetch_image(
    store: &crate::objstore::ObjectStore,
    blobs: &crate::blobs::BlobStore,
    templates_dir: &Path,
    digest: &str,
) -> Result<Image, Status> {
    if let Some(image) = local_image(blobs, templates_dir, digest).await {
        return Ok(image);
    }
    let parsed = crate::blobs::Digest::parse(digest)
        .ok_or_else(|| Status::data_loss(format!("{digest:?} is not an image digest")))?;
    let index = crate::snapshot::read_index(store, &remote_index_key(digest))
        .await?
        .ok_or_else(|| Status::not_found(format!("image {digest} is not in the object store")))?;
    let incoming = blobs.incoming_path(&parsed);
    let started = std::time::Instant::now();
    crate::chunks::get_image(store, &index, &incoming).await?;
    let actual = crate::blobs::hash_file(&incoming)
        .await
        .map_err(|err| Status::internal(format!("hashing fetched image {digest}: {err}")))?;
    if actual != parsed {
        let _ = tokio::fs::remove_file(&incoming).await;
        return Err(Status::data_loss(format!(
            "image {digest} from the object store hashed as {actual}"
        )));
    }
    tokio::fs::rename(&incoming, blobs.path(&parsed))
        .await
        .map_err(|err| Status::internal(format!("adopting image {digest}: {err}")))?;
    tracing::info!(
        image = digest,
        bytes = index.stored_bytes(),
        took_ms = started.elapsed().as_millis() as u64,
        "image fetched from the object store"
    );
    image_of(blobs, &blobs.path(&parsed)).await
}

/// The chunk digests every image index in the store names, and the digests
/// of the images themselves, for the collector. Indexes of images no manifest
/// names any more and older than `grace` are removed instead.
pub async fn remote_image_refs(
    store: &crate::objstore::ObjectStore,
    wanted: &std::collections::HashSet<String>,
    grace: std::time::Duration,
    out: &mut std::collections::HashSet<String>,
) -> Result<usize, Status> {
    let cutoff = std::time::SystemTime::now() - grace;
    let mut removed = 0;
    for (key, modified) in store.list_aged("images/").await? {
        let Some(digest) = key
            .strip_prefix("images/")
            .and_then(|rest| rest.strip_suffix(".index.json"))
        else {
            continue;
        };
        if !wanted.contains(digest) && modified.is_some_and(|at| at <= cutoff) {
            store.delete(&key).await?;
            removed += 1;
            continue;
        }
        if let Some(index) = crate::snapshot::read_index(store, &key).await? {
            out.extend(index.digests().map(str::to_string));
        }
    }
    Ok(removed)
}

/// Builds `dest` from a disk index: a clone of `image` where one is given,
/// with only the chunks that differ from it fetched, or every chunk fetched
/// where none is. Returns the bytes fetched.
pub async fn materialise(
    store: &crate::objstore::ObjectStore,
    index: &ImageIndex,
    image: Option<&Image>,
    dest: &Path,
) -> Result<u64, Status> {
    let Some(image) = image else {
        crate::chunks::get_image(store, index, dest).await?;
        return Ok(index.stored_bytes());
    };
    if index.chunk_size != image.index.chunk_size {
        return Err(Status::data_loss(
            "a disk index and its image are cut in different chunk sizes",
        ));
    }
    clone(&image.path, dest)
        .await
        .map_err(|err| Status::internal(format!("cloning image {}: {err}", image.digest)))?;
    let differing: HashMap<u64, Option<String>> = index
        .chunks
        .keys()
        .chain(image.index.chunks.keys())
        .copied()
        .filter(|n| index.chunks.get(n) != image.index.chunks.get(n))
        .map(|n| (n, index.chunks.get(&n).cloned()))
        .collect();
    crate::chunks::patch(store, dest, index.size, index.chunk_size, differing).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "burrow-rootdisk-{name}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_record_without_a_layout_is_an_overlay() {
        assert_eq!(DiskLayout::from_record(""), DiskLayout::Overlay);
        assert_eq!(DiskLayout::from_record("overlay"), DiskLayout::Overlay);
        assert_eq!(DiskLayout::from_record("root"), DiskLayout::Root);
        assert_eq!(DiskLayout::Root.as_str(), "root");
        // The agent pivots only when told, so the overlay has to say so.
        assert!(
            DiskLayout::Overlay
                .boot_args()
                .contains("burrow.layout=overlay")
        );
        assert!(DiskLayout::Root.boot_args().contains(" rw"));
        let drives = DiskLayout::Root.drives();
        assert_eq!(drives.len(), 1);
        assert!(drives[0].is_root && !drives[0].is_read_only);
    }

    #[test]
    fn an_asif_image_is_its_header_size_and_a_raw_disk_its_length() {
        let dir = scratch("asif");
        let raw = dir.join("raw");
        std::fs::write(&raw, vec![0u8; 4096]).unwrap();
        assert_eq!(provisioned_bytes(&raw), 4096);
        // The header of a 64 GiB image as `diskutil image create` wrote it.
        let mut header = vec![0u8; 512];
        header[..8].copy_from_slice(b"shdw\0\0\0\x01");
        header[0x30..0x38].copy_from_slice(&0x0800_0000u64.to_be_bytes());
        let asif = dir.join("disk.img");
        std::fs::write(&asif, &header).unwrap();
        assert_eq!(provisioned_bytes(&asif), 64 << 30);
        assert_eq!(provisioned_bytes(&dir.join("missing")), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_disk_is_the_image_plus_headroom_and_never_smaller() {
        assert_eq!(disk_mib(0, 300 * MIB).unwrap(), 300 + DEFAULT_HEADROOM_MIB);
        assert_eq!(
            disk_mib(0, 300 * MIB + 1).unwrap(),
            301 + DEFAULT_HEADROOM_MIB
        );
        assert_eq!(disk_mib(4096, 300 * MIB).unwrap(), 4096);
        assert_eq!(disk_mib(300, 300 * MIB).unwrap(), 300);
        assert_eq!(
            disk_mib(299, 300 * MIB).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn a_clone_has_the_image_bytes_and_holes() {
        let dir = scratch("clone");
        let image = dir.join("image");
        let file = std::fs::File::create(&image).unwrap();
        file.set_len(8 * MIB).unwrap();
        file.write_all_at(b"burrow", 3 * MIB).unwrap();
        drop(file);
        let disk = dir.join("disk");
        clone_blocking(&image, &disk).unwrap();
        assert_eq!(
            std::fs::read(&disk).unwrap(),
            std::fs::read(&image).unwrap()
        );
        // A second clone over the first replaces it.
        clone_blocking(&image, &disk).unwrap();
        assert_eq!(std::fs::metadata(&disk).unwrap().len(), 8 * MIB);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sparse_copy_keeps_the_size_and_the_data() {
        let dir = scratch("sparse");
        let image = dir.join("image");
        let file = std::fs::File::create(&image).unwrap();
        file.set_len(4 * MIB + 17).unwrap();
        file.write_all_at(&[7u8; 4096], MIB).unwrap();
        file.write_all_at(b"end", 4 * MIB + 14).unwrap();
        drop(file);
        let copy = dir.join("copy");
        sparse_copy(&image, &copy).unwrap();
        assert_eq!(
            std::fs::read(&copy).unwrap(),
            std::fs::read(&image).unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_disk_grows_and_never_shrinks() {
        let dir = scratch("grow");
        let disk = dir.join("disk");
        std::fs::File::create(&disk)
            .unwrap()
            .set_len(2 * MIB)
            .unwrap();
        assert!(grow(&disk, 4).await.unwrap());
        assert_eq!(std::fs::metadata(&disk).unwrap().len(), 4 * MIB);
        assert!(!grow(&disk, 4).await.unwrap());
        assert_eq!(
            grow(&disk, 3).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mappings_compare_by_where_the_bytes_sit() {
        let image = vec![
            Mapped {
                logical: 0,
                end: 4096,
                physical: Some(1 << 20),
            },
            Mapped {
                logical: 4096,
                end: 8192,
                physical: Some((1 << 20) + 4096),
            },
        ];
        // The same blocks, reported as one extent.
        let disk = vec![Mapped {
            logical: 0,
            end: 8192,
            physical: Some(1 << 20),
        }];
        assert_eq!(
            mapping_within(&image, 0, 8192),
            mapping_within(&disk, 0, 8192)
        );
        // Rewritten in the middle: elsewhere on the device.
        let rewritten = vec![
            Mapped {
                logical: 0,
                end: 4096,
                physical: Some(1 << 20),
            },
            Mapped {
                logical: 4096,
                end: 8192,
                physical: Some(9 << 20),
            },
        ];
        assert_ne!(
            mapping_within(&image, 0, 8192),
            mapping_within(&rewritten, 0, 8192)
        );
        assert_eq!(
            mapping_within(&image, 0, 4096),
            mapping_within(&rewritten, 0, 4096)
        );
    }

    #[tokio::test]
    async fn an_image_is_indexed_once_and_adopted_by_digest() {
        let dir = scratch("image");
        let blobs = crate::blobs::BlobStore::new(&dir);
        let path = dir.join("rootfs.ext4");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(3 * MIB).unwrap();
        file.write_all_at(b"x", 2 * MIB + 5).unwrap();
        drop(file);
        let image = image_of(&blobs, &path).await.unwrap();
        assert_eq!(image.index.size, 3 * MIB);
        assert_eq!(
            image.index.chunks.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(
            image.digest,
            crate::blobs::hash_file(&path).await.unwrap().to_string()
        );
        let found = local_image(&blobs, &dir, &image.digest).await.unwrap();
        assert_eq!(found.index.chunks, image.index.chunks);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A disk goes to the store as its image plus the chunks it changed, and
    /// comes back from a clone of the image with only those fetched.
    #[tokio::test]
    async fn a_disk_round_trips_as_its_image_and_its_changes() {
        let dir = scratch("roundtrip");
        let store = crate::objstore::fake::store(true).await;
        let blobs = crate::blobs::BlobStore::new(&dir);
        let image_path = dir.join(IMAGE);
        let file = std::fs::File::create(&image_path).unwrap();
        file.set_len(4 * MIB).unwrap();
        for n in 0..4 {
            file.write_all_at(&[n as u8 + 1; 4096], n * MIB).unwrap();
        }
        drop(file);
        let image = image_of(&blobs, &image_path).await.unwrap();
        upload_image(&store, &image).await.unwrap();

        // Grown by a chunk, one chunk rewritten, one emptied.
        let disk = dir.join(ROOT_DISK);
        clone_blocking(&image_path, &disk).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&disk).unwrap();
        file.set_len(5 * MIB).unwrap();
        file.write_all_at(&[9u8; 4096], MIB).unwrap();
        file.write_all_at(&[0u8; 4096], 2 * MIB).unwrap();
        file.write_all_at(b"new", 4 * MIB).unwrap();
        drop(file);
        let index = crate::chunks::put_disk(&store, &disk, Some(&image), &Default::default())
            .await
            .unwrap();
        assert_eq!(index.size, 5 * MIB);
        assert_eq!(index.chunks.get(&0), image.index.chunks.get(&0));
        assert_ne!(index.chunks.get(&1), image.index.chunks.get(&1));
        assert!(!index.chunks.contains_key(&2));

        let restored = dir.join("restored.ext4");
        let fetched = materialise(&store, &index, Some(&image), &restored)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(&restored).unwrap(),
            std::fs::read(&disk).unwrap()
        );
        assert_eq!(fetched, 2 * MIB);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
