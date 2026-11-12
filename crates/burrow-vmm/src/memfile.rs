//! Which pages each memory file in a snapshot chain defines.
//!
//! A diff snapshot is a sparse file the size of the guest. A hole in it means
//! "unchanged, look further down the chain" and a page of zeroes the guest
//! wrote means "zero", but the filesystem cannot be trusted to tell the two
//! apart: ZFS reports data per record, so one dirty page claims its 128 KiB
//! neighbours, and with compression on it stores a written zero page as a
//! hole. So every diff carries an exact map of the pages it defines, appended
//! after the guest's memory when the diff is written, and only a full image is
//! read through its extents, since there a hole and a zero page are the same.
//!
//! Extents are an optimisation and nothing more. A diff without a map is
//! refused.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The unit a map records, a guest page. Larger pages are recorded as the
/// 4 KiB pages they span.
pub const PAGE: u64 = 4096;

const MAGIC: &[u8; 8] = b"BRWPAGES";
const VERSION: u32 = 1;
/// Magic, version, page size, page count, checksum.
const FOOTER: u64 = 32;

/// The guest pages one diff defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageMap {
    pages: u64,
    words: Vec<u64>,
}

impl PageMap {
    pub fn new(pages: u64) -> Self {
        Self {
            pages,
            words: vec![0; pages.div_ceil(64) as usize],
        }
    }

    pub fn pages(&self) -> u64 {
        self.pages
    }

    pub fn insert(&mut self, page: u64) {
        self.words[(page / 64) as usize] |= 1 << (page % 64);
    }

    /// Marks every page `[start, end)` touches, in bytes.
    pub fn insert_bytes(&mut self, start: u64, end: u64) {
        for page in start / PAGE..end.div_ceil(PAGE).min(self.pages) {
            self.insert(page);
        }
    }

    pub fn remove_bytes(&mut self, start: u64, end: u64) {
        for page in start / PAGE..end.div_ceil(PAGE).min(self.pages) {
            self.words[(page / 64) as usize] &= !(1 << (page % 64));
        }
    }

    pub fn contains(&self, page: u64) -> bool {
        page < self.pages && self.words[(page / 64) as usize] & (1 << (page % 64)) != 0
    }

    pub fn count(&self) -> u64 {
        self.words
            .iter()
            .map(|word| u64::from(word.count_ones()))
            .sum()
    }

    /// The defined pages as sorted, merged byte ranges.
    pub fn ranges(&self) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = Vec::new();
        for page in (0..self.pages).filter(|&page| self.contains(page)) {
            let start = page * PAGE;
            match out.last_mut() {
                Some(last) if last.1 == start => last.1 = start + PAGE,
                _ => out.push((start, start + PAGE)),
            }
        }
        out
    }

    fn checksum(&self) -> u64 {
        // FNV-1a: enough to tell a map from guest memory that happens to end
        // in the magic, and from a torn write.
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in self
            .pages
            .to_le_bytes()
            .into_iter()
            .chain(self.words.iter().flat_map(|word| word.to_le_bytes()))
        {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len() * 8 + FOOTER as usize);
        for word in &self.words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(PAGE as u32).to_le_bytes());
        out.extend_from_slice(&self.pages.to_le_bytes());
        out.extend_from_slice(&self.checksum().to_le_bytes());
        out
    }
}

/// Appends `map` to the diff at `path`, whose length must be exactly the
/// guest's memory. Not synced here: the diff is synced with the rest of the
/// snapshot, and the map is part of the same file.
pub fn append_map(path: &Path, map: &PageMap) -> io::Result<()> {
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len();
    if len != map.pages * PAGE {
        return Err(io::Error::other(format!(
            "{} is {len} bytes but its page map covers {} pages",
            path.display(),
            map.pages
        )));
    }
    file.write_all_at(&map.encode(), len)
}

/// The map a diff carries, or `None` for a file without one.
pub fn read_map(file: &File) -> io::Result<Option<PageMap>> {
    let len = file.metadata()?.len();
    if len < FOOTER {
        return Ok(None);
    }
    let mut footer = [0u8; FOOTER as usize];
    file.read_exact_at(&mut footer, len - FOOTER)?;
    if &footer[..8] != MAGIC {
        return Ok(None);
    }
    let field = |at: usize, size: usize| {
        let mut bytes = [0u8; 8];
        bytes[..size].copy_from_slice(&footer[at..at + size]);
        u64::from_le_bytes(bytes)
    };
    let (version, page, pages, checksum) = (field(8, 4), field(12, 4), field(16, 8), field(24, 8));
    let corrupt = |why: &str| io::Error::other(format!("corrupt page map: {why}"));
    if version != u64::from(VERSION) || page != PAGE {
        return Err(corrupt("unknown version or page size"));
    }
    let bitmap = pages.div_ceil(64) * 8;
    if pages
        .checked_mul(PAGE)
        .and_then(|memory| memory.checked_add(bitmap + FOOTER))
        != Some(len)
    {
        return Err(corrupt("its length does not match the file's"));
    }
    let mut bytes = vec![0u8; bitmap as usize];
    file.read_exact_at(&mut bytes, pages * PAGE)?;
    let map = PageMap {
        pages,
        words: bytes
            .chunks_exact(8)
            .map(|word| u64::from_le_bytes(word.try_into().expect("8 bytes")))
            .collect(),
    };
    if map.checksum() != checksum {
        return Err(corrupt("checksum mismatch"));
    }
    Ok(Some(map))
}

/// Where a file's data is, according to its filesystem.
pub trait Extents: Sync {
    /// Sorted, non-overlapping `[start, end)` byte ranges holding data. An
    /// error when the filesystem cannot say.
    fn extents(&self, file: &File) -> io::Result<Vec<(u64, u64)>>;
}

/// `SEEK_DATA`/`SEEK_HOLE`.
pub struct Seek;

impl Extents for Seek {
    fn extents(&self, file: &File) -> io::Result<Vec<(u64, u64)>> {
        use std::os::fd::AsRawFd as _;
        let fd = file.as_raw_fd();
        let size = file.metadata()?.len() as libc::off_t;
        let mut extents = Vec::new();
        let mut cursor: libc::off_t = 0;
        while cursor < size {
            // SAFETY: `fd` is open; SEEK_DATA/SEEK_HOLE take plain integers.
            let start = unsafe { libc::lseek(fd, cursor, libc::SEEK_DATA) };
            if start < 0 {
                let err = io::Error::last_os_error();
                // ENXIO means "no data at or after here": the rest is a hole.
                if err.raw_os_error() == Some(libc::ENXIO) {
                    break;
                }
                return Err(err);
            }
            // SAFETY: as above.
            let end = unsafe { libc::lseek(fd, start, libc::SEEK_HOLE) };
            if end < 0 {
                return Err(io::Error::last_os_error());
            }
            if end <= start {
                break;
            }
            extents.push((start as u64, end as u64));
            cursor = end;
        }
        Ok(extents)
    }
}

/// The byte ranges of a full image that may hold data. A filesystem that
/// cannot say has the whole file read, which for a full image is only slower:
/// a hole there and a page of zeroes are the same thing. Never use this to
/// find what a diff defines.
pub fn data_extents(file: &File) -> io::Result<Vec<(u64, u64)>> {
    full_extents(file, &Seek)
}

fn full_extents(file: &File, extents: &dyn Extents) -> io::Result<Vec<(u64, u64)>> {
    match extents.extents(file) {
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {
            let size = file.metadata()?.len();
            Ok(if size == 0 {
                Vec::new()
            } else {
                vec![(0, size)]
            })
        }
        other => other,
    }
}

static HOLES_EXACT: AtomicBool = AtomicBool::new(false);

/// Records what [`probe`] found about the filesystem chains live on.
pub fn set_holes_exact(exact: bool) {
    HOLES_EXACT.store(exact, Ordering::Relaxed);
}

/// Whether the filesystem chains live on reports holes per page and keeps
/// written zero pages as data, so a diff's extents are its pages.
pub fn are_holes_exact() -> bool {
    HOLES_EXACT.load(Ordering::Relaxed)
}

/// What one layer of a chain holds: the guest memory's length, and the byte
/// ranges it defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub len: u64,
    /// Sorted, non-overlapping `[start, end)` byte ranges.
    pub defined: Vec<(u64, u64)>,
}

impl Layer {
    /// A full image defines every page, so its ranges are only where it may
    /// hold data: the rest reads as zeroes either way.
    pub fn full(len: u64, extents: Vec<(u64, u64)>) -> Self {
        Self {
            len,
            defined: extents,
        }
    }

    pub fn defines(&self, offset: u64) -> bool {
        let at = self.defined.partition_point(|&(_, end)| end <= offset);
        self.defined
            .get(at)
            .is_some_and(|&(start, _)| start <= offset)
    }

    /// The defined ranges cut to `[start, end)`.
    pub fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let first = self.defined.partition_point(|&(_, e)| e <= start);
        self.defined[first..]
            .iter()
            .take_while(move |&&(s, _)| s < end)
            .map(move |&(s, e)| (s.max(start), e.min(end)))
    }
}

/// Reads what a chain's layer defines. `index` 0 is the full base; every
/// other layer is a diff and must carry a map.
pub fn open_layer(path: &Path, file: &File, index: usize) -> io::Result<Layer> {
    open_layer_with(path, file, index, &Seek)
}

/// [`open_layer`] with the extents given.
pub fn open_layer_with(
    path: &Path,
    file: &File,
    index: usize,
    extents: &dyn Extents,
) -> io::Result<Layer> {
    if index == 0 {
        let len = file.metadata()?.len();
        return Ok(Layer::full(len, full_extents(file, extents)?));
    }
    let map = read_map(file)
        .map_err(|err| named(path, err))?
        .ok_or_else(|| {
            io::Error::other(format!(
                "{} has no page map: it was written by a suspend that did not finish; delete it",
                path.display()
            ))
        })?;
    Ok(Layer {
        len: map.pages * PAGE,
        defined: map.ranges(),
    })
}

fn named(path: &Path, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {err}", path.display()))
}

/// Opens a whole chain, oldest first.
pub fn open_chain(paths: &[PathBuf]) -> io::Result<Vec<(File, Layer)>> {
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let file = File::open(path)?;
            let layer = open_layer(path, &file, index)?;
            Ok((file, layer))
        })
        .collect()
}

/// The newest layer defining `offset`, if any does.
pub fn resolve<L: AsRef<Layer>>(layers: &[L], offset: u64) -> Option<usize> {
    layers
        .iter()
        .rposition(|layer| layer.as_ref().defines(offset))
}

impl AsRef<Layer> for Layer {
    fn as_ref(&self) -> &Layer {
        self
    }
}

/// Builds the map of a diff Firecracker just wrote from its extents. Only
/// sound where [`are_holes_exact`]: Firecracker writes each page it records,
/// zeroes included, into a fresh file.
pub fn map_from_extents(path: &Path) -> io::Result<PageMap> {
    if !are_holes_exact() {
        return Err(io::Error::other(
            "the data directory does not report holes per page, so a diff's pages \
             can only come from the page-fault handler",
        ));
    }
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut map = PageMap::new(len / PAGE);
    for (start, end) in Seek.extents(&file)? {
        map.insert_bytes(start, end);
    }
    Ok(map)
}

/// Copies a full image without filling in its holes.
///
/// `std::fs::copy` expands every hole into real zeroes, which turns merging a
/// mostly-untouched 512 MiB guest into 512 MiB of writes, and leaves the
/// merged base dense, so the next merge is expensive too. `--reflink=auto`
/// makes it metadata-only on filesystems that support it.
fn copy_preserving_holes(source: &Path, dest: &Path) -> io::Result<()> {
    let status = std::process::Command::new("cp")
        .args(["--sparse=always", "--reflink=auto"])
        .arg(source)
        .arg(dest)
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        // A slow merge beats a failed one.
        _ => std::fs::copy(source, dest).map(|_| ()),
    }
}

/// Flattens a snapshot chain into a single memory file.
///
/// A chain cannot grow without bound: every layer is another lookup on the
/// path of a page fault. The obvious way to reset it, taking a full snapshot,
/// is the worst way, because with the page-fault handler active it makes
/// Firecracker read the entire guest through this process, faulting in every
/// page to write it straight back out. Measured at 6.4s against 44ms for a
/// diff.
///
/// Merging on the host instead never touches the guest: it is sequential file
/// work over the layers already on disk. The output is written to a temporary
/// and renamed, so a merge that fails leaves the chain it was flattening
/// intact, and so that a `snapshot.mem` hard-linked from a warm template is
/// replaced rather than written through.
pub fn merge_chain(chain: &[PathBuf], out: &Path) -> io::Result<()> {
    let layers = open_chain(chain)?;
    merge_layers(&chain[0], &layers, out)
}

fn merge_layers(base: &Path, layers: &[(File, Layer)], out: &Path) -> io::Result<()> {
    let temp = out.with_extension("merging");
    let _ = std::fs::remove_file(&temp);
    copy_preserving_holes(base, &temp)?;

    let merged = std::fs::OpenOptions::new().write(true).open(&temp)?;
    let mut buffer = vec![0u8; 1024 * 1024];
    for (file, layer) in &layers[1..] {
        // Every page the diff defines, zeroes included: a zero page the guest
        // wrote has to replace what lies beneath it.
        for &(start, end) in &layer.defined {
            let mut at = start;
            while at < end {
                let len = ((end - at) as usize).min(buffer.len());
                file.read_exact_at(&mut buffer[..len], at)?;
                merged.write_all_at(&buffer[..len], at)?;
                at += len as u64;
            }
        }
    }
    drop(merged);
    std::fs::rename(&temp, out)
}

/// What [`probe`] found about a directory's filesystem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    /// One page written into a sparse file at an offset no record size
    /// aligns to was reported as exactly that page.
    pub is_page_granular: bool,
    /// A page of written zeroes was reported as data, not a hole.
    pub is_zero_page_kept: bool,
    /// Why the probe could not run, when it could not.
    pub error: Option<String>,
}

impl Probe {
    /// Whether a sparse file's extents are exactly the pages written to it.
    pub fn is_exact(&self) -> bool {
        self.is_page_granular && self.is_zero_page_kept
    }
}

const PROBE_FILE: &str = ".burrow-hole-probe";
/// Past 64 KiB and short of 128 KiB, so no common record or cluster size
/// lines up with it.
const PROBE_DATA: u64 = 68 * 1024;
const PROBE_ZERO: u64 = 200 * 1024;

/// Checks whether `dir`'s filesystem reports holes per 4 KiB page and keeps
/// written zero pages as data, before and after the file is synced.
pub fn probe(dir: &Path) -> Probe {
    probe_with(dir, &Seek)
}

fn probe_with(dir: &Path, extents: &dyn Extents) -> Probe {
    let path = dir.join(PROBE_FILE);
    let result = run_probe(&path, extents);
    let _ = std::fs::remove_file(&path);
    match result {
        Ok((is_page_granular, is_zero_page_kept)) => Probe {
            is_page_granular,
            is_zero_page_kept,
            error: None,
        },
        Err(err) => Probe {
            error: Some(err.to_string()),
            ..Probe::default()
        },
    }
}

fn run_probe(path: &Path, extents: &dyn Extents) -> io::Result<(bool, bool)> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(1024 * 1024)?;
    file.write_all_at(&[0xa5; PAGE as usize], PROBE_DATA)?;
    file.write_all_at(&[0; PAGE as usize], PROBE_ZERO)?;
    let before = judge(&extents.extents(&file)?);
    file.sync_all()?;
    let after = judge(&extents.extents(&file)?);
    Ok((before.0 && after.0, before.1 && after.1))
}

fn judge(extents: &[(u64, u64)]) -> (bool, bool) {
    let data = (PROBE_DATA, PROBE_DATA + PAGE);
    let zero = (PROBE_ZERO, PROBE_ZERO + PAGE);
    let is_page_granular = extents.contains(&data)
        && extents
            .iter()
            .all(|extent| *extent == data || *extent == zero);
    let is_zero_page_kept = extents
        .iter()
        .any(|&(start, end)| start <= zero.0 && end >= zero.1);
    (is_page_granular, is_zero_page_kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: u64 = 128 * 1024;

    /// ZFS with `recordsize=128K` and compression: data reported per record,
    /// and a record holding only zeroes stored as a hole.
    struct Records;

    impl Extents for Records {
        fn extents(&self, file: &File) -> io::Result<Vec<(u64, u64)>> {
            let len = file.metadata()?.len();
            let mut out: Vec<(u64, u64)> = Vec::new();
            let mut buf = vec![0u8; RECORD as usize];
            for start in (0..len).step_by(RECORD as usize) {
                let end = (start + RECORD).min(len);
                let buf = &mut buf[..(end - start) as usize];
                file.read_exact_at(buf, start)?;
                if buf.iter().all(|&b| b == 0) {
                    continue;
                }
                match out.last_mut() {
                    Some(last) if last.1 == start => last.1 = end,
                    _ => out.push((start, end)),
                }
            }
            Ok(out)
        }
    }

    /// A filesystem without `SEEK_DATA`.
    struct Unsupported;

    impl Extents for Unsupported {
        fn extents(&self, _file: &File) -> io::Result<Vec<(u64, u64)>> {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("burrow-memfile-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const PAGES: u64 = 96;

    fn page_of(byte: u8) -> Vec<u8> {
        vec![byte; PAGE as usize]
    }

    /// A chain written the way a suspend writes one: a full base, then diffs
    /// holding only the pages they name, each with its map appended. Returns
    /// the paths and what the guest's memory should read as.
    fn chain(dir: &Path) -> (Vec<PathBuf>, Vec<Vec<u8>>) {
        let mut memory: Vec<Vec<u8>> = (0..PAGES).map(|p| page_of(p as u8 + 1)).collect();
        let base = dir.join("snapshot.mem");
        let file = File::create(&base).unwrap();
        file.set_len(PAGES * PAGE).unwrap();
        for (page, bytes) in memory.iter().enumerate() {
            file.write_all_at(bytes, page as u64 * PAGE).unwrap();
        }
        // Each diff dirties one page in a 32-page record, zeroes another the
        // base holds data in, and the second rewrites a page of the first.
        let diffs: [&[(u64, u8)]; 2] = [&[(17, 0xd1), (40, 0), (70, 0xd1)], &[(17, 0xd2), (41, 0)]];
        let mut paths = vec![base];
        for (index, writes) in diffs.iter().enumerate() {
            let path = dir.join(format!("snapshot.diff{}.mem", index + 1));
            let file = File::create(&path).unwrap();
            file.set_len(PAGES * PAGE).unwrap();
            let mut map = PageMap::new(PAGES);
            for &(page, byte) in *writes {
                file.write_all_at(&page_of(byte), page * PAGE).unwrap();
                map.insert(page);
                memory[page as usize] = page_of(byte);
            }
            append_map(&path, &map).unwrap();
            paths.push(path);
        }
        (paths, memory)
    }

    fn open_with(paths: &[PathBuf], extents: &dyn Extents) -> io::Result<Vec<(File, Layer)>> {
        paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let file = File::open(path)?;
                let layer = open_layer_with(path, &file, index, extents)?;
                Ok((file, layer))
            })
            .collect()
    }

    /// What a restore serves for each page: the newest defining layer's bytes,
    /// or zeroes, exactly as the page-fault handler chooses.
    fn served(layers: &[(File, Layer)]) -> Vec<Vec<u8>> {
        let only: Vec<Layer> = layers.iter().map(|(_, layer)| layer.clone()).collect();
        (0..PAGES)
            .map(|page| {
                let mut buf = page_of(0);
                if let Some(index) = resolve(&only, page * PAGE) {
                    layers[index]
                        .0
                        .read_exact_at(&mut buf, page * PAGE)
                        .unwrap();
                }
                buf
            })
            .collect()
    }

    #[test]
    fn a_map_survives_being_appended_and_read_back() {
        let dir = scratch("roundtrip");
        let path = dir.join("diff");
        File::create(&path).unwrap().set_len(PAGES * PAGE).unwrap();
        let mut map = PageMap::new(PAGES);
        map.insert(0);
        map.insert(63);
        map.insert(64);
        map.insert(PAGES - 1);
        append_map(&path, &map).unwrap();
        assert_eq!(
            read_map(&File::open(&path).unwrap()).unwrap(),
            Some(map.clone())
        );
        assert_eq!(
            map.ranges(),
            vec![
                (0, PAGE),
                (63 * PAGE, 65 * PAGE),
                ((PAGES - 1) * PAGE, PAGES * PAGE)
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_map_is_an_error_and_a_missing_one_is_not() {
        let dir = scratch("damaged");
        let path = dir.join("diff");
        File::create(&path).unwrap().set_len(PAGES * PAGE).unwrap();
        assert_eq!(read_map(&File::open(&path).unwrap()).unwrap(), None);
        let mut map = PageMap::new(PAGES);
        map.insert(5);
        append_map(&path, &map).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all_at(&[0xff], PAGES * PAGE).unwrap();
        assert!(read_map(&File::open(&path).unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_map_must_cover_the_whole_diff() {
        let dir = scratch("length");
        let path = dir.join("diff");
        File::create(&path).unwrap().set_len(PAGES * PAGE).unwrap();
        assert!(append_map(&path, &PageMap::new(PAGES - 1)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restore_serves_the_guests_memory_whatever_the_filesystem_reports() {
        let dir = scratch("restore");
        let (paths, memory) = chain(&dir);
        for extents in [&Seek as &dyn Extents, &Records, &Unsupported] {
            let layers = open_with(&paths, extents).unwrap();
            assert_eq!(served(&layers), memory);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coarse_extents_would_have_corrupted_the_restore() {
        let dir = scratch("coarse");
        let (paths, memory) = chain(&dir);
        // What reading diffs through their extents would serve.
        let mut layers = open_with(&paths, &Records).unwrap();
        for (file, layer) in &mut layers[1..] {
            layer.defined = Records.extents(file).unwrap();
        }
        let served = served(&layers);
        assert_ne!(
            served[16], memory[16],
            "a neighbour of a dirty page reads as zero"
        );
        assert_ne!(
            served[40], memory[40],
            "a zeroed page shows the base through"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flattening_writes_the_guests_memory_whatever_the_filesystem_reports() {
        let dir = scratch("flatten");
        let (paths, memory) = chain(&dir);
        for extents in [&Seek as &dyn Extents, &Records, &Unsupported] {
            let out = dir.join("merged.mem");
            let layers = open_with(&paths, extents).unwrap();
            merge_layers(&paths[0], &layers, &out).unwrap();
            assert_eq!(std::fs::read(&out).unwrap(), memory.concat());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_diff_without_a_map_is_refused() {
        let dir = scratch("unmapped");
        let (paths, _) = chain(&dir);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&paths[1])
            .unwrap();
        file.set_len(PAGES * PAGE).unwrap();
        drop(file);

        let err = open_with(&paths[..2], &Seek).unwrap_err();
        assert!(err.to_string().contains("has no page map"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct Exact(Vec<(u64, u64)>);

    impl Extents for Exact {
        fn extents(&self, _file: &File) -> io::Result<Vec<(u64, u64)>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn the_probe_tells_page_holes_from_record_holes() {
        let dir = scratch("probe");
        let data = (PROBE_DATA, PROBE_DATA + PAGE);
        let zero = (PROBE_ZERO, PROBE_ZERO + PAGE);

        let exact = probe_with(&dir, &Exact(vec![data, zero]));
        assert!(exact.is_exact(), "{exact:?}");

        // Records cover both pages; compression drops the zero record.
        let records = probe_with(&dir, &Records);
        assert_eq!(
            (records.is_page_granular, records.is_zero_page_kept),
            (false, false)
        );
        let coarse = probe_with(&dir, &Exact(vec![(0, RECORD), (RECORD, 2 * RECORD)]));
        assert_eq!(
            (coarse.is_page_granular, coarse.is_zero_page_kept),
            (false, true)
        );
        let zero_as_hole = probe_with(&dir, &Exact(vec![data]));
        assert_eq!(
            (
                zero_as_hole.is_page_granular,
                zero_as_hole.is_zero_page_kept
            ),
            (true, false)
        );

        let unsupported = probe_with(&dir, &Unsupported);
        assert!(!unsupported.is_exact() && unsupported.error.is_some());
        assert!(!dir.join(PROBE_FILE).exists());

        // The real filesystem: whatever it is, the probe completes.
        let real = probe(&dir);
        assert!(real.error.is_none() || !real.is_exact(), "{real:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
