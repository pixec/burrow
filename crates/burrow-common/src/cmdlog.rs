//! A command's output log, as the node keeps it.
//!
//! Docker keeps a container's output on the host, where the container cannot
//! read, rewrite or fill it; so does Burrow, for every command a sandbox runs.
//! A log is a run of records in numbered files. Rotation, when a command asks
//! for it, starts the next file once one reaches `max_bytes` and drops the
//! oldest past `max_files`, as Docker's `max-size` and `max-file` do.
//!
//! Every record carries the output offset of its first byte, stdout and
//! stderr counted together from the command's start. That is what lets a
//! reader resume from wherever it got to, and what keeps a gap honest: output
//! the log never received is a jump in offsets, which a reader is told about
//! by how many bytes, rather than a seam nobody can see.
//!
//! Files are numbered rather than renamed on rotation, so a reader holding
//! one open is never handed a different file under the same name.

use std::collections::VecDeque;
use std::io::Write as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

/// A record's header: kind, output offset, payload length.
const HEADER: u64 = 13;

/// One piece of a command's output.
#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit { code: i32, signal: i32 },
}

impl Frame {
    /// Output bytes it holds. An exit holds none.
    pub fn len(&self) -> usize {
        match self {
            Frame::Stdout(bytes) | Frame::Stderr(bytes) => bytes.len(),
            Frame::Exit { .. } => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The part of this frame from `skip` output bytes in.
    pub fn tail(&self, skip: usize) -> Frame {
        match self {
            Frame::Stdout(bytes) => Frame::Stdout(bytes[skip.min(bytes.len())..].to_vec()),
            Frame::Stderr(bytes) => Frame::Stderr(bytes[skip.min(bytes.len())..].to_vec()),
            exit => exit.clone(),
        }
    }

    fn encode(&self) -> (u8, Vec<u8>) {
        match self {
            Frame::Stdout(bytes) => (0, bytes.clone()),
            Frame::Stderr(bytes) => (1, bytes.clone()),
            Frame::Exit { code, signal } => {
                let mut payload = code.to_le_bytes().to_vec();
                payload.extend_from_slice(&signal.to_le_bytes());
                (2, payload)
            }
        }
    }

    fn decode(kind: u8, payload: Vec<u8>) -> Frame {
        match kind {
            0 => Frame::Stdout(payload),
            1 => Frame::Stderr(payload),
            _ => {
                let word = |at: usize| {
                    payload
                        .get(at..at + 4)
                        .and_then(|b| b.try_into().ok())
                        .map(i32::from_le_bytes)
                        .unwrap_or_default()
                };
                Frame::Exit {
                    code: word(0),
                    signal: word(4),
                }
            }
        }
    }
}

/// How a log is bounded, as Docker's `max-size` and `max-file`.
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Rotation {
    /// Bytes per file before a new one is started; 0 never rotates.
    pub max_bytes: u64,
    /// Files kept once rotating, at least 1.
    pub max_files: u32,
}

/// Where one record sits.
#[derive(Clone, Copy, Debug)]
pub struct Record {
    /// Output offset of its first byte.
    pub at: u64,
    generation: u32,
    /// Position of its header in that file.
    pos: u64,
    kind: u8,
    len: u32,
}

impl Record {
    pub fn output_len(&self) -> u64 {
        if self.kind == 2 {
            0
        } else {
            u64::from(self.len)
        }
    }

    pub fn is_exit(&self) -> bool {
        self.kind == 2
    }
}

/// One command's log, and an index of it.
pub struct Log {
    dir: PathBuf,
    id: String,
    rotation: Rotation,
    /// Gone once a write has failed: the log stops there, and what follows is
    /// a gap a reader is told about.
    file: Option<std::fs::File>,
    generation: u32,
    oldest: u32,
    written: u64,
    records: VecDeque<Record>,
    /// Output offset the log holds up to.
    logged: u64,
}

/// One step of a replay.
pub enum Replayed {
    Frame(Frame),
    /// Output that is not in the log, by how many bytes.
    Lost(u64),
}

/// What a reader at some offset is owed, worked out from a log's index and
/// read from its files afterwards, without holding the log.
pub struct Plan {
    dir: PathBuf,
    id: String,
    offset: u64,
    /// Output from the offset on that rotation has already dropped.
    rotated: u64,
    records: Vec<Record>,
}

impl Log {
    /// Starts an empty log in `dir`, which is created if need be.
    pub fn create(dir: &Path, id: &str, rotation: Rotation) -> std::io::Result<Self> {
        let file = open(dir, &path(dir, id, 0))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            id: id.to_string(),
            rotation,
            file: Some(file),
            generation: 0,
            oldest: 0,
            written: 0,
            records: VecDeque::new(),
            logged: 0,
        })
    }

    /// Indexes a log already on disk and carries on writing it. A torn last
    /// record, from a write a crash interrupted, is cut off.
    pub fn reopen(dir: &Path, id: &str, rotation: Rotation) -> std::io::Result<Self> {
        let mut generations: Vec<u32> = std::fs::read_dir(dir)?
            .flatten()
            .filter_map(|file| generation_of(&file.file_name().into_string().ok()?, id))
            .collect();
        generations.sort_unstable();
        let mut log = Self {
            dir: dir.to_path_buf(),
            id: id.to_string(),
            rotation,
            file: None,
            generation: generations.last().copied().unwrap_or(0),
            oldest: generations.first().copied().unwrap_or(0),
            written: 0,
            records: VecDeque::new(),
            logged: 0,
        };
        for generation in generations {
            let file = std::fs::File::open(path(dir, id, generation))?;
            let end = file.metadata()?.len();
            let mut pos = 0u64;
            let mut header = [0u8; HEADER as usize];
            while pos + HEADER <= end && file.read_exact_at(&mut header, pos).is_ok() {
                let at = u64::from_le_bytes(header[1..9].try_into().expect("8 bytes"));
                let len = u32::from_le_bytes(header[9..].try_into().expect("4 bytes"));
                if pos + HEADER + u64::from(len) > end {
                    // Torn: cut it off so the next write lands where it began.
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(path(dir, id, generation))?;
                    file.set_len(pos)?;
                    break;
                }
                let record = Record {
                    at,
                    generation,
                    pos,
                    kind: header[0],
                    len,
                };
                log.logged = log.logged.max(at + record.output_len());
                pos += HEADER + u64::from(len);
                log.records.push_back(record);
            }
            if generation == log.generation {
                log.written = pos;
            }
        }
        log.file = Some(open_append(&path(dir, id, log.generation))?);
        Ok(log)
    }

    /// Every command a log in `dir` is kept for.
    pub fn ids_in(dir: &Path) -> Vec<String> {
        let mut ids: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|file| {
                let name = file.file_name().into_string().ok()?;
                let (id, rest) = name.split_once('.')?;
                rest.strip_suffix(".log")?.parse::<u32>().ok()?;
                Some(id.to_string())
            })
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    pub fn rotation(&self) -> Rotation {
        self.rotation
    }

    /// Output offset the log holds up to.
    pub fn logged(&self) -> u64 {
        self.logged
    }

    /// Where the oldest output still held starts.
    pub fn kept_from(&self) -> u64 {
        self.records.front().map_or(self.logged, |record| record.at)
    }

    /// Whether the command's exit is in the log.
    pub fn has_exit(&self) -> bool {
        self.records.back().is_some_and(Record::is_exit)
    }

    /// Output bytes the log holds: everything from its oldest record on, less
    /// any gaps.
    pub fn held_bytes(&self) -> u64 {
        self.records.iter().map(Record::output_len).sum()
    }

    pub fn bytes_on_disk(&self) -> u64 {
        (self.oldest..=self.generation)
            .filter_map(|generation| std::fs::metadata(path(&self.dir, &self.id, generation)).ok())
            .map(|meta| meta.len())
            .sum()
    }

    /// The log's files, for copying it whole: names within its directory.
    pub fn file_names(&self) -> Vec<String> {
        (self.oldest..=self.generation)
            .map(|generation| format!("{}.{generation}.log", self.id))
            .filter(|name| self.dir.join(name).exists())
            .collect()
    }

    pub fn remove(&self) {
        for generation in self.oldest..=self.generation {
            let _ = std::fs::remove_file(path(&self.dir, &self.id, generation));
        }
    }

    /// Appends `frame`, whose first byte is at output offset `at`.
    ///
    /// Output the log already holds is cut from the front of the frame, so a
    /// frame sent twice, as one is around a reconnect, is written once. A
    /// frame that starts past the end leaves a gap for readers to be told of.
    /// Returns whether anything was written.
    pub fn append(&mut self, at: u64, frame: &Frame) -> bool {
        let (at, frame) = if at < self.logged && !frame.is_empty() {
            let skip = (self.logged - at) as usize;
            if skip >= frame.len() {
                return false;
            }
            (self.logged, frame.tail(skip))
        } else {
            (at, frame.clone())
        };
        if matches!(frame, Frame::Exit { .. }) && self.has_exit() {
            return false;
        }
        let (kind, payload) = frame.encode();
        let size = HEADER + payload.len() as u64;
        if self.file.is_some()
            && self.rotation.max_bytes > 0
            && self.written > 0
            && self.written + size > self.rotation.max_bytes
            && self.rotate().is_err()
        {
            self.file = None;
        }
        let Some(file) = self.file.as_mut() else {
            return false;
        };
        let mut record = Vec::with_capacity(size as usize);
        record.push(kind);
        record.extend_from_slice(&at.to_le_bytes());
        record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        record.extend_from_slice(&payload);
        if file.write_all(&record).is_err() {
            self.file = None;
            return false;
        }
        let record = Record {
            at,
            generation: self.generation,
            pos: self.written,
            kind,
            len: payload.len() as u32,
        };
        self.written += size;
        self.logged = self.logged.max(at + record.output_len());
        self.records.push_back(record);
        true
    }

    /// Stops writing, closing the file. What is logged stays readable.
    pub fn close(&mut self) {
        self.file = None;
    }

    /// Starts the next file, and drops the oldest past `max_files`.
    fn rotate(&mut self) -> std::io::Result<()> {
        let next = self.generation + 1;
        self.file = Some(open(&self.dir, &path(&self.dir, &self.id, next))?);
        self.generation = next;
        self.written = 0;
        let keep = self.rotation.max_files.max(1);
        while self.generation - self.oldest + 1 > keep {
            let _ = std::fs::remove_file(path(&self.dir, &self.id, self.oldest));
            while self
                .records
                .front()
                .is_some_and(|record| record.generation == self.oldest)
            {
                self.records.pop_front();
            }
            self.oldest += 1;
        }
        Ok(())
    }

    /// Plans a read from output offset `offset` on.
    pub fn plan(&self, offset: u64) -> Plan {
        let kept_from = self.kept_from();
        Plan {
            dir: self.dir.clone(),
            id: self.id.clone(),
            offset: offset.max(kept_from),
            rotated: kept_from.min(self.logged).saturating_sub(offset),
            records: self
                .records
                .iter()
                .skip_while(|record| !record.is_exit() && record.at + record.output_len() <= offset)
                .copied()
                .collect(),
        }
    }
}

impl Plan {
    /// Where the read ends: the offset a follower picks up from.
    pub fn end(&self) -> u64 {
        self.records.last().map_or(self.offset, |record| {
            (record.at + record.output_len()).max(self.offset)
        })
    }

    /// Reads what the plan names, `budget` payload bytes at a time, calling
    /// `each` with what was read until it returns false. Blocking.
    pub fn read(
        &self,
        budget: usize,
        mut each: impl FnMut(Vec<Replayed>) -> bool,
    ) -> std::io::Result<()> {
        let mut out = Vec::new();
        if self.rotated > 0 {
            out.push(Replayed::Lost(self.rotated));
        }
        let mut expected = self.offset;
        let mut open_file: Option<(u32, std::fs::File)> = None;
        let mut batch_bytes = 0usize;
        for record in &self.records {
            // A jump in offsets is output the log never received.
            if record.at > expected {
                out.push(Replayed::Lost(record.at - expected));
                expected = record.at;
            }
            let skip = expected
                .saturating_sub(record.at)
                .min(u64::from(record.len)) as usize;
            if open_file
                .as_ref()
                .is_none_or(|(generation, _)| *generation != record.generation)
            {
                match std::fs::File::open(path(&self.dir, &self.id, record.generation)) {
                    Ok(file) => open_file = Some((record.generation, file)),
                    // Rotated away since the plan was made.
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        open_file = None;
                        let lost = record.output_len().saturating_sub(skip as u64);
                        if lost > 0 {
                            out.push(Replayed::Lost(lost));
                        }
                        expected = expected.max(record.at + record.output_len());
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            }
            let Some((_, file)) = &open_file else {
                continue;
            };
            let mut payload = vec![0u8; record.len as usize];
            file.read_exact_at(&mut payload, record.pos + HEADER)?;
            if !record.is_exit() {
                payload.drain(..skip);
            }
            batch_bytes += payload.len();
            out.push(Replayed::Frame(Frame::decode(record.kind, payload)));
            expected = expected.max(record.at + record.output_len());
            if batch_bytes >= budget {
                if !each(std::mem::take(&mut out)) {
                    return Ok(());
                }
                batch_bytes = 0;
            }
        }
        if !out.is_empty() {
            each(out);
        }
        Ok(())
    }
}

/// A size as Docker writes one: bytes, or a number with k, m or g.
pub fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim().to_ascii_lowercase();
    let (digits, scale) = match text.strip_suffix(['k', 'm', 'g']) {
        Some(digits) => (
            digits,
            match text.chars().last() {
                Some('k') => 1u64 << 10,
                Some('m') => 1 << 20,
                _ => 1 << 30,
            },
        ),
        None => (text.as_str(), 1),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not a size like 20m"))?;
    match value.checked_mul(scale) {
        Some(0) | None => Err(format!("{text:?} is not a size above zero")),
        Some(bytes) => Ok(bytes),
    }
}

fn path(dir: &Path, id: &str, generation: u32) -> PathBuf {
    dir.join(format!("{id}.{generation}.log"))
}

/// The generation a file named `name` holds for command `id`.
fn generation_of(name: &str, id: &str) -> Option<u32> {
    name.strip_prefix(id)?
        .strip_prefix('.')?
        .strip_suffix(".log")?
        .parse()
        .ok()
}

/// Creates a new log file, root's alone: a command's output is no more every
/// account's to read than its process is.
fn open(dir: &Path, path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "burrow-cmdlog-{tag}-{}-{}",
            std::process::id(),
            crate::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn replay(log: &Log, offset: u64) -> Vec<Replayed> {
        let mut out = Vec::new();
        log.plan(offset)
            .read(usize::MAX, |items| {
                out.extend(items);
                true
            })
            .unwrap();
        out
    }

    fn stdout(items: &[Replayed]) -> Vec<u8> {
        items
            .iter()
            .filter_map(|item| match item {
                Replayed::Frame(Frame::Stdout(bytes)) => Some(bytes.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[test]
    fn every_byte_is_kept_and_read_back_from_any_offset() {
        let dir = dir("all");
        let mut log = Log::create(&dir, "cmd_1", Rotation::default()).unwrap();
        log.append(0, &Frame::Stdout(b"hello ".to_vec()));
        log.append(6, &Frame::Stdout(b"world".to_vec()));
        log.append(11, &Frame::Exit { code: 3, signal: 0 });
        assert_eq!(stdout(&replay(&log, 0)), b"hello world");
        assert_eq!(stdout(&replay(&log, 8)), b"rld");
        assert!(log.has_exit());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A frame resent around a reconnect is written once, and only its new
    /// part if it overlaps.
    #[test]
    fn output_already_logged_is_not_written_twice() {
        let dir = dir("dup");
        let mut log = Log::create(&dir, "cmd_1", Rotation::default()).unwrap();
        log.append(0, &Frame::Stdout(b"abcd".to_vec()));
        assert!(!log.append(0, &Frame::Stdout(b"abcd".to_vec())));
        assert!(log.append(2, &Frame::Stdout(b"cdef".to_vec())));
        assert_eq!(stdout(&replay(&log, 0)), b"abcdef");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Output the log never received is a gap, reported where it falls.
    #[test]
    fn a_gap_is_reported_by_how_much() {
        let dir = dir("gap");
        let mut log = Log::create(&dir, "cmd_1", Rotation::default()).unwrap();
        log.append(0, &Frame::Stdout(b"kept".to_vec()));
        log.append(10, &Frame::Stdout(b"later".to_vec()));
        let items = replay(&log, 0);
        assert!(matches!(items[1], Replayed::Lost(6)));
        assert_eq!(stdout(&items), b"keptlater");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rotating_log_drops_its_oldest_file() {
        let dir = dir("rotate");
        let rotation = Rotation {
            max_bytes: 30,
            max_files: 2,
        };
        let mut log = Log::create(&dir, "cmd_1", rotation).unwrap();
        for (n, chunk) in [b"aaaaaaaa", b"bbbbbbbb", b"cccccccc", b"dddddddd"]
            .iter()
            .enumerate()
        {
            log.append(n as u64 * 8, &Frame::Stdout(chunk.to_vec()));
        }
        let items = replay(&log, 0);
        assert!(matches!(items.first(), Some(Replayed::Lost(16))));
        assert_eq!(stdout(&items), b"ccccccccdddddddd");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node that restarts finds its logs where they were, offsets and all,
    /// and goes on writing them.
    #[test]
    fn a_log_reopens_to_the_same_index() {
        let dir = dir("reopen");
        let mut log = Log::create(&dir, "cmd_1", Rotation::default()).unwrap();
        log.append(0, &Frame::Stdout(b"one".to_vec()));
        log.append(9, &Frame::Stderr(b"two".to_vec()));
        drop(log);
        assert_eq!(Log::ids_in(&dir), ["cmd_1"]);
        let mut log = Log::reopen(&dir, "cmd_1", Rotation::default()).unwrap();
        assert_eq!(log.logged(), 12);
        log.append(12, &Frame::Exit { code: 0, signal: 0 });
        let items = replay(&log, 0);
        assert!(matches!(items[1], Replayed::Lost(6)));
        assert!(log.has_exit());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
