//! The registry of commands the agent has run.
//!
//! A command used to live only on the Exec stream that started it: a client
//! that went away took the only handle on it with it. Here every command gets
//! an id, a log of everything it has printed and a broadcast of what it
//! produces from now on, so another process can list it, follow it, feed it
//! and signal it long after the stream that started it is gone.
//!
//! Logs work the way Docker's do. They are on the guest's own disk, not in
//! memory, and kept for as long as the command is: nothing is evicted by count
//! or age, and a finished command and its log go when PruneCommands removes
//! them or the VM boots afresh. By default a log is unbounded and holds every
//! byte; a command started with a size limit rotates instead, as Docker's
//! `max-size` and `max-file` do, dropping its oldest file.
//!
//! Output is counted by offset, stdout and stderr bytes together from the
//! command's start, so an attacher that comes back says where it got to and
//! is sent exactly what followed. Output it cannot have is reported by how
//! much rather than skipped in silence: what rotation dropped, and anything
//! after a failed write, a full disk being the likely one, which stops the log
//! while the command carries on.
//!
//! A command's input is a channel any stream may feed, so stdin does not die
//! with the stream that started it.

#![allow(clippy::result_large_err)]

use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{broadcast, mpsc};
use tonic::Status;

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::exec_output::Output;

/// Where command logs are kept. Root's alone: a command's output is no more
/// every user's to read than its process is.
const LOG_DIR: &str = "/var/lib/burrow/commands";
/// Frames a live attacher may fall behind by before it catches up from the
/// log instead.
const LIVE_BACKLOG: usize = 256;
const ATTACH_CAPACITY: usize = 64;
/// How much of the log an attacher reads at a time while catching up.
const REPLAY_CHUNK: usize = 256 * 1024;
/// A record's header: its kind and its payload's length.
const HEADER: u64 = 5;

/// One piece of a command's output, logged and broadcast alike.
#[derive(Clone)]
pub enum Frame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit { code: i32, signal: i32 },
}

impl Frame {
    fn len(&self) -> usize {
        match self {
            Frame::Stdout(bytes) | Frame::Stderr(bytes) => bytes.len(),
            Frame::Exit { .. } => 0,
        }
    }

    /// What goes on the wire for this frame: an exit a signal caused is
    /// reported as the signal and then the code.
    pub fn outputs(&self) -> Vec<Output> {
        match self {
            Frame::Stdout(bytes) => vec![Output::Stdout(bytes.clone())],
            Frame::Stderr(bytes) => vec![Output::Stderr(bytes.clone())],
            Frame::Exit { code, signal: 0 } => vec![Output::ExitCode(*code)],
            Frame::Exit { code, signal } => {
                vec![Output::ExitSignal(*signal), Output::ExitCode(*code)]
            }
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

/// A frame and the offset its first byte sits at.
type Placed = (u64, Frame);

/// Where one record sits in a log.
#[derive(Clone, Copy)]
struct Record {
    /// Output offset of its first byte.
    at: u64,
    /// Which of the log's files holds it.
    generation: u32,
    /// Position of its header in that file.
    pos: u64,
    kind: u8,
    len: u32,
}

impl Record {
    fn output_len(&self) -> u64 {
        if self.kind == 2 {
            0
        } else {
            u64::from(self.len)
        }
    }
}

/// How a command's log is bounded, as Docker's `max-size` and `max-file`.
#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct Rotation {
    /// Bytes per file before a new one is started; 0 never rotates.
    pub max_bytes: u64,
    /// Files kept once rotating, at least 1.
    pub max_files: u32,
}

/// A command's output on disk, in numbered files, and an index of it.
///
/// Files are numbered rather than renamed on rotation, so a reader that has
/// one open is never handed a different file under the same name.
struct Log {
    id: String,
    rotation: Rotation,
    /// Gone once a write has failed: the log stops there for good, so what it
    /// holds is always one unbroken run.
    file: Option<std::fs::File>,
    /// The file being written, and the oldest still kept.
    generation: u32,
    oldest: u32,
    written: u64,
    records: VecDeque<Record>,
    /// Output offset the log holds up to.
    logged: u64,
}

fn log_path(id: &str, generation: u32) -> PathBuf {
    Path::new(LOG_DIR).join(format!("{id}.{generation}.log"))
}

impl Log {
    fn create(id: &str, rotation: Rotation) -> Self {
        let file = open_log(&log_path(id, 0));
        if let Err(err) = &file {
            tracing::warn!(%err, command = id, "command output will not be kept");
        }
        Self {
            id: id.to_string(),
            rotation,
            file: file.ok(),
            generation: 0,
            oldest: 0,
            written: 0,
            records: VecDeque::new(),
            logged: 0,
        }
    }

    /// Indexes a finished command's log already on disk, as an agent picking
    /// up from the one it replaced does. `kept_from` is where the oldest file
    /// starts in the output. A torn last record is cut off.
    fn reopen(id: &str, rotation: Rotation, kept_from: u64) -> Self {
        let mut log = Self {
            id: id.to_string(),
            rotation,
            file: None,
            generation: 0,
            oldest: 0,
            written: 0,
            records: VecDeque::new(),
            logged: kept_from,
        };
        let mut generations: Vec<u32> = std::fs::read_dir(LOG_DIR)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|file| generation_of(&file.file_name().into_string().ok()?, id))
            .collect();
        generations.sort_unstable();
        log.oldest = generations.first().copied().unwrap_or(0);
        for generation in generations {
            let Ok(file) = std::fs::File::open(log_path(id, generation)) else {
                continue;
            };
            let end = file.metadata().map(|m| m.len()).unwrap_or(0);
            let mut pos = 0u64;
            let mut header = [0u8; HEADER as usize];
            while pos + HEADER <= end && file.read_exact_at(&mut header, pos).is_ok() {
                let len = u32::from_le_bytes(header[1..].try_into().expect("4 bytes"));
                if pos + HEADER + u64::from(len) > end {
                    break;
                }
                let record = Record {
                    at: log.logged,
                    generation,
                    pos,
                    kind: header[0],
                    len,
                };
                log.logged += record.output_len();
                pos += HEADER + u64::from(len);
                log.records.push_back(record);
            }
            log.generation = generation;
        }
        log
    }

    /// Where the oldest output still held starts.
    fn kept_from(&self) -> u64 {
        self.records.front().map_or(self.logged, |record| record.at)
    }

    fn bytes_on_disk(&self) -> u64 {
        (self.oldest..=self.generation)
            .filter_map(|generation| std::fs::metadata(log_path(&self.id, generation)).ok())
            .map(|meta| meta.len())
            .sum()
    }

    fn remove(&self) {
        for generation in self.oldest..=self.generation {
            let _ = std::fs::remove_file(log_path(&self.id, generation));
        }
    }

    /// Starts the next file, and drops the oldest past `max_files`.
    fn rotate(&mut self) -> std::io::Result<()> {
        let next = self.generation + 1;
        self.file = Some(open_log(&log_path(&self.id, next))?);
        self.generation = next;
        self.written = 0;
        let keep = self.rotation.max_files.max(1);
        while self.generation - self.oldest + 1 > keep {
            let _ = std::fs::remove_file(log_path(&self.id, self.oldest));
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

    fn append(&mut self, at: u64, frame: &Frame) {
        let (kind, payload) = frame.encode();
        let size = HEADER + payload.len() as u64;
        if self.file.is_some()
            && self.rotation.max_bytes > 0
            && self.written > 0
            && self.written + size > self.rotation.max_bytes
            && let Err(err) = self.rotate()
        {
            tracing::warn!(%err, command = self.id, "stopped keeping command output");
            self.file = None;
        }
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let mut record = Vec::with_capacity(size as usize);
        record.push(kind);
        record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        record.extend_from_slice(&payload);
        if let Err(err) = file.write_all(&record) {
            tracing::warn!(%err, command = self.id, "stopped keeping command output");
            self.file = None;
            return;
        }
        let record = Record {
            at,
            generation: self.generation,
            pos: self.written,
            kind,
            len: payload.len() as u32,
        };
        self.written += size;
        self.logged = at + record.output_len();
        self.records.push_back(record);
    }
}

/// The generation a log file named `name` holds for command `id`.
fn generation_of(name: &str, id: &str) -> Option<u32> {
    name.strip_prefix(id)?
        .strip_prefix('.')?
        .strip_suffix(".log")?
        .parse()
        .ok()
}

fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(LOG_DIR)?;
    std::fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

struct Entry {
    id: String,
    cmd: Vec<String>,
    user: String,
    pid: i32,
    started_at_ms: i64,
    ended_at_ms: i64,
    exit_code: Option<i32>,
    exit_signal: i32,
    log: Log,
    /// Output produced in all, which is where the next frame starts.
    produced: u64,
    live: broadcast::Sender<Placed>,
    /// Feeds the command's stdin, terminal and signals. Gone once it exits.
    input: Option<mpsc::Sender<guestpb::ExecInput>>,
}

/// What an attacher at some offset is owed, read under the entry's lock and
/// then sent without it.
struct CatchUp {
    id: String,
    /// Output from the offset on that rotation has already dropped.
    rotated: u64,
    /// Records holding output at or past the offset, the first possibly only
    /// in part.
    records: Vec<Record>,
    offset: u64,
    /// Output produced past both the offset and the log.
    unrecorded: u64,
    /// The exit, when the command has one the log does not.
    exit: Option<Frame>,
    live: broadcast::Receiver<Placed>,
    /// Where the live feed picks up.
    end: u64,
    is_finished: bool,
}

impl Entry {
    fn new(id: String, cmd: Vec<String>, user: String, pid: i32, log: Log) -> Self {
        Self {
            id,
            cmd,
            user,
            pid,
            started_at_ms: now_ms(),
            ended_at_ms: 0,
            exit_code: None,
            exit_signal: 0,
            produced: log.logged,
            log,
            live: broadcast::channel(LIVE_BACKLOG).0,
            input: None,
        }
    }

    fn info(&self) -> guestpb::CommandInfo {
        guestpb::CommandInfo {
            command_id: self.id.clone(),
            cmd: self.cmd.clone(),
            user: self.user.clone(),
            state: if self.exit_code.is_some() {
                "exited".into()
            } else {
                "running".into()
            },
            exit_code: self.exit_code.unwrap_or_default(),
            started_at_unix_ms: self.started_at_ms,
            ended_at_unix_ms: self.ended_at_ms,
            buffered_bytes: self.log.logged - self.log.kept_from(),
            exit_signal: self.exit_signal,
            output_bytes: self.produced,
        }
    }

    /// Logs a frame at the end of the output, returning where it starts.
    fn push(&mut self, frame: &Frame) -> u64 {
        let at = self.produced;
        self.produced += frame.len() as u64;
        self.log.append(at, frame);
        at
    }

    /// Plans an attacher's catch-up from `offset`, subscribing to what comes
    /// after under the same lock, so nothing produced in between is either
    /// missed or sent twice.
    fn catch_up(&self, offset: u64) -> CatchUp {
        let records: Vec<Record> = self
            .log
            .records
            .iter()
            .skip_while(|record| record.at + record.output_len() <= offset && record.kind != 2)
            .copied()
            .collect();
        let has_exit = records.iter().any(|record| record.kind == 2);
        let kept_from = self.log.kept_from();
        CatchUp {
            id: self.id.clone(),
            rotated: kept_from.min(self.log.logged).saturating_sub(offset),
            records,
            offset: offset.max(kept_from),
            unrecorded: self.produced.saturating_sub(offset.max(self.log.logged)),
            exit: match self.exit_code {
                Some(code) if !has_exit => Some(Frame::Exit {
                    code,
                    signal: self.exit_signal,
                }),
                _ => None,
            },
            live: self.live.subscribe(),
            end: self.produced,
            is_finished: self.exit_code.is_some(),
        }
    }
}

#[derive(Default)]
struct Registry {
    /// Insertion order, which is the order finished commands are evicted in.
    order: VecDeque<String>,
    entries: HashMap<String, Arc<Mutex<Entry>>>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_id() -> String {
    format!("cmd_{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

/// A registered command, held by the tasks pumping its output.
#[derive(Clone)]
pub struct Handle {
    id: String,
    entry: Arc<Mutex<Entry>>,
}

impl Handle {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Logs a frame and hands it to whoever is attached.
    pub fn record(&self, frame: Frame) {
        let mut entry = self.entry.lock().unwrap();
        let at = entry.push(&frame);
        // An error only means nobody is attached right now, which is the
        // ordinary case: the log above is what a later attacher reads.
        let _ = entry.live.send((at, frame));
    }

    /// Where the command's input goes, for any stream that feeds it.
    pub fn set_input(&self, input: mpsc::Sender<guestpb::ExecInput>) {
        self.entry.lock().unwrap().input = Some(input);
    }

    /// Records the exit status and marks the command finished.
    pub fn finish(&self, code: i32, signal: i32) {
        {
            let mut entry = self.entry.lock().unwrap();
            entry.exit_code = Some(code);
            entry.exit_signal = signal;
            entry.ended_at_ms = now_ms();
            entry.input = None;
            let frame = Frame::Exit { code, signal };
            let at = entry.push(&frame);
            // Nothing more is written; the descriptor is not held for the
            // rest of the command's stay in the registry.
            entry.log.file = None;
            let _ = entry.live.send((at, frame));
        }
    }
}

/// Registers a command that has just been spawned.
pub fn register(cmd: Vec<String>, user: String, pid: i32, rotation: Rotation) -> Handle {
    let id = next_id();
    let log = Log::create(&id, rotation);
    let entry = Arc::new(Mutex::new(Entry::new(id.clone(), cmd, user, pid, log)));
    let mut registry = registry().lock().unwrap();
    registry.order.push_back(id.clone());
    registry.entries.insert(id.clone(), Arc::clone(&entry));
    Handle { id, entry }
}

/// Removes every finished command and its log, returning how many there
/// were and the bytes freed.
pub fn prune() -> guestpb::PruneCommandsResponse {
    let mut registry = registry().lock().unwrap();
    let finished: Vec<String> = registry
        .order
        .iter()
        .filter(|id| registry.entries[*id].lock().unwrap().exit_code.is_some())
        .cloned()
        .collect();
    let mut freed_bytes = 0;
    for id in &finished {
        if let Some(entry) = registry.entries.remove(id) {
            let entry = entry.lock().unwrap();
            freed_bytes += entry.log.bytes_on_disk();
            entry.log.remove();
        }
    }
    let Registry { order, entries } = &mut *registry;
    order.retain(|id| entries.contains_key(id));
    guestpb::PruneCommandsResponse {
        removed: finished.len() as u32,
        freed_bytes,
    }
}

fn entry(id: &str) -> Result<Arc<Mutex<Entry>>, Status> {
    registry()
        .lock()
        .unwrap()
        .entries
        .get(id)
        .cloned()
        .ok_or_else(|| Status::not_found(format!("no such command: {id}")))
}

/// Whether any command is still running. An upgrade re-executes the agent,
/// and a running command's pipes and pty would not survive that.
pub fn has_running() -> bool {
    registry()
        .lock()
        .unwrap()
        .entries
        .values()
        .any(|entry| entry.lock().unwrap().exit_code.is_none())
}

pub fn list() -> guestpb::ListCommandsResponse {
    let registry = registry().lock().unwrap();
    guestpb::ListCommandsResponse {
        commands: registry
            .order
            .iter()
            .filter_map(|id| registry.entries.get(id))
            .map(|entry| entry.lock().unwrap().info())
            .collect(),
    }
}

pub fn get(id: &str) -> Result<guestpb::CommandInfo, Status> {
    Ok(entry(id)?.lock().unwrap().info())
}

/// Signals a command's process group: the command and whatever it started.
///
/// A command that has exited may have left children in its group, and they
/// are signalled too. That is safe because a group's id cannot be handed to
/// another process while anything is still in the group. With nothing left
/// in it, the command is reported as already exited.
pub fn signal(id: &str, signal: i32) -> Result<(), Status> {
    let entry = entry(id)?;
    let entry = entry.lock().unwrap();
    // 0 is the api's "whatever kills it": a caller who did not choose a signal
    // wants the command gone, not a no-op probe.
    let signal = if signal == 0 {
        nix::sys::signal::Signal::SIGKILL
    } else {
        nix::sys::signal::Signal::try_from(signal)
            .map_err(|_| Status::invalid_argument(format!("unknown signal {signal}")))?
    };
    // A pid of 1 or less names no group of the command's own: 1 is this
    // agent, and the rest would reach far more than one command.
    if entry.pid <= 1 {
        return Err(Status::failed_precondition(format!(
            "command {id} has no process to signal"
        )));
    }
    match nix::sys::signal::killpg(nix::unistd::Pid::from_raw(entry.pid), Some(signal)) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) if entry.exit_code.is_some() => Err(
            Status::failed_precondition(format!("command {id} has already exited")),
        ),
        Err(err) => Err(Status::internal(format!("signal {id}: {err}"))),
    }
}

/// Where a running command's input goes, for an attacher to feed.
pub fn input(id: &str) -> Result<mpsc::Sender<guestpb::ExecInput>, Status> {
    entry(id)?
        .lock()
        .unwrap()
        .input
        .clone()
        .ok_or_else(|| Status::failed_precondition(format!("command {id} has exited")))
}

/// Sends what the log holds from `offset` on, then follows the command live.
///
/// An attacher that falls behind the live feed catches up from the log again
/// rather than skipping what it missed. Output the log does not have is
/// reported by how much. A command that has already exited replays to its exit
/// status, and the stream then closes.
pub fn attach(
    id: &str,
    offset: u64,
) -> Result<mpsc::Receiver<Result<guestpb::ExecOutput, Status>>, Status> {
    let entry = entry(id)?;
    let (tx, rx) = mpsc::channel(ATTACH_CAPACITY);
    tokio::spawn(async move {
        let mut offset = offset;
        loop {
            let held = Arc::clone(&entry);
            let Ok(plan) =
                tokio::task::spawn_blocking(move || held.lock().unwrap().catch_up(offset)).await
            else {
                return;
            };
            let CatchUp {
                id,
                rotated,
                records,
                offset: from,
                unrecorded,
                exit,
                mut live,
                end,
                is_finished,
            } = plan;
            if rotated > 0 && tx.send(Ok(wrap(Output::LostBytes(rotated)))).await.is_err() {
                return;
            }
            if send_logged(&tx, id, records, from).await.is_err() {
                return;
            }
            if unrecorded > 0
                && tx
                    .send(Ok(wrap(Output::LostBytes(unrecorded))))
                    .await
                    .is_err()
            {
                return;
            }
            for output in exit.iter().flat_map(Frame::outputs) {
                if tx.send(Ok(wrap(output))).await.is_err() {
                    return;
                }
            }
            if is_finished {
                return;
            }
            offset = end;
            loop {
                match live.recv().await {
                    Ok((at, frame)) => {
                        let exited = matches!(frame, Frame::Exit { .. });
                        offset = at + frame.len() as u64;
                        for output in frame.outputs() {
                            if tx.send(Ok(wrap(output))).await.is_err() {
                                return;
                            }
                        }
                        if exited {
                            return;
                        }
                    }
                    // The attacher read slower than the command produced:
                    // back to the log from where it had got to.
                    Err(broadcast::error::RecvError::Lagged(_)) => break,
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    });
    Ok(rx)
}

/// Streams logged records from `offset` on, a chunk at a time, so a long log
/// is never read into memory whole.
async fn send_logged(
    tx: &mpsc::Sender<Result<guestpb::ExecOutput, Status>>,
    id: String,
    records: Vec<Record>,
    offset: u64,
) -> Result<(), ()> {
    let id = Arc::new(id);
    let mut batch: Vec<Record> = Vec::new();
    let mut batch_bytes = 0usize;
    for (n, record) in records.iter().enumerate() {
        batch.push(*record);
        batch_bytes += record.len as usize;
        if batch_bytes < REPLAY_CHUNK && n + 1 < records.len() {
            continue;
        }
        let reading = std::mem::take(&mut batch);
        batch_bytes = 0;
        let id = Arc::clone(&id);
        let replayed = tokio::task::spawn_blocking(move || read_records(&id, &reading, offset))
            .await
            .map_err(|_| ())?;
        for item in replayed {
            let outputs = match item {
                Replayed::Frame(frame) => frame.outputs(),
                Replayed::Lost(bytes) => vec![Output::LostBytes(bytes)],
                Replayed::Failed(err) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("reading command log: {err}"))))
                        .await;
                    return Err(());
                }
            };
            for output in outputs {
                tx.send(Ok(wrap(output))).await.map_err(|_| ())?;
            }
        }
    }
    Ok(())
}

/// One step of a replay.
enum Replayed {
    Frame(Frame),
    /// Output whose file rotation removed between planning and reading.
    Lost(u64),
    Failed(std::io::Error),
}

/// What `records` hold, the part of any before `offset` cut off.
fn read_records(id: &str, records: &[Record], offset: u64) -> Vec<Replayed> {
    let mut out = Vec::with_capacity(records.len());
    let mut open: Option<(u32, std::fs::File)> = None;
    for record in records {
        let skip = offset.saturating_sub(record.at).min(u64::from(record.len)) as usize;
        if open
            .as_ref()
            .is_none_or(|(generation, _)| *generation != record.generation)
        {
            match std::fs::File::open(log_path(id, record.generation)) {
                Ok(file) => open = Some((record.generation, file)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    open = None;
                    out.push(Replayed::Lost(record.output_len() - skip as u64));
                    continue;
                }
                Err(err) => {
                    out.push(Replayed::Failed(err));
                    return out;
                }
            }
        }
        let Some((_, file)) = &open else { continue };
        let mut payload = vec![0u8; record.len as usize];
        if let Err(err) = file.read_exact_at(&mut payload, record.pos + HEADER) {
            out.push(Replayed::Failed(err));
            return out;
        }
        if record.kind != 2 {
            payload.drain(..skip);
        }
        out.push(Replayed::Frame(Frame::decode(record.kind, payload)));
    }
    out
}

fn wrap(output: Output) -> guestpb::ExecOutput {
    guestpb::ExecOutput {
        output: Some(output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything an attacher at `offset` would be sent, read synchronously.
    fn replay(handle: &Handle, offset: u64) -> Vec<Output> {
        let plan = handle.entry.lock().unwrap().catch_up(offset);
        let mut out = Vec::new();
        if plan.rotated > 0 {
            out.push(Output::LostBytes(plan.rotated));
        }
        for item in read_records(&plan.id, &plan.records, plan.offset) {
            match item {
                Replayed::Frame(frame) => out.extend(frame.outputs()),
                Replayed::Lost(bytes) => out.push(Output::LostBytes(bytes)),
                Replayed::Failed(err) => panic!("{err}"),
            }
        }
        if plan.unrecorded > 0 {
            out.push(Output::LostBytes(plan.unrecorded));
        }
        out.extend(plan.exit.iter().flat_map(Frame::outputs));
        out
    }

    fn stdout_of(outputs: &[Output]) -> Vec<u8> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Stdout(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// All of it, not a tail: a command that printed far more than any memory
    /// buffer would hold replays from its first byte.
    #[test]
    fn every_byte_a_command_prints_is_kept() {
        let handle = register(vec!["yes".into()], String::new(), -1, Rotation::default());
        for n in 0..64u8 {
            handle.record(Frame::Stdout(vec![n; 64 * 1024]));
        }
        handle.finish(3, 0);
        let outputs = replay(&handle, 0);
        let bytes = stdout_of(&outputs);
        assert_eq!(bytes.len(), 64 * 64 * 1024);
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[bytes.len() - 1], 63);
        assert!(matches!(outputs.last(), Some(Output::ExitCode(3))));
        let info = get(handle.id()).unwrap();
        assert_eq!(info.state, "exited");
        assert_eq!(info.output_bytes, 64 * 64 * 1024);
        assert_eq!(info.buffered_bytes, info.output_bytes);
    }

    /// An attacher coming back says how far it got and is sent only what
    /// followed, even from the middle of a frame.
    #[test]
    fn an_attach_resumes_from_its_offset() {
        let handle = register(vec!["sh".into()], String::new(), -1, Rotation::default());
        handle.record(Frame::Stdout(b"hello ".to_vec()));
        handle.record(Frame::Stderr(b"world".to_vec()));
        let outputs = replay(&handle, 8);
        assert!(matches!(outputs.as_slice(), [Output::Stderr(b)] if b == b"rld"));
    }

    /// A log that stopped, the disk having filled, still accounts for every
    /// byte: what it kept, then how much it did not.
    #[test]
    fn output_the_log_missed_is_reported_by_how_much() {
        let handle = register(vec!["yes".into()], String::new(), -1, Rotation::default());
        handle.record(Frame::Stdout(b"kept".to_vec()));
        handle.entry.lock().unwrap().log.file = None;
        handle.record(Frame::Stdout(b"missed".to_vec()));
        handle.finish(0, 0);
        let outputs = replay(&handle, 0);
        assert!(matches!(
            outputs.as_slice(),
            [Output::Stdout(b), Output::LostBytes(6), Output::ExitCode(0)] if b == b"kept"
        ));
    }

    /// A command a signal ended reports the signal, then the shell-style code.
    #[test]
    fn a_signalled_exit_names_its_signal() {
        let handle = register(vec!["sleep".into()], String::new(), -1, Rotation::default());
        handle.finish(137, 9);
        assert!(matches!(
            replay(&handle, 0).as_slice(),
            [Output::ExitSignal(9), Output::ExitCode(137)]
        ));
        assert_eq!(get(handle.id()).unwrap().exit_signal, 9);
    }

    /// The agent that replaces this one finds the log where it was and indexes
    /// it the same way.
    #[test]
    fn a_log_reopens_to_the_same_index() {
        let handle = register(vec!["sh".into()], String::new(), -1, Rotation::default());
        handle.record(Frame::Stdout(b"one".to_vec()));
        handle.record(Frame::Stderr(b"two".to_vec()));
        handle.finish(1, 0);
        let reopened = Log::reopen(handle.id(), Rotation::default(), 0);
        assert_eq!(reopened.logged, 6);
        assert_eq!(reopened.records.len(), 3);
        assert_eq!(reopened.records[1].at, 3);
    }

    /// As Docker's `max-size` and `max-file`: the oldest file goes, and an
    /// attach from the start is told exactly how much went with it.
    #[test]
    fn a_rotating_log_drops_its_oldest_file() {
        let rotation = Rotation {
            max_bytes: 16,
            max_files: 2,
        };
        let handle = register(vec!["yes".into()], String::new(), -1, rotation);
        for chunk in [b"aaaaaaaa", b"bbbbbbbb", b"cccccccc", b"dddddddd"] {
            handle.record(Frame::Stdout(chunk.to_vec()));
        }
        let outputs = replay(&handle, 0);
        assert!(matches!(outputs.first(), Some(Output::LostBytes(16))));
        assert_eq!(stdout_of(&outputs), b"ccccccccdddddddd");
        let info = get(handle.id()).unwrap();
        assert_eq!(info.output_bytes, 32);
        assert_eq!(info.buffered_bytes, 16);
    }

    /// Pruning removes what has finished, logs included, and leaves running
    /// commands alone.
    #[test]
    fn pruning_removes_finished_commands_and_their_logs() {
        let done = register(vec!["true".into()], String::new(), -1, Rotation::default());
        done.record(Frame::Stdout(b"bye".to_vec()));
        done.finish(0, 0);
        let running = register(vec!["sleep".into()], String::new(), -1, Rotation::default());
        let pruned = prune();
        assert!(pruned.removed >= 1);
        assert!(pruned.freed_bytes > 0);
        assert_eq!(get(done.id()).unwrap_err().code(), tonic::Code::NotFound);
        assert!(!log_path(done.id(), 0).exists());
        assert_eq!(get(running.id()).unwrap().state, "running");
    }

    #[test]
    fn an_unknown_command_is_not_found() {
        assert_eq!(get("cmd_nope").unwrap_err().code(), tonic::Code::NotFound);
        assert_eq!(
            signal("cmd_nope", 15).unwrap_err().code(),
            tonic::Code::NotFound
        );
    }

    /// Signalling a command that has already gone would otherwise land on
    /// whatever pid the kernel has since handed out.
    #[test]
    fn a_finished_command_is_not_signalled() {
        let handle = register(vec!["true".into()], String::new(), -1, Rotation::default());
        handle.finish(0, 0);
        assert_eq!(
            signal(handle.id(), 15).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }
}

/// A finished command as written to disk across an agent re-exec.
///
/// Only finished ones travel: a running command's pipes and pty belong to
/// the old process, which is why an upgrade refuses while one runs.
#[derive(serde::Serialize, serde::Deserialize)]
struct SavedEntry {
    id: String,
    cmd: Vec<String>,
    user: String,
    pid: i32,
    started_at_ms: i64,
    ended_at_ms: i64,
    exit_code: i32,
    /// An agent that buffered output in memory wrote it here: (0 stdout,
    /// 1 stderr, 2 exit) and the bytes or the code's LE bytes. Empty from one
    /// that logs to disk.
    #[serde(default)]
    frames: Vec<(u8, Vec<u8>)>,
    #[serde(default)]
    exit_signal: i32,
    /// Whether the command has a log on disk, from an agent that keeps one.
    #[serde(default)]
    is_logged: bool,
    #[serde(default)]
    rotation: Rotation,
    /// Where the oldest kept log file starts in the output.
    #[serde(default)]
    kept_from: u64,
    /// Output produced in all, which can be more than the log holds.
    #[serde(default)]
    produced: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    next_id: u64,
    entries: Vec<SavedEntry>,
}

/// Writes every finished command to `path`, for the agent that replaces this
/// one to read back. Ids keep counting from where they were, so an id a
/// client holds stays unique. The logs stay where they are.
pub fn save(path: &str) -> std::io::Result<()> {
    let registry = registry().lock().unwrap();
    let entries = registry
        .order
        .iter()
        .filter_map(|id| registry.entries.get(id))
        .filter_map(|entry| {
            let entry = entry.lock().unwrap();
            let exit_code = entry.exit_code?;
            Some(SavedEntry {
                id: entry.id.clone(),
                cmd: entry.cmd.clone(),
                user: entry.user.clone(),
                pid: entry.pid,
                started_at_ms: entry.started_at_ms,
                ended_at_ms: entry.ended_at_ms,
                exit_code,
                frames: Vec::new(),
                exit_signal: entry.exit_signal,
                is_logged: true,
                rotation: entry.log.rotation,
                kept_from: entry.log.kept_from(),
                produced: entry.produced,
            })
        })
        .collect();
    let saved = Saved {
        next_id: COUNTER.load(Ordering::Relaxed),
        entries,
    };
    let bytes = serde_json::to_vec(&saved).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)
}

/// Reads what [`save`] wrote and removes the file. Best effort: a table that
/// cannot be read is an empty history, not a failed upgrade.
///
/// Logs no restored command names are removed. On a fresh boot that is all
/// of them: the commands they belonged to died with the VM.
pub fn restore(path: &str) {
    let saved = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Saved>(&bytes).ok());
    let _ = std::fs::remove_file(path);
    let mut kept = std::collections::HashSet::new();
    if let Some(saved) = saved {
        COUNTER.fetch_max(saved.next_id, Ordering::Relaxed);
        let mut registry = registry().lock().unwrap();
        for saved in saved.entries {
            let log = if saved.is_logged {
                Log::reopen(&saved.id, saved.rotation, saved.kept_from)
            } else {
                // What an agent that buffered in memory handed over, written
                // out as a log of its own.
                {
                    let mut log = Log::create(&saved.id, Rotation::default());
                    let mut at = 0;
                    for (kind, bytes) in saved.frames {
                        let frame = match kind {
                            2 => Frame::Exit {
                                code: i32::from_le_bytes(bytes.try_into().unwrap_or_default()),
                                signal: saved.exit_signal,
                            },
                            kind => Frame::decode(kind, bytes),
                        };
                        log.append(at, &frame);
                        at += frame.len() as u64;
                    }
                    log.file = None;
                    log
                }
            };
            kept.insert(saved.id.clone());
            let mut entry = Entry::new(saved.id.clone(), saved.cmd, saved.user, saved.pid, log);
            entry.started_at_ms = saved.started_at_ms;
            entry.ended_at_ms = saved.ended_at_ms;
            entry.exit_code = Some(saved.exit_code);
            entry.exit_signal = saved.exit_signal;
            entry.produced = entry.produced.max(saved.produced);
            registry.order.push_back(saved.id.clone());
            registry
                .entries
                .insert(saved.id, Arc::new(Mutex::new(entry)));
        }
    }
    if let Ok(dir) = std::fs::read_dir(LOG_DIR) {
        for log in dir.flatten() {
            let name = log.file_name();
            let owner = name
                .to_str()
                .and_then(|name| name.split_once('.'))
                .map(|(id, _)| id);
            if !owner.is_some_and(|id| kept.contains(id)) {
                let _ = std::fs::remove_file(log.path());
            }
        }
    }
}
