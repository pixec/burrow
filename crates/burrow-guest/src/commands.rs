//! The registry of commands the agent has run.
//!
//! A command used to live only on the Exec stream that started it: a client
//! that went away took the only handle on it with it. Here every command gets
//! an id, an input any stream may feed and a broadcast of what it produces, so
//! another process can list it, follow it, feed it and signal it long after
//! the stream that started it is gone.
//!
//! Output is kept on the host, the way Docker keeps a container's log outside
//! the container: what the guest held, it could read, rewrite or fill its own
//! disk with. Every frame goes on the feed, which the host drains with
//! [`feed`] and acknowledges once it has written it; the guest keeps only what
//! is not yet acknowledged, up to [`FEED_BYTES`], so a host that is away for a
//! moment, across a resume say, is sent what it missed when it comes back.
//! Past that the oldest is dropped, and the host sees the jump in offsets as a
//! gap it tells readers about.
//!
//! Output is counted by offset, stdout and stderr bytes together from the
//! command's start, which is what lets a reader resume exactly.
//!
//! Nothing here is specific to an OS. How a command is signalled is: each
//! platform registers a command with a [`Signaller`] for it.

#![allow(clippy::result_large_err)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{Notify, broadcast, mpsc};
use tokio_stream::StreamExt as _;
use tonic::{Status, Streaming};

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::exec_output::Output;

/// Output held for the host before the oldest is dropped.
const FEED_BYTES: usize = 16 * 1024 * 1024;
/// What an exit costs in the feed's budget, so a run of them is bounded too.
const EXIT_BYTES: usize = 16;
/// Frames a live attacher may fall behind by before it skips ahead.
const LIVE_BACKLOG: usize = 256;
const ATTACH_CAPACITY: usize = 64;
const FEED_CAPACITY: usize = 64;

/// One piece of a command's output.
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
}

/// How a command's log is bounded, as Docker's `max-size` and `max-file`.
/// The host keeps the log; the guest only passes this on.
#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct Rotation {
    pub max_bytes: u64,
    pub max_files: u32,
}

/// A frame waiting for the host to confirm it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Pending {
    seq: u64,
    id: String,
    at: u64,
    /// 0 stdout, 1 stderr, 2 exit.
    kind: u8,
    data: Vec<u8>,
    code: i32,
    signal: i32,
    /// Set on a command's first frame.
    rotation: Option<Rotation>,
}

impl Pending {
    fn end(&self) -> u64 {
        self.at
            + if self.kind == 2 {
                0
            } else {
                self.data.len() as u64
            }
    }

    fn cost(&self) -> usize {
        self.data.len().max(EXIT_BYTES)
    }

    fn to_wire(&self) -> guestpb::FeedFrame {
        use guestpb::feed_frame::Output as Out;
        guestpb::FeedFrame {
            seq: self.seq,
            command_id: self.id.clone(),
            at: self.at,
            output: Some(match self.kind {
                0 => Out::Stdout(self.data.clone()),
                1 => Out::Stderr(self.data.clone()),
                _ => Out::Exit(guestpb::FeedExit {
                    code: self.code,
                    signal: self.signal,
                }),
            }),
            log_max_bytes: self.rotation.map_or(0, |r| r.max_bytes),
            log_max_files: self.rotation.map_or(0, |r| r.max_files),
        }
    }
}

/// Output the host has not yet confirmed writing.
#[derive(Default)]
struct FeedBuffer {
    pending: VecDeque<Pending>,
    bytes: usize,
    next_seq: u64,
}

impl FeedBuffer {
    fn push(&mut self, mut item: Pending) {
        self.next_seq += 1;
        item.seq = self.next_seq;
        self.bytes += item.cost();
        self.pending.push_back(item);
        // Exits are kept: without one the host could not tell a reader the
        // command is over.
        while self.bytes > FEED_BYTES {
            let Some(oldest) = self.pending.iter().position(|item| item.kind != 2) else {
                break;
            };
            let dropped = self.pending.remove(oldest).expect("found");
            self.bytes -= dropped.cost();
        }
    }

    /// Lets go of what the host has confirmed.
    fn release(&mut self, upto: u64) {
        while self.pending.front().is_some_and(|item| item.seq <= upto) {
            let item = self.pending.pop_front().expect("checked");
            self.bytes -= item.cost();
        }
    }

    /// Lets go of output the host already holds, by where its logs end. An
    /// exit is kept: the host writes one only once, so resending it is safe,
    /// and an offset cannot say whether it has it.
    fn release_logged(&mut self, logged: &HashMap<String, u64>) {
        self.pending.retain(|item| {
            item.kind == 2 || logged.get(&item.id).is_none_or(|&end| item.end() > end)
        });
        self.bytes = self.pending.iter().map(Pending::cost).sum();
    }
}

fn feed_buffer() -> &'static Mutex<FeedBuffer> {
    static FEED: OnceLock<Mutex<FeedBuffer>> = OnceLock::new();
    FEED.get_or_init(Mutex::default)
}

/// Wakes the feed when there is something new to send.
fn feed_wake() -> &'static Notify {
    static WAKE: OnceLock<Notify> = OnceLock::new();
    WAKE.get_or_init(Notify::new)
}

/// How a running command is signalled, by whatever the platform holds of it.
pub trait Signaller: Send + Sync {
    /// Delivers `signal`, a Linux signal number, to the command and what it
    /// started.
    fn signal(&self, signal: i32) -> Result<(), SignalError>;
}

pub enum SignalError {
    /// A signal this platform cannot deliver: why.
    Invalid(String),
    /// The command has nothing of its own a signal could be sent to.
    NoProcess,
    /// Nothing of the command is left to signal: the platform's own error.
    Gone(String),
    Failed(String),
}

/// Which feed is current. A new one replaces the last, which notices and ends.
static FEED_EPOCH: AtomicU64 = AtomicU64::new(0);

struct Entry {
    id: String,
    cmd: Vec<String>,
    user: String,
    pid: i32,
    /// What signals the command; `None` when there is nothing of its own to
    /// signal.
    signaller: Option<Arc<dyn Signaller>>,
    started_at_ms: i64,
    ended_at_ms: i64,
    exit_code: Option<i32>,
    exit_signal: i32,
    rotation: Rotation,
    /// Whether the host has been sent this command's first frame, which
    /// carries its rotation.
    is_announced: bool,
    /// Output produced in all, which is where the next frame starts.
    produced: u64,
    live: broadcast::Sender<Frame>,
    /// Feeds the command's stdin, terminal and signals. Gone once it exits.
    input: Option<mpsc::Sender<guestpb::ExecInput>>,
}

impl Entry {
    fn new(
        id: String,
        cmd: Vec<String>,
        user: String,
        pid: i32,
        signaller: Option<Arc<dyn Signaller>>,
        rotation: Rotation,
    ) -> Self {
        Self {
            id,
            cmd,
            user,
            pid,
            signaller,
            started_at_ms: now_ms(),
            ended_at_ms: 0,
            exit_code: None,
            exit_signal: 0,
            rotation,
            is_announced: false,
            produced: 0,
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
            // The host holds the output, and says how much.
            buffered_bytes: 0,
            exit_signal: self.exit_signal,
            output_bytes: self.produced,
        }
    }

    /// Puts a frame on the feed and the live broadcast.
    fn emit(&mut self, frame: Frame) {
        let at = self.produced;
        self.produced += frame.len() as u64;
        let (kind, data, code, signal) = match &frame {
            Frame::Stdout(bytes) => (0, bytes.clone(), 0, 0),
            Frame::Stderr(bytes) => (1, bytes.clone(), 0, 0),
            Frame::Exit { code, signal } => (2, Vec::new(), *code, *signal),
        };
        let rotation = (!self.is_announced).then_some(self.rotation);
        self.is_announced = true;
        feed_buffer().lock().unwrap().push(Pending {
            seq: 0,
            id: self.id.clone(),
            at,
            kind,
            data,
            code,
            signal,
            rotation,
        });
        feed_wake().notify_waiters();
        // An error only means nobody is attached right now, which is the
        // ordinary case: the host's log is what a later reader reads.
        let _ = self.live.send(frame);
    }
}

#[derive(Default)]
struct Registry {
    /// Insertion order, which is the order commands are listed in.
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

    /// Sends a frame on to the host and to whoever is attached.
    pub fn record(&self, frame: Frame) {
        self.entry.lock().unwrap().emit(frame);
    }

    /// Output produced so far.
    pub fn produced(&self) -> u64 {
        self.entry.lock().unwrap().produced
    }

    /// Where the command's input goes, for any stream that feeds it.
    pub fn set_input(&self, input: mpsc::Sender<guestpb::ExecInput>) {
        self.entry.lock().unwrap().input = Some(input);
    }

    /// Records the exit status and marks the command finished.
    pub fn finish(&self, code: i32, signal: i32) {
        let mut entry = self.entry.lock().unwrap();
        entry.exit_code = Some(code);
        entry.exit_signal = signal;
        entry.ended_at_ms = now_ms();
        entry.input = None;
        entry.emit(Frame::Exit { code, signal });
    }
}

/// Registers a command that has just been spawned.
pub fn register(
    cmd: Vec<String>,
    user: String,
    pid: i32,
    signaller: Option<Arc<dyn Signaller>>,
    rotation: Rotation,
) -> Handle {
    let id = next_id();
    let entry = Arc::new(Mutex::new(Entry::new(
        id.clone(),
        cmd,
        user,
        pid,
        signaller,
        rotation,
    )));
    let mut registry = registry().lock().unwrap();
    registry.order.push_back(id.clone());
    registry.entries.insert(id.clone(), Arc::clone(&entry));
    Handle { id, entry }
}

/// Removes every finished command, returning which. The host removes their
/// logs, which are its to free.
pub fn prune() -> guestpb::PruneCommandsResponse {
    let mut registry = registry().lock().unwrap();
    let finished: Vec<String> = registry
        .order
        .iter()
        .filter(|id| registry.entries[*id].lock().unwrap().exit_code.is_some())
        .cloned()
        .collect();
    for id in &finished {
        registry.entries.remove(id);
    }
    let Registry { order, entries } = &mut *registry;
    order.retain(|id| entries.contains_key(id));
    guestpb::PruneCommandsResponse {
        removed: finished.len() as u32,
        freed_bytes: 0,
        command_ids: finished,
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

/// Whether any command is still running. An upgrade replaces the agent's
/// process, and a running command's pipes and terminal would not survive that.
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

/// Signals a command and whatever it started, through its [`Signaller`].
///
/// A command that has exited may have left processes behind, and they are
/// signalled too. With nothing left, the command is reported as already
/// exited.
pub fn signal(id: &str, signal: i32) -> Result<(), Status> {
    let entry = entry(id)?;
    let entry = entry.lock().unwrap();
    // 0 is the api's "whatever kills it": a caller who did not choose a signal
    // wants the command gone, not a no-op probe. SIGKILL's number.
    let signal = if signal == 0 { 9 } else { signal };
    let outcome = match &entry.signaller {
        Some(signaller) => signaller.signal(signal),
        None => Err(SignalError::NoProcess),
    };
    match outcome {
        Ok(()) => Ok(()),
        Err(SignalError::NoProcess) => Err(Status::failed_precondition(format!(
            "command {id} has no process to signal"
        ))),
        Err(SignalError::Invalid(why)) => Err(Status::invalid_argument(why)),
        Err(SignalError::Gone(_)) if entry.exit_code.is_some() => Err(Status::failed_precondition(
            format!("command {id} has already exited"),
        )),
        Err(SignalError::Gone(err) | SignalError::Failed(err)) => {
            Err(Status::internal(format!("signal {id}: {err}")))
        }
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

/// Follows a command live from now on, ending at its exit. What it printed
/// before is the host's to replay, from its log.
pub fn attach(id: &str) -> Result<mpsc::Receiver<Result<guestpb::ExecOutput, Status>>, Status> {
    let entry = entry(id)?;
    let (mut live, exit) = {
        let held = entry.lock().unwrap();
        (
            held.live.subscribe(),
            held.exit_code.map(|code| Frame::Exit {
                code,
                signal: held.exit_signal,
            }),
        )
    };
    let (tx, rx) = mpsc::channel(ATTACH_CAPACITY);
    tokio::spawn(async move {
        if let Some(exit) = exit {
            for output in exit.outputs() {
                let _ = tx.send(Ok(wrap(output))).await;
            }
            return;
        }
        loop {
            match live.recv().await {
                Ok(frame) => {
                    let exited = matches!(frame, Frame::Exit { .. });
                    for output in frame.outputs() {
                        if tx.send(Ok(wrap(output))).await.is_err() {
                            return;
                        }
                    }
                    if exited {
                        return;
                    }
                }
                // What was skipped is in the host's log.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    });
    Ok(rx)
}

/// Sends every command's output to the host as it is produced.
///
/// The first ack names where each of the host's logs ends, so nothing the
/// host already holds is sent again. Then everything still pending goes out
/// in order, and whatever follows as it comes; each later ack lets the guest
/// drop what it confirms. A newer feed replaces this one.
pub async fn feed(
    mut acks: Streaming<guestpb::FeedAck>,
) -> Result<mpsc::Receiver<Result<guestpb::FeedFrame, Status>>, Status> {
    let first = acks.next().await.transpose()?.unwrap_or_default();
    let logged: HashMap<String, u64> = first
        .positions
        .into_iter()
        .map(|p| (p.command_id, p.logged))
        .collect();
    {
        let mut buffer = feed_buffer().lock().unwrap();
        buffer.release(first.seq);
        buffer.release_logged(&logged);
    }
    let epoch = FEED_EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
    let current = move || FEED_EPOCH.load(Ordering::SeqCst) == epoch;

    tokio::spawn(async move {
        while let Some(Ok(ack)) = acks.next().await {
            if !current() {
                return;
            }
            feed_buffer().lock().unwrap().release(ack.seq);
        }
    });

    let (tx, rx) = mpsc::channel(FEED_CAPACITY);
    tokio::spawn(async move {
        let mut next = 0u64;
        loop {
            let wake = feed_wake().notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let due: Vec<guestpb::FeedFrame> = {
                let buffer = feed_buffer().lock().unwrap();
                buffer
                    .pending
                    .iter()
                    .filter(|item| item.seq >= next)
                    .map(Pending::to_wire)
                    .collect()
            };
            for frame in due {
                next = frame.seq + 1;
                if !current() || tx.send(Ok(frame)).await.is_err() {
                    return;
                }
            }
            // Woken by new output; the timeout is what notices a feed that
            // has been replaced while nothing was produced.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), wake).await;
            if !current() || tx.is_closed() {
                return;
            }
        }
    });
    Ok(rx)
}

fn wrap(output: Output) -> guestpb::ExecOutput {
    guestpb::ExecOutput {
        output: Some(output),
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
    #[serde(default)]
    exit_signal: i32,
    #[serde(default)]
    produced: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    next_id: u64,
    entries: Vec<SavedEntry>,
    /// Output the host had not yet confirmed, which the next agent sends.
    #[serde(default)]
    pending: Vec<Pending>,
    #[serde(default)]
    next_seq: u64,
}

/// Writes every finished command, and the output the host has not yet
/// confirmed, to `path`, for the agent that replaces this one to read back.
/// Ids keep counting from where they were, so an id a client holds stays
/// unique.
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
                exit_signal: entry.exit_signal,
                produced: entry.produced,
            })
        })
        .collect();
    let buffer = feed_buffer().lock().unwrap();
    let saved = Saved {
        next_id: COUNTER.load(Ordering::Relaxed),
        entries,
        pending: buffer.pending.iter().cloned().collect(),
        next_seq: buffer.next_seq,
    };
    let bytes = serde_json::to_vec(&saved).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)
}

/// Reads what [`save`] wrote and removes the file. Best effort: a table that
/// cannot be read is an empty history, not a failed upgrade. An older agent's
/// table, with each command's output inline rather than pending, still reads:
/// the output it carries is not sent on, since that agent kept it in the guest.
///
/// `signaller` gives a restored command what signals it, from its pid.
pub fn restore(path: &str, signaller: impl Fn(i32) -> Option<Arc<dyn Signaller>>) {
    let saved = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Saved>(&bytes).ok());
    let _ = std::fs::remove_file(path);
    let Some(saved) = saved else { return };
    COUNTER.fetch_max(saved.next_id, Ordering::Relaxed);
    let mut registry = registry().lock().unwrap();
    for saved in saved.entries {
        let mut entry = Entry::new(
            saved.id.clone(),
            saved.cmd,
            saved.user,
            saved.pid,
            signaller(saved.pid),
            Rotation::default(),
        );
        entry.started_at_ms = saved.started_at_ms;
        entry.ended_at_ms = saved.ended_at_ms;
        entry.exit_code = Some(saved.exit_code);
        entry.exit_signal = saved.exit_signal;
        entry.produced = saved.produced;
        entry.is_announced = true;
        registry.order.push_back(saved.id.clone());
        registry
            .entries
            .insert(saved.id, Arc::new(Mutex::new(entry)));
    }
    let mut buffer = feed_buffer().lock().unwrap();
    buffer.next_seq = buffer.next_seq.max(saved.next_seq);
    for item in saved.pending {
        buffer.bytes += item.cost();
        buffer.pending.push_back(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Held by every test here. The registry and the feed are one for the
    /// process: a prune removes every finished command, and an ack releases
    /// by sequence number across every command, so tests running at once
    /// would take each other's commands and frames.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn pending_for(id: &str) -> Vec<Pending> {
        feed_buffer()
            .lock()
            .unwrap()
            .pending
            .iter()
            .filter(|item| item.id == id)
            .cloned()
            .collect()
    }

    /// What a command prints goes on the feed, offsets and all, its rotation
    /// on the first frame only.
    #[test]
    fn output_goes_on_the_feed_with_its_offsets() {
        let _serial = serial();
        let rotation = Rotation {
            max_bytes: 20 << 20,
            max_files: 5,
        };
        let handle = register(vec!["sh".into()], String::new(), -1, None, rotation);
        handle.record(Frame::Stdout(b"hello ".to_vec()));
        handle.record(Frame::Stderr(b"world".to_vec()));
        handle.finish(3, 0);
        let pending = pending_for(handle.id());
        assert_eq!(pending.len(), 3);
        assert_eq!((pending[0].at, pending[1].at, pending[2].at), (0, 6, 11));
        assert_eq!(pending[0].rotation.map(|r| r.max_files), Some(5));
        assert!(pending[1].rotation.is_none());
        assert_eq!(pending[2].kind, 2);
        let info = get(handle.id()).unwrap();
        assert_eq!(
            (info.state.as_str(), info.exit_code, info.output_bytes),
            ("exited", 3, 11)
        );
    }

    /// What the host confirms, or already holds, the guest lets go of.
    #[test]
    fn confirmed_output_is_let_go() {
        let _serial = serial();
        let handle = register(
            vec!["sh".into()],
            String::new(),
            -1,
            None,
            Rotation::default(),
        );
        handle.record(Frame::Stdout(b"aaaa".to_vec()));
        handle.record(Frame::Stdout(b"bbbb".to_vec()));
        let logged = HashMap::from([(handle.id().to_string(), 4u64)]);
        feed_buffer().lock().unwrap().release_logged(&logged);
        let pending = pending_for(handle.id());
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].at, 4);
        let upto = pending[0].seq;
        feed_buffer().lock().unwrap().release(upto);
        assert!(pending_for(handle.id()).is_empty());
    }

    /// A command a signal ended reports the signal, then the shell-style code.
    #[test]
    fn a_signalled_exit_names_its_signal() {
        let _serial = serial();
        let handle = register(
            vec!["sleep".into()],
            String::new(),
            -1,
            None,
            Rotation::default(),
        );
        handle.finish(137, 9);
        let pending = pending_for(handle.id());
        assert_eq!((pending[0].code, pending[0].signal), (137, 9));
        assert_eq!(get(handle.id()).unwrap().exit_signal, 9);
    }

    /// Pruning removes what has finished and says which, and leaves running
    /// commands alone.
    #[test]
    fn pruning_names_the_finished_commands_it_removes() {
        let _serial = serial();
        let done = register(
            vec!["true".into()],
            String::new(),
            -1,
            None,
            Rotation::default(),
        );
        done.finish(0, 0);
        let running = register(
            vec!["sleep".into()],
            String::new(),
            -1,
            None,
            Rotation::default(),
        );
        let pruned = prune();
        assert!(pruned.command_ids.contains(&done.id().to_string()));
        assert!(!pruned.command_ids.contains(&running.id().to_string()));
        assert_eq!(get(done.id()).unwrap_err().code(), tonic::Code::NotFound);
        assert_eq!(get(running.id()).unwrap().state, "running");
    }

    struct Recorder(Mutex<Vec<i32>>);

    impl Signaller for Recorder {
        fn signal(&self, signal: i32) -> Result<(), SignalError> {
            match signal {
                10 => Err(SignalError::Invalid("no".into())),
                15 => Err(SignalError::Gone("gone".into())),
                _ => {
                    self.0.lock().unwrap().push(signal);
                    Ok(())
                }
            }
        }
    }

    /// 0 means kill; what the platform cannot deliver is the caller's error,
    /// and what it finds gone is only "exited" once the command has.
    #[test]
    fn signals_go_to_the_signaller() {
        let _serial = serial();
        let recorder = Arc::new(Recorder(Mutex::default()));
        let handle = register(
            vec!["x".into()],
            String::new(),
            -1,
            Some(recorder.clone()),
            Rotation::default(),
        );
        signal(handle.id(), 0).unwrap();
        signal(handle.id(), 2).unwrap();
        assert_eq!(*recorder.0.lock().unwrap(), [9, 2]);
        assert_eq!(
            signal(handle.id(), 10).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            signal(handle.id(), 15).unwrap_err().code(),
            tonic::Code::Internal
        );
        handle.finish(0, 0);
        assert_eq!(
            signal(handle.id(), 15).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[test]
    fn an_unknown_command_is_not_found() {
        let _serial = serial();
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
        let _serial = serial();
        let handle = register(
            vec!["true".into()],
            String::new(),
            -1,
            None,
            Rotation::default(),
        );
        handle.finish(0, 0);
        assert_eq!(
            signal(handle.id(), 15).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }
}
