//! The registry of commands the agent has run.
//!
//! A command used to live only on the Exec stream that started it: a client
//! that went away took the only handle on it with it. Here every command gets
//! an id, a bounded ring buffer of its recent output and a broadcast of what it
//! produces from now on, so another process can list it, follow it and signal
//! it long after the stream that started it is gone.
//!
//! Both bounds exist because a sandbox is long-lived and its commands are not
//! the agent's to grow for: output past [`RING_BYTES`] is dropped oldest first,
//! and only the last [`MAX_FINISHED`] finished commands are kept.

#![allow(clippy::result_large_err)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{broadcast, mpsc};
use tonic::Status;

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::exec_output::Output;

/// Output retained per command for a later attach.
const RING_BYTES: usize = 256 * 1024;
/// Finished commands kept before the oldest is evicted.
const MAX_FINISHED: usize = 64;
/// Frames a live attacher may fall behind by before it loses some.
const LIVE_BACKLOG: usize = 256;
const ATTACH_CAPACITY: usize = 64;

/// One piece of a command's output, buffered and broadcast alike.
#[derive(Clone)]
pub enum Frame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}

impl Frame {
    fn len(&self) -> usize {
        match self {
            Frame::Stdout(bytes) | Frame::Stderr(bytes) => bytes.len(),
            Frame::Exit(_) => 0,
        }
    }

    pub fn output(&self) -> Output {
        match self {
            Frame::Stdout(bytes) => Output::Stdout(bytes.clone()),
            Frame::Stderr(bytes) => Output::Stderr(bytes.clone()),
            Frame::Exit(code) => Output::ExitCode(*code),
        }
    }
}

struct Entry {
    id: String,
    cmd: Vec<String>,
    user: String,
    pid: i32,
    started_at_ms: i64,
    ended_at_ms: i64,
    exit_code: Option<i32>,
    buffer: VecDeque<Frame>,
    buffered: usize,
    live: broadcast::Sender<Frame>,
}

impl Entry {
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
            buffered_bytes: self.buffered as u64,
        }
    }

    fn push(&mut self, frame: Frame) {
        self.buffered += frame.len();
        self.buffer.push_back(frame);
        while self.buffered > RING_BYTES {
            match self.buffer.pop_front() {
                Some(dropped) => self.buffered -= dropped.len(),
                None => break,
            }
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

    /// Buffers a frame and hands it to whoever is attached.
    pub fn record(&self, frame: Frame) {
        let mut entry = self.entry.lock().unwrap();
        entry.push(frame.clone());
        // An error only means nobody is attached right now, which is the
        // ordinary case: the buffer above is what a later attacher reads.
        let _ = entry.live.send(frame);
    }

    /// Records the exit status and marks the command finished.
    pub fn finish(&self, code: i32) {
        {
            let mut entry = self.entry.lock().unwrap();
            entry.exit_code = Some(code);
            entry.ended_at_ms = now_ms();
            entry.push(Frame::Exit(code));
            let _ = entry.live.send(Frame::Exit(code));
        }
        evict();
    }
}

/// Registers a command that has just been spawned.
pub fn register(cmd: Vec<String>, user: String, pid: i32) -> Handle {
    let id = next_id();
    let entry = Arc::new(Mutex::new(Entry {
        id: id.clone(),
        cmd,
        user,
        pid,
        started_at_ms: now_ms(),
        ended_at_ms: 0,
        exit_code: None,
        buffer: VecDeque::new(),
        buffered: 0,
        live: broadcast::channel(LIVE_BACKLOG).0,
    }));
    let mut registry = registry().lock().unwrap();
    registry.order.push_back(id.clone());
    registry.entries.insert(id.clone(), Arc::clone(&entry));
    Handle { id, entry }
}

/// Drops the oldest finished commands once there are more than [`MAX_FINISHED`].
///
/// Running commands are never evicted: they still have a pid to signal and
/// output still to come.
fn evict() {
    let mut registry = registry().lock().unwrap();
    let finished: Vec<String> = registry
        .order
        .iter()
        .filter(|id| registry.entries[*id].lock().unwrap().exit_code.is_some())
        .cloned()
        .collect();
    let excess = finished.len().saturating_sub(MAX_FINISHED);
    for id in finished.into_iter().take(excess) {
        registry.entries.remove(&id);
        registry.order.retain(|held| held != &id);
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

pub fn signal(id: &str, signal: i32) -> Result<(), Status> {
    let entry = entry(id)?;
    let entry = entry.lock().unwrap();
    if entry.exit_code.is_some() {
        return Err(Status::failed_precondition(format!(
            "command {id} has already exited"
        )));
    }
    // 0 is the api's "whatever kills it": a caller who did not choose a signal
    // wants the command gone, not a no-op probe.
    let signal = if signal == 0 {
        nix::sys::signal::Signal::SIGKILL
    } else {
        nix::sys::signal::Signal::try_from(signal)
            .map_err(|_| Status::invalid_argument(format!("unknown signal {signal}")))?
    };
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(entry.pid), Some(signal))
        .map_err(|err| Status::internal(format!("signal {id}: {err}")))
}

/// Replays what the ring buffer still holds, then follows the command live.
///
/// The subscription is taken while the buffer is being copied, so a frame
/// produced between the two is delivered once by the broadcast rather than
/// missed. A command that has already exited replays its buffer, which ends
/// with its exit status, and the stream then closes.
pub fn attach(id: &str) -> Result<mpsc::Receiver<Result<guestpb::ExecOutput, Status>>, Status> {
    let entry = entry(id)?;
    let (replay, mut live, finished) = {
        let entry = entry.lock().unwrap();
        (
            entry.buffer.iter().cloned().collect::<Vec<_>>(),
            entry.live.subscribe(),
            entry.exit_code.is_some(),
        )
    };

    let (tx, rx) = mpsc::channel(ATTACH_CAPACITY);
    tokio::spawn(async move {
        for frame in replay {
            if tx.send(Ok(wrap(frame))).await.is_err() {
                return;
            }
        }
        if finished {
            return;
        }
        loop {
            match live.recv().await {
                Ok(frame) => {
                    let exited = matches!(frame, Frame::Exit(_));
                    if tx.send(Ok(wrap(frame))).await.is_err() || exited {
                        return;
                    }
                }
                // The attacher read slower than the command produced. Saying so
                // is better than a silent hole in the output.
                Err(broadcast::error::RecvError::Lagged(frames)) => {
                    tracing::warn!(frames, "an attacher fell behind; output was dropped");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    });
    Ok(rx)
}

fn wrap(frame: Frame) -> guestpb::ExecOutput {
    guestpb::ExecOutput {
        output: Some(frame.output()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chatty command must not be able to write the agent out of memory, and
    /// what it keeps has to be the tail: that is what an attacher wants to see.
    #[test]
    fn the_ring_buffer_drops_the_oldest_output() {
        let handle = register(vec!["yes".into()], String::new(), -1);
        for _ in 0..8 {
            handle.record(Frame::Stdout(vec![b'x'; 64 * 1024]));
        }
        let info = get(handle.id()).expect("registered");
        assert!(info.buffered_bytes <= RING_BYTES as u64);
        assert_eq!(info.state, "running");

        handle.finish(3);
        let info = get(handle.id()).expect("registered");
        assert_eq!(info.state, "exited");
        assert_eq!(info.exit_code, 3);
        assert!(info.ended_at_unix_ms >= info.started_at_unix_ms);
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
        let handle = register(vec!["true".into()], String::new(), -1);
        handle.finish(0);
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
    /// (0 stdout, 1 stderr, 2 exit) and the bytes or the code's LE bytes.
    frames: Vec<(u8, Vec<u8>)>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    next_id: u64,
    entries: Vec<SavedEntry>,
}

/// Writes every finished command to `path`, for the agent that replaces this
/// one to read back. Ids keep counting from where they were, so an id a
/// client holds stays unique.
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
                frames: entry
                    .buffer
                    .iter()
                    .map(|frame| match frame {
                        Frame::Stdout(bytes) => (0, bytes.clone()),
                        Frame::Stderr(bytes) => (1, bytes.clone()),
                        Frame::Exit(code) => (2, code.to_le_bytes().to_vec()),
                    })
                    .collect(),
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
pub fn restore(path: &str) {
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let _ = std::fs::remove_file(path);
    let Ok(saved) = serde_json::from_slice::<Saved>(&bytes) else {
        return;
    };
    COUNTER.fetch_max(saved.next_id, Ordering::Relaxed);
    let mut registry = registry().lock().unwrap();
    for saved in saved.entries {
        let mut entry = Entry {
            id: saved.id.clone(),
            cmd: saved.cmd,
            user: saved.user,
            pid: saved.pid,
            started_at_ms: saved.started_at_ms,
            ended_at_ms: saved.ended_at_ms,
            exit_code: Some(saved.exit_code),
            buffer: VecDeque::new(),
            buffered: 0,
            live: broadcast::channel(LIVE_BACKLOG).0,
        };
        for (kind, bytes) in saved.frames {
            entry.push(match kind {
                0 => Frame::Stdout(bytes),
                1 => Frame::Stderr(bytes),
                _ => Frame::Exit(i32::from_le_bytes(bytes.try_into().unwrap_or_default())),
            });
        }
        registry.order.push_back(saved.id.clone());
        registry
            .entries
            .insert(saved.id, Arc::new(Mutex::new(entry)));
    }
}
