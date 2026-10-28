//! The output of every command a sandbox runs, kept on the node.
//!
//! Docker's daemon captures a container's output and writes it on the host,
//! where the container cannot read, rewrite or fill it. Here the guest agent
//! sends every frame over its Feed, and the node writes it to one log per
//! command under `<data-dir>/command-logs/<sandbox>`, outside the jail the
//! VMM is confined to. Attach replays from these logs
//! and follows what arrives after, so history outlives the guest's memory,
//! survives a suspend, and goes with the sandbox when it moves.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use burrow_common::cmdlog::{Frame, Log, Plan, Rotation};
use burrow_proto::guest::v1 as guestpb;
use tokio::sync::broadcast;

/// Frames a follower may fall behind by before it rereads from the log.
const LIVE_BACKLOG: usize = 1024;

/// A frame as it was written, for followers.
#[derive(Clone)]
pub struct Live {
    pub id: String,
    pub at: u64,
    pub frame: Frame,
}

pub struct CommandLogs {
    dir: PathBuf,
    rotation: Rotation,
    state: Mutex<State>,
    live: broadcast::Sender<Live>,
    /// Whether a task is draining the guest's feed into these logs.
    pub feeding: AtomicBool,
}

#[derive(Default)]
struct State {
    logs: HashMap<String, Log>,
    is_loaded: bool,
    /// Set once the sandbox is gone from this node, so a feed still draining
    /// cannot write into, or recreate, a directory being removed.
    is_closed: bool,
}

/// Where a follower starts.
pub struct Follow {
    /// What the log holds from the follower's offset; `None` with no log yet.
    pub plan: Option<Plan>,
    pub has_exit: bool,
    pub live: broadcast::Receiver<Live>,
}

impl CommandLogs {
    /// Logs kept in `dir`, rotating as `rotation` says for a command that did
    /// not ask for its own.
    pub fn new(dir: &Path, rotation: Rotation) -> Self {
        Self {
            dir: dir.to_path_buf(),
            rotation,
            state: Mutex::default(),
            live: broadcast::channel(LIVE_BACKLOG).0,
            feeding: AtomicBool::new(false),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap();
        if !state.is_loaded {
            state.is_loaded = true;
            for id in Log::ids_in(&self.dir) {
                match Log::reopen(&self.dir, &id, self.rotation) {
                    Ok(mut log) => {
                        if log.has_exit() {
                            log.close();
                        }
                        state.logs.insert(id, log);
                    }
                    Err(err) => tracing::warn!(command = id, %err, "could not read a command log"),
                }
            }
        }
        state
    }

    /// Where each log ends, for the guest to skip what is already here.
    pub fn positions(&self) -> Vec<guestpb::FeedPosition> {
        self.state()
            .logs
            .iter()
            .map(|(id, log)| guestpb::FeedPosition {
                command_id: id.clone(),
                logged: log.logged(),
            })
            .collect()
    }

    /// Writes one frame from the guest's feed.
    pub fn append(&self, frame: guestpb::FeedFrame) {
        use guestpb::feed_frame::Output;
        let output = match frame.output {
            Some(Output::Stdout(bytes)) => Frame::Stdout(bytes),
            Some(Output::Stderr(bytes)) => Frame::Stderr(bytes),
            Some(Output::Exit(exit)) => Frame::Exit {
                code: exit.code,
                signal: exit.signal,
            },
            None => return,
        };
        // A command id names a file, so only the guest's own shape is taken.
        if !is_command_id(&frame.command_id) {
            return;
        }
        let mut state = self.state();
        if state.is_closed {
            return;
        }
        let log = match state.logs.entry(frame.command_id.clone()) {
            std::collections::hash_map::Entry::Occupied(held) => held.into_mut(),
            std::collections::hash_map::Entry::Vacant(slot) => {
                let rotation = if frame.log_max_bytes > 0 {
                    Rotation {
                        max_bytes: frame.log_max_bytes,
                        max_files: frame.log_max_files,
                    }
                } else {
                    self.rotation
                };
                match Log::create(&self.dir, &frame.command_id, rotation) {
                    Ok(log) => slot.insert(log),
                    Err(err) => {
                        tracing::warn!(command = frame.command_id, %err, "could not start a command log");
                        return;
                    }
                }
            }
        };
        let is_exit = matches!(output, Frame::Exit { .. });
        let written = log.append(frame.at, &output);
        if is_exit {
            log.close();
        }
        if written {
            let _ = self.live.send(Live {
                id: frame.command_id,
                at: frame.at,
                frame: output,
            });
        }
    }

    /// Starts following command `id` from output offset `from`: what the log
    /// holds now, and everything written after.
    pub fn follow(&self, id: &str, from: u64) -> Follow {
        let state = self.state();
        let live = self.live.subscribe();
        let log = state.logs.get(id);
        Follow {
            plan: log.map(|log| log.plan(from)),
            has_exit: log.is_some_and(Log::has_exit),
            live,
        }
    }

    /// Whether a log is kept for `id`, and whether it has the exit.
    pub fn exit_logged(&self, id: &str) -> Option<bool> {
        self.state().logs.get(id).map(Log::has_exit)
    }

    /// Output bytes held for `id`.
    pub fn held_bytes(&self, id: &str) -> u64 {
        self.state().logs.get(id).map_or(0, Log::held_bytes)
    }

    /// Removes the logs of `ids`, returning the bytes freed.
    pub fn remove(&self, ids: &[String]) -> u64 {
        let mut state = self.state();
        ids.iter()
            .filter_map(|id| state.logs.remove(id))
            .map(|log| {
                let freed = log.bytes_on_disk();
                log.remove();
                freed
            })
            .sum()
    }

    /// Removes every log. A cold boot starts the guest's ids over, and an old
    /// log under a reused id would be read as the new command's.
    pub fn clear(&self) {
        let mut state = self.state();
        for (_, log) in state.logs.drain() {
            log.remove();
        }
    }

    /// Stops writing for good: the sandbox is leaving this node.
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.is_closed = true;
        for log in state.logs.values_mut() {
            log.close();
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn claim_feed(&self) -> bool {
        !self.feeding.swap(true, Ordering::AcqRel)
    }

    pub fn release_feed(&self) {
        self.feeding.store(false, Ordering::Release);
    }
}

fn is_command_id(id: &str) -> bool {
    id.strip_prefix("cmd_")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The api's form of a frame read back.
pub fn outputs(frame: Frame) -> Vec<burrow_proto::api::v1::exec_output::Output> {
    use burrow_proto::api::v1::exec_output::Output;
    match frame {
        Frame::Stdout(bytes) => vec![Output::Stdout(bytes)],
        Frame::Stderr(bytes) => vec![Output::Stderr(bytes)],
        Frame::Exit { code, signal: 0 } => vec![Output::ExitCode(code)],
        Frame::Exit { code, signal } => vec![Output::ExitSignal(signal), Output::ExitCode(code)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("burrow-cmdlogs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn frame(id: &str, at: u64, output: guestpb::feed_frame::Output) -> guestpb::FeedFrame {
        guestpb::FeedFrame {
            seq: 0,
            command_id: id.into(),
            at,
            output: Some(output),
            log_max_bytes: 0,
            log_max_files: 0,
        }
    }

    #[test]
    fn a_feed_resent_after_a_reconnect_is_written_once() {
        use guestpb::feed_frame::Output;
        let dir = scratch("resent");
        let logs = CommandLogs::new(dir.as_path(), Rotation::default());
        logs.append(frame("cmd_1", 0, Output::Stdout(b"hello ".to_vec())));
        logs.append(frame("cmd_1", 0, Output::Stdout(b"hello world".to_vec())));
        logs.append(frame(
            "cmd_1",
            11,
            Output::Exit(guestpb::FeedExit { code: 0, signal: 0 }),
        ));
        assert_eq!(logs.held_bytes("cmd_1"), 11);
        assert_eq!(logs.exit_logged("cmd_1"), Some(true));

        // A node that restarts reads the logs back.
        let reread = CommandLogs::new(dir.as_path(), Rotation::default());
        assert_eq!(reread.positions()[0].logged, 11);
        assert_eq!(reread.exit_logged("cmd_1"), Some(true));
    }

    #[test]
    fn an_id_that_is_not_the_guests_is_not_written() {
        use guestpb::feed_frame::Output;
        let dir = scratch("foreign");
        let logs = CommandLogs::new(dir.as_path(), Rotation::default());
        logs.append(frame("../x", 0, Output::Stdout(b"x".to_vec())));
        assert!(logs.positions().is_empty());
    }

    #[test]
    fn a_closed_store_writes_nothing() {
        use guestpb::feed_frame::Output;
        let dir = scratch("closed");
        let logs = CommandLogs::new(&dir.as_path().join("gone"), Rotation::default());
        logs.close();
        logs.append(frame("cmd_1", 0, Output::Stdout(b"x".to_vec())));
        assert!(!dir.as_path().join("gone").exists());
    }

    #[test]
    fn pruning_frees_the_logs() {
        use guestpb::feed_frame::Output;
        let dir = scratch("pruned");
        let logs = CommandLogs::new(dir.as_path(), Rotation::default());
        logs.append(frame("cmd_1", 0, Output::Stdout(vec![b'x'; 100])));
        assert!(logs.remove(&["cmd_1".into()]) > 100);
        assert!(Log::ids_in(&dir).is_empty());
    }
}
