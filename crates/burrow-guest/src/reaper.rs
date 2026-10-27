//! Centralised child reaping.
//!
//! As PID 1 the agent inherits every orphaned process in the sandbox and must
//! reap them, but a generic `waitpid(-1)` loop also consumes the exit status
//! of processes started by `Exec`: whoever calls `waitpid` first wins, and the
//! loser gets ECHILD and loses the exit code.
//!
//! So there is exactly one waiter in the process: this reaper. Exec registers
//! interest in a pid before the child can exit and receives the status over a
//! channel; everything else reaped is an orphan and is simply discarded.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use tokio::sync::oneshot;

fn waiters() -> &'static Mutex<HashMap<i32, oneshot::Sender<i32>>> {
    static WAITERS: OnceLock<Mutex<HashMap<i32, oneshot::Sender<i32>>>> = OnceLock::new();
    WAITERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Registers interest in a child's exit status.
///
/// Must be called with no await point between spawning the child and this
/// call, so the reaper cannot consume the status before the waiter exists.
pub fn watch(pid: i32) -> oneshot::Receiver<i32> {
    let (tx, rx) = oneshot::channel();
    waiters().lock().unwrap().insert(pid, tx);
    rx
}

pub fn spawn() {
    tokio::spawn(async {
        let mut sigchld = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        {
            Ok(sig) => sig,
            Err(err) => {
                tracing::error!(%err, "cannot watch SIGCHLD; zombies will accumulate");
                return;
            }
        };
        loop {
            // Runs before the first await too: a child can exit between spawn
            // and the first signal delivery.
            reap_once();
            if sigchld.recv().await.is_none() {
                break;
            }
        }
    });
}

fn reap_once() {
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            // No child has exited right now.
            Ok(WaitStatus::StillAlive) => break,
            Ok(WaitStatus::Exited(pid, code)) => deliver(pid.as_raw(), code),
            // Shell convention for a signal-terminated process.
            Ok(WaitStatus::Signaled(pid, sig, _)) => deliver(pid.as_raw(), 128 + sig as i32),
            // Stop/continue notifications are not requested; ignore any that
            // arrive rather than treating them as exits.
            Ok(_) => continue,
            // No children at all.
            Err(nix::errno::Errno::ECHILD) => break,
            Err(err) => {
                tracing::warn!(%err, "waitpid failed");
                break;
            }
        }
    }
}

fn deliver(pid: i32, code: i32) {
    match waiters().lock().unwrap().remove(&pid) {
        Some(tx) => {
            let _ = tx.send(code);
        }
        // An orphan re-parented to us: nothing to report it to, and reaping it
        // is the whole job.
        None => tracing::debug!(pid, code, "reaped orphan"),
    }
}
