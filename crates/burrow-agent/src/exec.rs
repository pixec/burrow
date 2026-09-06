//! Running commands on behalf of the node daemon.
//!
//! Children are spawned with `std::process` rather than `tokio::process`
//! because the agent is PID 1 and owns a single centralised reaper: two
//! independent `waitpid` callers would race for exit statuses. See
//! [`crate::reaper`].

// Every fallible call here returns tonic's `Status`, which is large by design;
// boxing it would only obscure the signatures.
#![allow(clippy::result_large_err)]

use std::os::fd::OwnedFd;
use std::process::Stdio;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::{Status, Streaming};

use burrow_proto::agent::v1 as agentpb;
use burrow_proto::agent::v1::exec_input::Input;
use burrow_proto::agent::v1::exec_output::Output;

use crate::asyncfd::AsyncPipe;
use crate::commands::{self, Frame, Handle};
use crate::{pty, reaper, users};

/// Bounded so a chatty command cannot outrun the network and exhaust guest
/// memory; back-pressure propagates to the child through the pipe.
const CHANNEL_CAPACITY: usize = 64;
const READ_CHUNK: usize = 32 * 1024;

type OutputTx = mpsc::Sender<Result<agentpb::ExecOutput, Status>>;
type OutputRx = mpsc::Receiver<Result<agentpb::ExecOutput, Status>>;

fn chunk(output: Output) -> Result<agentpb::ExecOutput, Status> {
    Ok(agentpb::ExecOutput {
        output: Some(output),
    })
}

/// Handles one Exec stream: reads the mandatory `Start`, spawns the child,
/// and pumps its output back until it exits.
pub async fn run(mut inbound: Streaming<agentpb::ExecInput>) -> Result<OutputRx, Status> {
    let start = match inbound.next().await {
        Some(Ok(msg)) => match msg.input {
            Some(Input::Start(start)) => start,
            _ => return Err(Status::invalid_argument("first Exec message must be Start")),
        },
        Some(Err(err)) => return Err(err),
        None => return Err(Status::invalid_argument("Exec stream closed before Start")),
    };

    if start.cmd.is_empty() {
        return Err(Status::invalid_argument("cmd must not be empty"));
    }

    // Resolved before anything is spawned: a command asked to run as a user
    // who does not exist must fail as a request, not as a broken child.
    let credentials = if start.user.is_empty() {
        None
    } else {
        Some(users::credentials(&start.user)?)
    };

    let mut command = std::process::Command::new(&start.cmd[0]);
    command.args(&start.cmd[1..]);
    // The user's own environment first, so a caller's variables still win.
    if let Some(creds) = &credentials {
        command
            .env("HOME", &creds.home)
            .env("USER", &creds.name)
            .env("LOGNAME", &creds.name);
        if !creds.shell.is_empty() {
            command.env("SHELL", &creds.shell);
        }
    }
    command.envs(&start.env);
    match (start.cwd.as_str(), &credentials) {
        ("", None) => {}
        // A user's commands start in their own home rather than wherever the
        // agent happens to be, which is `/`.
        ("", Some(creds)) if !creds.home.is_empty() => {
            command.current_dir(&creds.home);
        }
        ("", Some(_)) => {}
        (cwd, _) => {
            command.current_dir(cwd);
        }
    }

    if start.pty {
        run_pty(command, &start, credentials, inbound)
    } else {
        run_pipes(command, &start, credentials, inbound)
    }
}

/// Makes the child run as `credentials`.
///
/// Done in a `pre_exec` rather than through `CommandExt::uid`/`gid`, because
/// the supplementary groups have to be set too and std runs pre-exec closures
/// *after* it has already dropped to the target uid, by which point
/// `setgroups` is no longer permitted. Order matters for the same reason:
/// groups, then gid, then uid, each while there is still privilege to do it.
fn drop_privileges(command: &mut std::process::Command, credentials: &users::Credentials) {
    use std::os::unix::process::CommandExt;

    let groups = credentials.groups.clone();
    let (uid, gid) = (credentials.uid, credentials.gid);
    // SAFETY: runs between fork and exec, so only async-signal-safe calls.
    // These are all bare syscalls.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::setgroups(groups.len() as _, groups.as_ptr()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::setgid(gid) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::setuid(uid) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn spawn_failed(cmd: &str, err: std::io::Error) -> Status {
    Status::failed_precondition(format!("spawn {cmd:?}: {err}"))
}

fn pipe(fd: impl Into<OwnedFd>) -> Result<AsyncPipe, Status> {
    AsyncPipe::new(fd.into()).map_err(|err| Status::internal(format!("child pipe: {err}")))
}

/// Non-interactive execution: separate stdout and stderr over pipes.
fn run_pipes(
    mut command: std::process::Command,
    start: &agentpb::ExecStart,
    credentials: Option<users::Credentials>,
    inbound: Streaming<agentpb::ExecInput>,
) -> Result<OutputRx, Status> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(creds) = &credentials {
        drop_privileges(&mut command, creds);
    }

    let mut child = command
        .spawn()
        .map_err(|err| spawn_failed(&start.cmd[0], err))?;

    // No await between spawn and watch, so the reaper cannot deliver this
    // child's status before there is somewhere to deliver it to.
    let pid = child.id() as i32;
    let exit = reaper::watch(pid);
    let handle = commands::register(start.cmd.clone(), start.user.clone(), pid);

    let stdin = child.stdin.take().map(pipe).transpose()?;
    let stdout = child.stdout.take().map(pipe).transpose()?;
    let stderr = child.stderr.take().map(pipe).transpose()?;
    // Dropping the handle neither waits nor kills; the reaper owns the status.
    drop(child);

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    announce(&tx, handle.id());
    tokio::spawn(control_pipes(inbound, stdin, pid));
    if let Some(pipe) = stdout {
        tokio::spawn(pump(pipe, tx.clone(), handle.clone(), Frame::Stdout));
    }
    if let Some(pipe) = stderr {
        tokio::spawn(pump(pipe, tx.clone(), handle.clone(), Frame::Stderr));
    }
    tokio::spawn(report_exit(exit, tx, handle));
    Ok(rx)
}

/// Puts the command's id on the stream before any of its output.
///
/// The channel is empty and its capacity is well above one, so this cannot
/// block; a caller that means to come back to the command has the id at once
/// rather than when the command finishes.
fn announce(tx: &OutputTx, id: &str) {
    let _ = tx.try_send(chunk(Output::CommandId(id.to_string())));
}

/// Interactive execution: the child gets a controlling terminal, so stdout and
/// stderr are inherently merged and reported as stdout.
fn run_pty(
    mut command: std::process::Command,
    start: &agentpb::ExecStart,
    credentials: Option<users::Credentials>,
    inbound: Streaming<agentpb::ExecInput>,
) -> Result<OutputRx, Status> {
    use std::os::unix::process::CommandExt;

    let pty = pty::open(start.rows, start.cols)
        .map_err(|err| Status::internal(format!("openpty: {err}")))?;

    // The terminal belongs to whoever is at it: a pty still owned by root
    // leaves job control and anything that reopens `/dev/tty` failing for the
    // user the command actually runs as.
    if let Some(creds) = &credentials {
        pty::own(&pty.slave, creds.uid)
            .map_err(|err| Status::internal(format!("chown pty: {err}")))?;
    }

    let dup = |label: &str| {
        pty.slave
            .try_clone()
            .map_err(|err| Status::internal(format!("dup pty for {label}: {err}")))
    };
    command
        .stdin(Stdio::from(dup("stdin")?))
        .stdout(Stdio::from(dup("stdout")?))
        .stderr(Stdio::from(dup("stderr")?));

    // SAFETY: runs between fork and exec, so only async-signal-safe calls.
    // A new session plus TIOCSCTTY is what makes the pty the child's
    // controlling terminal, which job control and REPLs require.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // After the session and controlling terminal are set, which need the
    // privilege the child is about to give up.
    if let Some(creds) = &credentials {
        drop_privileges(&mut command, creds);
    }

    let child = command
        .spawn()
        .map_err(|err| spawn_failed(&start.cmd[0], err))?;
    let pid = child.id() as i32;
    let exit = reaper::watch(pid);
    let handle = commands::register(start.cmd.clone(), start.user.clone(), pid);
    drop(child);

    // The parent's copy of the slave must go, or the master never sees EOF.
    drop(pty.slave);

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    announce(&tx, handle.id());
    tokio::spawn(control_pty(inbound, pty.writer, pid));
    tokio::spawn(pump(pty.reader, tx.clone(), handle.clone(), Frame::Stdout));
    tokio::spawn(report_exit(exit, tx, handle));
    Ok(rx)
}

/// Client -> child stdin, plus signal control, for the pipe case.
async fn control_pipes(
    mut inbound: Streaming<agentpb::ExecInput>,
    mut stdin: Option<AsyncPipe>,
    pid: i32,
) {
    while let Some(Ok(msg)) = inbound.next().await {
        match msg.input {
            Some(Input::Stdin(bytes)) => {
                let Some(pipe) = stdin.as_mut() else { continue };
                if pipe.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            // Dropping the pipe is what the child sees as EOF.
            Some(Input::StdinEof(true)) => drop(stdin.take()),
            Some(Input::Signal(sig)) => send_signal(pid, sig),
            // Resize is meaningless without a pty; ignore rather than failing
            // an otherwise healthy stream.
            Some(Input::Resize(_)) | Some(Input::StdinEof(false)) => {}
            Some(Input::Start(_)) => {
                tracing::warn!("ignoring duplicate Start on an active Exec stream");
            }
            None => {}
        }
    }
    drop(stdin);
}

/// Client -> pty, plus resize and signal control.
async fn control_pty(mut inbound: Streaming<agentpb::ExecInput>, mut master: AsyncPipe, pid: i32) {
    while let Some(Ok(msg)) = inbound.next().await {
        match msg.input {
            Some(Input::Stdin(bytes)) if master.write_all(&bytes).await.is_err() => break,
            Some(Input::Stdin(_)) => {}
            Some(Input::Resize(size)) => {
                if let Err(err) = pty::resize(master.raw_fd(), size.rows, size.cols) {
                    tracing::warn!(%err, "pty resize failed");
                }
            }
            Some(Input::Signal(sig)) => send_signal(pid, sig),
            // Closing the master would tear down the terminal; a pty client
            // signals EOF by sending the terminal's EOF character instead.
            Some(Input::StdinEof(_)) => {}
            Some(Input::Start(_)) => {
                tracing::warn!("ignoring duplicate Start on an active Exec stream");
            }
            None => {}
        }
    }
}

async fn report_exit(exit: tokio::sync::oneshot::Receiver<i32>, tx: OutputTx, handle: Handle) {
    let message = match exit.await {
        Ok(code) => {
            handle.finish(code);
            chunk(Output::ExitCode(code))
        }
        // The reaper dropped the sender, which should not happen while the
        // agent is alive.
        Err(_) => Err(Status::internal("lost track of the child process")),
    };
    // The pump tasks hold clones of `tx`; the exit code queues behind whatever
    // output they have already sent, so clients see complete output first.
    let _ = tx.send(message).await;
}

/// Child output -> the registry, and the stream that started it while it lasts.
///
/// The stream going away no longer stops the pump: a command outlives the
/// client that started it, and what it produces after that is what a later
/// attach replays. Reading also has to continue regardless, or the child would
/// block on a pipe nobody is draining.
async fn pump<R>(mut pipe: R, tx: OutputTx, handle: Handle, wrap: fn(Vec<u8>) -> Frame)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; READ_CHUNK];
    let mut streaming = true;
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let frame = wrap(buf[..n].to_vec());
                if streaming {
                    streaming = tx.send(chunk(frame.output())).await.is_ok();
                }
                handle.record(frame);
            }
        }
    }
}

fn send_signal(pid: i32, signal: i32) {
    let Ok(signal) = nix::sys::signal::Signal::try_from(signal) else {
        tracing::warn!(signal, "ignoring unknown signal");
        return;
    };
    if let Err(err) = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), Some(signal)) {
        tracing::warn!(pid, %err, "failed to signal child");
    }
}
