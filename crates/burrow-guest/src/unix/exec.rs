//! Running commands on behalf of the node daemon.
//!
//! Children are spawned with `std::process` rather than `tokio::process`
//! because the agent owns a single centralised reaper, which as Linux's PID 1
//! it has to: two independent `waitpid` callers would race for exit statuses.
//! See [`crate::unix::reaper`].

// Every fallible call here returns tonic's `Status`, which is large by design;
// boxing it would only obscure the signatures.
#![allow(clippy::result_large_err)]

use std::os::fd::OwnedFd;
use std::process::Stdio;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::{Status, Streaming};

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::exec_input::Input;
use burrow_proto::guest::v1::exec_output::Output;

use crate::commands::{self, Frame, Handle, SignalError, Signaller};
use crate::os::{Namespaces, users};
use crate::unix::asyncfd::AsyncPipe;
use crate::unix::{pty, reaper, signals};

/// Bounded so a chatty command cannot outrun the network and exhaust guest
/// memory; back-pressure propagates to the child through the pipe.
const CHANNEL_CAPACITY: usize = 64;
const READ_CHUNK: usize = 32 * 1024;
/// How long an exited command's pipes may stay quiet before its exit is
/// reported without waiting for them to close.
const DRAIN_IDLE: std::time::Duration = std::time::Duration::from_millis(500);

type OutputTx = mpsc::Sender<Result<guestpb::ExecOutput, Status>>;
type OutputRx = mpsc::Receiver<Result<guestpb::ExecOutput, Status>>;

fn chunk(output: Output) -> Result<guestpb::ExecOutput, Status> {
    Ok(guestpb::ExecOutput {
        output: Some(output),
    })
}

/// Handles one Exec stream: reads the mandatory `Start`, spawns the child,
/// and pumps its output back until it exits.
pub async fn run(mut inbound: Streaming<guestpb::ExecInput>) -> Result<OutputRx, Status> {
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
    if start.is_env_cleared {
        command.env_clear();
    }
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
    let cwd = match (start.cwd.as_str(), &credentials) {
        ("", None) => None,
        // A user's commands start in their own home rather than wherever the
        // agent happens to be, which is `/`.
        ("", Some(creds)) if !creds.home.is_empty() => Some(creds.home.as_str()),
        ("", Some(_)) => None,
        (cwd, _) => Some(cwd),
    };
    let namespaces = Namespaces::current()
        .map_err(|err| Status::unavailable(format!("entering systemd's namespaces: {err}")))?;
    match &namespaces {
        Some(namespaces) => namespaces
            .enter(&mut command, cwd)
            .map_err(|err| Status::invalid_argument(format!("cwd {cwd:?}: {err}")))?,
        None => {
            if let Some(cwd) = cwd {
                command.current_dir(cwd);
            }
        }
    }

    if start.is_pty {
        run_pty(command, &start, credentials, inbound, namespaces.as_ref())
    } else {
        run_pipes(command, &start, credentials, inbound, namespaces.as_ref())
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

fn spawn(
    command: &mut std::process::Command,
    namespaces: Option<&Namespaces>,
) -> std::io::Result<std::process::Child> {
    match namespaces {
        Some(namespaces) => namespaces.spawn(command),
        None => command.spawn(),
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
    start: &guestpb::ExecStart,
    credentials: Option<users::Credentials>,
    inbound: Streaming<guestpb::ExecInput>,
    namespaces: Option<&Namespaces>,
) -> Result<OutputRx, Status> {
    use std::os::unix::process::CommandExt;

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A group of its own, as a pty command gets from its session, so a
    // signal reaches what the command started and not only the command.
    // Without one it would share the agent's, and nothing could be sent to
    // the group without hitting the agent too.
    command.process_group(0);
    if let Some(creds) = &credentials {
        drop_privileges(&mut command, creds);
    }

    let gate = reaper::hold();
    let mut child =
        spawn(&mut command, namespaces).map_err(|err| spawn_failed(&start.cmd[0], err))?;
    let pid = child.id() as i32;
    let exit = reaper::watch(pid);
    drop(gate);
    let handle = commands::register(
        start.cmd.clone(),
        start.user.clone(),
        pid,
        process_group(pid),
        rotation(start),
    );

    let stdin = child.stdin.take().map(pipe).transpose()?;
    let stdout = child.stdout.take().map(pipe).transpose()?;
    let stderr = child.stderr.take().map(pipe).transpose()?;
    // Dropping the handle neither waits nor kills; the reaper owns the status.
    drop(child);

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    announce(&tx, handle.id());
    tokio::spawn(control_pipes(feed(inbound, &handle), stdin, pid));
    let mut pumps = Vec::new();
    if let Some(pipe) = stdout {
        pumps.push(tokio::spawn(pump(
            pipe,
            tx.clone(),
            handle.clone(),
            Frame::Stdout,
        )));
    }
    if let Some(pipe) = stderr {
        pumps.push(tokio::spawn(pump(
            pipe,
            tx.clone(),
            handle.clone(),
            Frame::Stderr,
        )));
    }
    tokio::spawn(report_exit(exit, pumps, tx, handle));
    Ok(rx)
}

/// How the command's log is bounded, from what the caller asked for.
fn rotation(start: &guestpb::ExecStart) -> commands::Rotation {
    commands::Rotation {
        max_bytes: start.log_max_bytes,
        max_files: start.log_max_files.max(1),
    }
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
    start: &guestpb::ExecStart,
    credentials: Option<users::Credentials>,
    inbound: Streaming<guestpb::ExecInput>,
    namespaces: Option<&Namespaces>,
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
            if nix::libc::ioctl(0, nix::libc::TIOCSCTTY as _, 0) < 0 {
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

    let gate = reaper::hold();
    let child = spawn(&mut command, namespaces).map_err(|err| spawn_failed(&start.cmd[0], err))?;
    let pid = child.id() as i32;
    let exit = reaper::watch(pid);
    drop(gate);
    let handle = commands::register(
        start.cmd.clone(),
        start.user.clone(),
        pid,
        process_group(pid),
        rotation(start),
    );
    drop(child);

    // The parent's copy of the slave must go, or the master never sees EOF.
    drop(pty.slave);

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    announce(&tx, handle.id());
    tokio::spawn(control_pty(feed(inbound, &handle), pty.writer, pid));
    let pumps = vec![tokio::spawn(pump(
        pty.reader,
        tx.clone(),
        handle.clone(),
        Frame::Stdout,
    ))];
    tokio::spawn(report_exit(exit, pumps, tx, handle));
    Ok(rx)
}

/// Gives the command an input channel any stream can feed, and feeds it from
/// the stream that started the command for as long as that lasts.
///
/// The stream ending does not end the input. A client that went away, or a
/// sandbox that slept and dropped the host's connection, is not the child
/// reaching EOF: only an explicit `is_stdin_eof` closes stdin, so a shell
/// survives for the next attacher to type into.
fn feed(
    mut inbound: Streaming<guestpb::ExecInput>,
    handle: &Handle,
) -> mpsc::Receiver<guestpb::ExecInput> {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    handle.set_input(tx.clone());
    tokio::spawn(async move {
        while let Some(Ok(msg)) = inbound.next().await {
            if tx.send(msg).await.is_err() {
                return;
            }
        }
    });
    rx
}

/// Input -> child stdin, plus signal control, for the pipe case.
async fn control_pipes(
    mut inbound: mpsc::Receiver<guestpb::ExecInput>,
    mut stdin: Option<AsyncPipe>,
    pid: i32,
) {
    while let Some(msg) = inbound.recv().await {
        match msg.input {
            Some(Input::Stdin(bytes)) => {
                let Some(pipe) = stdin.as_mut() else { continue };
                if pipe.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            // Dropping the pipe is what the child sees as EOF.
            Some(Input::IsStdinEof(true)) => drop(stdin.take()),
            Some(Input::Signal(sig)) => send_signal(pid, sig),
            // Resize is meaningless without a pty; ignore rather than failing
            // an otherwise healthy stream.
            Some(Input::Resize(_)) | Some(Input::IsStdinEof(false)) => {}
            Some(Input::Start(_)) => {
                tracing::warn!("ignoring duplicate Start on an active Exec stream");
            }
            None => {}
        }
    }
    drop(stdin);
}

/// Client -> pty, plus resize and signal control.
async fn control_pty(
    mut inbound: mpsc::Receiver<guestpb::ExecInput>,
    mut master: AsyncPipe,
    pid: i32,
) {
    while let Some(msg) = inbound.recv().await {
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
            Some(Input::IsStdinEof(_)) => {}
            Some(Input::Start(_)) => {
                tracing::warn!("ignoring duplicate Start on an active Exec stream");
            }
            None => {}
        }
    }
}

/// Reports the exit once the command's output is in, so it is the last thing
/// recorded. A child the command left running can hold its pipes open, so
/// the wait also ends once output stops arriving.
async fn report_exit(
    exit: tokio::sync::oneshot::Receiver<reaper::Exit>,
    pumps: Vec<tokio::task::JoinHandle<()>>,
    tx: OutputTx,
    handle: Handle,
) {
    let messages = match exit.await {
        Ok(exit) => {
            let mut drained = futures::future::join_all(pumps);
            loop {
                let before = handle.produced();
                tokio::select! {
                    _ = &mut drained => break,
                    // A full channel is a stream not yet read, behind which
                    // a pump holds output it has yet to send.
                    () = tokio::time::sleep(DRAIN_IDLE) => {
                        if handle.produced() == before && tx.capacity() > 0 {
                            break;
                        }
                    }
                }
            }
            handle.finish(exit.code, exit.signal);
            Frame::Exit {
                code: exit.code,
                signal: exit.signal,
            }
            .outputs()
            .into_iter()
            .map(chunk)
            .collect()
        }
        // The reaper dropped the sender, which should not happen while the
        // agent is alive.
        Err(_) => vec![Err(Status::internal("lost track of the child process"))],
    };
    // The pump tasks hold clones of `tx`; the exit code queues behind whatever
    // output they have already sent, so clients see complete output first.
    for message in messages {
        if tx.send(message).await.is_err() {
            return;
        }
    }
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
                let outputs = frame.outputs();
                handle.record(frame);
                for output in outputs {
                    if streaming {
                        streaming = tx.send(chunk(output)).await.is_ok();
                    }
                }
            }
        }
    }
}

/// A command's process group, which is what a signal to it reaches.
struct ProcessGroup(i32);

impl Signaller for ProcessGroup {
    /// A group's id cannot be handed to another process while anything is
    /// still in the group, so signalling one whose command has exited is safe.
    fn signal(&self, signal: i32) -> Result<(), SignalError> {
        let signal = signals::from_wire(signal)
            .map_err(|_| SignalError::Invalid(format!("unknown signal {signal}")))?;
        // A pid of 1 or less names no group of the command's own: 1 is this
        // agent, and the rest would reach far more than one command.
        if self.0 <= 1 {
            return Err(SignalError::NoProcess);
        }
        match nix::sys::signal::killpg(nix::unistd::Pid::from_raw(self.0), Some(signal)) {
            Ok(()) => Ok(()),
            Err(nix::errno::Errno::ESRCH) => {
                Err(SignalError::Gone(nix::errno::Errno::ESRCH.to_string()))
            }
            Err(err) => Err(SignalError::Failed(err.to_string())),
        }
    }
}

/// What signals the command running as `pid`, for the registry.
pub fn process_group(pid: i32) -> Option<std::sync::Arc<dyn Signaller>> {
    Some(std::sync::Arc::new(ProcessGroup(pid)))
}

fn send_signal(pid: i32, signal: i32) {
    let Ok(signal) = signals::from_wire(signal) else {
        tracing::warn!(signal, "ignoring unknown signal");
        return;
    };
    if let Err(err) = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), Some(signal)) {
        tracing::warn!(pid, %err, "failed to signal child");
    }
}
