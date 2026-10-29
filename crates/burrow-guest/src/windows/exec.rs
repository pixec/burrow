//! Running commands on behalf of the node daemon, on Windows.
//!
//! The stream protocol, the registry and the output feed are the Linux
//! agent's: a command gets an id, its output is pumped to the stream that
//! started it and to the feed, and its exit is reported once its output is
//! in. What differs is underneath: `CreateProcessW` with pipes or a pseudo
//! console (see [`super::process`]), a Job Object for the process tree, and
//! a command line built from the argv (see [`super::cmdline`]).

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::{Status, Streaming};

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::exec_input::Input;
use burrow_proto::guest::v1::exec_output::Output;

use crate::commands::{self, Frame, Handle, Signaller as _};
use crate::windows::{cmdline, process, token, users, win};

const CHANNEL_CAPACITY: usize = 64;
const READ_CHUNK: usize = 32 * 1024;
/// How long an exited command's pipes may stay quiet before its exit is
/// reported without waiting for them to close, as on Linux.
const DRAIN_IDLE: std::time::Duration = std::time::Duration::from_millis(500);

/// The variables a process cannot do without on Windows, kept even for a
/// command that asked for an empty environment: without `SystemRoot`,
/// Winsock and much of the C runtime fail to start.
const ESSENTIAL_ENV: &[&str] = &["SystemRoot", "SystemDrive", "windir", "ComSpec"];

type OutputTx = mpsc::Sender<Result<guestpb::ExecOutput, Status>>;
type OutputRx = mpsc::Receiver<Result<guestpb::ExecOutput, Status>>;

fn chunk(output: Output) -> Result<guestpb::ExecOutput, Status> {
    Ok(guestpb::ExecOutput {
        output: Some(output),
    })
}

/// An environment, keyed without regard to case as Windows looks names up,
/// keeping the case each name was first given in.
#[derive(Default)]
struct Env(HashMap<String, (String, String)>);

impl Env {
    fn set(&mut self, key: &str, value: &str) {
        self.0
            .insert(key.to_uppercase(), (key.to_string(), value.to_string()));
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(&key.to_uppercase())
            .map(|(_, value)| value.as_str())
    }

    fn into_pairs(self) -> Vec<(String, String)> {
        self.0.into_values().collect()
    }
}

/// The environment Windows gives `token`'s user: their profile paths,
/// `USERNAME`, `APPDATA` and the rest, over the machine's own variables.
fn user_environment(token: &token::UserToken) -> Result<Env, Status> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::Environment::{
        CreateEnvironmentBlock, DestroyEnvironmentBlock,
    };
    let mut block = std::ptr::null_mut();
    // SAFETY: `block` is destroyed below.
    win::check(unsafe { CreateEnvironmentBlock(&mut block, token.token.as_raw_handle(), 0) })
        .map_err(|err| Status::internal(format!("{}'s environment: {err}", token.name)))?;
    let mut env = Env::default();
    let mut at = block.cast::<u16>();
    // SAFETY: a block of NUL-terminated strings ending in an empty one.
    unsafe {
        while *at != 0 {
            let entry = win::from_wide_ptr(at);
            at = at.add(entry.encode_utf16().count() + 1);
            // `=C:=C:\` style entries are the shell's per-drive directories.
            if let Some((key, value)) = entry.split_once('=').filter(|(key, _)| !key.is_empty()) {
                env.set(key, value);
            }
        }
        DestroyEnvironmentBlock(block);
    }
    Ok(env)
}

/// The guest's POSIX shell, if it has one: `BURROW_SH` in the agent's
/// environment (a template sets it machine-wide), an `sh.exe` on `PATH`, or
/// Git for Windows' in its default place.
///
/// `bash.exe` on `PATH` is deliberately not looked for: on most Windows
/// images that is `System32\bash.exe`, WSL's launcher, not a shell.
fn posix_shell(path: &str) -> Option<String> {
    let exists = |path: &str| std::path::Path::new(path).is_file();
    if let Ok(shell) = std::env::var("BURROW_SH")
        && exists(&shell)
    {
        return Some(shell);
    }
    if let Some(shell) = path
        .split(';')
        .filter(|dir| !dir.is_empty())
        .map(|dir| format!("{}\\sh.exe", dir.trim_end_matches('\\')))
        .find(|candidate| exists(candidate))
    {
        return Some(shell);
    }
    let program_files = std::env::var("ProgramFiles")
        .unwrap_or_else(|_| format!("{}:\\Program Files", win::system_drive()));
    Some(format!("{program_files}\\Git\\bin\\sh.exe")).filter(|shell| exists(shell))
}

fn cmd_exe() -> String {
    let root = std::env::var("SystemRoot")
        .unwrap_or_else(|_| format!("{}:\\Windows", win::system_drive()));
    format!("{root}\\System32\\cmd.exe")
}

/// Handles one Exec stream: reads the mandatory `Start`, starts the command,
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

    let spawned = {
        let start = start.clone();
        tokio::task::spawn_blocking(move || prepare_and_spawn(&start))
            .await
            .map_err(|err| Status::internal(format!("spawn did not run: {err}")))??
    };
    let Prepared {
        started,
        profile,
        launch,
    } = spawned;
    if launch.is_shell_mapped {
        tracing::debug!(
            cmd = ?start.cmd,
            command_line = launch.command_line,
            "sh -c mapped onto cmd.exe"
        );
    }

    let process::Started {
        process,
        pid,
        tree,
        stdin,
        stdout,
        stderr,
    } = started;
    let signaller: Arc<dyn commands::Signaller> = tree.clone();
    let handle = commands::register(
        start.cmd.clone(),
        start.user.clone(),
        pid as i32,
        Some(signaller),
        commands::Rotation {
            max_bytes: start.log_max_bytes,
            max_files: start.log_max_files.max(1),
        },
    );

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let _ = tx.try_send(chunk(Output::CommandId(handle.id().to_string())));
    let is_pty = start.is_pty;
    tokio::spawn(control(
        feed(inbound, &handle),
        stdin,
        Arc::clone(&tree),
        is_pty,
    ));
    let mut pumps = Vec::new();
    if let Some(out) = stdout {
        pumps.push(tokio::spawn(pump(
            read_in_thread(out),
            tx.clone(),
            handle.clone(),
            Frame::Stdout,
        )));
    }
    if let Some(err) = stderr {
        pumps.push(tokio::spawn(pump(
            read_in_thread(err),
            tx.clone(),
            handle.clone(),
            Frame::Stderr,
        )));
    }
    tokio::spawn(async move {
        let waited = {
            let tree = Arc::clone(&tree);
            tokio::task::spawn_blocking(move || {
                let code = process::wait(&process);
                // Ends what is still attached to the console and lets its
                // output reach EOF, as a pty's slave closing does on Linux.
                if let Some(console) = &tree.console {
                    console.close();
                }
                code
            })
            .await
        };
        // Held until the command is over: its registry hive stays loaded for
        // as long as it runs.
        drop(profile);
        match waited {
            Ok(code) => {
                let (code, signal) = tree.exit_status(code);
                report_exit(code, signal, pumps, tx, handle).await;
            }
            Err(_) => {
                let _ = tx
                    .send(Err(Status::internal("lost track of the child process")))
                    .await;
            }
        }
    });
    Ok(rx)
}

struct Prepared {
    started: process::Started,
    profile: Option<users::Profile>,
    launch: cmdline::Launch,
}

/// Everything up to the process running, which is all blocking work: a
/// logon, a profile load and `CreateProcess`.
fn prepare_and_spawn(start: &guestpb::ExecStart) -> Result<Prepared, Status> {
    // Resolved before anything is spawned: a command asked to run as a user
    // who does not exist must fail as a request, not as a broken child.
    let user = if users::is_agent(&start.user) {
        None
    } else {
        Some(token::logon(&start.user)?)
    };
    let profile = user.as_ref().map(users::load_profile).transpose()?;

    let mut env = Env::default();
    match (&user, start.is_env_cleared) {
        (_, true) => {
            for key in ESSENTIAL_ENV {
                if let Ok(value) = std::env::var(key) {
                    env.set(key, &value);
                }
            }
            // The per-user variables, as Linux keeps HOME, USER and LOGNAME.
            if let (Some(user), Some(profile)) = (&user, &profile) {
                env.set("USERPROFILE", &profile.dir);
                env.set("USERNAME", &user.name);
            }
        }
        (Some(user), false) => env = user_environment(user)?,
        (None, false) => {
            for (key, value) in std::env::vars() {
                env.set(&key, &value);
            }
        }
    }
    for (key, value) in &start.env {
        env.set(key, value);
    }

    let cwd = match (start.cwd.as_str(), &profile) {
        // A user's commands start in their own profile, as on Linux in their
        // home, and everyone else's at the root of the system drive, as on
        // Linux at `/`.
        ("", Some(profile)) => profile.dir.clone(),
        ("", None) => format!("{}:\\", win::system_drive()),
        (cwd, _) => win::map_path(cwd)
            .map_err(|_| Status::invalid_argument(format!("cwd {cwd:?} is not a local path")))?,
    };
    if !std::path::Path::new(&cwd).is_dir() {
        return Err(Status::invalid_argument(format!(
            "cwd {cwd:?}: not a directory"
        )));
    }

    let path = env.get("PATH").unwrap_or_default().to_string();
    let pathext = env
        .get("PATHEXT")
        .unwrap_or(".COM;.EXE;.BAT;.CMD")
        .to_string();
    let launch = cmdline::plan(
        &start.cmd,
        &cmd_exe(),
        posix_shell(&path).as_deref(),
        |program| {
            cmdline::resolve_program(program, &path, &pathext, win::system_drive(), |candidate| {
                std::path::Path::new(candidate).is_file()
            })
        },
    )
    .map_err(|err| match err {
        cmdline::LaunchError::NotFound(_) => {
            Status::failed_precondition(format!("spawn {:?}: {err}", start.cmd[0]))
        }
        _ => Status::invalid_argument(err.to_string()),
    })?;

    let token = user.as_ref().map(token::UserToken::primary).transpose()?;
    let started = process::spawn(process::Spec {
        application: launch.application.clone(),
        command_line: launch.command_line.clone(),
        env: env.into_pairs(),
        cwd,
        token,
        pty: start.is_pty.then_some((start.rows, start.cols)),
    })
    .map_err(|err| Status::failed_precondition(format!("spawn {:?}: {err}", start.cmd[0])))?;
    Ok(Prepared {
        started,
        profile,
        launch,
    })
}

/// Reads a pipe to its end on a thread of its own, as chunks. Bounded, so a
/// chatty command is held up by its pipe rather than by the agent's memory.
fn read_in_thread(mut file: File) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let _ = std::thread::Builder::new()
        .name("exec-output".into())
        .spawn(move || {
            let mut buf = vec![0u8; READ_CHUNK];
            // Broken pipe is how a pipe's end reads on Windows.
            while let Ok(n) = file.read(&mut buf) {
                if n == 0 || tx.blocking_send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
    rx
}

/// Writes stdin on a thread of its own; closing the channel closes stdin.
fn write_in_thread(mut file: File) -> mpsc::Sender<Vec<u8>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    let _ = std::thread::Builder::new()
        .name("exec-input".into())
        .spawn(move || {
            while let Some(bytes) = rx.blocking_recv() {
                if file.write_all(&bytes).is_err() {
                    break;
                }
            }
        });
    tx
}

/// Gives the command an input channel any stream can feed, and feeds it from
/// the stream that started the command for as long as that lasts. As on
/// Linux, only an explicit `is_stdin_eof` closes stdin.
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

/// Input to the child, plus resize and signals.
async fn control(
    mut inbound: mpsc::Receiver<guestpb::ExecInput>,
    stdin: Option<File>,
    tree: Arc<process::Tree>,
    is_pty: bool,
) {
    let mut stdin = stdin.map(write_in_thread);
    while let Some(msg) = inbound.recv().await {
        match msg.input {
            Some(Input::Stdin(bytes)) => {
                let Some(pipe) = &stdin else { continue };
                if pipe.send(bytes).await.is_err() {
                    break;
                }
            }
            // Closing a pseudo console's input would tear the console down;
            // a terminal client sends its EOF character instead, as on Linux.
            Some(Input::IsStdinEof(true)) if !is_pty => drop(stdin.take()),
            Some(Input::IsStdinEof(_)) => {}
            Some(Input::Resize(size)) => {
                if let Some(console) = &tree.console
                    && let Err(err) = console.resize(size.rows, size.cols)
                {
                    tracing::warn!(%err, "pseudo console resize failed");
                }
            }
            Some(Input::Signal(signal)) if tree.signal(signal).is_err() => {
                tracing::warn!(signal, "failed to signal child");
            }
            Some(Input::Signal(_)) => {}
            Some(Input::Start(_)) => {
                tracing::warn!("ignoring duplicate Start on an active Exec stream");
            }
            None => {}
        }
    }
}

/// Reports the exit once the command's output is in, so it is the last thing
/// recorded; a process the command left running can hold its pipes open, so
/// the wait also ends once output stops arriving.
async fn report_exit(
    code: i32,
    signal: i32,
    pumps: Vec<tokio::task::JoinHandle<()>>,
    tx: OutputTx,
    handle: Handle,
) {
    let mut drained = futures::future::join_all(pumps);
    loop {
        let before = handle.produced();
        tokio::select! {
            _ = &mut drained => break,
            () = tokio::time::sleep(DRAIN_IDLE) => {
                if handle.produced() == before && tx.capacity() > 0 {
                    break;
                }
            }
        }
    }
    handle.finish(code, signal);
    for output in (Frame::Exit { code, signal }).outputs() {
        if tx.send(chunk(output)).await.is_err() {
            return;
        }
    }
}

/// Child output to the registry, and to the stream that started it while it
/// lasts. Reading goes on regardless, or the child would block on a pipe
/// nobody is draining.
async fn pump(
    mut chunks: mpsc::Receiver<Vec<u8>>,
    tx: OutputTx,
    handle: Handle,
    wrap: fn(Vec<u8>) -> Frame,
) {
    let mut streaming = true;
    while let Some(bytes) = chunks.recv().await {
        let frame = wrap(bytes);
        let outputs = frame.outputs();
        handle.record(frame);
        for output in outputs {
            if streaming {
                streaming = tx.send(chunk(output)).await.is_ok();
            }
        }
    }
}
