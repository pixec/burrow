//! Running as a Windows service, installing as one, and upgrading in place.
//!
//! `burrow-guest.exe` takes one subcommand:
//!
//! - `service`: what the Service Control Manager starts. With no subcommand
//!   the agent tries this first and falls back to `console` when it was not
//!   started by the SCM.
//! - `console`: serves in the foreground, logging to stderr, for debugging.
//! - `install [--start]`: registers the `burrow-guest` service for the binary
//!   where it is, as LocalSystem, started at boot, restarted when it exits
//!   with a failure (which is how an upgrade restarts it).
//! - `uninstall`: removes the service.
//! - `ctrl-event PID c|break`: the helper that raises a console control
//!   event for a SIGINT or SIGQUIT (see [`super::process`]).

#![allow(clippy::result_large_err)]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use tokio_stream::StreamExt as _;
use tonic::Status;
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, RegisterServiceCtrlHandlerExW, SC_ACTION, SC_ACTION_RESTART,
    SC_HANDLE, SC_MANAGER_ALL_ACCESS, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONS_FLAG,
    SERVICE_FAILURE_ACTIONSW, SERVICE_NO_CHANGE, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW,
};

use burrow_proto::guest::v1 as guestpb;

use crate::windows::{fs, vsock, win};

/// vsock port the node daemon dials, as on Linux.
const AGENT_PORT: u32 = 1024;
const SERVICE_NAME: &str = "burrow-guest";
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// What `StartServiceCtrlDispatcherW` fails with in a process the SCM did not
/// start.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;
const ERROR_SERVICE_EXISTS: u32 = 1073;
const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;

/// The privileges LocalSystem holds disabled that the agent's work needs:
/// the clock, S4U logons and the processes started with their tokens,
/// owners and ACLs set on others' files, and symlinks.
const PRIVILEGES: &[&str] = &[
    "SeSystemtimePrivilege",
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeRestorePrivilege",
    "SeBackupPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeCreateSymbolicLinkPrivilege",
];

/// The SCM's handle on this service, once it is running as one.
static STATUS_HANDLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static STATE: AtomicU32 = AtomicU32::new(0);

pub fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("console") => run(false),
        Some("service") => dispatch(),
        Some("install") => report(install(args.iter().any(|arg| arg == "--start"))),
        Some("uninstall") => report(uninstall()),
        Some("ctrl-event") => match (args.get(1).and_then(|pid| pid.parse().ok()), args.get(2)) {
            (Some(pid), Some(event)) => crate::windows::process::ctrl_event_helper(pid, event),
            _ => usage(),
        },
        None => match dispatch() {
            0 => 0,
            _ => run(false),
        },
        Some(_) => usage(),
    };
    std::process::exit(code);
}

fn usage() -> i32 {
    eprintln!("usage: burrow-guest [service | console | install [--start] | uninstall]");
    2
}

fn report(result: std::io::Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("burrow-guest: {err}");
            1
        }
    }
}

/// Hands this thread to the SCM, which calls [`service_main`] on another.
/// Non-zero when this process was not started as a service.
fn dispatch() -> i32 {
    let mut name = win::wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table and the name outlive the call, which returns once
    // the service has stopped.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        if win::last_error() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            return 1;
        }
        eprintln!("burrow-guest: service dispatcher: {}", win::last_io_error());
        return 1;
    }
    0
}

fn set_state(state: u32, exit_code: u32, specific: u32) {
    STATE.store(state, Ordering::SeqCst);
    let handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: specific,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: the handle the SCM gave this service.
    unsafe { SetServiceStatus(handle, &status) };
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event: u32,
    _data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP => {
            set_state(SERVICE_STOPPED, 0, 0);
            std::process::exit(0);
        }
        SERVICE_CONTROL_INTERROGATE => {
            set_state(STATE.load(Ordering::SeqCst), 0, 0);
            0
        }
        // ERROR_CALL_NOT_IMPLEMENTED.
        _ => 120,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = win::wide(SERVICE_NAME);
    // SAFETY: registers this process's handler for the service the SCM is
    // starting; the name is NUL-terminated.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), std::ptr::null())
    };
    STATUS_HANDLE.store(handle, Ordering::SeqCst);
    set_state(SERVICE_START_PENDING, 0, 0);
    let code = run(true);
    set_state(
        SERVICE_STOPPED,
        if code == 0 {
            0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
        code as u32,
    );
}

/// Whether this process is the SCM's service rather than a console run.
fn is_service() -> bool {
    !STATUS_HANDLE.load(Ordering::SeqCst).is_null()
}

fn init_logging(is_service: bool) {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into());
    // A service has no console; its log goes beside its other state.
    if is_service
        && let Ok(file) = std::fs::create_dir_all(win::state_dir()).and_then(|()| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(win::state_dir().join("burrow-guest.log"))
        })
    {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init();
        return;
    }
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn commands_state() -> std::path::PathBuf {
    win::state_dir().join("burrow-guest.commands")
}

fn run(is_service: bool) -> i32 {
    init_logging(is_service);
    if let Err(err) = win::enable_privileges(PRIVILEGES) {
        tracing::warn!(%err, "could not adjust the agent's privileges");
    }
    // What the last upgrade replaced; it could not be removed while it ran.
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(exe.with_extension("exe.old"));
    }
    crate::commands::restore(&commands_state().to_string_lossy(), |_| None);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!(%err, "no runtime");
            return 1;
        }
    };
    runtime.block_on(async {
        let listener = match vsock::listen_on(AGENT_PORT) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(%err, "cannot listen on vsock");
                return 1;
            }
        };
        set_state(SERVICE_RUNNING, 0, 0);
        tracing::debug!(
            port = AGENT_PORT,
            version = VERSION,
            "burrow-guest listening on vsock"
        );
        tokio::spawn(fs::close_idle());
        let incoming =
            tokio_stream::wrappers::ReceiverStream::new(listener).map(Ok::<_, std::io::Error>);
        match tonic::transport::Server::builder()
            .add_service(crate::agent::service())
            .serve_with_incoming(incoming)
            .await
        {
            Ok(()) => 0,
            Err(err) => {
                tracing::error!(%err, "agent server exited");
                1
            }
        }
    })
}

/// SHA-256 of the binary this process is running, as the host compares it.
pub fn self_digest() -> &'static str {
    static DIGEST: OnceLock<String> = OnceLock::new();
    DIGEST.get_or_init(|| {
        use sha2::Digest as _;
        std::env::current_exe()
            .and_then(std::fs::read)
            .map(|bytes| {
                sha2::Sha256::digest(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Replaces this agent with the binary streamed in, then restarts.
///
/// Written beside the running binary and verified before anything changes.
/// A running executable cannot be overwritten on Windows but can be renamed,
/// so the old one moves aside and the new one takes its name. A service then
/// stops with a failure, which the restart action [`install`] configured
/// turns into a start of the new binary; a console run starts it directly.
/// The finished-command table goes across as on Linux. Open `Fs` handles do
/// not: they belong to this process.
pub async fn upgrade(
    mut stream: tonic::Streaming<guestpb::UpgradeChunk>,
) -> Result<guestpb::UpgradeResponse, Status> {
    use sha2::Digest as _;
    use tokio::io::AsyncWriteExt as _;
    let exe =
        std::env::current_exe().map_err(|err| Status::internal(format!("own path: {err}")))?;
    let temp = exe.with_extension(format!("{}.new", std::process::id()));
    let mut file = tokio::fs::File::create(&temp)
        .await
        .map_err(|err| Status::internal(format!("creating {}: {err}", temp.display())))?;
    let mut hasher = sha2::Sha256::new();
    let mut expected = String::new();
    let mut written = 0usize;
    while let Some(chunk) = stream.message().await? {
        if !chunk.digest.is_empty() {
            expected = chunk.digest;
        }
        hasher.update(&chunk.data);
        file.write_all(&chunk.data)
            .await
            .map_err(|err| Status::internal(format!("writing {}: {err}", temp.display())))?;
        written += chunk.data.len();
    }
    file.sync_all()
        .await
        .map_err(|err| Status::internal(format!("syncing {}: {err}", temp.display())))?;
    drop(file);
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if written == 0 || expected.is_empty() || actual != expected {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(Status::invalid_argument(format!(
            "upgrade binary hashed as {actual}, expected {expected}"
        )));
    }
    if actual == self_digest() {
        let _ = tokio::fs::remove_file(&temp).await;
        return Ok(guestpb::UpgradeResponse {
            is_restarting: false,
        });
    }
    let old = exe.with_extension("exe.old");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old)
        .map_err(|err| Status::internal(format!("moving the old agent aside: {err}")))?;
    if let Err(err) = std::fs::rename(&temp, &exe) {
        let _ = std::fs::rename(&old, &exe);
        return Err(Status::internal(format!("installing the new agent: {err}")));
    }
    if let Err(err) = crate::commands::save(&commands_state().to_string_lossy()) {
        tracing::warn!(%err, "command history will not survive the upgrade");
    }
    tracing::warn!(digest = actual, "agent upgrading; restarting");
    // After the response has gone out.
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if is_service() {
            set_state(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 1);
            std::process::exit(1);
        }
        let args: Vec<String> = std::env::args().skip(1).collect();
        match std::process::Command::new(&exe).args(&args).spawn() {
            Ok(_) => std::process::exit(0),
            Err(err) => tracing::error!(%err, "restart failed; the old agent keeps serving"),
        }
    });
    Ok(guestpb::UpgradeResponse {
        is_restarting: true,
    })
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: opened by this module and closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn sc(handle: SC_HANDLE) -> std::io::Result<ScHandle> {
    if handle.is_null() {
        Err(win::last_io_error())
    } else {
        Ok(ScHandle(handle))
    }
}

/// Registers the service for this binary, where it is: a template build
/// copies the binary into place and runs `install` from there.
fn install(is_starting: bool) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let command = win::wide(&format!("\"{}\" service", exe.display()));
    let name = win::wide(SERVICE_NAME);
    let display = win::wide("Burrow guest agent");
    // SAFETY: local SCM, all access; closed on drop.
    let scm =
        sc(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS) })?;
    // SAFETY: every string is NUL-terminated; a null account is LocalSystem.
    let created = unsafe {
        CreateServiceW(
            scm.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    let service = if created.is_null() && win::last_error() == ERROR_SERVICE_EXISTS {
        // SAFETY: as above.
        let service = sc(unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_ALL_ACCESS) })?;
        // SAFETY: points the existing service at this binary.
        win::check(unsafe {
            ChangeServiceConfigW(
                service.0,
                SERVICE_NO_CHANGE,
                SERVICE_AUTO_START,
                SERVICE_NO_CHANGE,
                command.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        })?;
        service
    } else {
        sc(created)?
    };

    let mut description = win::wide("Serves the burrow node daemon over vsock.");
    let description = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_mut_ptr(),
    };
    // Restarted a second after any exit that is not a clean stop, the last
    // action repeating for every failure after the third: an upgrade exits
    // with a failure on purpose, and a crash should not leave the sandbox
    // without its agent.
    let mut actions = [SC_ACTION {
        Type: SC_ACTION_RESTART,
        Delay: 1000,
    }; 3];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    let flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: 1,
    };
    // SAFETY: each structure is the one its level reads.
    unsafe {
        win::check(ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            (&raw const description).cast(),
        ))?;
        win::check(ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&raw const failure).cast(),
        ))?;
        win::check(ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&raw const flag).cast(),
        ))?;
    }
    if is_starting {
        // SAFETY: starts the service with no arguments.
        win::check(unsafe { StartServiceW(service.0, 0, std::ptr::null()) })?;
    }
    Ok(())
}

fn uninstall() -> std::io::Result<()> {
    let name = win::wide(SERVICE_NAME);
    // SAFETY: as in `install`.
    let scm =
        sc(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS) })?;
    let service = sc(unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_ALL_ACCESS) })?;
    // SAFETY: marks the service for deletion.
    win::check(unsafe { DeleteService(service.0) })
}
