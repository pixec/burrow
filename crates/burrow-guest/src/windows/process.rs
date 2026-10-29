//! Starting a command's process and holding on to everything it starts.
//!
//! Every command runs in a Job Object of its own, assigned before its first
//! instruction (it is created suspended), so that whatever it starts belongs
//! to the job too. The job is what a signal acts on, as a process group is on
//! Linux: Windows has no signals, and terminating only the first process
//! would leave its children running.
//!
//! What the Linux signals become:
//!
//! - SIGINT: a Ctrl+C. On a pseudo console it is typed, the byte 0x03, which
//!   the console turns into CTRL_C_EVENT for every process attached, as a
//!   terminal's line discipline turns it into SIGINT. A pipe command runs on
//!   a console of its own with no window (`CREATE_NO_WINDOW`), and the event
//!   is raised there by a helper: the agent runs itself as `ctrl-event`,
//!   which attaches to that console and calls `GenerateConsoleCtrlEvent`. A
//!   process may only be attached to one console, so this cannot be done from
//!   the agent without detaching from its own.
//! - SIGQUIT: CTRL_BREAK_EVENT, through the same helper, which is what
//!   Windows programs treat as "quit and maybe dump" (Java prints its
//!   threads, as on SIGQUIT).
//! - SIGTERM, SIGKILL, SIGHUP: `TerminateJobObject`, every process in the
//!   job, with exit code 128 plus the signal, which is reported back as that
//!   signal. Windows has no polite request a console program can be relied
//!   on to honour, so SIGTERM cannot be one.
//! - Anything else: refused as having no Windows equivalent.

use std::fs::File;
use std::io::Write as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JobObjectBasicProcessIdList, QueryInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use crate::commands::{SignalError, Signaller};
use crate::windows::win;

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGQUIT: i32 = 3;
const SIGKILL: i32 = 9;
const SIGTERM: i32 = 15;

/// What a command is started with.
pub struct Spec {
    pub application: String,
    pub command_line: String,
    /// `KEY=VALUE` pairs, already merged.
    pub env: Vec<(String, String)>,
    pub cwd: String,
    /// A primary token to run as, or the agent's own identity.
    pub token: Option<OwnedHandle>,
    /// Rows and columns for a pseudo console, or plain pipes.
    pub pty: Option<(u32, u32)>,
}

/// A started command.
pub struct Started {
    pub process: OwnedHandle,
    pub pid: u32,
    pub tree: Arc<Tree>,
    /// Pipes: stdin to write, stdout and stderr to read. A pseudo console has
    /// only its input and one output, in `stdin` and `stdout`.
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
}

/// A pseudo console, closed once.
pub struct PseudoConsole(Mutex<Option<HPCON>>);

// SAFETY: an HPCON is an opaque handle any thread may use.
unsafe impl Send for PseudoConsole {}
unsafe impl Sync for PseudoConsole {}

fn coord(rows: u32, cols: u32) -> COORD {
    // Zero would make the console unusable; the Linux agent defaults the same.
    COORD {
        X: if cols == 0 {
            80
        } else {
            cols.min(i16::MAX as u32) as i16
        },
        Y: if rows == 0 {
            24
        } else {
            rows.min(i16::MAX as u32) as i16
        },
    }
}

impl PseudoConsole {
    pub fn resize(&self, rows: u32, cols: u32) -> std::io::Result<()> {
        let held = self.0.lock().unwrap();
        let Some(hpc) = *held else { return Ok(()) };
        // SAFETY: the console is open while held.
        let hr = unsafe { ResizePseudoConsole(hpc, coord(rows, cols)) };
        if hr < 0 {
            return Err(std::io::Error::from_raw_os_error(hr));
        }
        Ok(())
    }

    /// Closes the console, which ends what is still attached to it and is
    /// what lets the output pipe reach its end.
    pub fn close(&self) {
        if let Some(hpc) = self.0.lock().unwrap().take() {
            // SAFETY: closed exactly once, here.
            unsafe { ClosePseudoConsole(hpc) };
        }
    }
}

/// A command's job, and how to signal it.
pub struct Tree {
    job: OwnedHandle,
    /// The pseudo console's input, where a Ctrl+C is typed.
    console_input: Option<Arc<File>>,
    pub console: Option<Arc<PseudoConsole>>,
    /// The signal the agent terminated the job with, 0 if it has not.
    terminated_by: AtomicI32,
}

// SAFETY: handles, usable from any thread.
unsafe impl Send for Tree {}
unsafe impl Sync for Tree {}

impl Tree {
    /// Processes still in the job.
    fn pids(&self) -> Vec<u32> {
        // Room for a large tree; a larger one is still signalled, by whichever
        // fit. The ids follow the two counts, at the offset the layout puts
        // them, which is one usize on 64-bit targets.
        const ROOM: usize = 1024;
        let start = std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList)
            / std::mem::size_of::<usize>();
        let mut buf = vec![0usize; start + ROOM];
        // SAFETY: `buf` is the size passed and aligned for the structure.
        let ok = unsafe {
            QueryInformationJobObject(
                self.job.as_raw_handle(),
                JobObjectBasicProcessIdList,
                buf.as_mut_ptr().cast(),
                (buf.len() * std::mem::size_of::<usize>()) as u32,
                std::ptr::null_mut(),
            )
        };
        // ERROR_MORE_DATA still fills in as many as fit.
        if ok == 0 && win::last_error() != 234 {
            return Vec::new();
        }
        // SAFETY: the structure heads the buffer.
        let list = unsafe { &*buf.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
        let count = (list.NumberOfProcessIdsInList as usize).min(ROOM);
        buf[start..start + count]
            .iter()
            .map(|&pid| pid as u32)
            .collect()
    }

    /// What a finished command reports: an exit code 128 plus a signal the
    /// agent ended it with is that signal.
    pub fn exit_status(&self, code: u32) -> (i32, i32) {
        let signal = self.terminated_by.load(Ordering::SeqCst);
        if signal != 0 && code == 128 + signal as u32 {
            return (code as i32, signal);
        }
        (code as i32, 0)
    }

    fn console_event(&self, event: &str) -> Result<(), SignalError> {
        let Some(&pid) = self.pids().first() else {
            return Err(SignalError::Gone(
                "no process is left in the command's job".into(),
            ));
        };
        let exe = std::env::current_exe().map_err(|err| SignalError::Failed(err.to_string()))?;
        use std::os::windows::process::CommandExt as _;
        use windows_sys::Win32::System::Threading::DETACHED_PROCESS;
        let status = std::process::Command::new(exe)
            .args(["ctrl-event", &pid.to_string(), event])
            .creation_flags(DETACHED_PROCESS)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|err| SignalError::Failed(err.to_string()))?;
        if !status.success() {
            return Err(SignalError::Failed(format!(
                "console event helper exited {status}"
            )));
        }
        Ok(())
    }
}

impl Signaller for Tree {
    fn signal(&self, signal: i32) -> Result<(), SignalError> {
        match signal {
            SIGINT => match &self.console_input {
                Some(input) => {
                    if self.pids().is_empty() {
                        return Err(SignalError::Gone(
                            "no process is left in the command's job".into(),
                        ));
                    }
                    (&**input)
                        .write_all(&[0x03])
                        .map_err(|err| SignalError::Failed(err.to_string()))
                }
                None => self.console_event("c"),
            },
            SIGQUIT => self.console_event("break"),
            SIGHUP | SIGKILL | SIGTERM => {
                if self.pids().is_empty() {
                    return Err(SignalError::Gone(
                        "no process is left in the command's job".into(),
                    ));
                }
                self.terminated_by.store(signal, Ordering::SeqCst);
                // SAFETY: the job is open for the life of this value.
                win::check(unsafe {
                    TerminateJobObject(self.job.as_raw_handle(), 128 + signal as u32)
                })
                .map_err(|err| SignalError::Failed(err.to_string()))
            }
            _ => Err(SignalError::Invalid(format!(
                "signal {signal} has no equivalent on a Windows guest"
            ))),
        }
    }
}

/// The `ctrl-event PID c|break` helper: raises a console control event on the
/// console `pid` is attached to.
pub fn ctrl_event_helper(pid: u32, event: &str) -> i32 {
    use windows_sys::Win32::System::Console::{
        AttachConsole, CTRL_BREAK_EVENT, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
        SetConsoleCtrlHandler,
    };
    let event = if event == "break" {
        CTRL_BREAK_EVENT
    } else {
        CTRL_C_EVENT
    };
    // SAFETY: console calls on this short-lived process's own state. The
    // helper ignores the event itself, which it is about to receive too.
    unsafe {
        FreeConsole();
        if AttachConsole(pid) == 0 {
            return 1;
        }
        SetConsoleCtrlHandler(None, 1);
        // Group 0 is every process on the console: the command's tree.
        let ok = GenerateConsoleCtrlEvent(event, 0);
        FreeConsole();
        if ok == 0 { 1 } else { 0 }
    }
}

/// An anonymous pipe, with the end the child gets made inheritable.
fn pipe(child_reads: bool) -> std::io::Result<(File, OwnedHandle)> {
    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: both handles are owned below.
    win::check(unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) })?;
    // SAFETY: fresh handles nothing else owns.
    let (read, write) = unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    };
    let (ours, theirs) = if child_reads {
        (write, read)
    } else {
        (read, write)
    };
    // SAFETY: the handle is open.
    win::check(unsafe {
        SetHandleInformation(
            theirs.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    })?;
    Ok((File::from(ours), theirs))
}

/// A plain anonymous pipe for a pseudo console, which takes both its ends
/// without inheritance.
fn console_pipe() -> std::io::Result<(OwnedHandle, OwnedHandle)> {
    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: both handles are owned below.
    win::check(unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) })?;
    // SAFETY: fresh handles nothing else owns.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

/// An environment block: `KEY=VALUE` strings, each NUL-terminated, sorted
/// without regard to case as Windows expects, and a final NUL.
fn environment_block(env: &[(String, String)]) -> Vec<u16> {
    let mut sorted: Vec<&(String, String)> = env.iter().collect();
    sorted.sort_by_key(|(key, _)| key.to_uppercase());
    let mut block = Vec::new();
    for (key, value) in sorted {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// A `PROC_THREAD_ATTRIBUTE_LIST` and the values it points at, which must
/// outlive the CreateProcess call.
struct Attributes {
    buf: Vec<usize>,
    _handles: Box<[HANDLE]>,
    _hpc: Box<HPCON>,
}

impl Attributes {
    fn new(handles: Vec<HANDLE>, hpc: Option<HPCON>) -> std::io::Result<Self> {
        let count = u32::from(!handles.is_empty()) + u32::from(hpc.is_some());
        let mut size = 0usize;
        // SAFETY: a size query.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size) };
        let mut attributes = Attributes {
            buf: vec![0usize; size.div_ceil(std::mem::size_of::<usize>())],
            _handles: handles.into_boxed_slice(),
            _hpc: Box::new(hpc.unwrap_or(0)),
        };
        let list = attributes.list();
        // SAFETY: `list` has the size just asked for.
        win::check(unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) })?;
        if !attributes._handles.is_empty() {
            // SAFETY: the handle array lives as long as the list.
            win::check(unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    attributes._handles.as_ptr().cast(),
                    std::mem::size_of_val(&*attributes._handles),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            })?;
        }
        if hpc.is_some() {
            // The attribute's value is the HPCON itself, not a pointer to it.
            // SAFETY: as above.
            win::check(unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                    *attributes._hpc as *const std::ffi::c_void,
                    std::mem::size_of::<HPCON>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            })?;
        }
        Ok(attributes)
    }

    fn list(&mut self) -> *mut std::ffi::c_void {
        self.buf.as_mut_ptr().cast()
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: initialised in `new`.
        unsafe { DeleteProcThreadAttributeList(self.list()) };
    }
}

/// Starts `spec`, suspended until it is in its job.
pub fn spawn(spec: Spec) -> std::io::Result<Started> {
    // SAFETY: an unnamed job with default security.
    let job = win::owned(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })?;

    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    // Nothing of the agent's own stdio reaches the child: with a pseudo
    // console the handles are left empty for the console to fill.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    let mut flags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED;

    let mut child_ends = Vec::new();
    let mut console = None;
    let mut console_input = None;
    let (stdin, stdout, stderr, mut attributes) = match spec.pty {
        None => {
            let (ours_in, theirs_in) = pipe(true)?;
            let (ours_out, theirs_out) = pipe(false)?;
            let (ours_err, theirs_err) = pipe(false)?;
            startup.StartupInfo.hStdInput = theirs_in.as_raw_handle();
            startup.StartupInfo.hStdOutput = theirs_out.as_raw_handle();
            startup.StartupInfo.hStdError = theirs_err.as_raw_handle();
            let handles = vec![
                theirs_in.as_raw_handle(),
                theirs_out.as_raw_handle(),
                theirs_err.as_raw_handle(),
            ];
            child_ends.extend([theirs_in, theirs_out, theirs_err]);
            // A console of the command's own, which a Ctrl+C can be raised on
            // without reaching the agent or another command.
            flags |= CREATE_NO_WINDOW;
            (
                Some(ours_in),
                Some(ours_out),
                Some(ours_err),
                Attributes::new(handles, None)?,
            )
        }
        Some((rows, cols)) => {
            let (console_reads, ours_in) = console_pipe()?;
            let (ours_out, console_writes) = console_pipe()?;
            let mut hpc: HPCON = 0;
            // SAFETY: the pipe ends are open; the console duplicates them.
            let hr = unsafe {
                CreatePseudoConsole(
                    coord(rows, cols),
                    console_reads.as_raw_handle(),
                    console_writes.as_raw_handle(),
                    0,
                    &mut hpc,
                )
            };
            if hr < 0 {
                return Err(std::io::Error::from_raw_os_error(hr));
            }
            drop((console_reads, console_writes));
            let input = Arc::new(File::from(ours_in));
            console_input = Some(Arc::clone(&input));
            console = Some(Arc::new(PseudoConsole(Mutex::new(Some(hpc)))));
            let stdin = input.try_clone()?;
            (
                Some(stdin),
                Some(File::from(ours_out)),
                None,
                Attributes::new(Vec::new(), Some(hpc))?,
            )
        }
    };
    startup.lpAttributeList = attributes.list();

    let application = win::wide(&spec.application);
    let mut command_line = win::wide(&spec.command_line);
    let env = environment_block(&spec.env);
    let cwd = win::wide(&spec.cwd);
    // A user's process gets a window station and desktop of its own logon
    // session rather than the agent's, which it would have no access to:
    // the empty desktop name asks for exactly that.
    let mut empty_desktop = win::wide("");
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let inherit = i32::from(spec.pty.is_none());
    // SAFETY: every pointer is to a live local that outlives the call.
    let ok = unsafe {
        match &spec.token {
            Some(token) => {
                startup.StartupInfo.lpDesktop = empty_desktop.as_mut_ptr();
                CreateProcessAsUserW(
                    token.as_raw_handle(),
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    inherit,
                    flags,
                    env.as_ptr().cast(),
                    cwd.as_ptr(),
                    &startup.StartupInfo,
                    &mut info,
                )
            }
            None => CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                inherit,
                flags,
                env.as_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            ),
        }
    };
    if ok == 0 {
        let err = win::last_io_error();
        if let Some(console) = &console {
            console.close();
        }
        return Err(err);
    }
    drop(attributes);
    drop(child_ends);
    // SAFETY: handles CreateProcess returned to us.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };
    // SAFETY: both handles are open.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        let err = win::last_io_error();
        // SAFETY: the process never ran; nothing else holds it.
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(process.as_raw_handle(), 1)
        };
        return Err(err);
    }
    // SAFETY: the main thread, created suspended.
    unsafe { ResumeThread(thread.as_raw_handle()) };
    Ok(Started {
        process,
        pid: info.dwProcessId,
        tree: Arc::new(Tree {
            job,
            console_input,
            console,
            terminated_by: AtomicI32::new(0),
        }),
        stdin,
        stdout,
        stderr,
    })
}

/// Waits for the process to exit, on the calling thread, and returns its
/// exit code.
pub fn wait(process: &OwnedHandle) -> u32 {
    // SAFETY: the handle is open for both calls.
    unsafe {
        if WaitForSingleObject(process.as_raw_handle(), INFINITE) != WAIT_OBJECT_0 {
            return u32::MAX;
        }
        let mut code = 0u32;
        GetExitCodeProcess(process.as_raw_handle(), &mut code);
        code
    }
}
