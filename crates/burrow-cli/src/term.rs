//! Local terminal handling for interactive exec.
//!
//! An interactive session has two terminals: the pty the agent gives the guest
//! command, and the one the user is sitting at. The local one has to stop
//! interpreting input itself, or ^C and arrow keys are handled here instead of
//! reaching the program in the sandbox.

use std::cell::UnsafeCell;
use std::io::IsTerminal;
use std::mem::MaybeUninit;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::libc;
use nix::pty::Winsize;
use nix::sys::termios::{self, SetArg, Termios};

nix::ioctl_read_bad!(get_winsize, nix::libc::TIOCGWINSZ, Winsize);

/// Rows and columns of the local terminal, when there is one.
pub fn size() -> Option<(u32, u32)> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return None;
    }
    let mut size = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: stdin is a terminal, and `size` outlives the call.
    let fd = std::os::fd::AsRawFd::as_raw_fd(&stdin);
    unsafe { get_winsize(fd, &mut size) }.ok()?;
    if size.ws_row == 0 || size.ws_col == 0 {
        return None;
    }
    Some((size.ws_row as u32, size.ws_col as u32))
}

/// The terminal settings a signal handler puts back.
///
/// A handler cannot take a lock or allocate, so the saved state lives in a
/// static and `SAVED` says whether it holds anything. It is written once,
/// before the handlers that read it are installed, and cleared when raw mode
/// ends, so the handler never sees a half-written struct or restores settings
/// that are no longer current.
struct Saved(UnsafeCell<MaybeUninit<libc::termios>>);

// SAFETY: written only by `RawMode::enable`, before any handler that reads it
// exists, and read only by handlers, which check `SAVED` first.
unsafe impl Sync for Saved {}

static ORIGINAL: Saved = Saved(UnsafeCell::new(MaybeUninit::uninit()));
static SAVED: AtomicBool = AtomicBool::new(false);
static HANDLERS: Once = Once::new();

/// Puts the terminal back, then dies of the signal that got us here.
///
/// `Drop` covers every path this process takes on its own, but a SIGTERM or a
/// SIGHUP runs no destructor, and the shell that gets the tty back finds it in
/// raw mode with no echo. Re-raising after restoring the default disposition
/// leaves the parent seeing a process killed by the signal rather than one
/// that exited normally.
extern "C" fn restore_and_reraise(signal: libc::c_int) {
    if SAVED.load(Ordering::Acquire) {
        // SAFETY: initialised before this handler was installed, and only read
        // here. `tcsetattr` is a bare syscall, so it is safe in a handler; the
        // nix wrapper is avoided because it borrows a `Termios` we do not have.
        unsafe {
            libc::tcsetattr(
                libc::STDIN_FILENO,
                libc::TCSANOW,
                (*ORIGINAL.0.get()).as_ptr(),
            );
        }
    }
    // SAFETY: both are async-signal-safe.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

/// Raw mode, restored when this guard is dropped, or when the process is
/// signalled out from under the guard.
///
/// The guard is the only way to enable it: a CLI that exits with the terminal
/// still raw leaves the user's shell unusable, so the restore has to happen on
/// every path out, including an error one.
pub struct RawMode(Termios);

impl RawMode {
    pub fn enable() -> anyhow::Result<Self> {
        let stdin = std::io::stdin();
        let original = termios::tcgetattr(&stdin)?;

        // Saved before raw mode is entered, so a signal arriving between the
        // two finds either nothing to restore or the settings still in force.
        // SAFETY: the handlers that read this are installed below, and this is
        // the only writer.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, (*ORIGINAL.0.get()).as_mut_ptr()) } == 0 {
            SAVED.store(true, Ordering::Release);
            HANDLERS.call_once(|| {
                for signal in [libc::SIGTERM, libc::SIGHUP] {
                    // SAFETY: the handler only makes async-signal-safe calls.
                    unsafe {
                        libc::signal(
                            signal,
                            restore_and_reraise as *const () as libc::sighandler_t,
                        )
                    };
                }
            });
        }

        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&stdin, SetArg::TCSANOW, &raw)?;
        Ok(Self(original))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // Nothing useful to do if the restore fails, and reporting it would
        // scribble over whatever the command last printed.
        let _ = termios::tcsetattr(std::io::stdin(), SetArg::TCSANOW, &self.0);
        // The handler has nothing left to put back, and the settings it holds
        // are the ones now in force anyway.
        SAVED.store(false, Ordering::Release);
    }
}
