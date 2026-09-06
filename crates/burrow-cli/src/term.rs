//! Local terminal handling for interactive exec.
//!
//! An interactive session has two terminals: the pty the agent gives the guest
//! command, and the one the user is sitting at. The local one has to stop
//! interpreting input itself, or ^C and arrow keys are handled here instead of
//! reaching the program in the sandbox.

use std::io::IsTerminal;

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

/// Raw mode, restored when this guard is dropped.
///
/// The guard is the only way to enable it: a CLI that exits with the terminal
/// still raw leaves the user's shell unusable, so the restore has to happen on
/// every path out, including an error one.
pub struct RawMode(Termios);

impl RawMode {
    pub fn enable() -> anyhow::Result<Self> {
        let stdin = std::io::stdin();
        let original = termios::tcgetattr(&stdin)?;
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
    }
}
