//! Pseudo-terminal support for interactive exec.
//!
//! Without a pty, programs see a pipe and change behaviour: no colour, no
//! progress bars, and REPLs (python, node) refuse to run interactively. The
//! child gets the slave side as its controlling terminal; the agent reads and
//! writes the master.

use std::io;
use std::os::fd::{OwnedFd, RawFd};

use nix::pty::{OpenptyResult, Winsize, openpty};

use crate::asyncfd::AsyncPipe;

pub fn winsize(rows: u32, cols: u32) -> Winsize {
    Winsize {
        // Zero would make the terminal unusable; fall back to a sane default.
        ws_row: if rows == 0 { 24 } else { rows as u16 },
        ws_col: if cols == 0 { 80 } else { cols as u16 },
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

pub struct Pty {
    /// Master end for reading child output.
    pub reader: AsyncPipe,
    /// A duplicate of the master for writing input and resizing. Duplicating
    /// avoids putting the single fd behind a lock shared by both directions.
    pub writer: AsyncPipe,
    /// Slave end; hand copies to the child, then drop it in the parent or
    /// reads on the master never see EOF.
    pub slave: OwnedFd,
}

/// Opens a pty pair sized to `rows`x`cols`.
pub fn open(rows: u32, cols: u32) -> io::Result<Pty> {
    let OpenptyResult { master, slave } = openpty(&winsize(rows, cols), None)
        .map_err(|err| io::Error::from_raw_os_error(err as i32))?;
    let duplicate = master.try_clone()?;
    Ok(Pty {
        reader: AsyncPipe::new(master)?,
        writer: AsyncPipe::new(duplicate)?,
        slave,
    })
}

/// Hands the slave side to `uid`, as a login would.
///
/// The mode is the one `login` and `su` leave a terminal in: readable and
/// writable by its user, writable by the `tty` group where the image has one.
pub fn own(slave: &OwnedFd, uid: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `slave` is an open fd for the duration of both calls.
    unsafe {
        if nix::libc::fchown(slave.as_raw_fd(), uid, u32::MAX) < 0 {
            return Err(io::Error::last_os_error());
        }
        if nix::libc::fchmod(slave.as_raw_fd(), 0o620) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

nix::ioctl_write_ptr_bad!(set_winsize, nix::libc::TIOCSWINSZ, Winsize);

pub fn resize(fd: RawFd, rows: u32, cols: u32) -> io::Result<()> {
    let size = winsize(rows, cols);
    // SAFETY: the fd is a pty master and `size` outlives the call.
    unsafe { set_winsize(fd, &size) }
        .map(|_| ())
        .map_err(|err| io::Error::from_raw_os_error(err as i32))
}
