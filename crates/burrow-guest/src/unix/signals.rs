//! Signal numbers as the protocol carries them.
//!
//! The wire uses Linux's numbers: they are what every SDK and the host were
//! written against, and Windows maps the same ones. On Linux that is the
//! kernel's own numbering. macOS shares the classic ones (HUP through ABRT,
//! FPE, KILL, SEGV, PIPE, ALRM, TERM) and numbers the others differently, so
//! it translates both ways.

use nix::errno::Errno;
use nix::sys::signal::Signal;

#[cfg(target_os = "linux")]
pub fn from_wire(signal: i32) -> Result<Signal, Errno> {
    Signal::try_from(signal)
}

#[cfg(target_os = "linux")]
pub fn to_wire(signal: Signal) -> i32 {
    signal as i32
}

/// Linux's number for each signal macOS has. SIGEMT and SIGINFO have no
/// Linux counterpart and are neither sent nor reported by number.
#[cfg(target_os = "macos")]
const LINUX: &[(i32, Signal)] = &[
    (1, Signal::SIGHUP),
    (2, Signal::SIGINT),
    (3, Signal::SIGQUIT),
    (4, Signal::SIGILL),
    (5, Signal::SIGTRAP),
    (6, Signal::SIGABRT),
    (7, Signal::SIGBUS),
    (8, Signal::SIGFPE),
    (9, Signal::SIGKILL),
    (10, Signal::SIGUSR1),
    (11, Signal::SIGSEGV),
    (12, Signal::SIGUSR2),
    (13, Signal::SIGPIPE),
    (14, Signal::SIGALRM),
    (15, Signal::SIGTERM),
    (17, Signal::SIGCHLD),
    (18, Signal::SIGCONT),
    (19, Signal::SIGSTOP),
    (20, Signal::SIGTSTP),
    (21, Signal::SIGTTIN),
    (22, Signal::SIGTTOU),
    (23, Signal::SIGURG),
    (24, Signal::SIGXCPU),
    (25, Signal::SIGXFSZ),
    (26, Signal::SIGVTALRM),
    (27, Signal::SIGPROF),
    (28, Signal::SIGWINCH),
    (29, Signal::SIGIO),
    (31, Signal::SIGSYS),
];

#[cfg(target_os = "macos")]
pub fn from_wire(signal: i32) -> Result<Signal, Errno> {
    LINUX
        .iter()
        .find(|(linux, _)| *linux == signal)
        .map(|(_, native)| *native)
        .ok_or(Errno::EINVAL)
}

/// A signal without a Linux number is reported by its macOS one, which is
/// at least the number the process really died of.
#[cfg(target_os = "macos")]
pub fn to_wire(signal: Signal) -> i32 {
    LINUX
        .iter()
        .find(|(_, native)| *native == signal)
        .map_or(signal as i32, |(linux, _)| *linux)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn the_numbers_that_differ_are_translated_both_ways() {
        assert_eq!(from_wire(10), Ok(Signal::SIGUSR1));
        assert_eq!(Signal::SIGUSR1 as i32, 30);
        assert_eq!(to_wire(Signal::SIGUSR1), 10);
        assert_eq!(from_wire(19), Ok(Signal::SIGSTOP));
        assert_eq!(to_wire(Signal::SIGCHLD), 17);
        assert_eq!(from_wire(15), Ok(Signal::SIGTERM));
        assert_eq!(from_wire(16), Err(Errno::EINVAL));
        for (linux, native) in LINUX {
            assert_eq!(to_wire(*native), *linux);
        }
    }
}
