//! The burrow guest agent.
//!
//! One binary per guest OS, serving the same `Guest` service over vsock:
//!
//! - the OS-neutral core at the top: the service wiring ([`agent`]), the
//!   command registry and output feed ([`commands`]), path scopes and
//!   mapping ([`paths`]) and the errno names ([`errno`]);
//! - `unix`: what POSIX systems share, the `Fs` operations, file transfer as
//!   a user, exec, terminals and the reaper;
//! - `linux`: the microVM's PID 1, its network, systemd mode and vsock;
//! - `macos`: the LaunchDaemon, its handshake, Open Directory accounts and
//!   vsock;
//! - `windows`: the Windows service, ConPTY, job objects, viosock, local
//!   accounts and the Windows `Fs`.

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod agent;
#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
// Elsewhere only its tests are built, which leave the service half unused.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod commands;
#[cfg(any(windows, target_os = "macos", test))]
mod errno;
#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
mod paths;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as os;

// The Windows command-line and network builders are plain logic, built for
// tests everywhere so they run on the machine that cross-compiles the agent.
#[cfg(any(windows, test))]
mod windows;
#[cfg(windows)]
use windows as os;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn main() {
    os::main();
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn main() {
    eprintln!(
        "burrow-guest runs in a Linux, macOS or Windows guest; build it for one of those targets"
    );
    std::process::exit(2);
}
