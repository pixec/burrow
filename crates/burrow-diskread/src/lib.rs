//! Reading a guest's disk without trusting it.
//!
//! A guest controls every byte of its disk, so the host kernel never mounts
//! one and burrowd never parses one. The reader here does, in a process of
//! its own started from burrowd's binary. Before it reads a byte of the image
//! it confines itself: another user, its own network namespace, memory, CPU
//! and file limits, and a seccomp filter under which it can only read its
//! requests and the image, write its answers, and manage its own memory. It
//! is handed the image as a read-only descriptor and answers over pipes:
//! list a directory, stat a path, read part of a file, or stream a tree as a
//! tar archive.
//!
//! The filesystem is read with `ext4-view`, extended with inode numbers,
//! link counts and extended attributes (`vendor/ext4-view`). It replays a
//! journal in memory rather than ignoring it, so a disk whose guest was
//! stopped mid-transaction reads as the guest would see it on its next boot.

mod client;
#[cfg(target_os = "linux")]
mod confine;
mod image;
pub mod protocol;
mod server;

pub use client::{Limits, Reader};
pub use image::Image;

/// Why a tar stopped when whoever took its chunks stopped taking them.
pub const RECEIVER_GONE: &str = "the archive's receiver went away";

/// The argument burrowd is started with to be a reader.
pub const SUBCOMMAND: &str = "disk-reader";

/// Becomes a reader and never returns when this process was started as one.
/// Called first thing in `main`, before any thread exists: the seccomp
/// filter a reader installs holds only the thread that installs it.
pub fn run_if_reader() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(SUBCOMMAND) {
        server::serve(&args[2..]);
    }
}
