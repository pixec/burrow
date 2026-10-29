//! What a POSIX guest agent does the same on any POSIX system.
//!
//! Linux and macOS share this code. Where they differ is in how a path is
//! resolved and held, which `files` and `fs` do per system behind `cfg`; see
//! the crate's README for what each one's checks amount to.

pub mod asyncfd;
pub mod exec;
pub mod files;
pub mod fs;
pub mod pty;
pub mod reaper;
pub mod signals;

/// What the macOS SDK declares and `libc` does not bind yet.
#[cfg(target_os = "macos")]
pub mod darwin {
    use nix::libc::{c_int, gid_t, uid_t};

    /// open(2): resolution may not leave the directory descriptor.
    pub const O_RESOLVE_BENEATH: c_int = 0x1000;
    /// The `*at` calls: no symlink anywhere in the path, the last component
    /// included.
    pub const AT_SYMLINK_NOFOLLOW_ANY: c_int = 0x0800;

    unsafe extern "C" {
        /// Gives the calling thread its own credentials, as `uid` with `gid`
        /// as its only group; a later setgroups(2) on the thread changes that
        /// thread's groups and nobody else's. Needs a root process. Threads
        /// the thread starts inherit them.
        pub fn pthread_setugid_np(uid: uid_t, gid: gid_t) -> c_int;
        /// Gives the calling thread a working directory of its own, the
        /// directory `fd` is open on; -1 returns it to the process's.
        /// Apple's own fts(3) uses it; the SDK does not declare it.
        pub fn pthread_fchdir_np(fd: c_int) -> c_int;
    }
}
