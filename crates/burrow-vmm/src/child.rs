//! Spawning a VMM straight into its cgroup.
//!
//! Writing a pid into `cgroup.procs` takes the kernel's threadgroup lock for
//! writing, which waits out an RCU grace period: 10 to 20 ms per VM, paid on
//! every create. `clone3` with `CLONE_INTO_CGROUP` places the child at fork
//! instead, with no migration and no wait. A kernel or seccomp profile
//! without it gets the write, from the child before it execs.

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::ExitStatus;

/// A child process, killed when dropped unless it has been reaped.
pub struct Child {
    pid: libc::pid_t,
    /// Readable once the child exits; `None` where the kernel has no pidfds,
    /// and the exit is polled for.
    #[cfg(target_os = "linux")]
    pidfd: Option<tokio::io::unix::AsyncFd<OwnedFd>>,
    status: Option<ExitStatus>,
}

/// A spawned child and the parent's ends of its standard streams.
pub struct Spawned {
    pub child: Child,
    pub stdin: OwnedFd,
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
}

/// `struct clone_args`, as far as `cgroup` (`CLONE_ARGS_SIZE_VER2`).
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

#[cfg(target_os = "linux")]
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

#[cfg(target_os = "linux")]
fn cstring(value: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::CString::new(value.as_bytes())
        .map_err(|_| io::Error::other("an argument holds a NUL"))
}

/// `fd` moved above the standard streams, so a parent started with them
/// closed never hands the child a descriptor that its own `dup2`s onto 0, 1
/// and 2 would clobber or leave close-on-exec.
#[cfg(target_os = "linux")]
fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    // SAFETY: duplicates a descriptor this function owns.
    let moved = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if moved < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl just opened it and nothing else names it.
    Ok(unsafe { OwnedFd::from_raw_fd(moved) })
}

#[cfg(target_os = "linux")]
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd as _;
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both were just opened and are owned nowhere else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    Ok((above_stdio(read)?, above_stdio(write)?))
}

#[cfg(target_os = "linux")]
fn open_above_stdio(path: &Path, write: bool) -> io::Result<OwnedFd> {
    let file = std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .open(path)?;
    above_stdio(file.into())
}

/// Runs `program` with `args` in `cwd`, inside the cgroup directory
/// `cgroup` from its first instruction when one is given.
#[cfg(target_os = "linux")]
pub async fn spawn(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    cgroup: Option<&Path>,
) -> io::Result<Spawned> {
    use tokio::io::AsyncReadExt as _;
    let (spawned, status_read) = start(program, args, cwd, cgroup)?;
    let mut errno = Vec::new();
    tokio::net::unix::pipe::Receiver::from_owned_fd(status_read)?
        .read_to_end(&mut errno)
        .await?;
    if let Ok(errno) = <[u8; 4]>::try_from(errno.as_slice()) {
        return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(errno)));
    }
    if !errno.is_empty() {
        return Err(io::Error::other(
            "the child reported a malformed exec failure",
        ));
    }
    Ok(spawned)
}

/// The child started and the read end of its exec status pipe, which reaches
/// end of file once the exec succeeds.
#[cfg(target_os = "linux")]
fn start(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    cgroup: Option<&Path>,
) -> io::Result<(Spawned, OwnedFd)> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let program = cstring(program.as_os_str())?;
    let argv: Vec<std::ffi::CString> = std::iter::once(Ok(program.clone()))
        .chain(args.iter().map(|arg| cstring(arg)))
        .collect::<io::Result<_>>()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let cwd = cstring(cwd.as_os_str())?;

    let (stdin_read, stdin_write) = pipe()?;
    let (stdout_read, stdout_write) = pipe()?;
    let (stderr_read, stderr_write) = pipe()?;
    // Carries errno back if exec fails; closed by the exec when it succeeds.
    let (status_read, status_write) = pipe()?;
    let cgroup_dir = cgroup.map(|dir| open_above_stdio(dir, false)).transpose()?;
    let cgroup_procs = cgroup
        .map(|dir| open_above_stdio(&dir.join("cgroup.procs"), true))
        .transpose()?;

    let mut pidfd: libc::c_int = -1;
    let clone = |into_cgroup: bool, pidfd: &mut libc::c_int| {
        let mut args = CloneArgs {
            flags: libc::CLONE_PIDFD as u64,
            pidfd: std::ptr::from_mut(pidfd) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };
        if let (true, Some(dir)) = (into_cgroup, &cgroup_dir) {
            args.flags |= CLONE_INTO_CGROUP;
            args.cgroup = dir.as_raw_fd() as u64;
        }
        // SAFETY: a fork-style clone3 (no CLONE_VM, no new stack). The child
        // runs only async-signal-safe calls on memory prepared above before
        // exec or _exit, so no lock another thread held at the fork is ever
        // taken in it.
        let pid = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                std::ptr::addr_of_mut!(args),
                std::mem::size_of::<CloneArgs>(),
            )
        };
        (pid, io::Error::last_os_error().raw_os_error())
    };
    // Joined by the child's own write when it could not be cloned into the
    // cgroup: a kernel before 5.7 refuses the flag, and one before 5.3 or a
    // seccomp profile (Docker's default) has no clone3 at all.
    let mut is_joining = false;
    let (mut pid, mut errno) = clone(true, &mut pidfd);
    if pid < 0 && errno == Some(libc::EINVAL) && cgroup_dir.is_some() {
        is_joining = true;
        (pid, errno) = clone(false, &mut pidfd);
    }
    if pid < 0 && errno == Some(libc::ENOSYS) {
        is_joining = cgroup_dir.is_some();
        pidfd = -1;
        // SAFETY: as for clone3 above.
        pid = unsafe { libc::fork() } as libc::c_long;
    }
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: the child side; see above.
        unsafe {
            let fail = |fd: libc::c_int| -> ! {
                let errno = *libc::__errno_location();
                libc::write(fd, std::ptr::addr_of!(errno).cast(), 4);
                libc::_exit(127)
            };
            let status = status_write.as_raw_fd();
            if let (true, Some(procs)) = (is_joining, &cgroup_procs)
                && libc::write(procs.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1
            {
                fail(status);
            }
            for (from, to) in [
                (stdin_read.as_raw_fd(), 0),
                (stdout_write.as_raw_fd(), 1),
                (stderr_write.as_raw_fd(), 2),
            ] {
                if libc::dup2(from, to) < 0 {
                    fail(status);
                }
            }
            // Rust ignores SIGPIPE, and a signal ignored across exec stays
            // ignored; the mask is the spawning thread's.
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            if libc::chdir(cwd.as_ptr()) < 0 {
                fail(status);
            }
            libc::execv(program.as_ptr(), argv_ptrs.as_ptr());
            fail(status)
        }
    }

    // Held from here on, so any failure below kills the child as it returns.
    let mut child = Child {
        pid: pid as libc::pid_t,
        pidfd: None,
        status: None,
    };
    drop((
        status_write,
        stdin_read,
        stdout_write,
        stderr_write,
        cgroup_dir,
        cgroup_procs,
    ));
    if pidfd < 0 {
        // SAFETY: opens a pidfd for this process's own unreaped child.
        pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.pid, 0) } as libc::c_int;
    }
    if pidfd >= 0 {
        // SAFETY: a descriptor CLONE_PIDFD or pidfd_open gave this process.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        child.pidfd = Some(tokio::io::unix::AsyncFd::with_interest(
            pidfd,
            tokio::io::Interest::READABLE,
        )?);
    }
    Ok((
        Spawned {
            child,
            stdin: stdin_write,
            stdout: stdout_read,
            stderr: stderr_read,
        },
        status_read,
    ))
}

/// Elsewhere there is no cgroup to clone into, and only the tests run a VMM.
#[cfg(not(target_os = "linux"))]
pub async fn spawn(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    cgroup: Option<&Path>,
) -> io::Result<Spawned> {
    use std::process::Stdio;
    if cgroup.is_some() {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let mut child = std::process::Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let taken = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(stdin), Some(stdout), Some(stderr)) = taken else {
        unreachable!("every stream is piped");
    };
    Ok(Spawned {
        child: Child {
            pid: child.id() as libc::pid_t,
            status: None,
        },
        stdin: stdin.into(),
        stdout: stdout.into(),
        stderr: stderr.into(),
    })
}

impl Child {
    pub fn id(&self) -> Option<u32> {
        self.status.is_none().then_some(self.pid as u32)
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        let mut raw = 0;
        // SAFETY: `pid` is this process's own unreaped child.
        match unsafe { libc::waitpid(self.pid, &mut raw, libc::WNOHANG) } {
            0 => Ok(None),
            pid if pid == self.pid => {
                self.status = Some(ExitStatus::from_raw(raw));
                Ok(self.status)
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn start_kill(&mut self) -> io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        // SAFETY: an unreaped child's pid cannot have been reused.
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            match &self.pidfd {
                Some(pidfd) => pidfd.readable().await?.clear_ready(),
                None => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.status.is_some() || self.start_kill().is_err() {
            return;
        }
        let pid = self.pid;
        std::thread::spawn(move || {
            let mut raw = 0;
            // SAFETY: reaps the child just killed, which nothing else waits on.
            unsafe { libc::waitpid(pid, &mut raw, 0) };
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_in_its_directory_and_reports_how_it_ended() {
        let cwd = std::env::temp_dir();
        let script = ["-c".into(), "pwd; exit 3".into()];
        let mut spawned = spawn(Path::new("/bin/sh"), &script, &cwd, None)
            .await
            .unwrap();
        let status = spawned.child.wait().await.unwrap();
        assert_eq!(status.code(), Some(3));
        let out = std::fs::File::from(spawned.stdout);
        let printed = std::io::read_to_string(out).unwrap();
        assert_eq!(Path::new(printed.trim()), cwd.canonicalize().unwrap());
        assert_eq!(spawned.child.id(), None);
    }

    #[tokio::test]
    async fn a_missing_program_fails_the_spawn() {
        let err = spawn(Path::new("/nonexistent"), &[], Path::new("/"), None)
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn a_dropped_child_is_killed() {
        let spawned = spawn(
            Path::new("/bin/sleep"),
            &["60".into()],
            Path::new("/"),
            None,
        )
        .await
        .unwrap();
        let pid = spawned.child.pid;
        drop(spawned);
        for _ in 0..100 {
            // SAFETY: signal 0 only probes for the process.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the dropped child is still alive");
    }

    /// Needs a writable cgroup2 tree, as a node has; skipped elsewhere.
    #[tokio::test]
    async fn starts_inside_its_cgroup() {
        let dir = Path::new("/sys/fs/cgroup").join(format!("burrow-child-{}", std::process::id()));
        if std::fs::create_dir(&dir).is_err() {
            return;
        }
        let script = ["-c".into(), "cat /proc/self/cgroup".into()];
        let mut spawned = spawn(Path::new("/bin/sh"), &script, Path::new("/"), Some(&dir))
            .await
            .unwrap();
        spawned.child.wait().await.unwrap();
        let printed = std::io::read_to_string(std::fs::File::from(spawned.stdout)).unwrap();
        let _ = std::fs::remove_dir(&dir);
        let name = dir.file_name().unwrap().to_str().unwrap();
        assert!(printed.trim().ends_with(name), "{printed}");
    }
}
