//! Spawning a VMM straight into its cgroup.
//!
//! Writing a pid into `cgroup.procs` takes the kernel's threadgroup lock for
//! writing, which waits out an RCU grace period: 10 to 20 ms per VM, paid on
//! every create. `clone3` with `CLONE_INTO_CGROUP` places the child at fork
//! instead, with no migration and no wait.

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::ExitStatus;

/// A child process, killed when dropped unless it has been reaped.
pub struct Child {
    pid: libc::pid_t,
    #[cfg(target_os = "linux")]
    pidfd: tokio::io::unix::AsyncFd<OwnedFd>,
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

#[cfg(target_os = "linux")]
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd as _;
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both were just opened and are owned nowhere else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Runs `program` with `args` in `cwd`, inside the cgroup directory
/// `cgroup` from its first instruction when one is given.
#[cfg(target_os = "linux")]
pub fn spawn(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    cgroup: Option<&Path>,
) -> io::Result<Spawned> {
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
    let cgroup_dir = cgroup
        .map(|dir| std::fs::File::open(dir).map(OwnedFd::from))
        .transpose()?;

    let mut pidfd: libc::c_int = -1;
    let mut args = CloneArgs {
        flags: libc::CLONE_PIDFD as u64,
        pidfd: std::ptr::addr_of_mut!(pidfd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    if let Some(dir) = &cgroup_dir {
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = dir.as_raw_fd() as u64;
    }

    // SAFETY: a fork-style clone3 (no CLONE_VM, no new stack). The child runs
    // only async-signal-safe calls on memory prepared above before exec or
    // _exit, so no lock another thread held at the fork is ever taken in it.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::addr_of_mut!(args),
            std::mem::size_of::<CloneArgs>(),
        )
    };
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

    // SAFETY: CLONE_PIDFD stored a descriptor the parent now owns.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    let child = Child {
        pid: pid as libc::pid_t,
        pidfd: tokio::io::unix::AsyncFd::with_interest(pidfd, tokio::io::Interest::READABLE)?,
        status: None,
    };
    drop((
        status_write,
        stdin_read,
        stdout_write,
        stderr_write,
        cgroup_dir,
    ));
    let mut errno = [0u8; 4];
    let read = loop {
        // SAFETY: reads into a buffer of the length given.
        let read = unsafe { libc::read(status_read.as_raw_fd(), errno.as_mut_ptr().cast(), 4) };
        if read >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break read;
        }
    };
    if read == 4 {
        return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(errno)));
    }
    Ok(Spawned {
        child,
        stdin: stdin_write,
        stdout: stdout_read,
        stderr: stderr_read,
    })
}

/// Elsewhere there is no cgroup to clone into, and only the tests run a VMM.
#[cfg(not(target_os = "linux"))]
pub fn spawn(
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
            self.pidfd.readable().await?.clear_ready();
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
        let mut spawned = spawn(Path::new("/bin/sh"), &script, &cwd, None).unwrap();
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
}
