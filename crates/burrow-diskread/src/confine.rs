//! What a reader does to itself before it reads a byte of the image.

use std::collections::BTreeMap;
use std::io;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use crate::Limits;
use crate::server::IMAGE_FD;

/// The user a reader becomes when started as root.
const NOBODY: libc::uid_t = 65534;

fn check(rc: libc::c_int) -> io::Result<()> {
    match rc {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

fn limit(resource: libc::c_int, soft: u64, hard: u64) -> io::Result<()> {
    let value = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: a plain syscall on a value that outlives it.
    check(unsafe { libc::setrlimit(resource, &value) })
}

pub fn confine(limits: &Limits) -> io::Result<()> {
    // SAFETY: closes descriptors this process never uses.
    unsafe { libc::syscall(libc::SYS_close_range, IMAGE_FD + 1, u32::MAX, 0) };
    let memory = limits.memory_mib << 20;
    limit(libc::RLIMIT_AS, memory, memory)?;
    limit(libc::RLIMIT_CPU, limits.cpu_secs, limits.cpu_secs + 1)?;
    limit(
        libc::RLIMIT_NOFILE,
        (IMAGE_FD + 1) as u64,
        (IMAGE_FD + 1) as u64,
    )?;
    limit(libc::RLIMIT_FSIZE, 0, 0)?;
    limit(libc::RLIMIT_CORE, 0, 0)?;
    // SAFETY: plain syscalls with no pointers but the null group list.
    unsafe {
        if libc::geteuid() == 0 {
            check(libc::unshare(
                libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS,
            ))?;
            check(libc::setgroups(0, std::ptr::null()))?;
            check(libc::setresgid(NOBODY, NOBODY, NOBODY))?;
            check(libc::setresuid(NOBODY, NOBODY, NOBODY))?;
        }
        check(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0))?;
    }
    let filter = filter()
        .and_then(BpfProgram::try_from)
        .map_err(io::Error::other)?;
    seccompiler::apply_filter(&filter).map_err(io::Error::other)
}

fn on_fd(fds: &[i32]) -> Result<Vec<SeccompRule>, seccompiler::BackendError> {
    fds.iter()
        .map(|&fd| {
            SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                fd as u64,
            )?])
        })
        .collect()
}

/// Reading requests and the image, writing answers and errors, and the
/// memory, signal and exit calls the runtime makes. Anything else kills the
/// process.
fn filter() -> Result<SeccompFilter, seccompiler::BackendError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_read, on_fd(&[0])?);
    rules.insert(libc::SYS_pread64, on_fd(&[IMAGE_FD])?);
    rules.insert(libc::SYS_write, on_fd(&[1, 2])?);
    // What a debug build's descriptor drop asks before closing.
    rules.insert(
        libc::SYS_fcntl,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::F_GETFD as u64,
        )?])?],
    );
    for call in [
        libc::SYS_close,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_sched_yield,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        rules.insert(call, Vec::new());
    }
    SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into()?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `then` in a child under the filter and returns the signal that
    /// ended it, or 0 for a clean exit.
    fn under_filter(then: fn()) -> i32 {
        let program = BpfProgram::try_from(filter().unwrap()).unwrap();
        // SAFETY: the child makes only raw syscalls before it exits.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                if seccompiler::apply_filter(&program).is_err() {
                    libc::_exit(2);
                }
                then();
                libc::_exit(0);
            }
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            match libc::WIFSIGNALED(status) {
                true => libc::WTERMSIG(status),
                false => libc::WEXITSTATUS(status) * 1000,
            }
        }
    }

    #[test]
    fn the_filter_kills_anything_but_its_reads_and_writes() {
        assert_eq!(
            under_filter(|| unsafe {
                libc::write(2, b"".as_ptr().cast(), 0);
            }),
            0
        );
        assert_eq!(
            under_filter(|| unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    c"/etc/hostname".as_ptr(),
                    0,
                );
            }),
            libc::SIGSYS
        );
        assert_eq!(
            under_filter(|| unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            }),
            libc::SIGSYS
        );
        assert_eq!(
            under_filter(|| unsafe {
                libc::write(5, b"x".as_ptr().cast(), 1);
            }),
            libc::SIGSYS
        );
        assert_eq!(
            under_filter(|| unsafe {
                libc::read(IMAGE_FD, std::ptr::null_mut(), 0);
            }),
            libc::SIGSYS
        );
    }
}
