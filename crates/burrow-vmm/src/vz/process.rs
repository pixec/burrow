//! The process a machine runs in, for its CPU time.
//!
//! The framework runs each machine in an XPC service of its own, which it
//! spawns as the machine is created or started and never names. Its parent is
//! launchd, but its responsible process is whoever made the machine (or the
//! app that is responsible for that), so the service is found by listing
//! processes of that name with one of those as responsible, before and after
//! a start, and taking the one that appeared. Starts are serialised so that
//! one is never another machine's.

use std::collections::HashSet;
use std::ffi::{OsStr, c_void};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

/// The service's executable name, the last component of its path.
const SERVICE: &str = "com.apple.Virtualization.VirtualMachine";

/// Held from the listing before a machine starts to the listing after.
pub(super) static STARTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

unsafe extern "C" {
    /// Private, but exported from libsystem and stable since 10.14; what
    /// Activity Monitor and `launchctl` use for the same question.
    fn responsibility_get_pid_responsible_for_pid(pid: libc::pid_t) -> libc::pid_t;
    fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Timebase {
    numer: u32,
    denom: u32,
}

/// One machine's service process, and when it started, so a recycled pid is
/// never read as the machine's.
#[derive(Debug, Clone, Copy)]
pub(super) struct Process {
    pub pid: i32,
    started: u64,
}

impl Process {
    /// The one service process in `after` that was not in `before`.
    pub fn appeared(before: &HashSet<i32>, vm_id: &str) -> Option<Self> {
        let new: Vec<i32> = services().difference(before).copied().collect();
        let [pid] = new[..] else {
            tracing::error!(
                vm_id,
                candidates = ?new,
                "cannot tell which process runs this vz machine; its cpu is not metered"
            );
            return None;
        };
        let Some(usage) = rusage(pid) else {
            tracing::error!(
                vm_id,
                pid,
                "cannot read this vz machine's process; its cpu is not metered"
            );
            return None;
        };
        Some(Self {
            pid,
            started: usage.ri_proc_start_abstime,
        })
    }

    /// User and system time the process has spent, in microseconds.
    pub fn cpu_usage_usec(&self) -> Option<u64> {
        let usage = rusage(self.pid).filter(|u| u.ri_proc_start_abstime == self.started)?;
        Some(ticks_to_usec(
            usage.ri_user_time + usage.ri_system_time,
            timebase(),
        ))
    }
}

/// Every running machine service this process is responsible for.
pub(super) fn services() -> HashSet<i32> {
    let own = std::process::id() as i32;
    let mut ours = vec![own];
    // SAFETY: takes and returns a pid.
    let responsible = unsafe { responsibility_get_pid_responsible_for_pid(own) };
    if responsible > 1 {
        ours.push(responsible);
    }
    all_pids()
        .into_iter()
        .filter(|&pid| is_service(pid))
        // SAFETY: as above.
        .filter(|&pid| ours.contains(&unsafe { responsibility_get_pid_responsible_for_pid(pid) }))
        .collect()
}

fn all_pids() -> Vec<i32> {
    // SAFETY: a null buffer asks for the count; the second call fills at most
    // the buffer's size in bytes and returns how many pids it wrote.
    unsafe {
        let count = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if count <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; count as usize + 64];
        let written = libc::proc_listallpids(
            pids.as_mut_ptr().cast::<c_void>(),
            (pids.len() * size_of::<i32>()) as libc::c_int,
        );
        pids.truncate(written.max(0) as usize);
        pids
    }
}

fn is_service(pid: i32) -> bool {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: writes at most `buf.len()` bytes and returns the length.
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    len > 0
        && Path::new(OsStr::from_bytes(&buf[..len as usize])).file_name()
            == Some(OsStr::new(SERVICE))
}

fn rusage(pid: i32) -> Option<libc::rusage_info_v4> {
    // SAFETY: an all-zero struct of integers is valid, and the call writes
    // one `rusage_info_v4` for the V4 flavor.
    unsafe {
        let mut usage: libc::rusage_info_v4 = std::mem::zeroed();
        let done = libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V4,
            (&mut usage as *mut libc::rusage_info_v4).cast(),
        );
        (done == 0).then_some(usage)
    }
}

fn timebase() -> Timebase {
    static TIMEBASE: std::sync::OnceLock<Timebase> = std::sync::OnceLock::new();
    *TIMEBASE.get_or_init(|| {
        let mut base = Timebase { numer: 1, denom: 1 };
        // SAFETY: fills the struct it is given.
        unsafe { mach_timebase_info(&mut base) };
        base
    })
}

/// Mach absolute time units to microseconds.
fn ticks_to_usec(ticks: u64, base: Timebase) -> u64 {
    (u128::from(ticks) * u128::from(base.numer) / u128::from(base.denom.max(1)) / 1000) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mach_ticks_convert_to_microseconds() {
        // Apple silicon's 24 MHz timebase: 125/3 ns per tick.
        let base = Timebase {
            numer: 125,
            denom: 3,
        };
        assert_eq!(ticks_to_usec(24_000_000, base), 1_000_000);
        assert_eq!(
            ticks_to_usec(u64::MAX, base),
            (u128::from(u64::MAX) * 125 / 3 / 1000) as u64
        );
        let identity = Timebase { numer: 1, denom: 1 };
        assert_eq!(ticks_to_usec(5_000, identity), 5);
    }

    #[test]
    fn this_process_is_readable_and_not_a_machine() {
        let own = std::process::id() as i32;
        assert!(rusage(own).is_some());
        assert!(!is_service(own));
        assert!(!services().contains(&own));
    }
}
