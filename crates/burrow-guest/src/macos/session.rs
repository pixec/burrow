//! Running a user's command in their GUI session.
//!
//! The agent is a LaunchDaemon, so what it starts lives in the system
//! context: launchd's system domain and the boot audit session. A command
//! there reaches no login keychain and none of the per-user services of a
//! desktop, whoever it runs as. When the user it runs as is logged in at the
//! console (the auto-login user, say), the command is put in that login, as
//! `launchctl asuser` puts one:
//!
//! - the child joins the login's audit session while still root, which is
//!   how securityd finds the user's login keychain, and then drops to the
//!   user as any command does;
//! - it then execs `/bin/launchctl asuser <uid> <program> <args>`, which as
//!   the user in their own session takes the bootstrap port of their Aqua
//!   domain (launchd hands it out by session, through a private interface)
//!   and execs the program in place: the same pid, the user's credentials,
//!   no shell.
//!
//! The program is resolved on `PATH` first, so one that does not exist
//! fails the request as it does for anyone else rather than as launchctl's
//! exit status.

use nix::libc;

use burrow_proto::guest::v1 as guestpb;

/// Reported in Health: a user's command runs in their GUI session when they
/// have one.
pub const FEATURE_GUI_SESSION: &str = "gui-session";

type MachPort = u32;

/// `struct auditpinfo_addr` from `<bsm/audit.h>`.
#[repr(C)]
#[derive(Default)]
struct ProcessAudit {
    pid: libc::pid_t,
    auid: u32,
    mask: [u32; 2],
    termid_port: i32,
    termid_type: u32,
    termid_addr: [u32; 4],
    asid: i32,
    flags: u64,
}

const A_GETPINFO_ADDR: libc::c_int = 28;
/// The session has a window server: someone logged in at the console.
const AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS: u64 = 0x0010;
const PROC_UID_ONLY: u32 = 4;

unsafe extern "C" {
    fn auditon(cmd: libc::c_int, data: *mut libc::c_void, length: libc::c_int) -> libc::c_int;
    fn audit_session_port(asid: i32, port: *mut MachPort) -> libc::c_int;
    fn audit_session_join(port: MachPort) -> i32;
    fn proc_listpids(
        kind: u32,
        info: u32,
        buffer: *mut libc::c_void,
        size: libc::c_int,
    ) -> libc::c_int;
}

/// The audit session of `uid`'s console login, found by asking the kernel
/// about the processes running as them; `None` when they have none.
pub fn gui_session(uid: u32) -> Option<i32> {
    let mut pids = vec![0 as libc::pid_t; 4096];
    // SAFETY: the buffer is as large as said.
    let bytes = unsafe {
        proc_listpids(
            PROC_UID_ONLY,
            uid,
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<libc::pid_t>()) as libc::c_int,
        )
    };
    pids.truncate(bytes.max(0) as usize / size_of::<libc::pid_t>());
    pids.into_iter().filter(|pid| *pid > 0).find_map(|pid| {
        let mut audit = ProcessAudit {
            pid,
            ..Default::default()
        };
        // SAFETY: `audit` is the structure the command fills, of its size.
        let rc = unsafe {
            auditon(
                A_GETPINFO_ADDR,
                (&raw mut audit).cast(),
                size_of::<ProcessAudit>() as libc::c_int,
            )
        };
        (rc == 0 && audit.flags & AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS != 0).then_some(audit.asid)
    })
}

/// The command that runs `start` in the console user's Aqua domain, once the
/// child has joined their session and become them.
pub fn command(start: &guestpb::ExecStart, uid: u32) -> std::io::Result<std::process::Command> {
    let path = start
        .env
        .get("PATH")
        .cloned()
        .or_else(|| {
            (!start.is_env_cleared)
                .then(|| std::env::var("PATH").ok())
                .flatten()
        })
        .unwrap_or_else(|| DEFAULT_PATH.to_string());
    let program = resolve(&start.cmd[0], &path)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
    let mut command = std::process::Command::new(LAUNCHCTL);
    command
        .arg("asuser")
        .arg(uid.to_string())
        .arg(program)
        .args(&start.cmd[1..]);
    Ok(command)
}

const LAUNCHCTL: &str = "/bin/launchctl";
const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// `program` as execvp(3) would find it on `path`.
fn resolve(program: &str, path: &str) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let runnable = |candidate: &std::path::Path| {
        std::fs::metadata(candidate)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    };
    let candidate = std::path::PathBuf::from(program);
    // Relative to the command's own working directory, which is not this
    // process's: left for the exec to find.
    if program.contains('/') && candidate.is_relative() {
        return Some(candidate);
    }
    if program.contains('/') {
        return runnable(&candidate).then_some(candidate);
    }
    path.split(':')
        .filter(|dir| !dir.is_empty())
        .map(|dir| std::path::Path::new(dir).join(program))
        .find(|candidate| runnable(candidate))
}

/// Moves the calling process into audit session `asid`. Bare syscalls, for
/// the time between fork and exec; needs root.
pub fn join(asid: i32) -> std::io::Result<()> {
    let mut port: MachPort = 0;
    // SAFETY: `port` outlives the call; a port name is only passed on.
    unsafe {
        if audit_session_port(asid, &mut port) != 0 || audit_session_join(port) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_audit_record_has_the_kernel_layout() {
        assert_eq!(size_of::<ProcessAudit>(), 56);
        assert_eq!(std::mem::offset_of!(ProcessAudit, asid), 40);
    }

    #[test]
    fn a_program_is_found_as_execvp_finds_it() {
        assert_eq!(
            resolve("sh", "/nonexistent:/bin").as_deref(),
            Some(std::path::Path::new("/bin/sh"))
        );
        assert_eq!(
            resolve("/usr/bin/true", "").as_deref(),
            Some(std::path::Path::new("/usr/bin/true"))
        );
        assert!(resolve("no-such-program", DEFAULT_PATH).is_none());
        assert!(resolve("/etc/hosts", DEFAULT_PATH).is_none());
    }

    /// Nobody logs in as uid 0 at a console.
    #[test]
    fn root_has_no_gui_session() {
        assert_eq!(gui_session(0), None);
    }
}
