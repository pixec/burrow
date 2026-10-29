//! Small pieces every Windows module needs: wide strings, handles, errors,
//! privileges.

use std::os::windows::io::{FromRawHandle as _, OwnedHandle};

use windows_sys::Win32::Foundation::{
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID, NTSTATUS, RtlNtStatusToDosError,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::errno::Errno;

/// `s` as a NUL-terminated UTF-16 string.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A UTF-16 buffer up to its first NUL, or all of it.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// A NUL-terminated UTF-16 string a Windows API handed back.
///
/// # Safety
/// `ptr` must be null or point at a NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the caller promises a terminator.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` elements were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

pub fn last_error() -> u32 {
    // SAFETY: reads thread-local state.
    unsafe { GetLastError() }
}

pub fn last_io_error() -> std::io::Error {
    std::io::Error::from_raw_os_error(last_error() as i32)
}

/// The Win32 error an NTSTATUS stands for.
pub fn nt_error(status: NTSTATUS) -> u32 {
    // SAFETY: a pure lookup.
    unsafe { RtlNtStatusToDosError(status) }
}

/// A BOOL result as an `io::Result`.
pub fn check(ok: i32) -> std::io::Result<()> {
    if ok == 0 {
        Err(last_io_error())
    } else {
        Ok(())
    }
}

/// Takes ownership of a handle a Windows API returned, or reports why there is
/// none. Both null and `INVALID_HANDLE_VALUE` mean failure, depending on the API.
pub fn owned(handle: HANDLE) -> std::io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(last_io_error());
    }
    // SAFETY: a fresh handle nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Enables privileges LocalSystem holds but leaves disabled, so the calls
/// that need them succeed: setting the clock, logging users on without a
/// password, starting processes with their tokens, setting a file's owner.
pub fn enable_privileges(names: &[&str]) -> std::io::Result<()> {
    let mut token = std::ptr::null_mut();
    // SAFETY: `token` receives a handle this function closes.
    check(unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    })?;
    let token = owned(token)?;
    for name in names {
        let mut luid = LUID::default();
        let name_w = wide(name);
        // SAFETY: `name_w` is NUL-terminated and `luid` is written.
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), name_w.as_ptr(), &mut luid) } == 0 {
            tracing::warn!(privilege = name, err = %last_io_error(), "unknown privilege");
            continue;
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        use std::os::windows::io::AsRawHandle as _;
        // SAFETY: `privileges` outlives the call; no previous state is asked for.
        let ok = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &privileges,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // Succeeds even when the privilege is not held, setting
        // ERROR_NOT_ALL_ASSIGNED, which is what a non-SYSTEM console run sees.
        if ok == 0 || last_error() != 0 {
            tracing::debug!(privilege = name, err = %last_io_error(), "privilege not enabled");
        }
    }
    Ok(())
}

/// The drive Windows is installed on, which POSIX paths map onto.
pub fn system_drive() -> char {
    static DRIVE: std::sync::OnceLock<char> = std::sync::OnceLock::new();
    *DRIVE.get_or_init(|| {
        std::env::var("SystemDrive")
            .ok()
            .and_then(|drive| drive.chars().next())
            .filter(char::is_ascii_alphabetic)
            .unwrap_or('C')
            .to_ascii_uppercase()
    })
}

/// Maps a request's path onto the guest's drives; see [`crate::paths`].
pub fn map_path(path: &str) -> Result<String, Errno> {
    crate::paths::windows::to_windows(path, system_drive()).map_err(|err| match err {
        crate::paths::windows::PathError::Empty => Errno::ENOENT,
        crate::paths::windows::PathError::NotLocal => Errno::EACCES,
    })
}

/// Bytes from the system's RNG.
pub fn random<const N: usize>() -> [u8; N] {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut bytes = [0u8; N];
    // SAFETY: writes exactly N bytes into `bytes`.
    unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            N as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    bytes
}

/// Where the agent keeps its own state: logs, the command table across an
/// upgrade, the inspection CA.
pub fn state_dir() -> std::path::PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}:\\ProgramData", system_drive())));
    base.join("burrow")
}
