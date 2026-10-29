//! Acting as a guest user without their password.
//!
//! `CreateProcessWithLogonW` and `LogonUserW` both want the user's password,
//! which the agent does not have for an account the image made and should
//! not keep for one it made itself. Windows' answer is S4U ("service for
//! user"): a caller holding `SeTcbPrivilege`, as LocalSystem does, asks the
//! MSV1_0 package for a token for a local account by name alone. The token
//! is a real logon of that user, checked against their ACLs and groups; what
//! it lacks is the password, so it cannot authenticate to another machine,
//! which a sandbox has no business doing as the user anyway.
//!
//! The logon is of the `Network` type because every local account holds the
//! right for it by default ("Access this computer from the network"), where
//! `Batch` and `Interactive` need rights a fresh account may not have. The
//! token is duplicated into a primary token for `CreateProcessAsUserW`, and
//! used as is to impersonate for file work on one thread.

#![allow(clippy::result_large_err)]

use std::os::windows::io::{AsRawHandle as _, OwnedHandle};

use tonic::Status;
use windows_sys::Win32::Foundation::{HANDLE, LUID, STATUS_SUCCESS};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_STRING, LSA_UNICODE_STRING, LsaFreeReturnBuffer, LsaLogonUser,
    LsaLookupAuthenticationPackage, LsaRegisterLogonProcess, MSV1_0_PACKAGE_NAME, MSV1_0_S4U_LOGON,
    MsV1_0S4ULogon, SECURITY_LOGON_TYPE,
};
use windows_sys::Win32::Security::{
    AllocateLocallyUniqueId, DuplicateTokenEx, ImpersonateLoggedOnUser, QUOTA_LIMITS, RevertToSelf,
    SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_SOURCE, TokenPrimary,
};

use crate::windows::win;

/// A logged-on guest user.
pub struct UserToken {
    pub token: OwnedHandle,
    pub name: String,
}

fn lsa_string(s: &'static [u8]) -> LSA_STRING {
    LSA_STRING {
        Length: s.len() as u16,
        MaximumLength: s.len() as u16,
        Buffer: s.as_ptr().cast_mut(),
    }
}

/// The agent's trusted connection to the LSA, made once.
fn lsa() -> Result<(HANDLE, u32), Status> {
    static LSA: std::sync::OnceLock<Result<(usize, u32), String>> = std::sync::OnceLock::new();
    let result = LSA.get_or_init(|| {
        let name = lsa_string(b"burrow-guest");
        let mut handle = std::ptr::null_mut();
        let mut mode = 0u32;
        // SAFETY: `name` borrows a static and the outputs are written.
        let status = unsafe { LsaRegisterLogonProcess(&name, &mut handle, &mut mode) };
        if status != STATUS_SUCCESS {
            return Err(format!(
                "LsaRegisterLogonProcess: {} (the agent must run as LocalSystem)",
                std::io::Error::from_raw_os_error(win::nt_error(status) as i32)
            ));
        }
        // SAFETY: MSV1_0_PACKAGE_NAME is a static NUL-terminated string.
        let package_name = unsafe { std::ffi::CStr::from_ptr(MSV1_0_PACKAGE_NAME.cast()) };
        let package = LSA_STRING {
            Length: package_name.to_bytes().len() as u16,
            MaximumLength: package_name.to_bytes().len() as u16,
            Buffer: MSV1_0_PACKAGE_NAME.cast_mut(),
        };
        let mut id = 0u32;
        // SAFETY: as above.
        let status = unsafe { LsaLookupAuthenticationPackage(handle, &package, &mut id) };
        if status != STATUS_SUCCESS {
            return Err(format!(
                "LsaLookupAuthenticationPackage: {}",
                std::io::Error::from_raw_os_error(win::nt_error(status) as i32)
            ));
        }
        Ok((handle as usize, id))
    });
    match result {
        Ok((handle, id)) => Ok((*handle as HANDLE, *id)),
        Err(err) => Err(Status::internal(err.clone())),
    }
}

fn computer_name() -> Vec<u16> {
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;
    let mut buf = [0u16; 64];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` has room for `len` characters.
    unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut len) };
    buf[..len as usize].to_vec()
}

/// Logs `name`, a local account, on by S4U.
pub fn logon(name: &str) -> Result<UserToken, Status> {
    crate::windows::users::lookup_user(name)?;
    let (lsa, package) = lsa()?;

    let user: Vec<u16> = name.encode_utf16().collect();
    let domain = computer_name();
    // The structure and both strings in one block, the strings' pointers into
    // it: LsaLogonUser copies the block as a whole.
    let head = std::mem::size_of::<MSV1_0_S4U_LOGON>();
    let size = head + (user.len() + domain.len()) * 2;
    let mut block = vec![0u64; size.div_ceil(8)];
    let base = block.as_mut_ptr().cast::<u8>();
    // SAFETY: the block is `size` bytes, aligned for the structure, and the
    // strings are written after it, within it.
    unsafe {
        let user_at = base.add(head).cast::<u16>();
        std::ptr::copy_nonoverlapping(user.as_ptr(), user_at, user.len());
        let domain_at = user_at.add(user.len());
        std::ptr::copy_nonoverlapping(domain.as_ptr(), domain_at, domain.len());
        base.cast::<MSV1_0_S4U_LOGON>().write(MSV1_0_S4U_LOGON {
            MessageType: MsV1_0S4ULogon,
            Flags: 0,
            UserPrincipalName: LSA_UNICODE_STRING {
                Length: (user.len() * 2) as u16,
                MaximumLength: (user.len() * 2) as u16,
                Buffer: user_at,
            },
            DomainName: LSA_UNICODE_STRING {
                Length: (domain.len() * 2) as u16,
                MaximumLength: (domain.len() * 2) as u16,
                Buffer: domain_at,
            },
        });
    }

    let mut source = TOKEN_SOURCE {
        SourceName: b"burrow\0\0".map(|b| b as i8),
        SourceIdentifier: LUID::default(),
    };
    // SAFETY: writes the LUID.
    unsafe { AllocateLocallyUniqueId(&mut source.SourceIdentifier) };
    let origin = lsa_string(b"burrow-guest");
    let mut profile = std::ptr::null_mut();
    let mut profile_len = 0u32;
    let mut logon_id = LUID::default();
    let mut token = std::ptr::null_mut();
    let mut quotas: QUOTA_LIMITS = unsafe { std::mem::zeroed() };
    let mut substatus = 0i32;
    // SAFETY: every pointer is to a live local; the block is `size` bytes.
    let status = unsafe {
        LsaLogonUser(
            lsa,
            &origin,
            SECURITY_LOGON_TYPE::Network,
            package,
            block.as_ptr().cast(),
            size as u32,
            std::ptr::null(),
            &source,
            &mut profile,
            &mut profile_len,
            &mut logon_id,
            &mut token,
            &mut quotas,
            &mut substatus,
        )
    };
    if !profile.is_null() {
        // SAFETY: the LSA allocated it for us to free.
        unsafe { LsaFreeReturnBuffer(profile) };
    }
    if status != STATUS_SUCCESS {
        let err = std::io::Error::from_raw_os_error(win::nt_error(status) as i32);
        return Err(Status::permission_denied(format!(
            "logging {name} on: {err}"
        )));
    }
    let token = win::owned(token).map_err(|err| Status::internal(format!("logon token: {err}")))?;
    Ok(UserToken {
        token,
        name: name.to_string(),
    })
}

impl UserToken {
    /// A primary token for a process to run with.
    pub fn primary(&self) -> Result<OwnedHandle, Status> {
        let mut primary = std::ptr::null_mut();
        // SAFETY: duplicates a token this value holds open.
        win::check(unsafe {
            DuplicateTokenEx(
                self.token.as_raw_handle(),
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &mut primary,
            )
        })
        .and_then(|()| win::owned(primary))
        .map_err(|err| Status::internal(format!("duplicating {}'s token: {err}", self.name)))
    }

    /// Takes on the user's identity on the calling thread.
    ///
    /// Only ever called on a thread of its own that exits afterwards, never a
    /// pool thread: the identity stays with the thread.
    pub fn impersonate(&self) -> std::io::Result<()> {
        // SAFETY: the token is open for the call.
        win::check(unsafe { ImpersonateLoggedOnUser(self.token.as_raw_handle()) })
    }
}

/// Drops whatever identity the calling thread took on.
pub fn revert() {
    // SAFETY: affects only the calling thread.
    unsafe { RevertToSelf() };
}
