//! Guest users and groups, as local accounts and local groups.
//!
//! Made through the NetApi (`NetUserAdd`, `NetLocalGroupAdd`) rather than by
//! running `net user`: no output to parse, and names go in as UTF-16 values,
//! never through a command line. Names arrive from outside the guest.
//!
//! Windows has SIDs where Linux has numeric ids. The responses carry the
//! account's RID, the last component of its SID, as the uid or gid: unique on
//! the machine and stable for the account's life, which is all a caller
//! holding one can use it for. A local user's primary group is always
//! "None", RID 513, and that is the gid a user is reported with.

#![allow(clippy::result_large_err)]

use std::os::windows::io::{AsRawHandle as _, OwnedHandle};

use tonic::Status;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_3, NetApiBufferFree, NetLocalGroupAdd,
    NetLocalGroupAddMembers, NetLocalGroupDelMembers, NetLocalGroupGetInfo, NetUserAdd,
    NetUserGetInfo, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};

use crate::windows::win;

/// Where a group's members share files, on the system drive: `C:\srv\NAME`,
/// as `/srv/NAME` is on Linux and as `/srv/NAME` maps here.
const SHARED_ROOT: &str = "srv";
/// The RID of "None", every local user's primary group.
const PRIMARY_GROUP_RID: u32 = 513;
/// `PI_NOUI` for `LoadUserProfileW`: no dialog on a profile problem, which in
/// a service would wait for a click nobody can make.
const PI_NOUI: u32 = 1;

const NERR_SUCCESS: u32 = 0;
const NERR_GROUP_EXISTS: u32 = 2223;
const NERR_USER_EXISTS: u32 = 2224;
const NERR_USER_NOT_FOUND: u32 = 2221;
const ERROR_ALIAS_EXISTS: u32 = 1379;
const ERROR_NO_SUCH_ALIAS: u32 = 1376;
const ERROR_MEMBER_NOT_IN_ALIAS: u32 = 1377;
const ERROR_MEMBER_IN_ALIAS: u32 = 1378;
const ERROR_NO_SUCH_MEMBER: u32 = 1387;
const NERR_GROUP_NOT_FOUND: u32 = 2220;

/// The names that mean the agent's own identity, LocalSystem, where Linux
/// would run as root: empty, as every request has always meant it, and the
/// two names a caller might spell it with.
pub fn is_agent(name: &str) -> bool {
    name.is_empty() || name.eq_ignore_ascii_case("root") || name.eq_ignore_ascii_case("system")
}

/// The names this agent creates: POSIX portable, as on Linux, so a name that
/// works on one guest works on the other, and at most 20 characters, which is
/// as long as a Windows local account name can be.
pub fn validate_new(name: &str, max: usize) -> Result<(), Status> {
    let mut chars = name.chars();
    let ok = (1..=max).contains(&name.len())
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ok {
        return Err(Status::invalid_argument(format!(
            "name {name:?} must be 1-{max} characters matching [a-z_][a-z0-9_-]*"
        )));
    }
    Ok(())
}

/// An existing account's name, which the image may have given any case or
/// spelling Windows allows; only what Windows itself forbids, and a domain
/// prefix, is refused.
fn validate_existing(name: &str) -> Result<(), Status> {
    let bad = name.is_empty()
        || name.chars().count() > 64
        || name
            .chars()
            .any(|c| c.is_control() || "\"/\\[]:;|=,+*?<>@".contains(c));
    if bad {
        return Err(Status::invalid_argument(format!(
            "{name:?} is not a local account name"
        )));
    }
    Ok(())
}

fn net_error(action: &str, code: u32) -> Status {
    Status::internal(format!(
        "{action}: {}",
        std::io::Error::from_raw_os_error(code as i32)
    ))
}

/// Fails unless `name` is a local account.
pub fn lookup_user(name: &str) -> Result<(), Status> {
    validate_existing(name)?;
    let name_w = win::wide(name);
    let mut buf = std::ptr::null_mut();
    // SAFETY: `name_w` is NUL-terminated; the buffer is freed below.
    let rc = unsafe { NetUserGetInfo(std::ptr::null(), name_w.as_ptr(), 0, &mut buf) };
    if !buf.is_null() {
        // SAFETY: allocated by the call for us to free.
        unsafe { NetApiBufferFree(buf.cast()) };
    }
    match rc {
        NERR_SUCCESS => Ok(()),
        NERR_USER_NOT_FOUND => Err(Status::not_found(format!(
            "no such user in the guest: {name}"
        ))),
        code => Err(net_error(&format!("looking up {name}"), code)),
    }
}

fn lookup_group(name: &str) -> Result<(), Status> {
    validate_existing(name)?;
    let name_w = win::wide(name);
    let mut buf = std::ptr::null_mut();
    // SAFETY: as for users.
    let rc = unsafe { NetLocalGroupGetInfo(std::ptr::null(), name_w.as_ptr(), 0, &mut buf) };
    if !buf.is_null() {
        // SAFETY: allocated by the call for us to free.
        unsafe { NetApiBufferFree(buf.cast()) };
    }
    match rc {
        NERR_SUCCESS => Ok(()),
        ERROR_NO_SUCH_ALIAS | NERR_GROUP_NOT_FOUND => Err(Status::not_found(format!(
            "no such group in the guest: {name}"
        ))),
        code => Err(net_error(&format!("looking up group {name}"), code)),
    }
}

/// An account's SID, as bytes.
pub fn sid(name: &str) -> Result<Vec<u8>, Status> {
    use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};
    let name_w = win::wide(name);
    let mut sid = vec![0u8; 68];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: buffers are sized as passed.
    win::check(unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name_w.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    })
    .map_err(|err| Status::not_found(format!("no SID for {name}: {err}")))?;
    sid.truncate(sid_len as usize);
    Ok(sid)
}

/// The last sub-authority of a SID, its RID.
fn rid(sid: &[u8]) -> u32 {
    // A SID is revision, count, a six-byte authority, then `count` u32s.
    let count = usize::from(sid[1]);
    let at = 8 + (count - 1) * 4;
    u32::from_le_bytes(sid[at..at + 4].try_into().expect("four bytes"))
}

fn sid_string(sid: &[u8]) -> Result<String, Status> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut out = std::ptr::null_mut();
    // SAFETY: `sid` is a SID LookupAccountNameW wrote; `out` is LocalFree'd.
    win::check(unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut out) })
        .map_err(|err| Status::internal(format!("formatting a SID: {err}")))?;
    // SAFETY: a NUL-terminated string the call allocated.
    let text = unsafe { win::from_wide_ptr(out) };
    // SAFETY: freed once, as the call's documentation asks.
    unsafe { windows_sys::Win32::Foundation::LocalFree(out.cast()) };
    Ok(text)
}

/// A user's loaded profile: their registry hive and home directory, which
/// tools a process runs expect to find. Unloaded when dropped.
pub struct Profile {
    token: OwnedHandle,
    handle: HANDLE,
    pub dir: String,
}

impl Drop for Profile {
    fn drop(&mut self) {
        use windows_sys::Win32::UI::Shell::UnloadUserProfile;
        // SAFETY: both handles came from the LoadUserProfileW that made this.
        unsafe { UnloadUserProfile(self.token.as_raw_handle(), self.handle) };
    }
}

// SAFETY: a registry key handle, usable from any thread.
unsafe impl Send for Profile {}
unsafe impl Sync for Profile {}

/// Loads `name`'s profile, creating it under `C:\Users` the first time.
pub fn load_profile(token: &crate::windows::token::UserToken) -> Result<Profile, Status> {
    use windows_sys::Win32::UI::Shell::{GetUserProfileDirectoryW, LoadUserProfileW, PROFILEINFOW};
    let token_handle = token
        .token
        .try_clone()
        .map_err(|err| Status::internal(format!("token: {err}")))?;
    let mut name = win::wide(&token.name);
    let mut info: PROFILEINFOW = unsafe { std::mem::zeroed() };
    info.dwSize = std::mem::size_of::<PROFILEINFOW>() as u32;
    info.dwFlags = PI_NOUI;
    info.lpUserName = name.as_mut_ptr();
    // SAFETY: `info` and `name` outlive the call.
    win::check(unsafe { LoadUserProfileW(token_handle.as_raw_handle(), &mut info) })
        .map_err(|err| Status::internal(format!("loading {}'s profile: {err}", token.name)))?;
    let mut dir = vec![0u16; 512];
    let mut len = dir.len() as u32;
    // SAFETY: `dir` has room for `len` characters.
    unsafe { GetUserProfileDirectoryW(token_handle.as_raw_handle(), dir.as_mut_ptr(), &mut len) };
    Ok(Profile {
        token: token_handle,
        handle: info.hProfile,
        dir: win::from_wide(&dir),
    })
}

/// A password nobody is told: Windows will not create an account without one
/// under the default policy, and the agent never logs on with it, only by S4U.
fn throwaway_password() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let suffix: String = win::random::<24>()
        .iter()
        .map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()]))
        .collect();
    // One of each class, for a complexity policy.
    format!("Bw7!{suffix}")
}

pub async fn create_user(
    name: &str,
) -> Result<burrow_proto::guest::v1::CreateUserResponse, Status> {
    validate_new(name, 20)?;
    let name = name.to_string();
    tokio::task::spawn_blocking(move || create_user_blocking(&name))
        .await
        .map_err(|err| Status::internal(format!("create user did not run: {err}")))?
}

fn create_user_blocking(name: &str) -> Result<burrow_proto::guest::v1::CreateUserResponse, Status> {
    let mut name_w = win::wide(name);
    let mut password = win::wide(&throwaway_password());
    let mut info: USER_INFO_1 = unsafe { std::mem::zeroed() };
    info.usri1_name = name_w.as_mut_ptr();
    info.usri1_password = password.as_mut_ptr();
    info.usri1_priv = USER_PRIV_USER;
    info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    let mut parm = 0u32;
    // SAFETY: `info` and the strings it points at outlive the call.
    let rc = unsafe { NetUserAdd(std::ptr::null(), 1, (&raw const info).cast(), &mut parm) };
    password.fill(0);
    match rc {
        NERR_SUCCESS => {}
        NERR_USER_EXISTS => return Err(Status::already_exists(format!("user {name} exists"))),
        code => return Err(net_error(&format!("creating {name}"), code)),
    }
    let sid = sid(name)?;
    // The profile is the home: made on the first load, under `C:\Users`, and
    // private to the user by the ACL Windows gives it.
    let token = crate::windows::token::logon(name)?;
    let profile = load_profile(&token)?;
    Ok(burrow_proto::guest::v1::CreateUserResponse {
        username: name.to_string(),
        uid: rid(&sid),
        gid: PRIMARY_GROUP_RID,
        home: profile.dir.clone(),
    })
}

pub async fn create_group(
    name: &str,
) -> Result<burrow_proto::guest::v1::CreateGroupResponse, Status> {
    validate_new(name, 32)?;
    let name = name.to_string();
    tokio::task::spawn_blocking(move || create_group_blocking(&name))
        .await
        .map_err(|err| Status::internal(format!("create group did not run: {err}")))?
}

fn create_group_blocking(
    name: &str,
) -> Result<burrow_proto::guest::v1::CreateGroupResponse, Status> {
    let mut name_w = win::wide(name);
    let mut comment = win::wide("burrow sandbox group");
    let info = LOCALGROUP_INFO_1 {
        lgrpi1_name: name_w.as_mut_ptr(),
        lgrpi1_comment: comment.as_mut_ptr(),
    };
    let mut parm = 0u32;
    // SAFETY: as for users.
    match unsafe { NetLocalGroupAdd(std::ptr::null(), 1, (&raw const info).cast(), &mut parm) } {
        NERR_SUCCESS => {}
        NERR_GROUP_EXISTS | ERROR_ALIAS_EXISTS | NERR_USER_EXISTS => {
            return Err(Status::already_exists(format!("group {name} exists")));
        }
        code => return Err(net_error(&format!("creating group {name}"), code)),
    }
    let sid = sid(name)?;
    let shared = format!("{}:\\{SHARED_ROOT}\\{name}", win::system_drive());
    std::fs::create_dir_all(&shared)
        .map_err(|err| Status::internal(format!("create {shared}: {err}")))?;
    // What 2770 setgid is on Linux: SYSTEM and Administrators in full, the
    // group able to read, write and delete, inherited by everything created
    // inside, and nothing inherited from above, so nobody else gets in. The
    // group keeps files group-accessible by the inherited entry rather than
    // by ownership, which is how Windows does it.
    let sddl = format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301ff;;;{})",
        sid_string(&sid)?
    );
    set_dacl(&shared, &sddl)?;
    Ok(burrow_proto::guest::v1::CreateGroupResponse {
        groupname: name.to_string(),
        gid: rid(&sid),
        shared_dir: shared,
    })
}

/// Replaces `path`'s DACL with the one `sddl` describes.
fn set_dacl(path: &str, sddl: &str) -> Result<(), Status> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sddl_w = win::wide(sddl);
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: `descriptor` is LocalFree'd below.
    win::check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    })
    .map_err(|err| Status::internal(format!("parsing {sddl}: {err}")))?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    // SAFETY: `descriptor` is valid until freed.
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };
    let path_w = win::wide(path);
    // SAFETY: as above.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    // SAFETY: allocated by the conversion above.
    unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
    if rc != 0 {
        return Err(net_error(&format!("setting the ACL on {path}"), rc));
    }
    Ok(())
}

fn membership(user: &str, group: &str, is_adding: bool) -> Result<(), Status> {
    lookup_user(user)?;
    lookup_group(group)?;
    let mut user_w = win::wide(user);
    let group_w = win::wide(group);
    let member = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: user_w.as_mut_ptr(),
    };
    // SAFETY: `member` and the strings outlive the call.
    let rc = unsafe {
        if is_adding {
            NetLocalGroupAddMembers(
                std::ptr::null(),
                group_w.as_ptr(),
                3,
                (&raw const member).cast(),
                1,
            )
        } else {
            NetLocalGroupDelMembers(
                std::ptr::null(),
                group_w.as_ptr(),
                3,
                (&raw const member).cast(),
                1,
            )
        }
    };
    match rc {
        NERR_SUCCESS => Ok(()),
        // Already a member is what `usermod -aG` also treats as done.
        ERROR_MEMBER_IN_ALIAS if is_adding => Ok(()),
        ERROR_MEMBER_NOT_IN_ALIAS => Err(Status::failed_precondition(format!(
            "{user} is not a member of {group}"
        ))),
        ERROR_NO_SUCH_MEMBER => Err(Status::not_found(format!(
            "no such user in the guest: {user}"
        ))),
        code => Err(net_error(&format!("changing {group}'s members"), code)),
    }
}

pub async fn add_to_group(user: &str, group: &str) -> Result<(), Status> {
    let (user, group) = (user.to_string(), group.to_string());
    tokio::task::spawn_blocking(move || membership(&user, &group, true))
        .await
        .map_err(|err| Status::internal(format!("add to group did not run: {err}")))?
}

pub async fn remove_from_group(user: &str, group: &str) -> Result<(), Status> {
    let (user, group) = (user.to_string(), group.to_string());
    tokio::task::spawn_blocking(move || membership(&user, &group, false))
        .await
        .map_err(|err| Status::internal(format!("remove from group did not run: {err}")))?
}
