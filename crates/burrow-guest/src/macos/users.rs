//! Guest users and groups on macOS.
//!
//! Accounts live in Open Directory, not in `/etc/passwd`, so they are read
//! through libc's `getpwnam_r` and `getgrouplist`, which ask
//! opendirectoryd, and written with `dscl` and `dseditgroup` against the
//! local node, as root may without anyone's password. `sysadminctl` is not
//! used: it wants an administrator's credentials for a secure token, which a
//! sandbox account has no use for.
//!
//! Names are validated before they are used and passed as argv, never through
//! a shell: they arrive from outside the guest.

#![allow(clippy::result_large_err)]

use std::ffi::{CStr, CString};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Stdio;

use nix::libc;
use tokio::io::AsyncReadExt as _;
use tonic::Status;

use burrow_proto::guest::v1 as guestpb;

use crate::unix::asyncfd::AsyncPipe;
use crate::unix::reaper;

/// Where a group's members share files. `/srv` is on the sealed system
/// volume here; `/Users/Shared` is the data volume's place for it.
const SHARED_ROOT: &str = "/Users/Shared";
/// Where macOS starts ordinary accounts' ids.
const FIRST_ID: u32 = 501;
const LAST_ID: u32 = 60_000;
/// The most groups setgroups(2) takes on macOS.
const MAX_GROUPS: usize = 16;

/// The same rule as Linux's: `[a-z_][a-z0-9_-]*`, at most 32. Open Directory
/// takes more, but the name also becomes a home directory and an argv.
pub fn validate_name(name: &str) -> Result<(), Status> {
    let mut chars = name.chars();
    let ok = (1..=32).contains(&name.len())
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ok {
        return Err(Status::invalid_argument(format!(
            "name {name:?} must be 1-32 characters matching [a-z_][a-z0-9_-]*"
        )));
    }
    Ok(())
}

/// One account, as `getpwnam` reports it.
pub struct Passwd {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// What a command needs in order to run as somebody.
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub home: String,
    pub name: String,
    pub shell: String,
}

fn text(field: *const libc::c_char) -> String {
    if field.is_null() {
        return String::new();
    }
    // SAFETY: a NUL-terminated field of the passwd entry, live while its
    // buffer is.
    unsafe { CStr::from_ptr(field) }
        .to_string_lossy()
        .into_owned()
}

/// getpwnam_r or getpwuid_r, whichever `call` makes, into a buffer of our
/// own: the plain calls share one static entry across threads.
fn passwd_with(
    call: impl Fn(*mut libc::passwd, *mut libc::c_char, usize, *mut *mut libc::passwd) -> i32,
) -> Option<Passwd> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: all zeroes is a valid passwd.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    if call(&mut entry, buf.as_mut_ptr(), buf.len(), &mut found) != 0 || found.is_null() {
        return None;
    }
    Some(Passwd {
        name: text(entry.pw_name),
        uid: entry.pw_uid,
        gid: entry.pw_gid,
        home: text(entry.pw_dir),
        shell: text(entry.pw_shell),
    })
}

pub fn lookup_user(name: &str) -> Result<Passwd, Status> {
    let missing = || Status::not_found(format!("no such user in the guest: {name}"));
    let c_name = CString::new(name).map_err(|_| missing())?;
    // SAFETY: every pointer is to a live local of the size passed.
    passwd_with(|entry, buf, len, found| unsafe {
        libc::getpwnam_r(c_name.as_ptr(), entry, buf, len, found)
    })
    .ok_or_else(missing)
}

fn lookup_uid(uid: u32) -> Option<Passwd> {
    // SAFETY: as in `lookup_user`.
    passwd_with(|entry, buf, len, found| unsafe { libc::getpwuid_r(uid, entry, buf, len, found) })
}

fn group_exists(gid: u32) -> bool {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: all zeroes is a valid group.
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: every pointer is to a live local of the size passed.
    let rc = unsafe { libc::getgrgid_r(gid, &mut entry, buf.as_mut_ptr(), buf.len(), &mut found) };
    rc == 0 && !found.is_null()
}

fn lookup_group(name: &str) -> Result<u32, Status> {
    let missing = || Status::not_found(format!("no such group in the guest: {name}"));
    let c_name = CString::new(name).map_err(|_| missing())?;
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: all zeroes is a valid group.
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: every pointer is to a live local of the size passed.
    let rc = unsafe {
        libc::getgrnam_r(
            c_name.as_ptr(),
            &mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        return Err(missing());
    }
    Ok(entry.gr_gid)
}

/// `primary` and every group Open Directory says `name` is in, at most as
/// many as setgroups(2) takes; macOS resolves the rest through opendirectoryd
/// on each check, which a credential set by hand opts out of.
fn supplementary_groups(name: &str, primary: u32) -> Vec<u32> {
    let mut gids = vec![primary];
    let Ok(c_name) = CString::new(name) else {
        return gids;
    };
    let mut found = vec![0 as libc::c_int; 64];
    let mut count = found.len() as libc::c_int;
    // SAFETY: `found` holds `count` entries. A list longer than that comes
    // back truncated with -1, and what fits is still used.
    unsafe {
        libc::getgrouplist(
            c_name.as_ptr(),
            primary as libc::c_int,
            found.as_mut_ptr(),
            &mut count,
        )
    };
    for gid in found.iter().take(count.max(0) as usize) {
        let gid = *gid as u32;
        if !gids.contains(&gid) && gids.len() < MAX_GROUPS {
            gids.push(gid);
        }
    }
    gids
}

pub fn credentials(name: &str) -> Result<Credentials, Status> {
    let (user, group) = match name.split_once(':') {
        Some((user, group)) => (user, Some(group)),
        None => (name, None),
    };
    let passwd = if let Ok(uid) = user.parse::<u32>() {
        // As on Linux: a numeric user is honoured by uid, account or not.
        lookup_uid(uid).unwrap_or(Passwd {
            name: user.to_string(),
            uid,
            gid: uid,
            home: "/".to_string(),
            shell: "/bin/sh".to_string(),
        })
    } else {
        validate_name(user)?;
        lookup_user(user)?
    };
    let gid = match group {
        Some(group) => match group.parse::<u32>() {
            Ok(gid) => gid,
            Err(_) => {
                validate_name(group)?;
                lookup_group(group)?
            }
        },
        None => passwd.gid,
    };
    Ok(Credentials {
        groups: supplementary_groups(&passwd.name, gid),
        uid: passwd.uid,
        gid,
        home: passwd.home,
        name: passwd.name,
        shell: passwd.shell,
    })
}

/// Reads a child pipe to the end.
async fn drain(pipe: Option<impl Into<std::os::fd::OwnedFd>>) -> String {
    let Some(pipe) = pipe else {
        return String::new();
    };
    let Ok(mut pipe) = AsyncPipe::new(pipe.into()) else {
        return String::new();
    };
    let mut buf = Vec::new();
    let _ = pipe.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

/// Runs one of the system's tools to completion, through the reaper like
/// every other child of the agent, and returns what it printed.
async fn run_tool(tool: &str, args: &[&str]) -> Result<String, Status> {
    let mut command = std::process::Command::new(tool);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let gate = reaper::hold();
    let mut child = command
        .spawn()
        .map_err(|err| Status::internal(format!("spawn {tool}: {err}")))?;
    let exit = reaper::watch(child.id() as i32);
    drop(gate);
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    drop(child);
    let (out, err) = tokio::join!(drain(stdout), drain(stderr));
    let code = exit
        .await
        .map_err(|_| Status::internal("lost track of the child process"))?
        .code;
    if code != 0 {
        let detail = format!("{out}{err}");
        let detail = detail.trim();
        return Err(Status::internal(format!(
            "{tool} {} exited {code}{}{detail}",
            args.join(" "),
            if detail.is_empty() { "" } else { ": " },
        )));
    }
    Ok(out)
}

async fn dscl(args: &[&str]) -> Result<(), Status> {
    let mut argv = vec!["."];
    argv.extend_from_slice(args);
    run_tool("/usr/bin/dscl", &argv).await.map(drop)
}

/// The lowest id from 501 that is neither a user's nor a group's, so a user
/// and their own group can share it.
fn next_id() -> Result<u32, Status> {
    (FIRST_ID..LAST_ID)
        .find(|id| lookup_uid(*id).is_none() && !group_exists(*id))
        .ok_or_else(|| Status::resource_exhausted("no free account id"))
}

/// A local group record. `Password` `*` is no password, as for every group
/// macOS makes itself.
async fn create_group_record(name: &str, gid: u32) -> Result<(), Status> {
    let path = format!("/Groups/{name}");
    let gid = gid.to_string();
    dscl(&["-create", &path]).await?;
    dscl(&["-create", &path, "PrimaryGroupID", &gid]).await?;
    dscl(&["-create", &path, "RealName", name]).await?;
    dscl(&["-create", &path, "Password", "*"]).await
}

/// Opendirectoryd caches lookups; a record just written is otherwise not
/// always what the next getpwnam or getgrouplist sees.
async fn flush_cache() {
    if let Err(err) = run_tool("/usr/bin/dscacheutil", &["-flushcache"]).await {
        tracing::debug!(%err, "flushing the directory cache");
    }
}

/// A local account with a group of its own, as Linux's `useradd` makes one,
/// rather than macOS's shared `staff`: two sandbox users should not read each
/// other's group-readable files. The password is `*`, which nothing matches,
/// and the account is hidden from the login window; it exists to be taken on
/// by the agent, never to be logged into.
pub async fn create_user(name: &str) -> Result<guestpb::CreateUserResponse, Status> {
    validate_name(name)?;
    if lookup_user(name).is_ok() {
        return Err(Status::already_exists(format!("user {name} exists")));
    }
    if lookup_group(name).is_ok() {
        return Err(Status::already_exists(format!(
            "group {name} exists, which the user's own group would be"
        )));
    }
    let id = next_id()?;
    let home = format!("/Users/{name}");
    create_group_record(name, id).await?;
    let path = format!("/Users/{name}");
    let id_text = id.to_string();
    dscl(&["-create", &path]).await?;
    for (key, value) in [
        ("UniqueID", id_text.as_str()),
        ("PrimaryGroupID", id_text.as_str()),
        ("UserShell", "/bin/zsh"),
        ("NFSHomeDirectory", home.as_str()),
        ("RealName", name),
        ("Password", "*"),
        ("IsHidden", "1"),
    ] {
        dscl(&["-create", &path, key, value]).await?;
    }
    flush_cache().await;

    std::fs::create_dir_all(&home)
        .map_err(|err| Status::internal(format!("create {home}: {err}")))?;
    chown(&home, id, id)?;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| Status::internal(format!("chmod {home}: {err}")))?;

    let passwd = lookup_user(name)?;
    Ok(guestpb::CreateUserResponse {
        username: passwd.name,
        uid: passwd.uid,
        gid: passwd.gid,
        home: passwd.home,
    })
}

pub async fn create_group(name: &str) -> Result<guestpb::CreateGroupResponse, Status> {
    validate_name(name)?;
    if lookup_group(name).is_ok() {
        return Err(Status::already_exists(format!("group {name} exists")));
    }
    create_group_record(name, next_id()?).await?;
    flush_cache().await;
    let gid = lookup_group(name)?;

    let shared = Path::new(SHARED_ROOT).join(name);
    std::fs::create_dir_all(&shared)
        .map_err(|err| Status::internal(format!("create {}: {err}", shared.display())))?;
    // root and the group, 2770, as on Linux. A BSD directory gives what is
    // made in it its own group anyway; the setgid bit is kept so the mode
    // reads the same.
    chown(&shared, 0, gid)?;
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o2770))
        .map_err(|err| Status::internal(format!("chmod {}: {err}", shared.display())))?;

    Ok(guestpb::CreateGroupResponse {
        groupname: name.to_string(),
        gid,
        shared_dir: shared.to_string_lossy().into_owned(),
    })
}

async fn set_membership(user: &str, group: &str, flag: &str) -> Result<(), Status> {
    validate_name(user)?;
    validate_name(group)?;
    lookup_user(user)?;
    lookup_group(group)?;
    run_tool(
        "/usr/sbin/dseditgroup",
        &["-o", "edit", flag, user, "-t", "user", group],
    )
    .await?;
    flush_cache().await;
    Ok(())
}

pub async fn add_to_group(user: &str, group: &str) -> Result<(), Status> {
    set_membership(user, group, "-a").await
}

pub async fn remove_from_group(user: &str, group: &str) -> Result<(), Status> {
    set_membership(user, group, "-d").await
}

fn chown(path: impl AsRef<Path>, uid: u32, gid: u32) -> Result<(), Status> {
    let path = path.as_ref();
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
        .map_err(|err| Status::internal(format!("chown {}: {err}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_found_with_its_groups() {
        let root = credentials("root").unwrap();
        assert_eq!((root.uid, root.gid), (0, 0));
        assert_eq!(root.groups[0], 0);
        assert!(root.groups.len() <= MAX_GROUPS);
        assert_eq!(credentials("0:20").unwrap().gid, 20);
        assert_eq!(
            credentials("no-such-user").err().unwrap().code(),
            tonic::Code::NotFound
        );
    }
}
