//! Guest users and groups on macOS.
//!
//! Accounts live in Open Directory, not in `/etc/passwd`, so they are read
//! by querying it (see `directory`: libinfo's in-process cache would keep a
//! deleted account found), memberships through `getgrouplist`, and written
//! with `dscl` and `dseditgroup` against the local node, as root may without anyone's password. `sysadminctl` is not
//! used: it wants an administrator's credentials for a secure token, which a
//! sandbox account has no use for.
//!
//! Names are validated before they are used and passed as argv, never through
//! a shell: they arrive from outside the guest.

#![allow(clippy::result_large_err)]

use std::ffi::CString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Stdio;

use nix::libc;
use tokio::io::AsyncReadExt as _;
use tonic::Status;

use burrow_proto::guest::v1 as guestpb;

use super::directory;
use crate::unix::asyncfd::AsyncPipe;
use crate::unix::reaper;

/// Where a group's members share files. `/srv` is on the sealed system
/// volume here; `/Users/Shared` is the data volume's place for it.
const SHARED_ROOT: &str = "/Users/Shared";
/// Where macOS starts ordinary accounts' ids.
const FIRST_ID: u32 = 501;
const LAST_ID: u32 = 60_000;
/// The most groups a macOS credential holds; see `supplementary_groups`.
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

/// One account, as Open Directory has it now.
pub use super::directory::User as Passwd;

/// What a command needs in order to run as somebody.
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub home: String,
    pub name: String,
    pub shell: String,
    /// The audit session of the user's console login, for a command that is
    /// to run in it; see [`super::session`].
    pub gui_session: Option<i32>,
}

pub fn lookup_user(name: &str) -> Result<Passwd, Status> {
    directory::user_named(name)
        .ok_or_else(|| Status::not_found(format!("no such user in the guest: {name}")))
}

fn lookup_uid(uid: u32) -> Option<Passwd> {
    directory::user_with_id(uid)
}

fn group_exists(gid: u32) -> bool {
    directory::group_with_id(gid)
}

fn lookup_group(name: &str) -> Result<u32, Status> {
    directory::group_named(name)
        .ok_or_else(|| Status::not_found(format!("no such group in the guest: {name}")))
}

/// `primary` and every group Open Directory says `name` is in, at most as
/// many as the kernel holds in a credential (16). A user in more is not cut
/// off from the rest: the command or thread takes these through
/// initgroups(2) with the user as its membership uid, and the kernel asks
/// opendirectoryd about any group not in the list on each check.
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
        gui_session: None,
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
pub(super) async fn run_tool(tool: &str, args: &[&str]) -> Result<String, Status> {
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

/// Deletes a user create could have made, never an administrator or the
/// auto-login user the desktop session runs as. Refused while any process
/// runs as them: nothing is killed on the caller's behalf. They leave every
/// group first, so a later account of the same name inherits none; their own
/// group goes with them unless another account still uses it; their home is
/// kept, handed to root, unless `remove_home`.
pub async fn delete_user(
    name: &str,
    remove_home: bool,
) -> Result<guestpb::DeleteUserResponse, Status> {
    use crate::unix::accounts;
    use std::os::unix::fs::MetadataExt as _;

    validate_name(name)?;
    let passwd = lookup_user(name)?;
    // SAFETY: geteuid has no preconditions.
    accounts::check_deletable("user", name, passwd.uid, FIRST_ID..LAST_ID, unsafe {
        libc::geteuid()
    })?;
    if auto_login_user().await.as_deref() == Some(name) {
        return Err(Status::permission_denied(format!(
            "user {name} is the auto-login user the guest's desktop session runs as"
        )));
    }
    let admin = run_tool(
        "/usr/bin/dsmemberutil",
        &["checkmembership", "-U", name, "-G", "admin"],
    )
    .await?;
    if admin.trim() == "user is a member of the group" {
        return Err(Status::permission_denied(format!(
            "user {name} is an administrator"
        )));
    }
    if has_processes(passwd.uid) {
        return Err(Status::failed_precondition(format!(
            "user {name} has running processes; end them first"
        )));
    }
    let homes: Vec<String> = records("/Users", "NFSHomeDirectory")
        .await?
        .into_iter()
        .filter(|(user, _)| user != name)
        .map(|(_, home)| home.join(" "))
        .collect();
    let owned = |meta: &std::fs::Metadata| meta.uid() == passwd.uid;
    let own_home = match accounts::check_removable(&passwd.home, "/Users", &homes, owned) {
        Ok(()) => true,
        Err(err) if remove_home => return Err(err),
        Err(_) => false,
    };

    let groups = records("/Groups", "GroupMembership").await?;
    let uuid = run_tool(
        "/usr/bin/dscl",
        &[".", "-read", &format!("/Users/{name}"), "GeneratedUID"],
    )
    .await?;
    let uuid = uuid
        .trim()
        .trim_start_matches("GeneratedUID:")
        .trim()
        .to_string();
    // First, so a refusal leaves the account as it was. macOS 27's
    // opendirectoryd deletes a user record only for a caller with Full Disk
    // Access, which the node grants the agent on the disk before a cold boot.
    dscl(&["-delete", &format!("/Users/{name}")])
        .await
        .map_err(|err| match err.message().contains("eDSPermissionError") {
            true => Status::failed_precondition(format!(
                "macOS refused to delete user {name}: deleting a user takes Full Disk Access, \
                 which the node grants the agent before the guest boots and this boot did not \
                 get (see the node's log)"
            )),
            false => err,
        })?;
    flush_cache().await;
    for (group, _) in groups
        .iter()
        .filter(|(_, members)| members.iter().any(|m| m == name))
    {
        // By name and by UUID, as dseditgroup would, which needs the user to
        // still exist.
        let path = format!("/Groups/{group}");
        dscl(&["-delete", &path, "GroupMembership", name]).await?;
        if !uuid.is_empty() {
            let _ = dscl(&["-delete", &path, "GroupMembers", &uuid]).await;
        }
    }

    let others_in_own = groups
        .iter()
        .any(|(group, members)| group == name && members.iter().any(|m| m != name));
    if lookup_group(name).ok() == Some(passwd.gid)
        && !others_in_own
        && primary_of(passwd.gid).await?.is_none()
    {
        dscl(&["-delete", &format!("/Groups/{name}")]).await?;
        flush_cache().await;
    }

    let removed = if own_home {
        accounts::dispose(&passwd.home, owned, remove_home)?
    } else {
        None
    };
    Ok(guestpb::DeleteUserResponse {
        home: passwd.home,
        is_home_removed: removed == Some(true),
    })
}

/// Deletes a group create could have made. Refused while it is any user's
/// primary group; members simply lose it. Its shared directory is kept,
/// handed to root, unless `remove_shared_dir`.
pub async fn delete_group(
    name: &str,
    remove_shared_dir: bool,
) -> Result<guestpb::DeleteGroupResponse, Status> {
    use crate::unix::accounts;
    use std::os::unix::fs::MetadataExt as _;

    validate_name(name)?;
    let gid = lookup_group(name)?;
    // SAFETY: getegid has no preconditions.
    accounts::check_deletable("group", name, gid, FIRST_ID..LAST_ID, unsafe {
        libc::getegid()
    })?;
    if let Some(user) = primary_of(gid).await? {
        return Err(Status::failed_precondition(format!(
            "group {name} is the primary group of user {user}; delete the user instead"
        )));
    }
    let shared = format!("{SHARED_ROOT}/{name}");
    let owned = |meta: &std::fs::Metadata| meta.gid() == gid;
    if remove_shared_dir {
        let homes: Vec<String> = records("/Users", "NFSHomeDirectory")
            .await?
            .into_iter()
            .map(|(_, home)| home.join(" "))
            .collect();
        accounts::check_removable(&shared, SHARED_ROOT, &homes, owned)?;
    }
    dscl(&["-delete", &format!("/Groups/{name}")]).await?;
    flush_cache().await;
    let removed = accounts::dispose(&shared, owned, remove_shared_dir)?;
    Ok(guestpb::DeleteGroupResponse {
        shared_dir: if removed.is_some() {
            shared
        } else {
            String::new()
        },
        is_shared_dir_removed: removed == Some(true),
    })
}

/// `dscl . -list PATH KEY`: each record's name and that key's values.
async fn records(path: &str, key: &str) -> Result<Vec<(String, Vec<String>)>, Status> {
    let out = run_tool("/usr/bin/dscl", &[".", "-list", path, key]).await?;
    Ok(out
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((
                fields.next()?.to_string(),
                fields.map(String::from).collect(),
            ))
        })
        .collect())
}

/// The first user whose primary group is `gid`.
async fn primary_of(gid: u32) -> Result<Option<String>, Status> {
    let gid = gid.to_string();
    Ok(records("/Users", "PrimaryGroupID")
        .await?
        .into_iter()
        .find(|(_, ids)| ids.contains(&gid))
        .map(|(user, _)| user))
}

/// Who loginwindow logs in at boot, if anyone.
async fn auto_login_user() -> Option<String> {
    run_tool(
        "/usr/bin/defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "autoLoginUser",
        ],
    )
    .await
    .ok()
    .map(|user| user.trim().to_string())
    .filter(|user| !user.is_empty())
}

/// Whether any process runs with `uid` as its effective uid.
fn has_processes(uid: u32) -> bool {
    /// `PROC_UID_ONLY` from `<sys/proc_info.h>`, which `libc` does not bind.
    const PROC_UID_ONLY: u32 = 4;
    let mut pids = vec![0 as libc::c_int; 8192];
    let size = std::mem::size_of_val(pids.as_slice()) as libc::c_int;
    // SAFETY: `pids` holds `size` bytes.
    let bytes = unsafe { libc::proc_listpids(PROC_UID_ONLY, uid, pids.as_mut_ptr().cast(), size) };
    let count = bytes.max(0) as usize / std::mem::size_of::<libc::c_int>();
    pids.iter().take(count).any(|pid| *pid > 0)
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
