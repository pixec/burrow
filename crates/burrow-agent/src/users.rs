//! Guest users and groups.
//!
//! Burrow images are both busybox and full distros, so nothing here assumes a
//! particular userland: the tool that exists is the tool that is used, and a
//! guest carrying neither says so rather than half-creating an account.
//!
//! Names are validated before they are used and passed as argv, never through
//! a shell: they arrive from outside the guest.

#![allow(clippy::result_large_err)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::AsyncReadExt;
use tonic::Status;

use burrow_proto::agent::v1 as agentpb;

use crate::asyncfd::AsyncPipe;
use crate::reaper;

/// Where a group's members share files. Group-owned and setgid, so a file
/// created inside it belongs to the group rather than its author's own.
const SHARED_ROOT: &str = "/srv";

/// POSIX portable user and group names: `[a-z_][a-z0-9_-]*`, at most 32.
///
/// `useradd` and `adduser` disagree about what else they will accept, and the
/// name reaches `/etc/passwd`, a home directory path and an argv, so the
/// strictest reading of the three is the one enforced.
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

/// Finds a tool on the paths a guest keeps its administrative binaries on.
///
/// `PATH` is not consulted: the agent inherits whatever the kernel handed init,
/// which on a minimal image is nothing at all.
fn locate(tool: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(tool))
        .find(|path| path.is_file())
}

/// Reads a child pipe to the end. What these tools print is a few lines, and
/// what it is wanted for is the message on a failure.
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

/// Runs one of the guest's own tools to completion, capturing its diagnostics.
///
/// Spawned through `std::process` and awaited through the reaper for the same
/// reason exec is: the agent is PID 1 and a second `waitpid` caller would race
/// it for the exit status. See [`crate::reaper`].
async fn run_tool(tool: &Path, args: &[&str]) -> Result<(), Status> {
    let mut command = std::process::Command::new(tool);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|err| Status::internal(format!("spawn {}: {err}", tool.display())))?;
    // No await between spawn and watch, so the reaper cannot deliver this
    // child's status before there is somewhere to deliver it to.
    let exit = reaper::watch(child.id() as i32);
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    drop(child);

    // Both drained at once: a tool that filled one pipe while the agent was
    // reading the other would block forever on a write nobody is taking.
    let (out, err) = tokio::join!(drain(stdout), drain(stderr));
    let diagnostics = format!("{out}{err}");

    let code = exit
        .await
        .map_err(|_| Status::internal("lost track of the child process"))?;
    if code != 0 {
        let detail = diagnostics.trim();
        return Err(Status::internal(format!(
            "{} exited {code}{}{}",
            tool.display(),
            if detail.is_empty() { "" } else { ": " },
            detail
        )));
    }
    Ok(())
}

/// Runs the first of `candidates` the guest actually has.
///
/// `None` means it has none of them, which is not an error: burrow's smallest
/// images are a busybox built without the user applets at all, and the account
/// files are then written directly instead.
async fn run_first(candidates: &[(&str, &[&str])]) -> Option<Result<(), Status>> {
    for (tool, args) in candidates {
        if let Some(path) = locate(tool) {
            return Some(run_tool(&path, args).await);
        }
    }
    None
}

/// One line of `/etc/passwd`.
pub struct Passwd {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// Reads a user out of `/etc/passwd`.
///
/// Parsed rather than looked up through libc: the agent is built against musl,
/// whose `getpwnam` would want NSS shared objects the guest image need not
/// have, and `/etc/passwd` is where every tool used here writes anyway.
pub fn lookup_user(name: &str) -> Result<Passwd, Status> {
    let text = std::fs::read_to_string("/etc/passwd")
        .map_err(|err| Status::internal(format!("read /etc/passwd: {err}")))?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 || fields[0] != name {
            continue;
        }
        return Ok(Passwd {
            name: fields[0].to_string(),
            uid: fields[2]
                .parse()
                .map_err(|_| Status::internal(format!("user {name} has an unreadable uid")))?,
            gid: fields[3]
                .parse()
                .map_err(|_| Status::internal(format!("user {name} has an unreadable gid")))?,
            home: fields[5].to_string(),
            shell: fields[6].to_string(),
        });
    }
    Err(Status::not_found(format!(
        "no such user in the guest: {name}"
    )))
}

fn lookup_group(name: &str) -> Result<u32, Status> {
    let text = std::fs::read_to_string("/etc/group")
        .map_err(|err| Status::internal(format!("read /etc/group: {err}")))?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == name {
            return fields[2]
                .parse()
                .map_err(|_| Status::internal(format!("group {name} has an unreadable gid")));
        }
    }
    Err(Status::not_found(format!(
        "no such group in the guest: {name}"
    )))
}

/// Every group `name` is listed in, plus its own primary group.
///
/// Without the supplementary set a user spawned with `setuid` alone would lose
/// exactly the memberships that make a shared directory work.
fn supplementary_groups(name: &str, primary: u32) -> Vec<u32> {
    let mut gids = vec![primary];
    let Ok(text) = std::fs::read_to_string("/etc/group") else {
        return gids;
    };
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 {
            continue;
        }
        let member = fields[3].split(',').any(|m| m == name);
        if let Ok(gid) = fields[2].parse::<u32>()
            && member
            && !gids.contains(&gid)
        {
            gids.push(gid);
        }
    }
    gids
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

pub fn credentials(name: &str) -> Result<Credentials, Status> {
    validate_name(name)?;
    let passwd = lookup_user(name)?;
    Ok(Credentials {
        groups: supplementary_groups(&passwd.name, passwd.gid),
        uid: passwd.uid,
        gid: passwd.gid,
        home: passwd.home,
        name: passwd.name,
        shell: passwd.shell,
    })
}

pub async fn create_user(name: &str) -> Result<agentpb::CreateUserResponse, Status> {
    validate_name(name)?;
    if lookup_user(name).is_ok() {
        return Err(Status::already_exists(format!("user {name} exists")));
    }

    match run_first(&[
        // shadow-utils, on a full distro.
        ("useradd", &["-m", "-s", "/bin/sh", name]),
        // busybox. `-D` is "no password", not "no home".
        ("adduser", &["-D", "-s", "/bin/sh", name]),
    ])
    .await
    {
        Some(result) => result?,
        None => write_account(name)?,
    }

    let passwd = lookup_user(name)?;
    // busybox's `adduser` gives the user a gid with no group behind it, which
    // leaves the account's primary group dangling and, worse, free for the
    // next `addgroup` to hand to somebody else, after which two accounts share
    // a group nobody asked them to share.
    ensure_primary_group(&passwd.name, passwd.gid)?;

    // A home the tooling left group- or world-readable is not a boundary. Both
    // tools create it; only their modes differ.
    if !passwd.home.is_empty() {
        std::fs::create_dir_all(&passwd.home)
            .map_err(|err| Status::internal(format!("create {}: {err}", passwd.home)))?;
        chown(&passwd.home, passwd.uid, passwd.gid)?;
        std::fs::set_permissions(&passwd.home, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| Status::internal(format!("chmod {}: {err}", passwd.home)))?;
    }

    Ok(agentpb::CreateUserResponse {
        username: passwd.name,
        uid: passwd.uid,
        gid: passwd.gid,
        home: passwd.home,
    })
}

pub async fn create_group(name: &str) -> Result<agentpb::CreateGroupResponse, Status> {
    validate_name(name)?;
    if lookup_group(name).is_ok() {
        return Err(Status::already_exists(format!("group {name} exists")));
    }

    match run_first(&[("groupadd", &[name]), ("addgroup", &[name])]).await {
        Some(result) => result?,
        None => {
            append_line(
                "/etc/group",
                &format!("{name}:x:{}:", next_id("/etc/group")?),
            )?;
        }
    }

    let gid = lookup_group(name)?;
    let shared = Path::new(SHARED_ROOT).join(name);
    std::fs::create_dir_all(&shared)
        .map_err(|err| Status::internal(format!("create {}: {err}", shared.display())))?;
    // Owned by root and the group, 2770: members may read and write, the setgid
    // bit keeps what they create inside owned by the group, and nobody else
    // gets in.
    chown(&shared, 0, gid)?;
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o2770))
        .map_err(|err| Status::internal(format!("chmod {}: {err}", shared.display())))?;

    Ok(agentpb::CreateGroupResponse {
        groupname: name.to_string(),
        gid,
        shared_dir: shared.to_string_lossy().into_owned(),
    })
}

pub async fn add_to_group(user: &str, group: &str) -> Result<(), Status> {
    validate_name(user)?;
    validate_name(group)?;
    lookup_user(user)?;
    lookup_group(group)?;
    match run_first(&[
        ("usermod", &["-aG", group, user]),
        ("addgroup", &[user, group]),
    ])
    .await
    {
        Some(result) => result,
        None => set_membership(user, group, true),
    }
}

pub async fn remove_from_group(user: &str, group: &str) -> Result<(), Status> {
    validate_name(user)?;
    validate_name(group)?;
    lookup_user(user)?;
    lookup_group(group)?;
    match run_first(&[
        ("gpasswd", &["-d", user, group]),
        ("delgroup", &[user, group]),
    ])
    .await
    {
        Some(result) => result,
        None => set_membership(user, group, false),
    }
}

/// Writes an account straight into `/etc/passwd`, `/etc/group` and, where the
/// image has one, `/etc/shadow`.
///
/// The fallback for an image with no user tooling at all (burrow's smallest
/// template is a busybox built without the `adduser` applet), where the choice
/// is between doing what that applet would have done and having no users. The
/// account is locked: it exists to be `setuid`-ed into by the agent, never to
/// be logged into.
fn write_account(name: &str) -> Result<(), Status> {
    let uid = next_id("/etc/passwd")?;
    let gid = next_id("/etc/group")?;
    let home = format!("/home/{name}");

    // The group first: a passwd entry naming a gid that does not exist yet is
    // a broken account for as long as the second write has not landed.
    append_line("/etc/group", &format!("{name}:x:{gid}:"))?;
    append_line(
        "/etc/passwd",
        &format!("{name}:x:{uid}:{gid}::{home}:/bin/sh"),
    )?;
    if Path::new("/etc/shadow").exists() {
        // `!` is a locked password: no login, by any route.
        append_line("/etc/shadow", &format!("{name}:!:20000:0:99999:7:::"))?;
    }
    Ok(())
}

/// Gives a user's primary gid a group of its own, if nothing claims it yet.
fn ensure_primary_group(name: &str, gid: u32) -> Result<(), Status> {
    let text = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let claimed = text
        .lines()
        .filter_map(|line| line.split(':').nth(2)?.parse::<u32>().ok())
        .any(|held| held == gid);
    if claimed {
        return Ok(());
    }
    append_line("/etc/group", &format!("{name}:x:{gid}:"))
}

/// The next free id at or above 1000 in an account file.
///
/// 1000 is where every distro starts ordinary accounts, and staying above it
/// keeps a created user clear of whatever the image reserved for itself.
fn next_id(path: &str) -> Result<u32, Status> {
    const FIRST: u32 = 1000;
    const LAST: u32 = 60_000;

    // A missing account file is an image with no accounts, not a failure.
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let highest = text
        .lines()
        .filter_map(|line| line.split(':').nth(2)?.parse::<u32>().ok())
        .filter(|id| (FIRST..LAST).contains(id))
        .max();
    match highest {
        Some(id) => Ok(id + 1),
        None => Ok(FIRST),
    }
}

fn append_line(path: &str, line: &str) -> Result<(), Status> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|err| Status::internal(format!("open {path}: {err}")))?;
    writeln!(file, "{line}").map_err(|err| Status::internal(format!("append to {path}: {err}")))
}

/// Adds or removes a member in `/etc/group`'s member list.
///
/// Rewritten through a temporary file and renamed into place, so a crash
/// halfway leaves the old file rather than a truncated one.
fn set_membership(user: &str, group: &str, member: bool) -> Result<(), Status> {
    let text = std::fs::read_to_string("/etc/group")
        .map_err(|err| Status::internal(format!("read /etc/group: {err}")))?;

    let mut out = String::with_capacity(text.len() + user.len() + 1);
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 || fields[0] != group {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let mut members: Vec<&str> = fields[3].split(',').filter(|m| !m.is_empty()).collect();
        members.retain(|held| *held != user);
        if member {
            members.push(user);
        }
        out.push_str(&format!(
            "{}:{}:{}:{}\n",
            fields[0],
            fields[1],
            fields[2],
            members.join(",")
        ));
    }

    let temporary = "/etc/group.burrow";
    std::fs::write(temporary, &out)
        .map_err(|err| Status::internal(format!("write {temporary}: {err}")))?;
    std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o644))
        .map_err(|err| Status::internal(format!("chmod {temporary}: {err}")))?;
    std::fs::rename(temporary, "/etc/group")
        .map_err(|err| Status::internal(format!("replace /etc/group: {err}")))
}

/// `libc::chown` directly: nix gates its wrapper behind a feature this
/// workspace does not enable, and enabling it for one call would change what
/// every other crate compiles.
fn chown(path: impl AsRef<Path>, uid: u32, gid: u32) -> Result<(), Status> {
    use std::os::unix::ffi::OsStrExt;

    let path = path.as_ref();
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Status::internal(format!("path {} contains a nul", path.display())))?;
    // SAFETY: `c_path` is a valid nul-terminated string for the call.
    if unsafe { nix::libc::chown(c_path.as_ptr(), uid, gid) } < 0 {
        return Err(Status::internal(format!(
            "chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_name;

    #[test]
    fn a_portable_name_is_accepted() {
        for good in ["agent", "_svc", "a", "agent-1", "a_b-9", &"a".repeat(32)] {
            assert!(validate_name(good).is_ok(), "{good:?}");
        }
    }

    /// These names reach an argv, `/etc/passwd` and a directory path, so
    /// anything that could be read as a flag, a second field or a path
    /// component is refused rather than escaped.
    #[test]
    fn a_name_that_could_be_read_as_something_else_is_refused() {
        for bad in [
            "",
            "-rf",
            "Agent",
            "1agent",
            "a b",
            "a:b",
            "../etc",
            "root\n",
            "a/b",
            &"a".repeat(33),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }
}
