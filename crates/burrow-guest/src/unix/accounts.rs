//! What deleting an account means on a POSIX guest, the same on Linux and
//! macOS: which accounts may go, and what becomes of the directory one leaves.

#![allow(clippy::result_large_err)]

use std::fs::Metadata;
use std::ops::Range;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path};

use tonic::Status;

/// Names the image or the agent depends on, whatever ids they carry.
const RESERVED: &[&str] = &[
    "root", "nobody", "nogroup", "daemon", "wheel", "admin", "staff",
];

/// Refuses an account that create could not have made: an id outside
/// `range`, which is where create allocates, a reserved name, or the id the
/// agent runs as.
pub fn check_deletable(
    kind: &str,
    name: &str,
    id: u32,
    range: Range<u32>,
    own: u32,
) -> Result<(), Status> {
    if RESERVED.contains(&name) || !range.contains(&id) || id == own {
        return Err(Status::permission_denied(format!(
            "{kind} {name} (id {id}) is not one burrow could have created; only ids {}-{} may be deleted",
            range.start,
            range.end - 1
        )));
    }
    Ok(())
}

/// Refuses removing `dir` unless it lies directly under `root`, is not where
/// any of `others` (the other accounts' homes) is or lies, and, if it exists,
/// is a real directory that `owned` says is the account's.
pub fn check_removable(
    dir: &str,
    root: &str,
    others: &[String],
    owned: impl Fn(&Metadata) -> bool,
) -> Result<(), Status> {
    let path = Path::new(dir);
    let refuse = |why: &str| {
        Err(Status::failed_precondition(format!(
            "{dir} {why}; not removing it"
        )))
    };
    let plain = path
        .components()
        .all(|part| matches!(part, Component::RootDir | Component::Normal(_)));
    if !plain || path.parent() != Some(Path::new(root)) {
        return refuse(&format!("is not directly under {root}"));
    }
    if others
        .iter()
        .any(|other| Path::new(other).starts_with(path))
    {
        return refuse("is shared with another account");
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_dir() || !owned(&meta) => refuse("is not the account's own directory"),
        _ => Ok(()),
    }
}

/// Removes `dir`, or keeps it handed to root with mode 0700 so an account
/// that later reuses the id does not inherit it. Only a real directory that
/// `owned` says is the account's is touched. `None` when there was none;
/// otherwise whether it was removed.
pub fn dispose(
    dir: &str,
    owned: impl Fn(&Metadata) -> bool,
    remove: bool,
) -> Result<Option<bool>, Status> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() && owned(&meta) => {}
        _ => return Ok(None),
    }
    if remove {
        std::fs::remove_dir_all(dir)
            .map_err(|err| Status::internal(format!("remove {dir}: {err}")))?;
        return Ok(Some(true));
    }
    std::os::unix::fs::lchown(dir, Some(0), Some(0))
        .map_err(|err| Status::internal(format!("chown {dir}: {err}")))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| Status::internal(format!("chmod {dir}: {err}")))?;
    Ok(Some(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_id_create_could_have_made_may_go() {
        assert!(check_deletable("user", "alice", 1001, 1000..60_000, 0).is_ok());
        for (name, id) in [
            ("root", 0),
            ("daemon", 2),
            ("nobody", 65_534),
            ("nobody", 1005),
            ("alice", 999),
            ("alice", 60_000),
        ] {
            let err = check_deletable("user", name, id, 1000..60_000, 0).unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied, "{name} {id}");
        }
        assert!(check_deletable("user", "agent", 1001, 1000..60_000, 1001).is_err());
    }

    #[test]
    fn a_home_must_be_its_own_directory_under_the_root() {
        let none = |_: &Metadata| true;
        let others = vec!["/home/bob".to_string(), "/".to_string()];
        assert!(check_removable("/home/alice", "/home", &others, none).is_ok());
        for dir in [
            "/home",
            "/home/",
            "/home/alice/sub",
            "/home/../etc",
            "/home/./alice/..",
            "/srv/alice",
            "/",
            "relative/home",
        ] {
            assert!(
                check_removable(dir, "/home", &others, none).is_err(),
                "{dir}"
            );
        }
        let shared = vec!["/home/alice/bob".to_string()];
        assert!(check_removable("/home/alice", "/home", &shared, none).is_err());
        let same = vec!["/home/alice".to_string()];
        assert!(check_removable("/home/alice", "/home", &same, none).is_err());
    }

    #[test]
    fn a_directory_someone_else_owns_is_neither_removed_nor_kept() {
        let dir = std::env::temp_dir().join(format!("burrow-accounts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_text = dir.to_str().unwrap();
        let root = dir.parent().unwrap().to_str().unwrap();
        let err = check_removable(dir_text, root, &[], |_| false).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(dispose(dir_text, |_| false, true).unwrap(), None);
        assert!(dir.exists());
        assert_eq!(dispose(dir_text, |_| true, true).unwrap(), Some(true));
        assert!(!dir.exists());
        assert_eq!(dispose(dir_text, |_| true, true).unwrap(), None);
    }
}
