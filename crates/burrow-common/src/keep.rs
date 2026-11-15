//! The paths a recreate carries from the old root disk to the new one.
//!
//! Shared by the CLI, the orchestrator and the node so all three refuse the
//! same paths with the same words.

/// The most paths one recreate keeps.
pub const MAX_PATHS: usize = 32;
/// The longest path kept.
pub const MAX_PATH_BYTES: usize = 4096;

/// Trees that are not the guest's files: kernel interfaces and the agent's
/// tmpfs, rebuilt on every boot.
const REFUSED: [&str; 4] = ["/proc", "/sys", "/dev", "/run"];

/// Checks the paths a recreate is asked to keep, and returns them normalized
/// (no trailing or repeated slashes, no `.`) and without any path another
/// one already covers.
pub fn validate(paths: &[String]) -> Result<Vec<String>, String> {
    if paths.len() > MAX_PATHS {
        return Err(format!(
            "a recreate keeps at most {MAX_PATHS} paths, not {}",
            paths.len()
        ));
    }
    let mut kept: Vec<String> = Vec::new();
    for path in paths {
        let normal = normalize(path)?;
        if !kept.iter().any(|other| covers(other, &normal)) {
            kept.retain(|other| !covers(&normal, other));
            kept.push(normal);
        }
    }
    kept.sort();
    Ok(kept)
}

fn normalize(path: &str) -> Result<String, String> {
    if path.len() > MAX_PATH_BYTES {
        return Err(format!(
            "--keep {path:.64}...: longer than {MAX_PATH_BYTES} bytes"
        ));
    }
    if !path.starts_with('/') {
        return Err(format!("--keep {path}: not an absolute path"));
    }
    if path.chars().any(char::is_control) {
        return Err(format!("--keep {path:?}: holds a control character"));
    }
    if path.split('/').any(|part| part == "..") {
        return Err(format!("--keep {path}: holds `..`"));
    }
    let normal = clean(path);
    if normal.is_empty() {
        return Err("--keep /: the whole disk is what a recreate replaces; keep the paths that matter, or put them on a volume".into());
    }
    if let Some(refused) = REFUSED.iter().find(|refused| covers(refused, &normal)) {
        return Err(format!(
            "--keep {path}: {refused} is not on the root disk, it is made afresh at boot"
        ));
    }
    Ok(normal)
}

/// `path` without repeated or trailing slashes or `.` components, as
/// [`covers`] compares paths; `/` is the empty string.
pub fn clean(path: &str) -> String {
    let mut normal = String::new();
    for part in path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        normal.push('/');
        normal.push_str(part);
    }
    normal
}

/// Whether `outer` is `inner` or one of its ancestors.
pub fn covers(outer: &str, inner: &str) -> bool {
    inner == outer
        || inner
            .strip_prefix(outer)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(paths: &[&str]) -> Result<Vec<String>, String> {
        validate(&paths.iter().map(|p| p.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn paths_are_normalized_and_deduplicated() {
        assert_eq!(
            kept(&["/home/", "//var/lib/./app", "/home/me", "/var/lib/app"]).unwrap(),
            ["/home", "/var/lib/app"]
        );
        assert_eq!(kept(&["/var/lib/app", "/var"]).unwrap(), ["/var"]);
        assert_eq!(kept(&["/homes", "/home"]).unwrap(), ["/home", "/homes"]);
        assert_eq!(clean("//data/./x/"), "/data/x");
        assert_eq!(clean("/"), "");
    }

    #[test]
    fn unsafe_paths_are_refused() {
        for path in [
            "/",
            "//",
            "/.",
            "home",
            "",
            "/home/../etc",
            "/..",
            "/proc",
            "/proc/1",
            "/sys/fs",
            "/dev",
            "/run/x",
            "/a\nb",
        ] {
            assert!(kept(&[path]).is_err(), "{path:?} was kept");
        }
        assert!(kept(&["/devices", "/procfs"]).is_ok());
        let many: Vec<String> = (0..=MAX_PATHS).map(|i| format!("/p{i}")).collect();
        assert!(validate(&many).is_err());
    }
}
