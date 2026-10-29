//! What a path from the host or an SDK names on a Windows guest.
//!
//! SDKs are written against Linux guests and send POSIX paths: `/work`,
//! `/tmp/x`, `/home/user`. A Windows template has no single root, so every
//! path is mapped onto a drive before anything opens it:
//!
//! - `C:\x`, `C:/x` and `\\?\C:\x` are taken as written.
//! - `/c/x`, a first component of one letter, is drive `C:` in the MSYS and
//!   Git Bash convention, so a path a POSIX shell on the guest printed comes
//!   back to the same file. A top-level directory with a one-letter name is
//!   therefore not reachable in POSIX form; it is in its drive form.
//! - Any other absolute POSIX path lands on the system drive: `/work` is
//!   `C:\work`, `/` is `C:\`.
//! - A relative path is relative to the system drive's root, as the Linux
//!   agent's are to `/`.
//!
//! `.` and `..` are resolved here, lexically, which is what Win32 path
//! normalization would do to them anyway; the agent then opens the long
//! (`\\?\`) form, which Windows does not normalize again. UNC and device
//! paths are refused: the agent serves the guest's own volumes, not shares
//! or devices it can reach.

// Built off Windows only for its tests.
#![cfg_attr(not(windows), allow(dead_code))]

/// Why a path names nothing the agent will open.
#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    Empty,
    /// A UNC share or a `\\.\` device.
    NotLocal,
}

/// The Windows form of `path`, `X:\a\b`, with `system_drive` (a letter) for
/// paths that do not name a drive.
pub fn to_windows(path: &str, system_drive: char) -> Result<String, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    let path = path.replace('/', "\\");
    let path = if let Some(rest) = path
        .strip_prefix("\\\\?\\")
        .or_else(|| path.strip_prefix("\\??\\"))
    {
        if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case("UNC\\") {
            return Err(PathError::NotLocal);
        }
        rest.to_string()
    } else if path.starts_with("\\\\") {
        return Err(PathError::NotLocal);
    } else {
        path
    };

    let bytes = path.as_bytes();
    let (drive, rest) = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        (bytes[0] as char, &path[2..])
    } else if let Some(rest) = path.strip_prefix('\\') {
        let first = rest.split('\\').next().unwrap_or("");
        if first.len() == 1 && first.as_bytes()[0].is_ascii_alphabetic() {
            (first.as_bytes()[0] as char, &rest[1..])
        } else {
            (system_drive, rest)
        }
    } else {
        (system_drive, path.as_str())
    };

    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    Ok(format!(
        "{}:\\{}",
        drive.to_ascii_uppercase(),
        parts.join("\\")
    ))
}

/// The long form of a mapped path, which lifts `MAX_PATH` and stops Windows
/// from normalizing a name a second time.
pub fn long(windows: &str) -> String {
    format!("\\\\?\\{windows}")
}

/// What `GetFinalPathNameByHandleW` returns, back in the form [`to_windows`]
/// produces: `\\?\C:\x` is `C:\x`. A volume with no drive letter keeps its
/// prefix and so matches no scope.
pub fn from_final(final_path: &str) -> String {
    match final_path.strip_prefix("\\\\?\\") {
        Some(rest)
            if rest.len() >= 2
                && rest.as_bytes()[0].is_ascii_alphabetic()
                && rest.as_bytes()[1] == b':' =>
        {
            let mut out = rest.to_string();
            out[..1].make_ascii_uppercase();
            if out.len() == 2 {
                out.push('\\');
            }
            out
        }
        _ => final_path.to_string(),
    }
}

/// The directory holding the last component, and that component. `None`
/// for a drive root, which has no parent to act in.
pub fn split(windows: &str) -> Option<(&str, &str)> {
    let index = windows.rfind('\\')?;
    let name = &windows[index + 1..];
    if name.is_empty() {
        return None;
    }
    // `C:\x` has the parent `C:\`, which keeps its separator.
    let parent = if index == 2 {
        &windows[..3]
    } else {
        &windows[..index]
    };
    Some((parent, name))
}

/// Whether `path` lies in one of `scopes`, matched on whole components and
/// without regard to case, as NTFS compares names: `C:\data` does not admit
/// `C:\database`, and does admit `c:\DATA\x`.
///
/// Both sides are already in [`to_windows`] form.
pub fn within(scopes: &[String], path: &str) -> bool {
    super::within_by(scopes, path, |path| {
        path.split('\\')
            .filter(|part| !part.is_empty())
            .map(str::to_lowercase)
            .collect()
    })
}

/// Joins a mapped directory and a name.
pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('\\') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(path: &str) -> String {
        to_windows(path, 'C').unwrap()
    }

    #[test]
    fn drive_paths_are_taken_as_written() {
        assert_eq!(map("C:\\x\\y"), "C:\\x\\y");
        assert_eq!(map("c:/x/y"), "C:\\x\\y");
        assert_eq!(map("D:\\"), "D:\\");
        assert_eq!(map("\\\\?\\C:\\x"), "C:\\x");
        assert_eq!(map("C:"), "C:\\");
    }

    #[test]
    fn posix_paths_land_on_the_system_drive() {
        assert_eq!(map("/work"), "C:\\work");
        assert_eq!(map("/work/a/b.txt"), "C:\\work\\a\\b.txt");
        assert_eq!(map("/"), "C:\\");
        assert_eq!(to_windows("/tmp", 'D').unwrap(), "D:\\tmp");
    }

    #[test]
    fn msys_drive_paths_name_their_drive() {
        assert_eq!(map("/c/x"), "C:\\x");
        assert_eq!(map("/d"), "D:\\");
        assert_eq!(map("/d/projects/app"), "D:\\projects\\app");
        // Two letters is a directory, not a drive.
        assert_eq!(map("/cd/x"), "C:\\cd\\x");
    }

    #[test]
    fn relative_paths_are_relative_to_the_drive_root() {
        assert_eq!(map("work/x"), "C:\\work\\x");
        assert_eq!(map("./x"), "C:\\x");
    }

    #[test]
    fn dots_resolve_lexically_and_stop_at_the_root() {
        assert_eq!(map("/work/../etc/./x"), "C:\\etc\\x");
        assert_eq!(map("/../../x"), "C:\\x");
        assert_eq!(map("C:\\a\\b\\.."), "C:\\a");
        assert_eq!(map("/work//x/"), "C:\\work\\x");
    }

    #[test]
    fn shares_and_devices_are_refused() {
        assert_eq!(
            to_windows("\\\\server\\share\\x", 'C'),
            Err(PathError::NotLocal)
        );
        assert_eq!(to_windows("//server/share", 'C'), Err(PathError::NotLocal));
        assert_eq!(
            to_windows("\\\\?\\UNC\\server\\x", 'C'),
            Err(PathError::NotLocal)
        );
        assert_eq!(
            to_windows("\\\\.\\PhysicalDrive0", 'C'),
            Err(PathError::NotLocal)
        );
        assert_eq!(to_windows("", 'C'), Err(PathError::Empty));
    }

    #[test]
    fn final_paths_come_back_in_drive_form() {
        assert_eq!(from_final("\\\\?\\c:\\Work\\x"), "C:\\Work\\x");
        assert_eq!(from_final("\\\\?\\C:"), "C:\\");
        assert_eq!(
            from_final("\\\\?\\Volume{1234}\\x"),
            "\\\\?\\Volume{1234}\\x"
        );
    }

    #[test]
    fn split_keeps_the_root_separator() {
        assert_eq!(split("C:\\x"), Some(("C:\\", "x")));
        assert_eq!(split("C:\\a\\b"), Some(("C:\\a", "b")));
        assert_eq!(split("C:\\"), None);
    }

    #[test]
    fn scopes_match_whole_components_without_case() {
        let scopes = vec![map("/data")];
        assert!(within(&scopes, "C:\\data"));
        assert!(within(&scopes, "c:\\DATA\\x"));
        assert!(!within(&scopes, "C:\\database"));
        assert!(!within(&scopes, "D:\\data"));
        assert!(within(&[map("C:\\")], "C:\\anything"));
    }
}
