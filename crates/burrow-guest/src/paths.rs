//! Paths as requests name them, and the scopes a request holds them to.

#[cfg(any(windows, test))]
pub mod windows;

/// Whether `path`'s components start with one scope's, each path split by
/// `components`.
fn within_by<T: PartialEq>(
    scopes: &[String],
    path: &str,
    components: impl Fn(&str) -> Vec<T>,
) -> bool {
    let wanted = components(path);
    scopes.iter().any(|scope| {
        let scope = components(scope);
        wanted.len() >= scope.len() && wanted[..scope.len()] == scope[..]
    })
}

/// Whether `path` lies in one of `scopes`, matched on whole components so
/// that `/data` does not admit `/database`.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub fn within_posix(scopes: &[String], path: &str) -> bool {
    within_by(scopes, path, |path| {
        path.split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_string)
            .collect()
    })
}

/// The links at the top of every macOS system: `/tmp`, `/var` and `/etc`
/// lead into `/private`.
const MACOS_ALIASES: [&str; 3] = ["tmp", "var", "etc"];

/// `path` with a leading macOS alias replaced by what it links to, as the
/// kernel would read it.
///
/// Safe to follow where no other link is: they live on the sealed system
/// volume, which nobody, root included, can change while the system runs.
/// The kernel names what is under them by the `/private` path, so a scope
/// written as `/tmp/work` has to be read this way to match anything.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn macos_unaliased(path: &str) -> std::borrow::Cow<'_, str> {
    let Some(rest) = path.strip_prefix('/') else {
        return path.into();
    };
    let first = rest.split('/').next().unwrap_or_default();
    if MACOS_ALIASES.contains(&first) {
        format!("/private/{rest}").into()
    } else {
        path.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_macos_aliases_lead_into_private() {
        assert_eq!(macos_unaliased("/tmp"), "/private/tmp");
        assert_eq!(macos_unaliased("/var/folders/x"), "/private/var/folders/x");
        assert_eq!(
            macos_unaliased("/etc/ssl/cert.pem"),
            "/private/etc/ssl/cert.pem"
        );
        assert_eq!(macos_unaliased("/tmpfoo/x"), "/tmpfoo/x");
        assert_eq!(macos_unaliased("/Users/burrow"), "/Users/burrow");
        assert_eq!(macos_unaliased("tmp/x"), "tmp/x");
        assert_eq!(macos_unaliased("/private/tmp"), "/private/tmp");
    }

    #[test]
    fn posix_scopes_match_whole_components() {
        let scopes = vec!["/data".to_string()];
        assert!(within_posix(&scopes, "/data"));
        assert!(within_posix(&scopes, "/data/./x"));
        assert!(!within_posix(&scopes, "/database"));
        assert!(!within_posix(&scopes, "/DATA"));
        assert!(within_posix(&["/".to_string()], "/anything"));
    }
}
