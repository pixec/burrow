//! The two pattern languages a network policy speaks: host patterns and
//! request path globs.

/// Whether `host` matches a policy host pattern: an exact host, `*.x` for the
/// subdomains of `x` (never `x` itself), or `*` / `**` for every host. A port
/// suffix on either side is ignored, as are case and a trailing dot.
pub fn is_host_match(pattern: &str, host: &str) -> bool {
    let pattern = strip_port(pattern.trim()).trim_end_matches('.');
    let host = strip_port(host.trim()).trim_end_matches('.');
    if pattern == "*" || pattern == "**" {
        return !host.is_empty();
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            let Some(label_end) = host.len().checked_sub(suffix.len() + 1) else {
                return false;
            };
            let (head, tail) = host.as_bytes().split_at(label_end);
            !head.is_empty() && tail[0] == b'.' && tail[1..].eq_ignore_ascii_case(suffix.as_bytes())
        }
        None => pattern.eq_ignore_ascii_case(host),
    }
}

fn strip_port(s: &str) -> &str {
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => s,
    }
}

/// Whether a request path matches a path glob. `*` matches any run of
/// characters within one segment, `**` any run across segments, and `?` one
/// character. The query string is not part of the path.
pub fn is_path_match(glob: &str, path: &str) -> bool {
    is_match_at(glob.as_bytes(), path.as_bytes())
}

fn is_match_at(g: &[u8], p: &[u8]) -> bool {
    match g.first() {
        None => p.is_empty(),
        Some(b'*') if g.get(1) == Some(&b'*') => {
            // `/**` at the end also matches the directory itself, so
            // `/allowed/**` admits `/allowed`.
            let rest = &g[2..];
            if rest.first() == Some(&b'/') && p.is_empty() {
                return is_match_at(&rest[1..], p) || rest.len() == 1;
            }
            (0..=p.len()).any(|i| is_match_at(rest, &p[i..]))
        }
        Some(b'*') => {
            let rest = &g[1..];
            let limit = p.iter().position(|b| *b == b'/').unwrap_or(p.len());
            (0..=limit).any(|i| is_match_at(rest, &p[i..]))
        }
        Some(b'?') => !p.is_empty() && p[0] != b'/' && is_match_at(&g[1..], &p[1..]),
        Some(c) => {
            // A trailing `/**` admits the bare directory path.
            if *c == b'/' && g.len() == 3 && &g[1..] == b"**" && p.is_empty() {
                return true;
            }
            !p.is_empty() && p[0] == *c && is_match_at(&g[1..], &p[1..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_patterns_match_only_themselves() {
        assert!(is_host_match("pypi.org", "pypi.org"));
        assert!(!is_host_match("pypi.org", "evil-pypi.org"));
        assert!(!is_host_match("pypi.org", "sub.pypi.org"));
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_the_apex() {
        assert!(is_host_match(
            "*.pythonhosted.org",
            "files.pythonhosted.org"
        ));
        assert!(is_host_match("*.pythonhosted.org", "a.b.pythonhosted.org"));
        assert!(!is_host_match("*.pythonhosted.org", "pythonhosted.org"));
    }

    #[test]
    fn wildcard_does_not_match_a_lookalike_suffix() {
        // The classic bypass: registering evilpythonhosted.org.
        assert!(!is_host_match("*.pythonhosted.org", "evilpythonhosted.org"));
        assert!(!is_host_match(
            "*.pythonhosted.org",
            "pythonhosted.org.evil.com"
        ));
    }

    #[test]
    fn matching_ignores_case_trailing_dot_and_port() {
        assert!(is_host_match("PyPI.org", "pypi.org."));
        assert!(is_host_match("*.example.com", "WWW.Example.Com"));
        assert!(is_host_match("api.github.com:443", "api.github.com"));
        assert!(is_host_match("api.github.com", "api.github.com:443"));
    }

    #[test]
    fn a_bare_star_matches_every_host() {
        assert!(is_host_match("*", "anything.test"));
        assert!(is_host_match("**", "anything.test"));
        assert!(!is_host_match("*", ""));
    }

    #[test]
    fn paths() {
        assert!(is_path_match("/allowed/**", "/allowed/x/y"));
        assert!(is_path_match("/allowed/**", "/allowed/"));
        assert!(is_path_match("/allowed/**", "/allowed"));
        assert!(!is_path_match("/allowed/**", "/allowedx"));
        assert!(is_path_match("/repos/*/issues", "/repos/foo/issues"));
        assert!(!is_path_match("/repos/*/issues", "/repos/a/b/issues"));
        assert!(is_path_match("/repos/**/issues", "/repos/a/b/issues"));
        assert!(is_path_match("/v1/*", "/v1/x"));
        assert!(!is_path_match("/v1/*", "/v1/x/y"));
        assert!(is_path_match("/a?c", "/abc"));
        assert!(is_path_match("/allowed/secret/**", "/allowed/secret/k"));
    }
}
