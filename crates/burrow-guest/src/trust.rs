//! What a handshake put in a trust store, so the next one replaces it.
//!
//! A guest is told one root per handshake, and a sandbox that changes nodes
//! or roots is told another. Appending each would leave every root it was
//! ever given trusted for the rest of its life. Burrow's certificates are
//! written between markers instead, and each install rewrites that block and
//! nothing else, so everything the image trusted on its own stays as it was.

/// The lines around the certificates a handshake installed in a PEM bundle.
/// Comments to every PEM reader, which skip text outside BEGIN and END.
pub const BEGIN: &[u8] = b"# BEGIN burrow inspection ca";
pub const END: &[u8] = b"# END burrow inspection ca";

/// The name a handshake gives what it adds to a Windows certificate store,
/// which is how the next one finds it.
#[cfg_attr(not(windows), allow(dead_code))]
pub const FRIENDLY_NAME: &str = "Burrow inspection CA";

/// `bundle` holding `pem` as its one Burrow block, in place of any it had.
///
/// An unmarked copy of `pem` is dropped too: agents before the markers
/// appended the certificate bare. The result equals `bundle` when it already
/// holds exactly this, which is how a caller knows there is nothing to write.
pub fn with_ca(bundle: &[u8], pem: &str) -> Vec<u8> {
    let pem = pem.trim().as_bytes();
    let mut kept = Vec::with_capacity(bundle.len() + pem.len() + BEGIN.len() + END.len() + 3);
    let mut inside = false;
    for line in bundle.split_inclusive(|byte| *byte == b'\n') {
        let bare = line.trim_ascii();
        if bare == BEGIN {
            inside = true;
        } else if bare == END {
            inside = false;
        } else if !inside {
            kept.extend_from_slice(line);
        }
    }
    if let Some(at) = find(&kept, pem) {
        let mut end = at + pem.len();
        if kept.get(end) == Some(&b'\n') {
            end += 1;
        }
        kept.drain(at..end);
    }
    if !kept.is_empty() && !kept.ends_with(b"\n") {
        kept.push(b'\n');
    }
    for part in [BEGIN, pem, END] {
        kept.extend_from_slice(part);
        kept.push(b'\n');
    }
    kept
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Which of the certificates a handshake tagged in a store to delete: every
/// one the new root is not, in the order given.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn stale<'a>(tagged: &[&'a [u8]], wanted: &[Vec<u8>]) -> Vec<&'a [u8]> {
    tagged
        .iter()
        .copied()
        .filter(|der| !wanted.iter().any(|want| want.as_slice() == *der))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "-----BEGIN CERTIFICATE-----\nimage\n-----END CERTIFICATE-----\n";
    const OLD: &str = "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n";
    const NEW: &str = "-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n";

    fn count(bundle: &[u8], needle: &str) -> usize {
        String::from_utf8_lossy(bundle).matches(needle).count()
    }

    #[test]
    fn a_new_root_replaces_the_one_a_handshake_installed() {
        let first = with_ca(IMAGE.as_bytes(), OLD);
        let second = with_ca(&first, NEW);
        assert!(
            second.starts_with(IMAGE.as_bytes()),
            "the image's own roots stay"
        );
        assert_eq!(count(&second, "old"), 0);
        assert_eq!(count(&second, "new"), 1);
        assert_eq!(count(&second, "# BEGIN burrow"), 1);
    }

    #[test]
    fn many_moves_leave_exactly_one_block() {
        let mut bundle = IMAGE.as_bytes().to_vec();
        for i in 0..5 {
            bundle = with_ca(
                &bundle,
                &format!("-----BEGIN CERTIFICATE-----\nroot{i}\n-----END CERTIFICATE-----\n"),
            );
        }
        assert_eq!(count(&bundle, "# BEGIN burrow"), 1);
        assert_eq!(count(&bundle, "-----BEGIN CERTIFICATE-----"), 2);
        assert_eq!(count(&bundle, "root4"), 1);
    }

    #[test]
    fn the_same_root_again_changes_nothing() {
        let once = with_ca(IMAGE.as_bytes(), NEW);
        assert_eq!(with_ca(&once, NEW), once);
    }

    #[test]
    fn a_bare_copy_from_an_older_agent_is_folded_into_the_block() {
        let legacy = format!("{IMAGE}{NEW}");
        let bundle = with_ca(legacy.as_bytes(), NEW);
        assert_eq!(count(&bundle, "new"), 1);
        assert!(bundle.starts_with(IMAGE.as_bytes()));
    }

    #[test]
    fn a_bundle_without_a_trailing_newline_is_not_glued_to_the_block() {
        let bundle = with_ca(IMAGE.trim_end().as_bytes(), NEW);
        assert!(String::from_utf8_lossy(&bundle).contains("-----END CERTIFICATE-----\n# BEGIN"));
    }

    #[test]
    fn bytes_that_are_not_utf8_survive() {
        let mut image = b"\xff\xfe junk\n".to_vec();
        image.extend_from_slice(IMAGE.as_bytes());
        let bundle = with_ca(&with_ca(&image, OLD), NEW);
        assert!(bundle.starts_with(&image));
    }

    #[test]
    fn only_tagged_certificates_the_new_root_is_not_are_stale() {
        let (old, new) = (b"old".as_slice(), b"new".as_slice());
        assert_eq!(stale(&[old, new], &[new.to_vec()]), vec![old]);
        assert!(stale(&[new], &[new.to_vec()]).is_empty());
        assert!(stale(&[], &[new.to_vec()]).is_empty());
    }
}
