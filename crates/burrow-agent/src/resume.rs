//! Post-restore fixups.
//!
//! Every sandbox restored from the same snapshot starts with byte-identical
//! memory: the same RNG pool and the same wall clock. Left alone, two
//! sandboxes would generate identical "random" values and think it is still
//! the moment the snapshot was taken. The host supplies fresh entropy and its
//! own clock on every handshake, and these apply them.

use std::fs::OpenOptions;
use std::os::fd::AsRawFd;

use nix::libc::c_int;

/// Mirrors the kernel's `struct rand_pool_info`. The trailing buffer is
/// fixed-size here because the host only ever sends a small seed.
#[repr(C)]
struct RandPoolInfo {
    entropy_count: c_int,
    buf_size: c_int,
    buf: [u8; 256],
}

// RNDADDENTROPY is _IOW('R', 0x03, int[2]): the encoded size is that of the
// two leading ints, and the kernel reads the variable-length tail itself.
nix::ioctl_write_ptr!(rnd_add_entropy, b'R', 0x03, [c_int; 2]);

/// Mixes host-supplied entropy into the guest pool *and credits it*, so
/// `/dev/random` and anything reading it diverge immediately across clones.
pub fn reseed_rng(entropy: &[u8]) -> anyhow::Result<()> {
    if entropy.is_empty() {
        return Ok(());
    }
    let len = entropy.len().min(256);
    let mut pool = RandPoolInfo {
        entropy_count: (len * 8) as c_int,
        buf_size: len as c_int,
        buf: [0u8; 256],
    };
    pool.buf[..len].copy_from_slice(&entropy[..len]);

    let file = OpenOptions::new().write(true).open("/dev/random")?;
    // SAFETY: `pool` outlives the call and matches the layout the kernel reads.
    unsafe {
        rnd_add_entropy(file.as_raw_fd(), (&raw const pool).cast::<[c_int; 2]>())?;
    }
    tracing::debug!(bytes = len, "rng reseeded from host entropy");
    Ok(())
}

/// Sets the guest wall clock from the host. A restored guest otherwise
/// believes it is still snapshot time, which breaks TLS certificate
/// validation and anything else that compares timestamps.
pub fn set_clock(unix_nanos: i64) -> anyhow::Result<()> {
    if unix_nanos <= 0 {
        return Ok(());
    }
    let spec =
        nix::sys::time::TimeSpec::new(unix_nanos / 1_000_000_000, unix_nanos % 1_000_000_000);
    nix::time::clock_settime(nix::time::ClockId::CLOCK_REALTIME, spec)?;
    tracing::debug!(unix_nanos, "guest clock synced to host");
    Ok(())
}

/// Trust stores a Linux userland might read, in the order they are tried.
///
/// Appended to rather than replaced: an image ships a bundle its own tools
/// depend on, and overwriting it would break verification of everything the
/// sandbox was already able to reach.
const TRUST_BUNDLES: [&str; 4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

/// Where the certificate is always written, whether or not a bundle exists.
///
/// Tools that take an explicit path (`SSL_CERT_FILE`, `curl --cacert`) can be
/// pointed here even in an image that ships no trust store at all.
pub const CA_PATH: &str = "/etc/ssl/certs/burrow-inspection-ca.pem";

/// Installs the CA a sandbox was told to trust.
///
/// Only called when the sandbox opted in to inspection: without it the proxy's
/// certificate would be rejected and every HTTPS request would fail, which is
/// the correct outcome for a sandbox that did *not* opt in.
///
/// Fail-closed. A bundle that is *there* and could not be updated is an error,
/// because the caller is about to put an inspecting proxy in front of a guest
/// that would then reject it on every request with nothing to say why. A
/// bundle that is simply absent is not: an image that ships no trust store
/// gets [`CA_PATH`] and the tools that take an explicit path, which is all
/// there ever was to give it.
pub fn install_inspection_ca(
    pem: &str,
    extra: &[burrow_proto::agent::v1::TrustBundle],
) -> anyhow::Result<TrustTiming> {
    let mut timing = TrustTiming::default();
    if pem.trim().is_empty() {
        return Ok(timing);
    }
    // Already done, by this same process, for this same certificate and the
    // same set of bundles: there is nothing to write and nothing to check.
    //
    // Cheap where it matters most. A warm snapshot is taken of a guest that
    // has already been through here, and guest *memory* is captured by the
    // snapshot alongside the scratch disk holding the overlay these bundles
    // live in, so a restored clone inherits the note and the files it
    // describes together, or neither. That makes the trust store the one piece
    // of handshake work a create does not have to repeat.
    if installed_already(pem, extra) {
        tracing::debug!("the inspection ca is already installed; nothing to do");
        return Ok(timing);
    }
    let began = std::time::Instant::now();
    if let Some(parent) = std::path::Path::new(CA_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Renamed into place like the bundles are, so nothing can read a
    // half-written certificate out of it. This is also the first write the
    // guest makes after waking, so it carries whatever the first write costs.
    write_atomically(std::path::Path::new(CA_PATH), pem.as_bytes())?;
    timing.write += began.elapsed();

    // Every well-known path first, then what the image named, and each
    // resolved to the file it actually designates.
    let mut targets: Vec<(std::path::PathBuf, bool)> = TRUST_BUNDLES
        .iter()
        .map(|bundle| (std::path::PathBuf::from(bundle), false))
        .collect();
    // The host derived these from the image's own environment, but the value
    // in that environment is the image's; it is checked again here because
    // this is the process that would do the writing.
    for bundle in extra {
        if !usable_bundle_path(&bundle.path) {
            tracing::warn!(
                path = bundle.path,
                "refusing a trust bundle path that is not absolute and free of .."
            );
            continue;
        }
        targets.push((
            std::path::PathBuf::from(&bundle.path),
            bundle.create_if_missing,
        ));
    }

    let mut done: Vec<std::path::PathBuf> = Vec::new();
    let mut installed = 0;
    for (path, create) in targets {
        // `/etc/ssl/cert.pem` is a symlink to `ca-certificates.crt` on Alpine,
        // and the two well-known paths are far from the only pair like it.
        // Resolving first means the bundle is read and rewritten once rather
        // than once per name, and, more than a saving, it means the write
        // lands on the file the symlink designates instead of replacing the
        // symlink with a regular copy and quietly forking the two.
        let began = std::time::Instant::now();
        let target = std::fs::canonicalize(&path).unwrap_or(path);
        timing.read += began.elapsed();
        if done.contains(&target) {
            continue;
        }
        let began = std::time::Instant::now();
        let outcome = append_ca(&target, pem, create, &mut timing);
        tracing::debug!(
            bundle = %target.display(),
            ?outcome,
            took_us = began.elapsed().as_micros() as u64,
            "trust bundle"
        );
        match outcome {
            Bundle::Installed => {
                installed += 1;
                done.push(target);
            }
            Bundle::Absent => {}
            Bundle::Failed => {
                anyhow::bail!("could not add the ca to {}", target.display());
            }
        }
    }
    tracing::debug!(bundles = installed, "installed the inspection ca");
    remember_installed(pem, extra);
    Ok(timing)
}

/// One bundle's path and whether the certificate was already present in it.
type BundleNote = (String, bool);

/// What the last successful install put where.
///
/// Recorded only after every bundle succeeded, so a partial install leaves no
/// note and the next handshake does the work again for real. That is what
/// keeps the fast path honest: the note can only ever say "this exact
/// certificate is in all of these bundles", and it is written by the code that
/// just made that true.
static INSTALLED: std::sync::Mutex<Option<(String, Vec<BundleNote>)>> = std::sync::Mutex::new(None);

/// The request's identity, for comparing one install against the next.
///
/// The bundle list is part of it, not just the certificate: the same CA going
/// into a template that names an extra bundle is a different job, and matching
/// on the certificate alone would skip it.
fn install_identity(extra: &[burrow_proto::agent::v1::TrustBundle]) -> Vec<(String, bool)> {
    extra
        .iter()
        .map(|bundle| (bundle.path.clone(), bundle.create_if_missing))
        .collect()
}

fn installed_already(pem: &str, extra: &[burrow_proto::agent::v1::TrustBundle]) -> bool {
    INSTALLED
        .lock()
        .map(|seen| seen.as_ref() == Some(&(pem.to_string(), install_identity(extra))))
        .unwrap_or(false)
}

fn remember_installed(pem: &str, extra: &[burrow_proto::agent::v1::TrustBundle]) {
    if let Ok(mut seen) = INSTALLED.lock() {
        *seen = Some((pem.to_string(), install_identity(extra)));
    }
}

/// Where the time in a trust-store update went, summed over every bundle.
///
/// Reported to the host rather than only logged: the agent's log is the
/// emulated serial console, which is exactly the thing not to write to on the
/// path being measured.
#[derive(Default, Clone, Copy)]
pub struct TrustTiming {
    pub read: std::time::Duration,
    pub scan: std::time::Duration,
    pub write: std::time::Duration,
}

/// What became of one trust bundle.
#[derive(Debug, PartialEq, Eq)]
enum Bundle {
    /// The certificate is in it, either because it was added or was already
    /// there.
    Installed,
    /// Nothing to update: the image does not ship this bundle.
    Absent,
    /// It exists and could not be updated. Fatal to the handshake.
    Failed,
}

/// Whether a path handed over at handshake may be written to.
///
/// The same rule the host applies, repeated because the guest is where the
/// write happens: an image naming a relative path, or one walking out through
/// `..`, gets nothing rather than a write somewhere it chose.
fn usable_bundle_path(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && !path.contains('\0')
        && !std::path::Path::new(path)
            .components()
            .any(|component| component == std::path::Component::ParentDir)
}

/// Adds the certificate to one bundle, leaving what is already there intact.
///
/// `create` is for a file of *additional* CAs only. A full bundle that is not
/// there is an image pointing at something absent, and replacing it with a
/// file holding one certificate would drop every root the tool needs.
fn append_ca(path: &std::path::Path, pem: &str, create: bool, timing: &mut TrustTiming) -> Bundle {
    let bundle = path.display().to_string();
    let began = std::time::Instant::now();
    let read = std::fs::read(path);
    timing.read += began.elapsed();
    let existing = match read {
        Ok(bytes) => bytes,
        // Read as bytes, and skipped on failure rather than treated as empty:
        // a bundle that cannot be read (a non-UTF-8 byte, a permission error,
        // a dangling symlink) must not be *replaced* by the one certificate,
        // which would throw away everything the image already trusted.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Bundle::Absent;
            }
            Vec::new()
        }
        Err(err) => {
            tracing::warn!(bundle, %err, "cannot read a trust bundle that is there");
            return Bundle::Failed;
        }
    };
    // Read-modify-write rather than append, so a re-handshake after a
    // resume does not add the certificate a second time.
    let began = std::time::Instant::now();
    let already = contains(&existing, pem.trim().as_bytes());
    timing.scan += began.elapsed();
    if already {
        return Bundle::Installed;
    }
    let mut merged = existing;
    // A bundle whose last line has no newline would otherwise be glued to the
    // BEGIN line of the certificate, and neither block would parse.
    if !merged.is_empty() && !merged.ends_with(b"\n") {
        merged.push(b'\n');
    }
    merged.extend_from_slice(pem.as_bytes());
    if let Some(parent) = path.parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        tracing::warn!(bundle, %err, "could not create a trust bundle's directory");
        return Bundle::Failed;
    }
    // Written to a temporary in the same directory and renamed over, so a
    // failure part way through leaves the original bundle intact rather
    // than a truncated trust store.
    let began = std::time::Instant::now();
    let written = write_atomically(path, &merged);
    timing.write += began.elapsed();
    match written {
        Ok(()) => Bundle::Installed,
        Err(err) => {
            tracing::warn!(bundle, %err, "could not update a trust bundle");
            Bundle::Failed
        }
    }
}

/// Whether `haystack` already carries `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Replaces a file's contents in one step.
///
/// The temporary lives in the same directory so the rename stays within one
/// filesystem, which is what makes it a replacement rather than a copy.
///
/// Deliberately not fsynced. What has to hold is that no reader ever sees a
/// truncated trust store, and that is `rename(2)`'s doing, not `fsync`'s: every
/// open gets either the whole old file or the whole new one. There is nothing
/// here for durability to protect, because this file lives on the sandbox's own
/// scratch overlay, which exists only while its guest does. A suspend does
/// outlive a running guest, and it captures guest memory, page cache included,
/// alongside the disk.
///
/// On an ext4 overlay under nested virtualisation, the `fsync` was 100-140 ms
/// of a warm create, for a 648-byte certificate.
fn write_atomically(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("/"));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let temp = parent.join(format!(".{name}.burrow.tmp"));

    let outcome = (|| {
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(contents)
    })();
    if let Err(err) = outcome {
        let _ = std::fs::remove_file(&temp);
        return Err(err);
    }
    // The original's mode is what tools expect to find; a fresh file would be
    // whatever the umask happened to be.
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&temp, meta.permissions());
    }
    if let Err(err) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(err);
    }
    Ok(())
}

/// Reapplies the guest's network address after a restore.
///
/// A clone restored from a shared warm snapshot wakes holding whatever address
/// was baked into that snapshot. Every clone would otherwise claim the same
/// one, and the host, which routes a distinct /30 to each tap, would have no
/// way to deliver their traffic. The host tells each clone its real address on
/// handshake; this applies it.
pub async fn apply_network(config: &burrow_proto::agent::v1::NetworkConfig) -> anyhow::Result<()> {
    if config.ip.is_empty() {
        return Ok(());
    }
    let ip = config.ip.parse()?;
    let gateway = if config.gateway.is_empty() {
        None
    } else {
        Some(config.gateway.parse()?)
    };
    let dns = (!config.dns.is_empty()).then_some(config.dns.as_str());

    crate::netconf::apply(ip, config.prefix_len.max(1) as u8, gateway, dns).await?;
    tracing::debug!(ip = config.ip, "network reapplied after restore");
    Ok(())
}

#[cfg(test)]
mod trust_bundle_tests {
    use super::*;

    #[test]
    fn a_bundle_is_appended_to_not_replaced() {
        let dir = std::env::temp_dir().join(format!("burrow-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = dir.join("ca-certificates.crt");
        std::fs::write(&bundle, b"-----EXISTING-----\n").unwrap();

        let mut merged = std::fs::read(&bundle).unwrap();
        merged.extend_from_slice(b"-----NEW-----\n");
        write_atomically(&bundle, &merged).unwrap();

        let after = std::fs::read(&bundle).unwrap();
        assert!(contains(&after, b"-----EXISTING-----"));
        assert!(contains(&after, b"-----NEW-----"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bug this exists to prevent: a bundle holding a byte that is not
    /// UTF-8 used to read as "" and be overwritten with just the new CA.
    #[test]
    fn a_non_utf8_bundle_still_reads_as_its_bytes() {
        let dir = std::env::temp_dir().join(format!("burrow-ca-raw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = dir.join("cert.pem");
        std::fs::write(&bundle, [0xff, 0xfe, b'\n']).unwrap();

        assert!(std::fs::read_to_string(&bundle).is_err());
        assert_eq!(std::fs::read(&bundle).unwrap(), vec![0xff, 0xfe, b'\n']);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_certificate_touches_nothing() {
        assert!(install_inspection_ca("   \n", &[]).is_ok());
    }

    /// The note that lets a restored clone skip the whole trust store.
    ///
    /// It has to be exact in both directions: matching when the job really is
    /// the same one, so a create costs nothing, and *not* matching on any
    /// change, such as a rotated CA or a template naming a bundle the last one
    /// did not, because a false match is a sandbox that believes it is
    /// inspected and has no certificate to prove it.
    #[test]
    fn the_install_note_matches_only_the_same_job() {
        fn bundle(path: &str) -> burrow_proto::agent::v1::TrustBundle {
            burrow_proto::agent::v1::TrustBundle {
                path: path.into(),
                create_if_missing: false,
            }
        }
        let extra = [bundle("/etc/ssl/one.pem")];

        // Nothing recorded yet, so there is nothing to skip.
        assert!(!installed_already(PEM, &extra));

        remember_installed(PEM, &extra);
        assert!(installed_already(PEM, &extra));

        // A different certificate is a different job.
        assert!(!installed_already(
            "-----BEGIN CERTIFICATE-----\nother\n",
            &extra
        ));
        // So is the same certificate into a different set of bundles.
        assert!(!installed_already(PEM, &[]));
        assert!(!installed_already(PEM, &[bundle("/etc/ssl/two.pem")]));
        // Down to the flag, which decides whether a missing bundle is created.
        assert!(!installed_already(
            PEM,
            &[burrow_proto::agent::v1::TrustBundle {
                path: "/etc/ssl/one.pem".into(),
                create_if_missing: true,
            }]
        ));

        // Left as it was found, so no other test sees this one's note.
        *INSTALLED.lock().unwrap() = None;
    }

    /// Two PEM blocks glued together parse as neither.
    #[test]
    fn a_bundle_without_a_trailing_newline_gains_one() {
        let dir = scratch("newline");
        let bundle = dir.join("cacert.pem");
        std::fs::write(&bundle, b"-----END CERTIFICATE-----").unwrap();

        assert_eq!(
            append_ca(&bundle, PEM, false, &mut TrustTiming::default()),
            Bundle::Installed
        );

        let after = std::fs::read(&bundle).unwrap();
        assert!(contains(&after, b"-----END CERTIFICATE-----\n-----BEGIN"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bundle_already_ending_in_a_newline_gains_no_second_one() {
        let dir = scratch("newline-once");
        let bundle = dir.join("cacert.pem");
        std::fs::write(&bundle, b"-----END CERTIFICATE-----\n").unwrap();

        assert_eq!(
            append_ca(&bundle, PEM, false, &mut TrustTiming::default()),
            Bundle::Installed
        );

        let after = std::fs::read(&bundle).unwrap();
        assert!(!contains(&after, b"\n\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_bundle_is_created_only_when_it_holds_extra_cas() {
        let dir = scratch("missing");
        let absent = dir.join("cacert.pem");

        assert_eq!(
            append_ca(&absent, PEM, false, &mut TrustTiming::default()),
            Bundle::Absent
        );
        assert!(!absent.exists(), "a full bundle is not invented");

        let extra = dir.join("node/extra.pem");
        assert_eq!(
            append_ca(&extra, PEM, true, &mut TrustTiming::default()),
            Bundle::Installed
        );
        assert_eq!(std::fs::read(&extra).unwrap(), PEM.as_bytes());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_handshake_does_not_add_the_certificate_twice() {
        let dir = scratch("idempotent");
        let bundle = dir.join("cacert.pem");
        std::fs::write(&bundle, b"-----EXISTING-----\n").unwrap();

        assert_eq!(
            append_ca(&bundle, PEM, false, &mut TrustTiming::default()),
            Bundle::Installed
        );
        let once = std::fs::read(&bundle).unwrap();
        assert_eq!(
            append_ca(&bundle, PEM, false, &mut TrustTiming::default()),
            Bundle::Installed
        );
        assert_eq!(std::fs::read(&bundle).unwrap(), once);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_absolute_paths_free_of_parent_links_are_written() {
        assert!(usable_bundle_path("/cacert.pem"));
        assert!(usable_bundle_path("/etc/ssl/certs/ca-certificates.crt"));
        assert!(!usable_bundle_path(""));
        assert!(!usable_bundle_path("cacert.pem"));
        assert!(!usable_bundle_path("./cacert.pem"));
        assert!(!usable_bundle_path("/etc/../root/.ssh/authorized_keys"));
        assert!(!usable_bundle_path("/etc/ssl/.."));
        assert!(!usable_bundle_path("/etc/ssl/\0cert.pem"));
    }

    /// The bug this exists to prevent: Alpine's `/etc/ssl/cert.pem` is a
    /// symlink to `ca-certificates.crt`, and rewriting both names in turn
    /// rewrote a 180 KiB bundle twice, or worse, replaced the symlink with a
    /// regular file, leaving two trust stores that no longer track each other.
    #[test]
    fn a_symlinked_bundle_is_written_once_through_the_link() {
        let dir = scratch("symlink");
        let real = dir.join("ca-certificates.crt");
        let link = dir.join("cert.pem");
        std::fs::write(&real, b"-----EXISTING-----\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert_eq!(
            std::fs::canonicalize(&link).unwrap(),
            std::fs::canonicalize(&real).unwrap(),
            "both names have to resolve to one file for the dedup to fire"
        );
        assert_eq!(
            append_ca(
                &std::fs::canonicalize(&link).unwrap(),
                PEM,
                false,
                &mut TrustTiming::default()
            ),
            Bundle::Installed
        );

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link is still a link"
        );
        let after = std::fs::read(&real).unwrap();
        assert!(contains(&after, b"-----EXISTING-----"));
        assert!(contains(&after, PEM.trim().as_bytes()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed: a bundle that is there and cannot be updated fails the
    /// handshake rather than leaving a sandbox that believes it is inspected
    /// and rejects every request the proxy answers.
    #[test]
    fn a_bundle_that_cannot_be_read_fails_the_install() {
        let dir = scratch("unreadable");
        // A directory where a bundle should be: present, so not `Absent`, and
        // unreadable as a file, so not something to overwrite either.
        let bundle = dir.join("cacert.pem");
        std::fs::create_dir(&bundle).unwrap();

        assert_eq!(
            append_ca(&bundle, PEM, false, &mut TrustTiming::default()),
            Bundle::Failed
        );

        // And a dangling name is simply absent: nothing to preserve, and an
        // image that points at a bundle it does not ship is not a failure.
        let missing = dir.join("nowhere.pem");
        assert_eq!(
            append_ca(&missing, PEM, false, &mut TrustTiming::default()),
            Bundle::Absent
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nburrow\n-----END CERTIFICATE-----\n";

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow-ca-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
