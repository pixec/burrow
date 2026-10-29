//! The host's handshake, on macOS: entropy, clock, trust, network.
//!
//! Entropy: XNU has no call that credits outside entropy the way Linux's
//! `RNDADDENTROPY` does. What it has is `/dev/random` taking writes from
//! root, which it mixes into its generator (a Fortuna that also reseeds
//! itself continuously from interrupt timing). The host's bytes are written
//! there; it is the strongest a guest can do, and it is mixing, not credit.
//!
//! Trust: the system keychain's trust settings cannot be changed without a
//! person. `security add-trusted-cert` and the Security framework under it
//! need the `com.apple.trust-settings.admin` right, which is "entitled or an
//! administrator authenticating in a dialog", and macOS 27 keeps trustd's
//! settings where root cannot write them. So the CA goes where it can: a file
//! of its own, the system's PEM bundle (`/etc/ssl/cert.pem`, which LibreSSL,
//! curl and most of what is built on OpenSSL read) and any bundle the image
//! named. What verifies through the Security framework (URLSession, Safari,
//! Go's crypto/x509, Swift) does not see it; the README says so.
//!
//! Network: the guest takes its address by DHCP from whatever stack the host
//! puts behind its NIC, so there is nothing to apply; what the host sent is
//! logged.

#![allow(clippy::result_large_err)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tonic::Status;

use burrow_proto::guest::v1 as guestpb;

use crate::macos::vsock;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The CA on its own, for tools that take a path.
pub const CA_PATH: &str = "/private/etc/ssl/certs/burrow-inspection-ca.pem";
/// The system's PEM bundle. `/etc` is a link to `/private/etc`.
const SYSTEM_BUNDLE: &str = "/private/etc/ssl/cert.pem";

pub async fn handshake(
    arrival: Option<vsock::Arrival>,
    req: guestpb::HandshakeRequest,
) -> Result<guestpb::HandshakeResponse, Status> {
    tracing::debug!(restored = req.is_restored, "handshake from host");
    // Refused before anything changes, as on Windows: a caller that gets a
    // successful handshake is entitled to find its volumes mounted.
    if !req.volumes.is_empty() {
        return Err(Status::unimplemented(
            "volumes are not supported on macOS guests",
        ));
    }
    let started = std::time::Instant::now();
    if let Err(err) = reseed(&req.entropy) {
        tracing::error!(%err, "failed to reseed rng");
    }
    let reseeded = started.elapsed();
    if let Err(err) = set_clock(req.host_time_unix_nanos) {
        tracing::error!(%err, "failed to set guest clock");
    }
    let clocked = started.elapsed();

    // Fatal, as on Linux: a sandbox told to trust a CA and unable to would
    // fail every HTTPS request through the inspecting proxy.
    let pem = req.inspection_ca_pem.clone();
    let bundles = req.extra_trust_bundles.clone();
    tokio::task::spawn_blocking(move || install_inspection_ca(&pem, &bundles))
        .await
        .map_err(|err| Status::internal(format!("trust install did not run: {err}")))?
        .map_err(|err| {
            tracing::error!(%err, "failed to install the inspection ca");
            Status::internal(format!("installing the inspection ca: {err}"))
        })?;
    let trusted = started.elapsed();

    if let Some(network) = &req.network {
        tracing::info!(
            ip = network.ip,
            ip6 = network.ip6,
            "network from host; the guest has it by DHCP"
        );
    }

    let total = started.elapsed();
    let timing = guestpb::GuestResumeTiming {
        parked_us: arrival.map_or(0, |a| a.parked.as_micros() as u64),
        accept_to_call_us: arrival.map_or(0, |a| {
            a.accepted_at.elapsed().saturating_sub(total).as_micros() as u64
        }),
        reseed_us: reseeded.as_micros() as u64,
        clock_us: (clocked - reseeded).as_micros() as u64,
        trust_us: (trusted - clocked).as_micros() as u64,
        trust_write_us: (trusted - clocked).as_micros() as u64,
        network_us: (total - trusted).as_micros() as u64,
        total_us: total.as_micros() as u64,
        ..Default::default()
    };
    Ok(guestpb::HandshakeResponse {
        agent_version: VERSION.into(),
        timing: Some(timing),
        agent_digest: crate::macos::self_digest().to_string(),
    })
}

fn reseed(entropy: &[u8]) -> std::io::Result<()> {
    if entropy.is_empty() {
        return Ok(());
    }
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/random")?
        .write_all(entropy)?;
    tracing::debug!(bytes = entropy.len(), "rng mixed with host entropy");
    Ok(())
}

/// settimeofday(2), which root may call; `timed` disciplines the clock from
/// there if the template keeps network time on.
fn set_clock(unix_nanos: i64) -> std::io::Result<()> {
    if unix_nanos <= 0 {
        return Ok(());
    }
    let tv = nix::libc::timeval {
        tv_sec: unix_nanos.div_euclid(1_000_000_000),
        tv_usec: (unix_nanos.rem_euclid(1_000_000_000) / 1_000) as nix::libc::suseconds_t,
    };
    // SAFETY: `tv` outlives the call; no timezone is passed.
    if unsafe { nix::libc::settimeofday(&tv, std::ptr::null()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    tracing::debug!(unix_nanos, "guest clock synced to host");
    Ok(())
}

/// What this process has already installed, so a repeated handshake has
/// nothing to do.
static INSTALLED: Mutex<Option<(String, Vec<guestpb::TrustBundle>)>> = Mutex::new(None);

/// Installs the CA a sandbox was told to trust. An empty PEM leaves every
/// store as it is.
///
/// Fail-closed as on Linux: a bundle that is there and could not be updated
/// is an error; one that is absent is skipped, unless the image said it holds
/// only extra CAs, when it is created.
fn install_inspection_ca(pem: &str, extra: &[guestpb::TrustBundle]) -> anyhow::Result<()> {
    if pem.trim().is_empty() {
        return Ok(());
    }
    let mut held = INSTALLED.lock().unwrap();
    if held
        .as_ref()
        .is_some_and(|(done, bundles)| done == pem && bundles == extra)
    {
        return Ok(());
    }
    if let Some(parent) = Path::new(CA_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomically(Path::new(CA_PATH), pem.as_bytes())?;

    let mut targets = vec![(PathBuf::from(SYSTEM_BUNDLE), false)];
    for bundle in extra {
        let path = Path::new(&bundle.path);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| part == std::path::Component::ParentDir)
        {
            tracing::warn!(
                path = bundle.path,
                "refusing a trust bundle path that is not absolute and free of .."
            );
            continue;
        }
        targets.push((path.to_path_buf(), bundle.is_created_if_missing));
    }
    let mut done: Vec<PathBuf> = Vec::new();
    for (path, create) in targets {
        // Resolved, so a bundle reached by two names is written once and a
        // link to it stays a link.
        let target = std::fs::canonicalize(&path).unwrap_or(path);
        if done.contains(&target) {
            continue;
        }
        let existing = match std::fs::read_to_string(&target) {
            Ok(existing) => Some(existing),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => anyhow::bail!("reading {}: {err}", target.display()),
        };
        let contents = match existing {
            Some(existing) if existing.contains(pem.trim()) => {
                done.push(target);
                continue;
            }
            Some(mut existing) => {
                if !existing.is_empty() && !existing.ends_with('\n') {
                    existing.push('\n');
                }
                existing.push_str(pem.trim());
                existing.push('\n');
                existing
            }
            None if create => format!("{}\n", pem.trim()),
            None => continue,
        };
        write_atomically(&target, contents.as_bytes()).map_err(|err| {
            anyhow::anyhow!("could not add the ca to {}: {err}", target.display())
        })?;
        done.push(target);
    }
    *held = Some((pem.to_string(), extra.to_vec()));
    tracing::debug!(bundles = done.len(), "installed the inspection ca");
    Ok(())
}

/// Writes `path` through a sibling and a rename, keeping an existing file's
/// mode, so nothing reads it half-written.
fn write_atomically(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path).map_or(0o644, |meta| meta.permissions().mode() & 0o7777);
    let temp = path.with_extension(format!("burrow.{}", std::process::id()));
    let result = std::fs::write(&temp, contents)
        .and_then(|()| std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode)))
        .and_then(|()| std::fs::rename(&temp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_is_rewritten_whole_and_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("burrow-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = dir.join("bundle.pem");
        std::fs::write(&bundle, "old").unwrap();
        std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o640)).unwrap();
        write_atomically(&bundle, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&bundle).unwrap(), "new");
        assert_eq!(
            std::fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
            0o640
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
