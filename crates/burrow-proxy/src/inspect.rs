//! Looking inside TLS, so a request cannot lie about where it is going.
//!
//! Every other check is on a name the client volunteered. The SNI says
//! `allowed.example` and DNS pinning proves the address really is one that name
//! resolves to, and then the request inside the encrypted session asks for a
//! different host entirely. Where both names live behind one provider every
//! outer check passes, and no amount of looking at the outside of the
//! connection finds it. That is domain fronting.
//!
//! Seeing the inner request means terminating the TLS session, so this is
//! opt-in per sandbox: the default remains that burrow sees hostnames and never
//! payloads. Turning it on trades that privacy for checking the inner host.
//!
//! The certificate authority is generated on the node, kept there, and
//! installed into guests that opt in. It signs only for sandboxes that asked
//! for inspection, and never leaves the node.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Filenames the authority is kept under, beside the node's other state.
const CA_CERT: &str = "inspect-ca.pem";
const CA_KEY: &str = "inspect-ca.key";

/// How many leaf certificates are kept.
///
/// The key is a hostname the sandbox chose, so without a cap a sandbox that
/// asks for a new name every connection makes the proxy generate a keypair and
/// hold it forever. Well above the handful of hosts a real workload uses.
const MAX_LEAVES: usize = 1024;

/// Extra trust anchors, for this crate's own tests only.
///
/// A test stands up its endpoint on loopback, which no public authority will
/// sign for. Compiled out of everything a node runs: a runtime path to this
/// would be the "skip verification" flag the forward leg deliberately lacks.
#[cfg(test)]
static TEST_ROOTS: std::sync::Mutex<Vec<CertificateDer<'static>>> =
    std::sync::Mutex::new(Vec::new());

/// Trusts one more authority for the rest of the test binary's life.
#[cfg(test)]
pub(crate) fn trust_in_tests(certificate: CertificateDer<'static>) {
    TEST_ROOTS.lock().unwrap().push(certificate);
}

/// A TLS client that verifies the far side against the public roots.
///
/// The one place the proxy's outbound trust is decided, so the inspected
/// upstream leg and the forward leg cannot drift apart on which certificates
/// they accept. Verification is not a parameter: there is no argument that
/// turns it off, and no way to name a different set of anchors.
pub fn verified_client(alpn: Vec<Vec<u8>>) -> Arc<rustls::ClientConfig> {
    #[allow(unused_mut)]
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    #[cfg(test)]
    for certificate in TEST_ROOTS.lock().unwrap().iter() {
        let _ = roots.add(certificate.clone());
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

/// Which version of HTTP an inspected session speaks.
///
/// Exactly one is offered to the sandbox, whichever the origin agreed to, so
/// both halves of an inspected session speak the same version and nothing on
/// the policy path translates between them. Translation is where an
/// intermediary's framing and a server's stop agreeing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http11,
    H2,
}

impl Protocol {
    pub fn alpn(self) -> &'static [u8] {
        match self {
            Protocol::Http11 => b"http/1.1",
            Protocol::H2 => b"h2",
        }
    }
}

/// One host's leaf, configured for each protocol it may be presented with.
///
/// Both are built from a single signed leaf: which protocol a connection ends
/// up on is not known until the origin has answered, and minting a second
/// certificate for the same name would cost a keypair per protocol. Leaves live
/// in memory only and are re-minted on every start, so their validity window is
/// left at rcgen's default.
#[derive(Clone)]
struct Leaf {
    http11: Arc<rustls::ServerConfig>,
    h2: Arc<rustls::ServerConfig>,
}

impl Leaf {
    fn select(&self, protocol: Protocol) -> Arc<rustls::ServerConfig> {
        match protocol {
            Protocol::Http11 => Arc::clone(&self.http11),
            Protocol::H2 => Arc::clone(&self.h2),
        }
    }
}

/// A certificate authority for inspected connections.
pub struct Authority {
    ca: rcgen::Certificate,
    key: rcgen::KeyPair,
    cert_pem: String,
    /// Leaves already minted, by hostname. Signing is not free and a sandbox
    /// talks to the same handful of hosts over and over.
    leaves: RwLock<HashMap<String, Leaf>>,
}

impl Authority {
    /// Loads the node's authority, generating one the first time.
    ///
    /// Persisted rather than regenerated per start, because the certificate is
    /// installed inside guests: a new one each boot would break every sandbox
    /// that survived a restart.
    pub fn load_or_create(dir: &Path) -> Result<Self, String> {
        let cert_path = dir.join(CA_CERT);
        let key_path = dir.join(CA_KEY);

        // An authority that exists is loaded or the load fails. Regenerating
        // over an unreadable one would silently invalidate the certificate
        // every surviving guest was told to trust, turning a permissions
        // mistake into a fleet-wide outage that looks like a TLS error.
        match (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            (Ok(cert_pem), Ok(key_pem)) => return Self::from_pem(&cert_pem, &key_pem),
            (Err(err), _) | (_, Err(err)) if err.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("reading the inspection authority: {err}"));
            }
            _ => {}
        }
        if cert_path.exists() || key_path.exists() {
            return Err(format!(
                "the inspection authority in {} is incomplete; refusing to overwrite it",
                dir.display()
            ));
        }

        let authority = Self::generate()?;
        std::fs::create_dir_all(dir).map_err(|err| format!("creating {}: {err}", dir.display()))?;
        std::fs::write(&cert_path, &authority.cert_pem)
            .map_err(|err| format!("writing the ca certificate: {err}"))?;
        // The private key signs certificates guests are told to trust, so it
        // is created readable only by the daemon that uses it. Creating it open
        // and narrowing afterwards leaves a window to copy it in.
        Self::write_private(&key_path, &authority.key.serialize_pem())
            .map_err(|err| format!("writing the ca key: {err}"))?;
        tracing::info!(path = %cert_path.display(), "generated a TLS inspection authority");
        Ok(authority)
    }

    /// Writes a file only the owner can read, from the moment it exists.
    fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
        use std::io::Write;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()
    }

    fn generate() -> Result<Self, String> {
        let key = rcgen::KeyPair::generate().map_err(|err| format!("ca key: {err}"))?;
        let mut params =
            rcgen::CertificateParams::new(Vec::new()).map_err(|err| format!("ca params: {err}"))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "burrow sandbox inspection");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "burrow");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        let ca = params
            .self_signed(&key)
            .map_err(|err| format!("ca certificate: {err}"))?;
        let cert_pem = ca.pem();
        Ok(Self {
            ca,
            key,
            cert_pem,
            leaves: RwLock::new(HashMap::new()),
        })
    }

    fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
        let key = rcgen::KeyPair::from_pem(key_pem).map_err(|err| format!("ca key: {err}"))?;
        let params = rcgen::CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|err| format!("ca certificate: {err}"))?;
        let ca = params
            .self_signed(&key)
            .map_err(|err| format!("ca certificate: {err}"))?;
        Ok(Self {
            ca,
            key,
            cert_pem: cert_pem.to_string(),
            leaves: RwLock::new(HashMap::new()),
        })
    }

    /// The certificate guests must trust, in PEM.
    pub fn certificate_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A TLS server configuration presenting a certificate for `host` and
    /// offering exactly `protocol`.
    ///
    /// One protocol, never a list: the caller has already learned which one the
    /// origin agreed to, and offering the sandbox anything else would leave the
    /// two halves of the session speaking different versions of HTTP.
    pub fn server_config(
        &self,
        host: &str,
        protocol: Protocol,
    ) -> Result<Arc<rustls::ServerConfig>, String> {
        if let Some(leaf) = self.leaves.read().unwrap().get(host) {
            return Ok(leaf.select(protocol));
        }

        let key = rcgen::KeyPair::generate().map_err(|err| format!("leaf key: {err}"))?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
            .map_err(|err| format!("leaf params: {err}"))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;

        let leaf = params
            .signed_by(&key, &self.ca, &self.key)
            .map_err(|err| format!("signing a leaf for {host}: {err}"))?;

        let chain = vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(self.ca.der().to_vec()),
        ];
        let private = PrivateKeyDer::try_from(key.serialize_der())
            .map_err(|err| format!("leaf key: {err}"))?;

        let configure = |protocol: Protocol| -> Result<Arc<rustls::ServerConfig>, String> {
            let mut config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain.clone(), private.clone_key())
                .map_err(|err| format!("tls config for {host}: {err}"))?;
            config.alpn_protocols = vec![protocol.alpn().to_vec()];
            Ok(Arc::new(config))
        };
        let leaf = Leaf {
            http11: configure(Protocol::Http11)?,
            h2: configure(Protocol::H2)?,
        };

        let mut leaves = self.leaves.write().unwrap();
        // Two connections for the same new host race here; whichever arrives
        // second uses the leaf the first cached rather than adding its own, so
        // one host never occupies two entries.
        if let Some(existing) = leaves.get(host) {
            return Ok(existing.select(protocol));
        }
        // The key is a name the sandbox chose. Bounded, and cleared wholesale
        // rather than tracking use order: re-minting a leaf costs a keypair,
        // and the alternative is a cache a sandbox can grow without limit.
        if leaves.len() >= MAX_LEAVES {
            tracing::debug!("leaf certificate cache full; clearing it");
            leaves.clear();
        }
        let selected = leaf.select(protocol);
        leaves.insert(host.to_string(), leaf);
        Ok(selected)
    }
}

/// Checks a request's host against the allowlist.
///
/// The one place that decision is made, so the plaintext relay and the
/// inspected one cannot drift apart on what counts as allowed.
pub fn host_allowed(allowed: &[String], host: &str) -> Result<(), &'static str> {
    if !allowed
        .iter()
        .any(|pattern| crate::policy::matches(pattern, host))
    {
        return Err("request host is not in the allowlist");
    }
    Ok(())
}

/// Checks the host a request asked for once TLS has been stripped.
///
/// This is the check that fronting fails: the outer name passed the allowlist
/// and the address passed pinning, and now the inner request names somewhere
/// else entirely.
pub fn inner_host_allowed(sni: &str, inner: &str, allowed: &[String]) -> Result<(), &'static str> {
    host_allowed(allowed, inner)?;
    // Even an allowlisted inner host is refused when it disagrees with the
    // name the connection was opened for: that is fronting between two
    // permitted names, and it defeats per-name reasoning about where a sandbox
    // actually talks.
    if !inner.eq_ignore_ascii_case(sni) {
        return Err("request host does not match the name the session was opened for");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow-ca-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_authority_is_generated_and_reused() {
        let dir = scratch("persist");
        let first = Authority::load_or_create(&dir).unwrap();
        let pem = first.certificate_pem().to_string();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

        // Reloaded rather than regenerated: the certificate is installed inside
        // guests, and a new one each boot would break every surviving sandbox.
        let second = Authority::load_or_create(&dir).unwrap();
        assert_eq!(second.certificate_pem(), pem);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_private_key_is_not_world_readable() {
        let dir = scratch("perms");
        let _ = Authority::load_or_create(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CA_KEY))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "the ca key must not be readable by others");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A CA that cannot be read is an error, never a reason to mint a new one:
    /// every guest already trusts the old certificate, and replacing it turns
    /// a permissions mistake into a fleet-wide TLS failure.
    #[test]
    fn a_corrupt_authority_is_not_silently_replaced() {
        let dir = scratch("corrupt");
        let pem = Authority::load_or_create(&dir)
            .unwrap()
            .certificate_pem()
            .to_string();

        std::fs::write(dir.join(CA_KEY), "not a key at all").unwrap();
        assert!(Authority::load_or_create(&dir).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join(CA_CERT)).unwrap(),
            pem,
            "the existing certificate must survive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_leaf_is_minted_per_host_and_cached() {
        let dir = scratch("leaves");
        let ca = Authority::load_or_create(&dir).unwrap();
        let a = ca.server_config("example.com", Protocol::Http11).unwrap();
        let b = ca.server_config("example.com", Protocol::Http11).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "the same host should reuse its leaf");

        let c = ca.server_config("other.example", Protocol::Http11).unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Exactly one protocol is offered, and it is the one the caller asked for:
    /// a session where the two halves disagree about the version of HTTP would
    /// need translating, and translation is where framing stops agreeing.
    #[test]
    fn a_leaf_offers_only_the_protocol_it_was_asked_for() {
        let dir = scratch("alpn");
        let ca = Authority::load_or_create(&dir).unwrap();
        let h1 = ca.server_config("example.com", Protocol::Http11).unwrap();
        let h2 = ca.server_config("example.com", Protocol::H2).unwrap();

        assert_eq!(h1.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert_eq!(h2.alpn_protocols, vec![b"h2".to_vec()]);
        // One signature covers both: the protocol is not known until the origin
        // has answered, and the certificate does not depend on it.
        assert!(!Arc::ptr_eq(&h1, &h2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The case that motivates all of this.
    #[test]
    fn fronting_is_refused_even_between_two_allowed_names() {
        let allowed = vec!["allowed.example".to_string(), "other.example".to_string()];
        assert!(inner_host_allowed("allowed.example", "allowed.example", &allowed).is_ok());

        // Outer name allowed, inner name allowed, but they disagree.
        assert_eq!(
            inner_host_allowed("allowed.example", "other.example", &allowed),
            Err("request host does not match the name the session was opened for")
        );
    }

    #[test]
    fn an_inner_host_outside_the_allowlist_is_refused() {
        let allowed = vec!["allowed.example".to_string()];
        assert_eq!(
            inner_host_allowed("allowed.example", "evil.example", &allowed),
            Err("request host is not in the allowlist")
        );
    }

    #[test]
    fn host_comparison_ignores_case() {
        let allowed = vec!["allowed.example".to_string()];
        assert!(inner_host_allowed("allowed.example", "ALLOWED.example", &allowed).is_ok());
    }

    #[test]
    fn a_wildcard_allowlist_still_pins_the_session_to_one_name() {
        let allowed = vec!["*.example.com".to_string()];
        assert!(inner_host_allowed("a.example.com", "a.example.com", &allowed).is_ok());
        // Both match the wildcard, but the session was opened for one of them.
        assert!(inner_host_allowed("a.example.com", "b.example.com", &allowed).is_err());
    }
}
