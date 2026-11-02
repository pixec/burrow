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
//! Leaves are signed by a certificate authority on the node, whose key never
//! leaves it, and are presented only to sandboxes that asked for inspection.
//! What a guest is told to trust is the root that authority chains to. In a
//! fleet, that is one operator-made root over a per-node intermediate, so a
//! sandbox that moves keeps trusting the node it lands on. A node given no
//! root generates its own authority and is its own root, and a sandbox
//! inspected there cannot move to a node with another.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::policy::{Decision, SandboxPolicy};

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
/// in memory only and are re-minted on every start and once they are half way
/// through their life.
#[derive(Clone)]
struct Leaf {
    http11: Arc<rustls::ServerConfig>,
    h2: Arc<rustls::ServerConfig>,
    minted: std::time::Instant,
}

impl Leaf {
    fn select(&self, protocol: Protocol) -> Arc<rustls::ServerConfig> {
        match protocol {
            Protocol::Http11 => Arc::clone(&self.http11),
            Protocol::H2 => Arc::clone(&self.h2),
        }
    }

    fn is_fresh(&self) -> bool {
        self.minted.elapsed() < LEAF_LIFETIME / 2
    }
}

/// How long a leaf is valid for.
///
/// Apple's TLS stack refuses a server certificate valid for more than 825
/// days whatever root it chains to, and a short life is also what bounds a
/// leaf outliving the authority that signed it.
const LEAF_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 3600);

/// How long a node intermediate issued by `burrowd ca issue` lasts unless
/// told otherwise.
pub const NODE_CA_LIFETIME: std::time::Duration = std::time::Duration::from_secs(365 * 24 * 3600);

/// How long a fleet root made by `burrowd ca init` lasts unless told
/// otherwise.
pub const ROOT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10 * 365 * 24 * 3600);

/// The name the chain is checked against at startup. Never resolvable, so
/// the leaf minted for the check is no use to anything else.
const CHAIN_CHECK_HOST: &str = "chain-check.burrow.invalid";

/// A certificate authority for inspected connections.
pub struct Authority {
    /// The signing certificate as rcgen needs it: the node CA's name and key
    /// identifier, re-signed by its own key. Never presented to anyone.
    ca: rcgen::Certificate,
    key: rcgen::KeyPair,
    /// The node CA exactly as it was issued, sent behind every leaf.
    ca_der: CertificateDer<'static>,
    /// What guests trust, in PEM: the fleet root, or the node CA itself when
    /// it is its own root.
    root_pem: String,
    root_fingerprint: String,
    /// When the node CA stops being valid, and with it every leaf it signs.
    expires_at: std::time::SystemTime,
    /// Leaves already minted, by hostname. Signing is not free and a sandbox
    /// talks to the same handful of hosts over and over.
    leaves: RwLock<HashMap<String, Leaf>>,
}

/// The hex SHA-256 of a certificate's DER, which is how nodes and sandboxes
/// name the root they trust.
pub fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(der))
}

/// [`fingerprint`] of the first certificate in `pem`, or empty when it holds
/// none.
pub fn pem_fingerprint(pem: &str) -> String {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .and_then(Result::ok)
        .map(|der| fingerprint(&der))
        .unwrap_or_default()
}

/// The certificates in a PEM file, as DER.
fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = std::fs::read(path).map_err(|err| format!("reading {}: {err}", path.display()))?;
    let certificates = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parsing {}: {err}", path.display()))?;
    if certificates.is_empty() {
        return Err(format!("{} holds no certificate", path.display()));
    }
    Ok(certificates)
}

fn pem_of(der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// A CA certificate's parameters, refusing one that is not a CA.
fn ca_params(der: &CertificateDer<'_>, what: &str) -> Result<rcgen::CertificateParams, String> {
    let params = rcgen::CertificateParams::from_ca_cert_der(der)
        .map_err(|err| format!("parsing the {what}: {err}"))?;
    if !matches!(params.is_ca, rcgen::IsCa::Ca(_)) {
        return Err(format!(
            "the {what} is not a CA certificate (its basic constraints do not say CA:TRUE); \
             issue one with `burrowd ca issue`"
        ));
    }
    Ok(params)
}

/// Parameters for a CA certificate valid from now for `lifetime`.
fn new_ca_params(
    common_name: &str,
    lifetime: std::time::Duration,
    path_len: rcgen::BasicConstraints,
) -> Result<rcgen::CertificateParams, String> {
    let mut params =
        rcgen::CertificateParams::new(Vec::new()).map_err(|err| format!("ca params: {err}"))?;
    params.is_ca = rcgen::IsCa::Ca(path_len);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "burrow");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - std::time::Duration::from_secs(3600);
    params.not_after = now + lifetime;
    Ok(params)
}

/// Makes a fleet root: its certificate and private key, in PEM.
pub fn create_root(
    common_name: &str,
    lifetime: std::time::Duration,
) -> Result<(String, String), String> {
    let key = rcgen::KeyPair::generate().map_err(|err| format!("root key: {err}"))?;
    let root = new_ca_params(
        common_name,
        lifetime,
        rcgen::BasicConstraints::Constrained(1),
    )?
    .self_signed(&key)
    .map_err(|err| format!("root certificate: {err}"))?;
    Ok((root.pem(), key.serialize_pem()))
}

/// Issues the intermediate a node signs leaves with, under a fleet root: its
/// certificate and private key, in PEM.
///
/// Constrained to signing leaves, so a node's key can mint certificates for
/// hosts and never another authority.
pub fn issue_node_ca(
    root_pem: &str,
    root_key_pem: &str,
    node_id: &str,
    lifetime: std::time::Duration,
) -> Result<(String, String), String> {
    let root_key =
        rcgen::KeyPair::from_pem(root_key_pem).map_err(|err| format!("root key: {err}"))?;
    let root_der = rustls_pemfile::certs(&mut root_pem.as_bytes())
        .next()
        .ok_or("the root file holds no certificate")?
        .map_err(|err| format!("root certificate: {err}"))?;
    let root = ca_params(&root_der, "root certificate")?
        .self_signed(&root_key)
        .map_err(|err| format!("root certificate: {err}"))?;
    let key = rcgen::KeyPair::generate().map_err(|err| format!("node key: {err}"))?;
    let mut params = new_ca_params(
        &format!("burrow inspection {node_id}"),
        lifetime,
        rcgen::BasicConstraints::Constrained(0),
    )?;
    params.use_authority_key_identifier_extension = true;
    let node = params
        .signed_by(&key, &root, &root_key)
        .map_err(|err| format!("signing the node certificate: {err}"))?;
    let key_pem = key.serialize_pem();
    Authority::with_root(node.der(), &key_pem, &root_der)?;
    Ok((node.pem(), key_pem))
}

impl Authority {
    /// Loads the node's own authority, generating one the first time: what a
    /// node runs with when it is given no fleet root, and its own root then.
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

        let (cert_pem, key_pem) = Self::generate()?;
        std::fs::create_dir_all(dir).map_err(|err| format!("creating {}: {err}", dir.display()))?;
        std::fs::write(&cert_path, &cert_pem)
            .map_err(|err| format!("writing the ca certificate: {err}"))?;
        // The private key signs certificates guests are told to trust, so it
        // is created readable only by the daemon that uses it. Creating it open
        // and narrowing afterwards leaves a window to copy it in.
        write_private(&key_path, &key_pem).map_err(|err| format!("writing the ca key: {err}"))?;
        tracing::info!(path = %cert_path.display(), "generated a TLS inspection authority");
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Loads a node intermediate and the fleet root it must chain to.
    ///
    /// Refuses one that is not a CA, has expired, does not match its key, or
    /// does not chain to the root: each would start a node whose inspected
    /// sandboxes reject every connection, which is worse than not starting.
    pub fn load(cert: &Path, key: &Path, root: &Path) -> Result<Self, String> {
        let node = read_certificates(cert)?.remove(0);
        let mut roots = read_certificates(root)?;
        if roots.len() > 1 {
            return Err(format!(
                "{} holds {} certificates; give the fleet root on its own",
                root.display(),
                roots.len()
            ));
        }
        let key_pem = std::fs::read_to_string(key)
            .map_err(|err| format!("reading {}: {err}", key.display()))?;
        Self::with_root(&node, &key_pem, &roots.remove(0))
            .map_err(|err| format!("{}: {err}", cert.display()))
    }

    /// An authority signing with `node`, checked to chain to `root`.
    fn with_root(
        node: &CertificateDer<'static>,
        key_pem: &str,
        root: &CertificateDer<'static>,
    ) -> Result<Self, String> {
        ca_params(root, "root certificate")?;
        let authority = Self::from_der(node, key_pem, root)?;
        authority.check_chain(root)?;
        Ok(authority)
    }

    fn generate() -> Result<(String, String), String> {
        let key = rcgen::KeyPair::generate().map_err(|err| format!("ca key: {err}"))?;
        let ca = new_ca_params(
            "burrow sandbox inspection",
            ROOT_LIFETIME,
            rcgen::BasicConstraints::Unconstrained,
        )?
        .self_signed(&key)
        .map_err(|err| format!("ca certificate: {err}"))?;
        Ok((ca.pem(), key.serialize_pem()))
    }

    fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or("no certificate in the ca file")?
            .map_err(|err| format!("ca certificate: {err}"))?;
        Self::from_der(&der, key_pem, &der)
    }

    fn from_der(
        der: &CertificateDer<'static>,
        key_pem: &str,
        root: &CertificateDer<'static>,
    ) -> Result<Self, String> {
        let key = rcgen::KeyPair::from_pem(key_pem).map_err(|err| format!("ca key: {err}"))?;
        let params = ca_params(der, "node CA certificate")?;
        let expires_at = std::time::SystemTime::from(params.not_after);
        if expires_at <= std::time::SystemTime::now() {
            return Err(format!(
                "the node CA certificate expired at {}; issue a new one with `burrowd ca issue`",
                params.not_after
            ));
        }
        let ca = params
            .self_signed(&key)
            .map_err(|err| format!("ca certificate: {err}"))?;
        Ok(Self {
            ca,
            key,
            ca_der: der.clone(),
            root_pem: pem_of(root),
            root_fingerprint: fingerprint(root),
            expires_at,
            leaves: RwLock::new(HashMap::new()),
        })
    }

    /// Mints a leaf and verifies it the way a client trusting only `root`
    /// would, which settles at once that the node CA is a CA, is current,
    /// matches its key and chains to the root.
    fn check_chain(&self, root: &CertificateDer<'static>) -> Result<(), String> {
        let mut anchors = rustls::RootCertStore::empty();
        anchors
            .add(root.clone())
            .map_err(|err| format!("the root certificate is unusable: {err}"))?;
        use rustls::client::danger::ServerCertVerifier as _;
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(anchors),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|err| format!("building a verifier: {err}"))?;
        let (leaf, _) = self.mint(CHAIN_CHECK_HOST)?;
        let host = rustls::pki_types::ServerName::try_from(CHAIN_CHECK_HOST)
            .expect("a valid name")
            .to_owned();
        verifier
            .verify_server_cert(
                &leaf,
                std::slice::from_ref(&self.ca_der),
                &host,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .map_err(|err| {
                format!(
                    "the node CA does not chain to the root {} ({err}); it must be issued by \
                     that root, with the key given beside it",
                    self.root_fingerprint
                )
            })?;
        Ok(())
    }

    /// The certificate guests must trust, in PEM: the fleet root.
    pub fn certificate_pem(&self) -> &str {
        &self.root_pem
    }

    /// The SHA-256 of the root guests trust, in hex.
    pub fn root_fingerprint(&self) -> &str {
        &self.root_fingerprint
    }

    /// When the node's CA expires.
    pub fn expires_at(&self) -> std::time::SystemTime {
        self.expires_at
    }

    /// Signs a leaf for `host`, returning it and its key.
    fn mint(&self, host: &str) -> Result<(CertificateDer<'static>, rcgen::KeyPair), String> {
        let key = rcgen::KeyPair::generate().map_err(|err| format!("leaf key: {err}"))?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
            .map_err(|err| format!("leaf params: {err}"))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        // Apple's TLS stack refuses a server certificate without this.
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - std::time::Duration::from_secs(3600);
        params.not_after = (now + LEAF_LIFETIME).min(time::OffsetDateTime::from(self.expires_at));
        let leaf = params
            .signed_by(&key, &self.ca, &self.key)
            .map_err(|err| format!("signing a leaf for {host}: {err}"))?;
        Ok((CertificateDer::from(leaf.der().to_vec()), key))
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
        if let Some(leaf) = self.leaves.read().unwrap().get(host)
            && leaf.is_fresh()
        {
            return Ok(leaf.select(protocol));
        }

        let (leaf, key) = self.mint(host)?;
        let chain = vec![leaf, self.ca_der.clone()];
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
            minted: std::time::Instant::now(),
        };

        let mut leaves = self.leaves.write().unwrap();
        // Two connections for the same new host race here; whichever arrives
        // second uses the leaf the first cached rather than adding its own, so
        // one host never occupies two entries.
        if let Some(existing) = leaves.get(host)
            && existing.is_fresh()
        {
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

/// Writes a file only the owner can read, from the moment it exists, and
/// refuses to replace one that is there.
pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
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

/// Checks a request's host against the allowlist.
///
/// The one place that decision is made, so the plaintext relay and the
/// inspected one cannot drift apart on what counts as allowed.
pub fn host_allowed(policy: &SandboxPolicy, host: &str) -> Result<(), &'static str> {
    match policy.admits(host) {
        Decision::Allow => Ok(()),
        Decision::Deny(reason) => Err(reason),
    }
}

/// Checks the host a request asked for once TLS has been stripped.
///
/// This is the check that fronting fails: the outer name passed the allowlist
/// and the address passed pinning, and now the inner request names somewhere
/// else entirely.
pub fn inner_host_allowed(
    sni: &str,
    inner: &str,
    policy: &SandboxPolicy,
) -> Result<(), &'static str> {
    host_allowed(policy, inner)?;
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

    /// A fleet root and one node intermediate under it, written to `dir`.
    fn fleet(dir: &Path, node: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root_cert = dir.join("root.pem");
        let root_key = dir.join("root.key");
        if !root_cert.exists() {
            let (cert, key) = create_root("test fleet", ROOT_LIFETIME).unwrap();
            std::fs::write(&root_cert, cert).unwrap();
            std::fs::write(&root_key, key).unwrap();
        }
        let (cert, key) = issue_node_ca(
            &std::fs::read_to_string(&root_cert).unwrap(),
            &std::fs::read_to_string(&root_key).unwrap(),
            node,
            NODE_CA_LIFETIME,
        )
        .unwrap();
        let (node_cert, node_key) = (
            dir.join(format!("{node}.pem")),
            dir.join(format!("{node}.key")),
        );
        std::fs::write(&node_cert, cert).unwrap();
        std::fs::write(&node_key, key).unwrap();
        (node_cert, node_key, root_cert)
    }

    /// Completes a handshake against `authority`'s leaf for `host` as a client
    /// that trusts only `root_pem`.
    async fn handshake(authority: &Authority, root_pem: &str, host: &str) -> Result<(), String> {
        let mut roots = rustls::RootCertStore::empty();
        for der in rustls_pemfile::certs(&mut root_pem.as_bytes()) {
            roots.add(der.unwrap()).unwrap();
        }
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server = authority.server_config(host, Protocol::Http11).unwrap();
        let (a, b) = tokio::io::duplex(64 * 1024);
        let accept =
            tokio::spawn(async move { tokio_rustls::TlsAcceptor::from(server).accept(b).await });
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        let connected = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(name, a)
            .await
            .map(|_| ())
            .map_err(|err| err.to_string());
        let _ = accept.await;
        connected
    }

    /// The point of a fleet root: a guest told to trust it once verifies the
    /// leaves of every node, so moving between them changes nothing inside.
    #[tokio::test]
    async fn every_node_under_one_root_is_trusted_through_it() {
        let dir = scratch("fleet");
        let (a_cert, a_key, root) = fleet(&dir, "node-a");
        let (b_cert, b_key, _) = fleet(&dir, "node-b");
        let a = Authority::load(&a_cert, &a_key, &root).unwrap();
        let b = Authority::load(&b_cert, &b_key, &root).unwrap();

        let root_pem = std::fs::read_to_string(&root).unwrap();
        assert_eq!(a.certificate_pem().trim(), root_pem.trim());
        assert_eq!(a.root_fingerprint(), b.root_fingerprint());
        let root_der = rustls_pemfile::certs(&mut root_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(a.root_fingerprint(), fingerprint(&root_der));

        // The intermediate travels in the chain; the guest holds only the root.
        handshake(&a, &root_pem, "example.com").await.unwrap();
        handshake(&b, &root_pem, "example.com").await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_node_authority_is_trusted_through_itself() {
        let dir = scratch("legacy-trust");
        let ca = Authority::load_or_create(&dir).unwrap();
        let pem = std::fs::read_to_string(dir.join(CA_CERT)).unwrap();
        assert_eq!(ca.certificate_pem().trim(), pem.trim());
        handshake(&ca, &pem, "example.com").await.unwrap();

        // Another node's authority is another root.
        let other = scratch("legacy-other");
        let other = Authority::load_or_create(&other).unwrap();
        assert_ne!(ca.root_fingerprint(), other.root_fingerprint());
        assert!(handshake(&other, &pem, "example.com").await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_node_ca_from_another_root_is_refused() {
        let dir = scratch("wrong-root");
        let (cert, key, _) = fleet(&dir, "node-a");
        let other = scratch("wrong-root-other");
        let (_, _, other_root) = fleet(&other, "node-b");
        let err = Authority::load(&cert, &key, &other_root).err().unwrap();
        assert!(err.contains("does not chain to the root"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn a_node_ca_with_another_nodes_key_is_refused() {
        let dir = scratch("wrong-key");
        let (a_cert, _, root) = fleet(&dir, "node-a");
        let (_, b_key, _) = fleet(&dir, "node-b");
        let err = Authority::load(&a_cert, &b_key, &root).err().unwrap();
        assert!(err.contains("does not chain to the root"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_certificate_that_is_not_a_ca_is_refused() {
        let dir = scratch("not-ca");
        let (_, _, root) = fleet(&dir, "node-a");
        let root_pem = std::fs::read_to_string(&root).unwrap();
        let root_key =
            rcgen::KeyPair::from_pem(&std::fs::read_to_string(dir.join("root.key")).unwrap())
                .unwrap();
        let issuer = rcgen::CertificateParams::from_ca_cert_pem(&root_pem)
            .unwrap()
            .self_signed(&root_key)
            .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["node.example".into()])
            .unwrap()
            .signed_by(&key, &issuer, &root_key)
            .unwrap();
        std::fs::write(dir.join("leaf.pem"), leaf.pem()).unwrap();
        std::fs::write(dir.join("leaf.key"), key.serialize_pem()).unwrap();
        let err = Authority::load(&dir.join("leaf.pem"), &dir.join("leaf.key"), &root)
            .err()
            .unwrap();
        assert!(err.contains("not a CA certificate"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_expired_node_ca_is_refused() {
        let dir = scratch("expired");
        let (_, _, root) = fleet(&dir, "node-a");
        let err = issue_node_ca(
            &std::fs::read_to_string(&root).unwrap(),
            &std::fs::read_to_string(dir.join("root.key")).unwrap(),
            "node-a",
            std::time::Duration::ZERO,
        )
        .err()
        .unwrap();
        assert!(err.contains("expired"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Apple's TLS stack rejects a server certificate without serverAuth or
    /// valid for longer than 825 days, whatever root it chains to.
    #[test]
    fn a_leaf_is_short_lived_and_for_servers() {
        let dir = scratch("leaf-shape");
        let (cert, key, root) = fleet(&dir, "node-a");
        let ca = Authority::load(&cert, &key, &root).unwrap();
        let (leaf, _) = ca.mint("example.com").unwrap();
        let params = rcgen::CertificateParams::from_ca_cert_der(&leaf).unwrap();
        assert_eq!(
            params.extended_key_usages,
            vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth]
        );
        assert!(params.not_after - params.not_before < time::Duration::days(825));
        assert!(std::time::SystemTime::from(params.not_after) <= ca.expires_at());
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
        let allowed = SandboxPolicy::allowing(&["allowed.example", "other.example"]);
        assert!(inner_host_allowed("allowed.example", "allowed.example", &allowed).is_ok());

        // Outer name allowed, inner name allowed, but they disagree.
        assert_eq!(
            inner_host_allowed("allowed.example", "other.example", &allowed),
            Err("request host does not match the name the session was opened for")
        );
    }

    #[test]
    fn an_inner_host_outside_the_allowlist_is_refused() {
        let allowed = SandboxPolicy::allowing(&["allowed.example"]);
        assert_eq!(
            inner_host_allowed("allowed.example", "evil.example", &allowed),
            Err("host not in allowlist")
        );
    }

    #[test]
    fn host_comparison_ignores_case() {
        let allowed = SandboxPolicy::allowing(&["allowed.example"]);
        assert!(inner_host_allowed("allowed.example", "ALLOWED.example", &allowed).is_ok());
    }

    #[test]
    fn a_wildcard_allowlist_still_pins_the_session_to_one_name() {
        let allowed = SandboxPolicy::allowing(&["*.example.com"]);
        assert!(inner_host_allowed("a.example.com", "a.example.com", &allowed).is_ok());
        // Both match the wildcard, but the session was opened for one of them.
        assert!(inner_host_allowed("a.example.com", "b.example.com", &allowed).is_err());
    }
}
