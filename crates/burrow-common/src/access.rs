//! Tokens for a node's Access service.
//!
//! The orchestrator signs them and nodes check them, so exec and file traffic
//! can go straight to the node that holds a sandbox. A token is a JWT signed
//! with Ed25519, and nothing else is accepted: the algorithm is fixed here
//! rather than read from the token, which is what keeps `alg: none` and
//! key-confusion tokens out. Nodes hold only public keys, so a node that is
//! taken over can mint nothing for any other.
//!
//! A token names one sandbox (`sub`) on one node (`aud`), so it is refused for
//! any other sandbox and by any other node, which is also how it stops working
//! once the sandbox moves. It lives minutes, not hours: there is no list of
//! revoked tokens, and the expiry is what bounds a leaked one.

use std::collections::HashMap;
use std::path::Path;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use ring::signature::KeyPair as _;
use serde::{Deserialize, Serialize};

pub const OP_EXEC: &str = "exec";
/// Download, list and watch.
pub const OP_FILES_READ: &str = "files:read";
/// Upload.
pub const OP_FILES_WRITE: &str = "files:write";
pub const ALL_OPS: [&str; 3] = [OP_EXEC, OP_FILES_READ, OP_FILES_WRITE];

pub const ISSUER: &str = "burrow";
pub const DEFAULT_TTL_SECS: u32 = 300;
pub const MAX_TTL_SECS: u32 = 3600;
/// Node clocks are not the orchestrator's, so expiry is judged this loosely.
const LEEWAY_SECS: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Key(String),
    #[error("signing an access token: {0}")]
    Sign(jsonwebtoken::errors::Error),
    #[error("access token refused: {0}")]
    Refused(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    /// The node the token is for.
    pub aud: String,
    /// The sandbox the token is for.
    pub sub: String,
    pub ops: Vec<String>,
    /// Guest user every exec runs as; empty is root.
    #[serde(default)]
    pub user: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
}

impl Claims {
    /// A grant for `sandbox` on `node`, from now for `ttl_secs`.
    pub fn new(node: &str, sandbox: &str, ops: Vec<String>, user: String, ttl_secs: u32) -> Self {
        let now = crate::unix_now() as u64;
        Self {
            iss: ISSUER.into(),
            aud: node.into(),
            sub: sandbox.into(),
            ops,
            user,
            iat: now,
            exp: now + u64::from(ttl_secs),
            jti: uuid::Uuid::new_v4().simple().to_string(),
        }
    }

    pub fn allows(&self, op: &str) -> bool {
        self.ops.iter().any(|held| held == op)
    }
}

/// The orchestrator's half: a private key and the id tokens name it by.
pub struct Signer {
    key: EncodingKey,
    kid: String,
    public_key: Vec<u8>,
}

impl Signer {
    /// Opens the PKCS#8 key at `path`, PEM or DER, creating one when there is
    /// none. Every orchestrator replica has to sign with the same key, or a
    /// node knows only the key of whichever replica it last heard from.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let key_err = |what: String| Error::Key(format!("{}: {what}", path.display()));
        let der = match std::fs::read(path) {
            Ok(bytes) => pkcs8_der(&bytes).ok_or_else(|| key_err("not a PKCS#8 key".into()))?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let der = ring::signature::Ed25519KeyPair::generate_pkcs8(
                    &ring::rand::SystemRandom::new(),
                )
                .map_err(|_| key_err("no entropy".into()))?
                .as_ref()
                .to_vec();
                match publish(path, pem("PRIVATE KEY", &der).as_bytes()) {
                    Ok(()) => {
                        tracing::info!(path = %path.display(), "generated an access signing key");
                        der
                    }
                    // Replicas sharing a volume start together, and the one
                    // that lost the race signs with the winner's key.
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Self::open(path);
                    }
                    Err(err) => return Err(key_err(err.to_string())),
                }
            }
            Err(err) => return Err(key_err(err.to_string())),
        };
        Self::from_pkcs8(&der).map_err(|err| key_err(err.to_string()))
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map_err(|_| Error::Key("not an Ed25519 PKCS#8 key".into()))?;
        let public_key = pair.public_key().as_ref().to_vec();
        Ok(Self {
            key: EncodingKey::from_ed_der(der),
            kid: kid_of(&public_key),
            public_key,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Raw 32-byte Ed25519 public key, as nodes are handed it.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn sign(&self, claims: &Claims) -> Result<String, Error> {
        provider::install();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.key).map_err(Error::Sign)
    }
}

/// A key nodes should accept but nothing signs with: the next key during a
/// rotation, before replicas switch to it, or the previous one after, until
/// the last token it signed has expired. Read from a public key PEM, or from
/// a private key, of which only the public half is kept.
pub fn trusted_key(path: &Path) -> Result<(String, Vec<u8>), Error> {
    let key_err = |what: &str| Error::Key(format!("{}: {what}", path.display()));
    let bytes = std::fs::read(path).map_err(|err| key_err(&err.to_string()))?;
    let text = std::str::from_utf8(&bytes).unwrap_or_default();
    let public_key = if let Some(der) = pem_body(text, "PUBLIC KEY") {
        der.strip_prefix(ED25519_SPKI_PREFIX)
            .filter(|key| key.len() == 32)
            .ok_or_else(|| key_err("not an Ed25519 public key"))?
            .to_vec()
    } else {
        let der = pkcs8_der(&bytes).ok_or_else(|| key_err("not a PKCS#8 key"))?;
        Signer::from_pkcs8(&der)
            .map_err(|err| key_err(&err.to_string()))?
            .public_key
    };
    Ok((kid_of(&public_key), public_key))
}

/// What precedes the 32 key bytes in an Ed25519 SubjectPublicKeyInfo.
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The node's half: the public keys tokens may be signed with.
#[derive(Default)]
pub struct Verifier {
    keys: HashMap<String, DecodingKey>,
    raw: HashMap<String, Vec<u8>>,
}

impl Verifier {
    /// Keys are `(kid, raw public key)`. One that is not 32 bytes is skipped:
    /// it could never verify anything.
    pub fn new(keys: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        let raw: HashMap<String, Vec<u8>> = keys
            .into_iter()
            .filter(|(_, key)| key.len() == 32)
            .collect();
        Self {
            keys: raw
                .iter()
                .map(|(kid, key)| (kid.clone(), DecodingKey::from_ed_der(key)))
                .collect(),
            raw,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn same_keys(&self, other: &Verifier) -> bool {
        self.raw == other.raw
    }

    /// Checks `token` is signed by a known key, current, issued by burrow and
    /// meant for `node_id`.
    pub fn verify(&self, token: &str, node_id: &str) -> Result<Claims, Error> {
        provider::install();
        let refused = |why: &str| Error::Refused(why.to_string());
        let header = jsonwebtoken::decode_header(token).map_err(|_| refused("malformed"))?;
        if header.alg != Algorithm::EdDSA {
            return Err(refused("not signed with EdDSA"));
        }
        let key = header
            .kid
            .as_deref()
            .and_then(|kid| self.keys.get(kid))
            .ok_or_else(|| refused("signed with a key this node does not know"))?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = LEEWAY_SECS;
        validation.set_audience(&[node_id]);
        validation.set_issuer(&[ISSUER]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        let claims = jsonwebtoken::decode::<Claims>(token, key, &validation)
            .map_err(|err| match err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => refused("expired"),
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    refused("issued for another node")
                }
                _ => refused("invalid"),
            })?
            .claims;
        Ok(claims)
    }
}

/// Ed25519 through ring, the crypto the rest of the workspace uses, and no
/// other algorithm at all. jsonwebtoken's own backends bring RSA and ECDSA
/// implementations along that nothing here would ever call.
mod provider {
    use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
    use jsonwebtoken::errors::{ErrorKind, Result, new_error};
    use jsonwebtoken::signature;
    use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, EncodingKey};

    struct Ed25519Signer(ring::signature::Ed25519KeyPair);

    impl signature::Signer<Vec<u8>> for Ed25519Signer {
        fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
            Ok(self.0.sign(msg).as_ref().to_vec())
        }
    }

    impl JwtSigner for Ed25519Signer {
        fn algorithm(&self) -> Algorithm {
            Algorithm::EdDSA
        }
    }

    struct Ed25519Verifier(Vec<u8>);

    impl signature::Verifier<Vec<u8>> for Ed25519Verifier {
        fn verify(&self, msg: &[u8], sig: &Vec<u8>) -> std::result::Result<(), signature::Error> {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.0)
                .verify(msg, sig)
                .map_err(|_| signature::Error::new())
        }
    }

    impl JwtVerifier for Ed25519Verifier {
        fn algorithm(&self) -> Algorithm {
            Algorithm::EdDSA
        }
    }

    fn signer(alg: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
        if *alg != Algorithm::EdDSA || key.family() != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::UnsupportedAlgorithm));
        }
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(key.as_bytes())
            .map_err(|_| new_error(ErrorKind::InvalidEddsaKey))?;
        Ok(Box::new(Ed25519Signer(pair)))
    }

    fn verifier(alg: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
        if *alg != Algorithm::EdDSA || key.family() != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::UnsupportedAlgorithm));
        }
        let raw = key.try_get_as_bytes()?;
        if raw.len() != 32 {
            return Err(new_error(ErrorKind::InvalidEddsaKey));
        }
        Ok(Box::new(Ed25519Verifier(raw.to_vec())))
    }

    static PROVIDER: CryptoProvider = CryptoProvider {
        signer_factory: signer,
        verifier_factory: verifier,
        key_utils: KeyUtils::new_unimplemented(),
    };

    pub fn install() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = PROVIDER.install_default();
        });
    }
}

/// Puts `bytes` at `path` whole or not at all: written beside it, then linked
/// in, which fails rather than overwrites when another process got there
/// first. A reader never sees half a key.
fn publish(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp = path.with_extension(format!("{}.new", uuid::Uuid::new_v4().simple()));
    crate::vault::write_private(&temp, bytes)?;
    let linked = std::fs::hard_link(&temp, path);
    let _ = std::fs::remove_file(&temp);
    linked
}

/// Names a key by its public half, so every replica holding one key
/// announces it under one id.
fn kid_of(public_key: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, public_key);
    digest.as_ref()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The DER inside a PEM file, or the bytes themselves when they are not PEM.
fn pkcs8_der(bytes: &[u8]) -> Option<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Some(bytes.to_vec());
    };
    if !text.contains("-----BEGIN") {
        return Some(bytes.to_vec());
    }
    pem_body(text, "PRIVATE KEY")
}

fn pem_body(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    if !text.contains(&begin) {
        return None;
    }
    let body: String = text
        .lines()
        .skip_while(|line| !line.starts_with(&begin))
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        let der = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap();
        Signer::from_pkcs8(der.as_ref()).unwrap()
    }

    fn claims(aud: &str, exp_in: i64) -> Claims {
        let now = crate::unix_now() as u64;
        Claims {
            iss: ISSUER.into(),
            aud: aud.into(),
            sub: "sbx_a".into(),
            ops: vec![OP_EXEC.into()],
            user: String::new(),
            iat: now,
            exp: (now as i64 + exp_in) as u64,
            jti: "j".into(),
        }
    }

    fn verifier(signer: &Signer) -> Verifier {
        Verifier::new([(signer.kid().to_string(), signer.public_key().to_vec())])
    }

    #[test]
    fn a_token_verifies_on_its_node_only() {
        let signer = signer();
        let token = signer.sign(&claims("node_a", 300)).unwrap();
        let verifier = verifier(&signer);
        assert_eq!(verifier.verify(&token, "node_a").unwrap().sub, "sbx_a");
        assert!(verifier.verify(&token, "node_b").is_err());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let signer = signer();
        let token = signer.sign(&claims("node_a", -120)).unwrap();
        assert!(verifier(&signer).verify(&token, "node_a").is_err());
    }

    #[test]
    fn another_keys_token_is_refused() {
        let token = signer().sign(&claims("node_a", 300)).unwrap();
        assert!(verifier(&signer()).verify(&token, "node_a").is_err());
    }

    #[test]
    fn an_unsigned_token_is_refused() {
        let signer = signer();
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        let header = format!(r#"{{"alg":"none","kid":"{}"}}"#, signer.kid());
        let body = serde_json::to_string(&claims("node_a", 300)).unwrap();
        let token = format!("{}.{}.", b64(&header), b64(&body));
        assert!(verifier(&signer).verify(&token, "node_a").is_err());
    }

    #[test]
    fn a_tampered_token_is_refused() {
        let signer = signer();
        let token = signer.sign(&claims("node_a", 300)).unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let mut forged = claims("node_a", 300);
        forged.sub = "sbx_other".into();
        parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&forged).unwrap());
        assert!(
            verifier(&signer)
                .verify(&parts.join("."), "node_a")
                .is_err()
        );
    }

    #[test]
    fn a_generated_key_is_reopened_with_the_same_id() {
        let dir = std::env::temp_dir().join(format!(
            "burrow-access-{}-{}",
            std::process::id(),
            crate::unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("access.key");
        let first = Signer::open(&path).unwrap();
        let again = Signer::open(&path).unwrap();
        assert_eq!(first.kid(), again.kid());
        let token = first.sign(&claims("node_a", 300)).unwrap();
        assert!(verifier(&again).verify(&token, "node_a").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_trusted_key_reads_from_either_half() {
        let dir = std::env::temp_dir().join(format!(
            "burrow-access-trusted-{}-{}",
            std::process::id(),
            crate::unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let private = dir.join("next.key");
        let signer = Signer::open(&private).unwrap();
        let mut spki = ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(signer.public_key());
        let public = dir.join("next.pub");
        std::fs::write(&public, pem("PUBLIC KEY", &spki)).unwrap();
        let expected = (signer.kid().to_string(), signer.public_key().to_vec());
        assert_eq!(trusted_key(&private).unwrap(), expected);
        assert_eq!(trusted_key(&public).unwrap(), expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replicas_opening_a_missing_key_at_once_share_one() {
        let dir = std::env::temp_dir().join(format!(
            "burrow-access-race-{}-{}",
            std::process::id(),
            crate::unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("access.key");
        let kids: Vec<String> = std::thread::scope(|scope| {
            let opens: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| Signer::open(&path).unwrap().kid().to_string()))
                .collect();
            opens.into_iter().map(|open| open.join().unwrap()).collect()
        });
        assert!(kids.iter().all(|kid| *kid == kids[0]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
