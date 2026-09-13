//! Node, disco and pre-shared keys, and the tunnel address a node key
//! implies.
//!
//! All three keys are 32 bytes. Node keys are the WireGuard identity and,
//! for a server, the unguessable part of its address. Disco keys sign the
//! path-discovery messages that travel in cleartext on direct UDP paths, so
//! they are derived from the node key in a way that cannot be reversed:
//! seeing a disco key on the wire must not reveal the address.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;

use crypto_box::SalsaBox;
use crypto_box::aead::Aead;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

const NODE_PRIVATE_PREFIX: &str = "privkey:";
const NODE_PUBLIC_PREFIX: &str = "nodekey:";
const DISCO_PUBLIC_PREFIX: &str = "discokey:";
const PRESHARED_PREFIX: &str = "psk:";

/// Tailscale's ULA range, `fd7a:115c:a1e0::/48`, which tunnel addresses are
/// carved from.
pub const ULA_PREFIX: [u8; 6] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0];

fn clamp(k: &mut [u8; KEY_LEN]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn parse_hex(s: &str, prefix: &str) -> Option<[u8; KEY_LEN]> {
    let rest = s.strip_prefix(prefix)?;
    let mut out = [0u8; KEY_LEN];
    hex::decode_to_slice(rest, &mut out).ok()?;
    Some(out)
}

fn seal(b: &SalsaBox, plaintext: &[u8]) -> Vec<u8> {
    let nonce = random_bytes::<NONCE_LEN>();
    let mut out = nonce.to_vec();
    out.extend(
        b.encrypt((&nonce).into(), plaintext)
            .expect("sealing cannot fail"),
    );
    out
}

fn open(b: &SalsaBox, ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < NONCE_LEN {
        return None;
    }
    let (nonce, boxed) = ciphertext.split_at(NONCE_LEN);
    b.decrypt(nonce.into(), boxed).ok()
}

/// A node's WireGuard private key.
#[derive(Clone, PartialEq, Eq)]
pub struct NodePrivate([u8; KEY_LEN]);

impl NodePrivate {
    pub fn generate() -> Self {
        let mut k = random_bytes();
        clamp(&mut k);
        Self(k)
    }

    pub fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self(raw)
    }

    pub fn raw(&self) -> [u8; KEY_LEN] {
        self.0
    }

    pub fn public(&self) -> NodePublic {
        NodePublic(PublicKey::from(&self.static_secret()).to_bytes())
    }

    pub(crate) fn static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.0)
    }

    /// The path-discovery key for this node.
    ///
    /// Derived, rather than random, so a server restarted from a persisted
    /// node key keeps the disco key its published address carries.
    pub fn disco(&self) -> DiscoPrivate {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("any key length is valid");
        mac.update(b"github.com/tailscale/tailcat disco key v1");
        let mut raw: [u8; KEY_LEN] = mac.finalize().into_bytes().into();
        clamp(&mut raw);
        DiscoPrivate(raw)
    }

    fn salsa_box(&self, peer: &NodePublic) -> SalsaBox {
        SalsaBox::new(
            &crypto_box::PublicKey::from(peer.0),
            &crypto_box::SecretKey::from(self.0),
        )
    }

    /// Seals `plaintext` to `peer` as a NaCl box: a random 24-byte nonce
    /// followed by the ciphertext.
    pub(crate) fn seal_to(&self, peer: &NodePublic, plaintext: &[u8]) -> Vec<u8> {
        seal(&self.salsa_box(peer), plaintext)
    }

    pub(crate) fn open_from(&self, peer: &NodePublic, ciphertext: &[u8]) -> Option<Vec<u8>> {
        open(&self.salsa_box(peer), ciphertext)
    }
}

impl fmt::Debug for NodePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{NODE_PRIVATE_PREFIX}[redacted]")
    }
}

impl fmt::Display for NodePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{NODE_PRIVATE_PREFIX}{}", hex::encode(self.0))
    }
}

impl FromStr for NodePrivate {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_hex(s, NODE_PRIVATE_PREFIX)
            .map(Self)
            .ok_or(KeyParseError("node private key"))
    }
}

/// A node's WireGuard public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodePublic([u8; KEY_LEN]);

impl NodePublic {
    pub const fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self(raw)
    }

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        b.try_into().ok().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; KEY_LEN]
    }

    /// The tunnel address of the node with this key: Tailscale's ULA prefix
    /// with the remaining 80 bits taken from the key.
    pub fn addr(&self) -> Ipv6Addr {
        let mut a = [0u8; 16];
        a[..6].copy_from_slice(&ULA_PREFIX);
        a[6..].copy_from_slice(&self.0[..10]);
        Ipv6Addr::from(a)
    }

    /// A short form for logs, matching Tailscale's `[abcde]` style.
    pub fn short(&self) -> String {
        use base64::Engine;
        let s = base64::engine::general_purpose::STANDARD.encode(self.0);
        format!("[{}]", &s[..5])
    }

    pub(crate) fn x25519(&self) -> PublicKey {
        PublicKey::from(self.0)
    }
}

impl fmt::Debug for NodePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for NodePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{NODE_PUBLIC_PREFIX}{}", hex::encode(self.0))
    }
}

impl FromStr for NodePublic {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_hex(s, NODE_PUBLIC_PREFIX)
            .map(Self)
            .ok_or(KeyParseError("node public key"))
    }
}

/// A node's path-discovery private key. See [`NodePrivate::disco`].
#[derive(Clone)]
pub struct DiscoPrivate([u8; KEY_LEN]);

impl DiscoPrivate {
    pub fn public(&self) -> DiscoPublic {
        DiscoPublic(PublicKey::from(&StaticSecret::from(self.0)).to_bytes())
    }

    /// The precomputed box key for disco messages with `peer`.
    pub fn shared(&self, peer: &DiscoPublic) -> DiscoShared {
        DiscoShared(Arc::new(SalsaBox::new(
            &crypto_box::PublicKey::from(peer.0),
            &crypto_box::SecretKey::from(self.0),
        )))
    }
}

impl fmt::Debug for DiscoPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "discoprivkey:[redacted]")
    }
}

/// A node's path-discovery public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiscoPublic([u8; KEY_LEN]);

impl DiscoPublic {
    pub const fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self(raw)
    }

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        b.try_into().ok().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; KEY_LEN]
    }

    pub fn short(&self) -> String {
        format!("d:{}", &hex::encode(self.0)[..8])
    }
}

impl fmt::Debug for DiscoPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for DiscoPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{DISCO_PUBLIC_PREFIX}{}", hex::encode(self.0))
    }
}

impl FromStr for DiscoPublic {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_hex(s, DISCO_PUBLIC_PREFIX)
            .map(Self)
            .ok_or(KeyParseError("disco public key"))
    }
}

/// The box key shared between two disco keys.
#[derive(Clone)]
pub struct DiscoShared(Arc<SalsaBox>);

impl DiscoShared {
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        seal(&self.0, plaintext)
    }

    pub fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        open(&self.0, ciphertext)
    }
}

/// A WireGuard pre-shared key.
///
/// Mixed into the handshake, it keeps a relay operator who has seen both
/// node keys out of the tunnel and adds a post-quantum layer. It lives in
/// the tailcat address, so an address carrying one is a secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PresharedKey([u8; KEY_LEN]);

impl PresharedKey {
    pub fn generate() -> Self {
        loop {
            let k = Self(random_bytes());
            if !k.is_zero() {
                return k;
            }
        }
    }

    pub const fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self(raw)
    }

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        b.try_into().ok().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; KEY_LEN]
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PRESHARED_PREFIX}[redacted]")
    }
}

impl fmt::Display for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PRESHARED_PREFIX}{}", hex::encode(self.0))
    }
}

impl FromStr for PresharedKey {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_hex(s, PRESHARED_PREFIX)
            .map(Self)
            .ok_or(KeyParseError("pre-shared key"))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid {0}")]
pub struct KeyParseError(&'static str);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disco_key_is_stable_and_unlinkable() {
        let node = NodePrivate::generate();
        let a = node.disco().public();
        let b = node.disco().public();
        assert_eq!(a, b);
        assert_ne!(a.as_bytes(), node.public().as_bytes());
    }

    #[test]
    fn node_box_round_trips() {
        let a = NodePrivate::generate();
        let b = NodePrivate::generate();
        let sealed = a.seal_to(&b.public(), b"hello");
        assert_eq!(sealed.len(), NONCE_LEN + 16 + 5);
        assert_eq!(b.open_from(&a.public(), &sealed).unwrap(), b"hello");
        assert!(
            NodePrivate::generate()
                .open_from(&a.public(), &sealed)
                .is_none()
        );
    }

    #[test]
    fn disco_box_round_trips() {
        let a = NodePrivate::generate().disco();
        let b = NodePrivate::generate().disco();
        let sealed = a.shared(&b.public()).seal(b"ping");
        assert_eq!(b.shared(&a.public()).open(&sealed).unwrap(), b"ping");
    }

    #[test]
    fn text_forms_round_trip() {
        let k = NodePrivate::generate();
        assert_eq!(k.to_string().parse::<NodePrivate>().unwrap(), k);
        let p = k.public();
        assert!(p.to_string().starts_with("nodekey:"));
        assert_eq!(p.to_string().parse::<NodePublic>().unwrap(), p);
        assert!("nodekey:zz".parse::<NodePublic>().is_err());
        let psk = PresharedKey::generate();
        assert_eq!(psk.to_string().parse::<PresharedKey>().unwrap(), psk);
    }

    #[test]
    fn addr_uses_ula_prefix_and_key_bytes() {
        let mut raw = [0u8; 32];
        raw[..10].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let addr = NodePublic::from_raw(raw).addr();
        assert_eq!(addr.to_string(), "fd7a:115c:a1e0:102:304:506:708:90a");
    }
}
