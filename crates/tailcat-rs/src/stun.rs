//! Just enough STUN (RFC 5389) to learn our own UDP endpoint from a DERP
//! node.
//!
//! Tailscale's STUN servers insist on the `tailnode` software attribute and
//! a trailing fingerprint, so requests carry both.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand::RngCore;
use rand::rngs::OsRng;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;

const SOFTWARE: &[u8] = b"tailnode";
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const HEADER_LEN: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TxId(pub [u8; 12]);

impl TxId {
    pub fn random() -> Self {
        let mut b = [0u8; 12];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }
}

fn fingerprint(b: &[u8]) -> u32 {
    crc32fast::hash(b) ^ 0x5354554e
}

pub fn request(tx: TxId) -> Vec<u8> {
    let attrs_len = 4 + SOFTWARE.len() + 8;
    let mut b = Vec::with_capacity(HEADER_LEN + attrs_len);
    b.extend_from_slice(&[0x00, 0x01]);
    b.extend_from_slice(&(attrs_len as u16).to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(&tx.0);
    b.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    b.extend_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    b.extend_from_slice(SOFTWARE);
    let fp = fingerprint(&b);
    b.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&fp.to_be_bytes());
    b
}

pub fn is_stun(b: &[u8]) -> bool {
    b.len() >= HEADER_LEN && b[0] & 0b1100_0000 == 0 && b[4..8] == MAGIC_COOKIE
}

fn for_each_attr(mut b: &[u8], mut f: impl FnMut(u16, &[u8])) -> Option<()> {
    while !b.is_empty() {
        if b.len() < 4 {
            return None;
        }
        let typ = u16::from_be_bytes([b[0], b[1]]);
        let len = u16::from_be_bytes([b[2], b[3]]) as usize;
        let padded = (len + 3) & !3;
        b = &b[4..];
        if padded > b.len() {
            return None;
        }
        f(typ, &b[..len]);
        b = &b[padded..];
    }
    Some(())
}

fn addr_from(fam: u8, port: u16, raw: &[u8]) -> Option<SocketAddr> {
    let ip = match fam {
        0x01 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(raw.get(..4)?).ok()?)),
        0x02 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw.get(..16)?).ok()?)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn xor_mapped(tx: &TxId, attr: &[u8]) -> Option<SocketAddr> {
    if attr.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([attr[2], attr[3]]) ^ 0x2112;
    let key: Vec<u8> = MAGIC_COOKIE.iter().chain(tx.0.iter()).copied().collect();
    let raw: Vec<u8> = attr[4..]
        .iter()
        .zip(key.iter())
        .map(|(a, k)| a ^ k)
        .collect();
    addr_from(attr[1], port, &raw)
}

fn mapped(attr: &[u8]) -> Option<SocketAddr> {
    if attr.len() < 4 {
        return None;
    }
    addr_from(attr[1], u16::from_be_bytes([attr[2], attr[3]]), &attr[4..])
}

/// Parses a binding success response into its transaction ID and the
/// mapped address the server saw.
pub fn parse_response(b: &[u8]) -> Option<(TxId, SocketAddr)> {
    if !is_stun(b) || b[0] != 0x01 || b[1] != 0x01 {
        return None;
    }
    let tx = TxId(b[8..20].try_into().unwrap());
    let attrs_len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let attrs = b[HEADER_LEN..].get(..attrs_len)?;
    let mut xor = None;
    let mut plain = None;
    for_each_attr(attrs, |typ, attr| match typ {
        ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS_ALT => xor = xor_mapped(&tx, attr),
        ATTR_MAPPED_ADDRESS => plain = mapped(attr),
        _ => {}
    })?;
    xor.or(plain).map(|addr| (tx, addr))
}

/// Parses a binding request, as sent by [`request`]. Used by the test STUN
/// server.
#[cfg(test)]
pub fn parse_request(b: &[u8]) -> Option<TxId> {
    if !is_stun(b) || b[..2] != [0x00, 0x01] {
        return None;
    }
    Some(TxId(b[8..20].try_into().unwrap()))
}

/// Encodes a binding success response reporting `addr` as the mapped
/// address, the way Tailscale's servers do.
#[cfg(test)]
pub fn response(tx: TxId, addr: SocketAddr) -> Vec<u8> {
    let (fam, ip): (u8, Vec<u8>) = match addr.ip() {
        IpAddr::V4(ip) => (1, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2, ip.octets().to_vec()),
    };
    let attrs_len = 8 + ip.len();
    let mut b = Vec::with_capacity(HEADER_LEN + attrs_len);
    b.extend_from_slice(&[0x01, 0x01]);
    b.extend_from_slice(&(attrs_len as u16).to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(&tx.0);
    b.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    b.extend_from_slice(&((4 + ip.len()) as u16).to_be_bytes());
    b.push(0);
    b.push(fam);
    b.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
    let key: Vec<u8> = MAGIC_COOKIE.iter().chain(tx.0.iter()).copied().collect();
    b.extend(ip.iter().zip(key.iter()).map(|(a, k)| a ^ k));
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_software_and_fingerprint() {
        let tx = TxId::random();
        let req = request(tx);
        assert_eq!(req.len(), 40);
        assert!(is_stun(&req));
        assert_eq!(parse_request(&req), Some(tx));
        assert_eq!(&req[24..32], b"tailnode");
        let fp = u32::from_be_bytes(req[36..40].try_into().unwrap());
        assert_eq!(fp, fingerprint(&req[..32]));
    }

    #[test]
    fn response_round_trips() {
        for addr in ["203.0.113.7:41641", "[2001:db8::1]:5000"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let tx = TxId::random();
            let (got_tx, got_addr) = parse_response(&response(tx, addr)).unwrap();
            assert_eq!(got_tx, tx);
            assert_eq!(got_addr, addr);
        }
    }

    #[test]
    fn rejects_non_responses() {
        assert!(parse_response(&request(TxId::random())).is_none());
        assert!(parse_response(b"meow").is_none());
    }
}
