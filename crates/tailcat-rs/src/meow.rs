//! The meow handshake: how a client registers with a server over DERP.
//!
//! Meow messages are raw DERP packets, not disco-framed. A 4-byte magic
//! prefix distinguishes them from WireGuard messages (which start with a
//! type byte of 1 to 4) and from disco's `TS💬`, since all three share the
//! relay path. A ping carries the client's node and disco public keys; the
//! server answers with a bare "meowed" once the client is configured as a
//! WireGuard peer, which is the client's cue to start dialing.

use crate::key::{DiscoPublic, KEY_LEN, NodePublic};

const MAGIC: &[u8; 4] = b"meow";
const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;

pub fn is_meow(pkt: &[u8]) -> bool {
    pkt.len() >= 4 && &pkt[..4] == MAGIC
}

pub fn is_meowed(pkt: &[u8]) -> bool {
    pkt.len() >= 5 && &pkt[..4] == MAGIC && pkt[4] == TYPE_PONG
}

pub fn encode_ping(node: &NodePublic, disco: &DiscoPublic) -> Vec<u8> {
    let mut b = Vec::with_capacity(5 + 2 * KEY_LEN);
    b.extend_from_slice(MAGIC);
    b.push(TYPE_PING);
    b.extend_from_slice(node.as_bytes());
    b.extend_from_slice(disco.as_bytes());
    b
}

pub fn encode_meowed() -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    b.push(TYPE_PONG);
    b
}

/// Parses a meow ping into the sender's node and disco keys. The keys are
/// read from fixed offsets; trailing bytes are ignored. A zero disco key is
/// rejected, since nothing could ever be sealed to it.
pub fn parse_ping(pkt: &[u8]) -> Option<(NodePublic, DiscoPublic)> {
    if !is_meow(pkt) || pkt.len() < 5 + 2 * KEY_LEN || pkt[4] != TYPE_PING {
        return None;
    }
    let node = NodePublic::from_slice(&pkt[5..5 + KEY_LEN])?;
    let disco = DiscoPublic::from_slice(&pkt[5 + KEY_LEN..5 + 2 * KEY_LEN])?;
    if disco.is_zero() {
        return None;
    }
    Some((node, disco))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::NodePrivate;

    fn keys() -> (NodePublic, DiscoPublic) {
        let k = NodePrivate::generate();
        (k.public(), NodePrivate::generate().disco().public())
    }

    #[test]
    fn ping_round_trips() {
        let (node, disco) = keys();
        let pkt = encode_ping(&node, &disco);
        assert!(is_meow(&pkt));
        assert!(!is_meowed(&pkt));
        assert_eq!(parse_ping(&pkt), Some((node, disco)));
        let mut trailing = pkt.clone();
        trailing.extend_from_slice(b"xyz");
        assert_eq!(parse_ping(&trailing), Some((node, disco)));
    }

    #[test]
    fn meowed_round_trips() {
        let pkt = encode_meowed();
        assert!(is_meow(&pkt));
        assert!(is_meowed(&pkt));
        assert!(parse_ping(&pkt).is_none());
        assert!(!is_meowed(b"meow\x01"));
        assert!(!is_meowed(b"meow\x03"));
        assert!(!is_meowed(b"woem\x02"));
    }

    #[test]
    fn is_meow_classifies() {
        assert!(!is_meow(b""));
        assert!(!is_meow(b"meo"));
        assert!(is_meow(b"meow"));
        assert!(!is_meow(b"woem\x01"));
        assert!(!is_meow(&[1, 0, 0, 0]));
        assert!(!is_meow(b"TS\xf0\x9f\x92\xac"));
    }

    #[test]
    fn malformed_pings_are_rejected() {
        let (node, disco) = keys();
        let full = encode_ping(&node, &disco);
        for n in 0..full.len() {
            assert!(parse_ping(&full[..n]).is_none(), "accepted {n}-byte prefix");
        }
        let mut unknown = full.clone();
        unknown[4] = 0x7f;
        assert!(parse_ping(&unknown).is_none());
        let zero_disco = encode_ping(&node, &DiscoPublic::from_raw([0; 32]));
        assert_eq!(zero_disco.len(), 69);
        assert!(parse_ping(&zero_disco).is_none());
    }
}
