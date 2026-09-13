//! Tailcat addresses: how a server tells clients where to find it.
//!
//! An [`Addr`] is `"tc"` followed by the URL-safe base64 of a CBOR map. The
//! map uses single-character keys so an address stays short even with a
//! DERP region embedded. Those keys are the wire format shared with the
//! stock client and must never change or be reused:
//!
//! | key | field |
//! |-----|-------|
//! | `p` | server node public key |
//! | `k` | server disco public key |
//! | `q` | WireGuard pre-shared key |
//! | `r` | embedded DERP regions |
//! | `i` | DERP region ID |
//! | `c`, `m`, `N` | region code, name, nodes |
//! | `n`, `h`, `t`, `4`, `6`, `s`, `d`, `x` | node name, host name, cert name, IPv4, IPv6, STUN port, DERP port, insecure-for-tests |
//!
//! Region and node IDs, region codes, and node names that a parser can
//! reconstruct are dropped before encoding and restored by [`Addr::parse`].

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value;

use crate::derpmap::{DerpNode, DerpRegion, ExpandOptions};
use crate::error::{Error, Result};
use crate::key::{DiscoPublic, KEY_LEN, NodePublic, PresharedKey};

const PREFIX: &str = "tc";

/// A compact, URL-safe tailcat address.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Addr(String);

impl Addr {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the address, restoring the implicit fields the encoder
    /// stripped.
    pub fn parse(&self) -> Result<ConnInfo> {
        let rest = self
            .0
            .strip_prefix(PREFIX)
            .ok_or_else(|| Error::Addr("tailcat address doesn't start with \"tc\"".into()))?;
        let raw = URL_SAFE_NO_PAD
            .decode(rest)
            .map_err(|err| Error::Addr(format!("base64 decode: {err}")))?;
        let value: Value = ciborium::de::from_reader(raw.as_slice())
            .map_err(|err| Error::Addr(format!("CBOR unmarshal: {err}")))?;
        let mut ci = decode_conn_info(&value)?;

        for (i, r) in ci.region.iter_mut().enumerate() {
            if r.region_id == 0 {
                r.region_id = i as i64 + 1;
            }
            if r.region_code.is_empty() {
                r.region_code = r.region_id.to_string();
            }
            for n in &mut r.nodes {
                if n.name.is_empty() {
                    n.name = n.host_name.clone();
                }
                if n.region_id == 0 {
                    n.region_id = r.region_id;
                }
            }
        }
        Ok(ci)
    }

    /// A self-contained equivalent with the relay's details embedded, so
    /// that using it later needs no DERP map fetch. An address that already
    /// embeds a region is returned unchanged; otherwise the region is looked
    /// up and trimmed to two nodes to keep the address short.
    pub async fn resolve(&self, opts: &ExpandOptions) -> Result<Addr> {
        let mut ci = self.parse()?;
        if !ci.region.is_empty() {
            return Ok(self.clone());
        }
        ci.expand(opts).await?;
        for r in &mut ci.region {
            r.nodes.truncate(2);
        }
        ci.region_id = 0;
        Ok(ci.addr())
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Addr({})", self.0)
    }
}

impl From<Addr> for String {
    fn from(a: Addr) -> String {
        a.0
    }
}

/// How to reach a server: its keys and the relay to bootstrap through.
///
/// Either `region` or `region_id` is set. An embedded region spares the
/// client a DERP map fetch at the cost of a longer address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnInfo {
    pub server_public: NodePublic,
    pub server_disco_public: Option<DiscoPublic>,
    pub preshared_key: Option<PresharedKey>,
    pub region: Vec<DerpRegion>,
    /// A region of the DERP map, or `-1` to pick the nearest at startup.
    pub region_id: i64,
}

impl Default for NodePublic {
    fn default() -> Self {
        Self::from_raw([0; KEY_LEN])
    }
}

impl ConnInfo {
    /// Encodes into an [`Addr`].
    pub fn addr(&self) -> Addr {
        let mut m = Vec::new();
        entry(
            &mut m,
            "p",
            Value::Bytes(self.server_public.as_bytes().to_vec()),
        );
        if let Some(k) = &self.server_disco_public {
            entry(&mut m, "k", Value::Bytes(k.as_bytes().to_vec()));
        }
        if let Some(q) = &self.preshared_key {
            entry(&mut m, "q", Value::Bytes(q.as_bytes().to_vec()));
        }
        if !self.region.is_empty() {
            entry(
                &mut m,
                "r",
                Value::Array(self.region.iter().map(encode_region).collect()),
            );
        }
        if self.region_id != 0 {
            entry(&mut m, "i", Value::Integer(self.region_id.into()));
        }
        let mut raw = Vec::with_capacity(128);
        ciborium::ser::into_writer(&Value::Map(m), &mut raw).expect("in-memory write");
        Addr(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)))
    }
}

fn entry(m: &mut Vec<(Value, Value)>, key: &str, v: Value) {
    m.push((Value::Text(key.into()), v));
}

fn text_entry(m: &mut Vec<(Value, Value)>, key: &str, s: &str) {
    if !s.is_empty() {
        entry(m, key, Value::Text(s.into()));
    }
}

fn int_entry(m: &mut Vec<(Value, Value)>, key: &str, v: i64) {
    if v != 0 {
        entry(m, key, Value::Integer(v.into()));
    }
}

// The region's own ID, code and name are dropped; a client only needs the
// nodes, and the parser synthesises IDs and codes. STUN-only nodes go too,
// since an embedded region exists only to relay.
fn encode_region(r: &DerpRegion) -> Value {
    let mut m = Vec::new();
    let nodes: Vec<Value> = r
        .nodes
        .iter()
        .filter(|n| !n.stun_only)
        .map(encode_node)
        .collect();
    if !nodes.is_empty() {
        entry(&mut m, "N", Value::Array(nodes));
    }
    Value::Map(m)
}

fn encode_node(n: &DerpNode) -> Value {
    let mut m = Vec::new();
    if n.host_name.is_empty() {
        text_entry(&mut m, "n", &n.name);
    }
    text_entry(&mut m, "h", &n.host_name);
    text_entry(&mut m, "t", &n.cert_name);
    text_entry(&mut m, "4", &n.ipv4);
    text_entry(&mut m, "6", &n.ipv6);
    int_entry(&mut m, "s", n.stun_port.into());
    int_entry(&mut m, "d", n.derp_port.into());
    if n.insecure_for_tests {
        entry(&mut m, "x", Value::Bool(true));
    }
    Value::Map(m)
}

fn as_map<'a>(v: &'a Value, what: &str) -> Result<&'a [(Value, Value)]> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(Error::Addr(format!("{what} is not a map"))),
    }
}

fn as_key32(v: &Value, what: &str) -> Result<Option<[u8; KEY_LEN]>> {
    match v {
        Value::Null => Ok(None),
        Value::Bytes(b) => {
            b.as_slice().try_into().map(Some).map_err(|_| {
                Error::Addr(format!("invalid {what} length {}, want {KEY_LEN}", b.len()))
            })
        }
        _ => Err(Error::Addr(format!("{what} is not a byte string"))),
    }
}

fn as_i64(v: &Value, what: &str) -> Result<i64> {
    match v {
        Value::Integer(i) => {
            i64::try_from(*i).map_err(|_| Error::Addr(format!("{what} out of range")))
        }
        _ => Err(Error::Addr(format!("{what} is not an integer"))),
    }
}

fn as_text(v: &Value, what: &str) -> Result<String> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(Error::Addr(format!("{what} is not a string"))),
    }
}

fn as_bool(v: &Value, what: &str) -> Result<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(Error::Addr(format!("{what} is not a boolean"))),
    }
}

fn decode_conn_info(v: &Value) -> Result<ConnInfo> {
    let mut ci = ConnInfo::default();
    for (k, v) in as_map(v, "address")? {
        let Value::Text(k) = k else { continue };
        match k.as_str() {
            "p" => {
                if let Some(raw) = as_key32(v, "node public key")? {
                    ci.server_public = NodePublic::from_raw(raw);
                }
            }
            "k" => {
                ci.server_disco_public = as_key32(v, "disco public key")?.map(DiscoPublic::from_raw)
            }
            "q" => {
                ci.preshared_key =
                    as_key32(v, "WireGuard pre-shared key")?.map(PresharedKey::from_raw)
            }
            "i" => ci.region_id = as_i64(v, "region ID")?,
            "r" => {
                let Value::Array(regions) = v else {
                    return Err(Error::Addr("regions is not an array".into()));
                };
                for (i, r) in regions.iter().enumerate() {
                    if matches!(r, Value::Null) {
                        return Err(Error::Addr(format!("region {i} is null")));
                    }
                    ci.region.push(decode_region(r, i)?);
                }
            }
            _ => {}
        }
    }
    Ok(ci)
}

fn decode_region(v: &Value, index: usize) -> Result<DerpRegion> {
    let mut r = DerpRegion::default();
    for (k, v) in as_map(v, "region")? {
        let Value::Text(k) = k else { continue };
        match k.as_str() {
            "i" => r.region_id = as_i64(v, "region ID")?,
            "c" => r.region_code = as_text(v, "region code")?,
            "m" => r.region_name = as_text(v, "region name")?,
            "N" => {
                let Value::Array(nodes) = v else {
                    return Err(Error::Addr("nodes is not an array".into()));
                };
                for (j, n) in nodes.iter().enumerate() {
                    if matches!(n, Value::Null) {
                        return Err(Error::Addr(format!("region {index} node {j} is null")));
                    }
                    r.nodes.push(decode_node(n)?);
                }
            }
            _ => {}
        }
    }
    Ok(r)
}

fn decode_node(v: &Value) -> Result<DerpNode> {
    let mut n = DerpNode::default();
    for (k, v) in as_map(v, "node")? {
        let Value::Text(k) = k else { continue };
        match k.as_str() {
            "n" => n.name = as_text(v, "node name")?,
            "i" => n.region_id = as_i64(v, "node region ID")?,
            "h" => n.host_name = as_text(v, "host name")?,
            "t" => n.cert_name = as_text(v, "cert name")?,
            "4" => n.ipv4 = as_text(v, "IPv4")?,
            "6" => n.ipv6 = as_text(v, "IPv6")?,
            "s" => n.stun_port = as_i64(v, "STUN port")? as i32,
            "d" => n.derp_port = as_i64(v, "DERP port")? as i32,
            "x" => n.insecure_for_tests = as_bool(v, "insecure-for-tests")?,
            _ => {}
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::NodePrivate;

    fn key() -> NodePublic {
        let mut raw = [0u8; 32];
        raw[0] = 0xa1;
        raw[7] = 0x5c;
        raw[31] = 0xe0;
        NodePublic::from_raw(raw)
    }

    fn node(name: &str, host: &str, ipv4: &str) -> DerpNode {
        DerpNode {
            name: name.into(),
            host_name: host.into(),
            ipv4: ipv4.into(),
            ..Default::default()
        }
    }

    #[test]
    fn key_only_address() {
        let ci = ConnInfo {
            server_public: key(),
            ..Default::default()
        };
        let addr = ci.addr();
        assert_eq!(
            addr.as_str(),
            "tcoWFwWCChAAAAAAAAXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4A"
        );
        assert_eq!(addr.parse().unwrap(), ci);
    }

    #[test]
    fn region_id_only_address() {
        let ci = ConnInfo {
            server_public: key(),
            region_id: 10,
            ..Default::default()
        };
        let addr = ci.addr();
        assert_eq!(
            addr.as_str(),
            "tcomFwWCChAAAAAAAAXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4GFpCg"
        );
        assert_eq!(addr.parse().unwrap(), ci);
    }

    #[test]
    fn an_embedded_region_gets_its_ids_and_names_back() {
        let ci = ConnInfo {
            server_public: key(),
            region: vec![DerpRegion {
                nodes: vec![
                    node("a", "relay-a.example.net", "198.51.100.4"),
                    node("b", "relay-b.example.net", "198.51.100.5"),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let back = ci.addr().parse().unwrap();
        let r = &back.region[0];
        assert_eq!(r.region_id, 1);
        assert_eq!(r.region_code, "1");
        assert_eq!(r.nodes.len(), 2);
        assert_eq!(r.nodes[0].name, "relay-a.example.net");
        assert_eq!(r.nodes[0].region_id, 1);
        assert_eq!(r.nodes[1].host_name, "relay-b.example.net");
        assert_eq!(r.nodes[1].ipv4, "198.51.100.5");
    }

    #[test]
    fn redundant_fields_are_dropped_and_rebuilt() {
        let mut region = DerpRegion {
            region_id: 123,
            region_name: "Kuala Lumpur".into(),
            nodes: vec![
                node("a", "relay-a.example.net", ""),
                node("b", "relay-b.example.net", ""),
            ],
            ..Default::default()
        };
        for n in &mut region.nodes {
            n.region_id = 123;
        }
        let ci = ConnInfo {
            server_public: key(),
            region: vec![region],
            ..Default::default()
        };
        let back = ci.addr().parse().unwrap();
        let r = &back.region[0];
        assert_eq!(r.region_id, 1);
        assert_eq!(r.region_code, "1");
        assert_eq!(r.region_name, "");
        assert_eq!(r.nodes[0].name, "relay-a.example.net");
        assert_eq!(r.nodes[1].name, "relay-b.example.net");
        assert_eq!(r.nodes[1].region_id, 1);
    }

    #[test]
    fn stun_only_nodes_are_dropped_and_others_kept() {
        let ci = ConnInfo {
            server_public: key(),
            region: vec![DerpRegion {
                nodes: vec![
                    DerpNode {
                        name: "a".into(),
                        host_name: "relay-a.example.net".into(),
                        cert_name: "cert.example.net".into(),
                        ipv4: "198.51.100.4".into(),
                        ipv6: "2001:db8::4".into(),
                        stun_port: 3478,
                        derp_port: 8443,
                        can_port80: true,
                        ..Default::default()
                    },
                    DerpNode {
                        name: "s".into(),
                        host_name: "stun-only.example.net".into(),
                        stun_only: true,
                        ..Default::default()
                    },
                    DerpNode {
                        name: "c".into(),
                        host_name: "relay-c.example.net".into(),
                        ipv6: "none".into(),
                        stun_port: -1,
                        insecure_for_tests: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let back = ci.addr().parse().unwrap();
        let nodes = &back.region[0].nodes;
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].cert_name, "cert.example.net");
        assert_eq!(nodes[0].stun_port, 3478);
        assert_eq!(nodes[0].derp_port, 8443);
        assert!(
            !nodes[0].can_port80,
            "CanPort80 is not part of the wire format"
        );
        assert_eq!(nodes[1].ipv6, "none");
        assert_eq!(nodes[1].stun_port, -1);
        assert!(nodes[1].insecure_for_tests);
    }

    #[test]
    fn disco_and_preshared_keys_round_trip() {
        let priv_key = NodePrivate::generate();
        let psk = PresharedKey::generate();
        let ci = ConnInfo {
            server_public: priv_key.public(),
            server_disco_public: Some(priv_key.disco().public()),
            preshared_key: Some(psk),
            region_id: 10,
            ..Default::default()
        };
        let back = ci.addr().parse().unwrap();
        assert_eq!(back, ci);
        let without = ConnInfo {
            preshared_key: None,
            ..ci.clone()
        };
        assert!(without.addr().as_str().len() < ci.addr().as_str().len());
    }

    #[test]
    fn readme_examples() {
        let short = Addr::new("tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu");
        let ci = short.parse().unwrap();
        assert_eq!(
            ci.server_public.to_string(),
            "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34"
        );
        assert_eq!(ci.region_id, 302);
        assert_eq!(ci.addr(), short);

        let resolved = Addr::new(
            "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFygaFhToGjYWhudGMzMDJhLmlwbi5kZXZhNG0yMDguMTExLjM5LjM4YTZzMjYwNzpmNzQwOjA6M2Y6OjcyMA",
        );
        let ci = resolved.parse().unwrap();
        assert_eq!(ci.region_id, 0);
        let n = &ci.region[0].nodes[0];
        assert_eq!(n.host_name, "tc302a.ipn.dev");
        assert_eq!(n.name, "tc302a.ipn.dev");
        assert_eq!(n.ipv4, "208.111.39.38");
        assert_eq!(n.ipv6, "2607:f740:0:3f::720");
        assert_eq!(ci.addr(), resolved);
    }

    fn encode(v: &Value) -> Addr {
        let mut raw = Vec::new();
        ciborium::ser::into_writer(v, &mut raw).unwrap();
        Addr(format!("tc{}", URL_SAFE_NO_PAD.encode(raw)))
    }

    #[test]
    fn malformed_addresses_are_rejected() {
        assert!(Addr::new("xx").parse().is_err());
        assert!(Addr::new("tc!!").parse().is_err());
        assert!(Addr::new("tcAA").parse().is_err());

        let short_key = encode(&Value::Map(vec![(
            Value::Text("p".into()),
            Value::Bytes(vec![1; 31]),
        )]));
        assert!(short_key.parse().is_err());

        let short_disco = encode(&Value::Map(vec![
            (Value::Text("p".into()), Value::Bytes(vec![1; 32])),
            (Value::Text("k".into()), Value::Bytes(vec![1; 3])),
        ]));
        assert!(short_disco.parse().is_err());

        let short_psk = encode(&Value::Map(vec![
            (Value::Text("p".into()), Value::Bytes(vec![1; 32])),
            (Value::Text("q".into()), Value::Bytes(vec![1; 33])),
        ]));
        assert!(short_psk.parse().is_err());
    }

    #[test]
    fn nulls_in_arrays_are_rejected() {
        let null_region = encode(&Value::Map(vec![
            (Value::Text("p".into()), Value::Bytes(vec![1; 32])),
            (Value::Text("r".into()), Value::Array(vec![Value::Null])),
        ]));
        let err = null_region.parse().unwrap_err().to_string();
        assert!(err.contains("region 0 is null"), "{err}");

        let null_node = encode(&Value::Map(vec![
            (Value::Text("p".into()), Value::Bytes(vec![1; 32])),
            (
                Value::Text("r".into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text("N".into()),
                    Value::Array(vec![Value::Map(vec![]), Value::Null]),
                )])]),
            ),
        ]));
        let err = null_node.parse().unwrap_err().to_string();
        assert!(err.contains("region 0 node 1 is null"), "{err}");

        // A null disco key or PSK is merely absent, as a nil pointer is.
        let null_keys = encode(&Value::Map(vec![
            (Value::Text("p".into()), Value::Bytes(vec![1; 32])),
            (Value::Text("k".into()), Value::Null),
            (Value::Text("q".into()), Value::Null),
        ]));
        let ci = null_keys.parse().unwrap();
        assert!(ci.server_disco_public.is_none());
        assert!(ci.preshared_key.is_none());
    }
}
