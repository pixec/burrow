//! The DERP map: which relays exist, and how a server picks one.
//!
//! The JSON types mirror Tailscale's `tailcfg.DERPMap`, so the map served
//! at [`crate::DEFAULT_DERP_MAP_URL`], or one from a
//! self-hosted `derper`, decodes as is.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::DEFAULT_DERP_MAP_URL;
use crate::addr::ConnInfo;
use crate::error::{Error, Result};
use crate::stun;

pub const DEFAULT_STUN_PORT: u16 = 3478;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const FETCH_LIMIT: usize = 8 << 20;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpNode {
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: i64,
    pub host_name: String,
    /// The expected TLS certificate name when it differs from `host_name`.
    /// Carried through the wire format for compatibility; connections
    /// verify against `host_name`.
    pub cert_name: String,
    #[serde(rename = "IPv4")]
    pub ipv4: String,
    #[serde(rename = "IPv6")]
    pub ipv6: String,
    /// The STUN port, `-1` to disable STUN for this node, `0` for the
    /// default.
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
    /// The DERP port, `0` for the default.
    #[serde(rename = "DERPPort")]
    pub derp_port: i32,
    pub insecure_for_tests: bool,
    #[serde(rename = "CanPort80")]
    pub can_port80: bool,
}

impl DerpNode {
    /// The literal addresses to dial, if the map gives any. `"none"` is how
    /// a map says a node has no address of that family.
    pub fn ip_addrs(&self) -> Vec<IpAddr> {
        [&self.ipv4, &self.ipv6]
            .into_iter()
            .filter(|s| !s.is_empty() && *s != "none")
            .filter_map(|s| s.parse().ok())
            .collect()
    }

    pub fn stun_port(&self) -> Option<u16> {
        match self.stun_port {
            -1 => None,
            0 => Some(DEFAULT_STUN_PORT),
            p => u16::try_from(p).ok(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: i64,
    pub region_code: String,
    pub region_name: String,
    pub avoid: bool,
    pub nodes: Vec<DerpNode>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpMap {
    pub regions: BTreeMap<i64, DerpRegion>,
}

/// Whose behalf a DERP map is fetched on. Sent as a hint header, which lets
/// the map server tailor the regions it returns to a server that is about
/// to listen through one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

impl Mode {
    fn header(self) -> &'static str {
        match self {
            Mode::Client => "client",
            Mode::Server => "server",
        }
    }
}

pub async fn fetch_derp_map(url: &str, mode: Mode) -> Result<DerpMap> {
    let client = reqwest::Client::builder().timeout(FETCH_TIMEOUT).build()?;
    let mut resp = client
        .get(url)
        .header("Tailcat-Mode", mode.header())
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(Error::DerpMap(format!("fetching {url}: {}", resp.status())));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > FETCH_LIMIT {
            return Err(Error::DerpMap(format!(
                "DERP map from {url} exceeds {FETCH_LIMIT} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|err| Error::DerpMap(format!("invalid DERP map JSON from {url}: {err}")))
}

async fn recv_stun(sock: Option<&UdpSocket>) -> Option<stun::TxId> {
    let sock = sock?;
    let mut buf = [0u8; 1500];
    loop {
        let n = sock.recv(&mut buf).await.ok()?;
        if let Some((tx, _)) = stun::parse_response(&buf[..n]) {
            return Some(tx);
        }
    }
}

/// Probes every region's STUN servers and returns the region that answered
/// fastest, or `None` if nothing answered within a few seconds.
pub async fn pick_best_region(map: &DerpMap) -> Option<i64> {
    let v4 = UdpSocket::bind("0.0.0.0:0").await.ok();
    let v6 = UdpSocket::bind("[::]:0").await.ok();
    let mut sent: HashMap<stun::TxId, (i64, Instant)> = HashMap::new();
    for (id, region) in &map.regions {
        for node in &region.nodes {
            let Some(port) = node.stun_port() else {
                continue;
            };
            for ip in node.ip_addrs() {
                let sock = match ip {
                    IpAddr::V4(_) => v4.as_ref(),
                    IpAddr::V6(_) => v6.as_ref(),
                };
                let Some(sock) = sock else {
                    continue;
                };
                let tx = stun::TxId::random();
                if sock
                    .send_to(&stun::request(tx), SocketAddr::new(ip, port))
                    .await
                    .is_ok()
                {
                    sent.insert(tx, (*id, Instant::now()));
                }
            }
        }
    }
    if sent.is_empty() {
        return None;
    }

    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let mut best: Option<(i64, Duration)> = None;
    let mut answered = 0;
    while answered < sent.len() {
        let tx = tokio::select! {
            Some(tx) = recv_stun(v4.as_ref()) => tx,
            Some(tx) = recv_stun(v6.as_ref()) => tx,
            _ = tokio::time::sleep_until(deadline) => break,
        };
        let Some((id, at)) = sent.remove(&tx) else {
            continue;
        };
        answered += 1;
        let latency = at.elapsed();
        if best.is_none_or(|(_, b)| latency < b) {
            best = Some((id, latency));
        }
    }
    best.map(|(id, _)| id)
}

#[derive(Clone, Debug, Default)]
pub struct ExpandOptions {
    /// An alternate map URL, for a fleet running its own relays.
    pub derp_map_url: Option<String>,
    /// A DERP map to expand from instead of fetching one.
    pub derp_map: Option<DerpMap>,
    /// Whether the fetch is on behalf of a server; see [`Mode`].
    pub for_server: bool,
}

impl ConnInfo {
    /// Populates `region` from a DERP map when only `region_id` is set.
    ///
    /// A `region_id` of `-1` asks for the lowest-latency region, measured by
    /// STUN probes, with a random region as the fallback when nothing
    /// answers. Already-expanded info is left alone.
    pub async fn expand(&mut self, opts: &ExpandOptions) -> Result<()> {
        for r in &mut self.region {
            if r.region_id == 0 {
                r.region_id = 1;
            }
            for n in &mut r.nodes {
                if n.region_id == 0 {
                    n.region_id = r.region_id;
                }
            }
        }
        if !self.region.is_empty() || self.region_id == 0 {
            return Ok(());
        }

        let url = opts
            .derp_map_url
            .clone()
            .unwrap_or_else(|| DEFAULT_DERP_MAP_URL.to_string());
        let (mut map, source) = match &opts.derp_map {
            Some(m) => (m.clone(), "provided DERP map".to_string()),
            None => {
                let mode = if opts.for_server {
                    Mode::Server
                } else {
                    Mode::Client
                };
                let map = fetch_derp_map(&url, mode).await.map_err(|err| {
                    Error::DerpMap(format!(
                        "fetching DERPMap for region {}: {err}",
                        self.region_id
                    ))
                })?;
                (map, url)
            }
        };

        if self.region_id == -1 {
            for r in map.regions.values_mut() {
                r.nodes.shuffle(&mut rand::thread_rng());
            }
            let id = match pick_best_region(&map).await {
                Some(id) => id,
                None => {
                    let ids: Vec<i64> = map.regions.keys().copied().collect();
                    *ids.choose(&mut rand::thread_rng())
                        .ok_or_else(|| Error::DerpMap("failed to auto-detect any regions".into()))?
                }
            };
            self.region_id = 0;
            self.region = vec![map.regions[&id].clone()];
            return Ok(());
        }

        let region = map.regions.get(&self.region_id).ok_or_else(|| {
            Error::DerpMap(format!(
                "tailcat address specified DERP RegionID {} but no such region exists in {source}",
                self.region_id
            ))
        })?;
        self.region.push(region.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_public_map_shape() {
        let json = r#"{"Regions":{"301":{"RegionID":301,"RegionCode":"nyc","RegionName":"New York City","Latitude":40.7,"Longitude":-74,"Nodes":[{"Name":"301a","RegionID":301,"HostName":"tc301a.ipn.dev","IPv4":"199.38.181.166","IPv6":"2607:f740:f::26b","CanPort80":true}]}}}"#;
        let map: DerpMap = serde_json::from_str(json).unwrap();
        let r = &map.regions[&301];
        assert_eq!(r.region_code, "nyc");
        let n = &r.nodes[0];
        assert_eq!(n.host_name, "tc301a.ipn.dev");
        assert!(n.can_port80);
        assert_eq!(n.stun_port(), Some(DEFAULT_STUN_PORT));
        assert_eq!(n.ip_addrs().len(), 2);
    }

    #[test]
    fn node_address_helpers() {
        let n = DerpNode {
            ipv4: "none".into(),
            ipv6: "2001:db8::1".into(),
            stun_port: -1,
            ..Default::default()
        };
        assert_eq!(n.ip_addrs(), vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
        assert_eq!(n.stun_port(), None);
    }

    #[tokio::test]
    async fn expand_from_provided_map() {
        let mut map = DerpMap::default();
        map.regions.insert(
            7,
            DerpRegion {
                region_id: 7,
                region_code: "x".into(),
                ..Default::default()
            },
        );
        let opts = ExpandOptions {
            derp_map: Some(map),
            ..Default::default()
        };
        let mut ci = ConnInfo {
            region_id: 7,
            ..Default::default()
        };
        ci.expand(&opts).await.unwrap();
        assert_eq!(ci.region[0].region_code, "x");

        let mut missing = ConnInfo {
            region_id: 8,
            ..Default::default()
        };
        assert!(missing.expand(&opts).await.is_err());
    }
}
