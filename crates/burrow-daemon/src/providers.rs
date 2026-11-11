//! Where public addresses come from, and the calls that move them.
//!
//! A provider is asked two things: deliver an address to this node, which a
//! move does before the sandbox restores here, and set its reverse DNS name.
//! Credentials live in a file in this node's configuration
//! (`--ip-providers-file`), never in the orchestrator's store.
//!
//! `static` needs no call: its addresses only ever reach the node they were
//! configured on. `ovh` and `hetzner` are written against those providers'
//! published APIs and tested against a fake server; neither has been run
//! against the real service. `bgp` is not built.

use std::collections::HashMap;
use std::sync::Arc;

use burrow_proto::common::v1::IpProvider;
use futures::future::BoxFuture;

pub trait Provider: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;
    /// Has the provider deliver `address` to this node.
    fn route_here<'a>(&'a self, address: &'a str) -> BoxFuture<'a, anyhow::Result<()>>;
    /// Sets the PTR record of `address` to `name`.
    fn set_rdns<'a>(&'a self, address: &'a str, name: &'a str)
    -> BoxFuture<'a, anyhow::Result<()>>;
}

/// The providers this node holds credentials for, plus `static`.
#[derive(Debug, Default)]
pub struct Providers(HashMap<IpProvider, Arc<dyn Provider>>);

/// `--ip-providers-file`, JSON.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidersFile {
    pub ovh: Option<OvhConfig>,
    pub hetzner: Option<HetznerConfig>,
}

impl Providers {
    pub fn load(path: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let file: ProvidersFile = match path {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)
                .map_err(|err| anyhow::anyhow!("{}: {err}", path.display()))?,
            None => ProvidersFile::default(),
        };
        Ok(Self::from_file(file))
    }

    pub fn from_file(file: ProvidersFile) -> Self {
        let mut out: HashMap<IpProvider, Arc<dyn Provider>> = HashMap::new();
        out.insert(IpProvider::Static, Arc::new(Static));
        out.insert(IpProvider::Bgp, Arc::new(Bgp));
        if let Some(config) = file.ovh {
            out.insert(IpProvider::Ovh, Arc::new(Ovh::new(config)));
        }
        if let Some(config) = file.hetzner {
            out.insert(IpProvider::Hetzner, Arc::new(Hetzner::new(config)));
        }
        Self(out)
    }

    pub fn get(&self, provider: IpProvider) -> Option<Arc<dyn Provider>> {
        let provider = match provider {
            IpProvider::Unspecified => IpProvider::Static,
            provider => provider,
        };
        self.0.get(&provider).cloned()
    }

    /// Those this node can call, for its registration.
    pub fn registered(&self) -> Vec<i32> {
        let mut providers: Vec<i32> = self
            .0
            .keys()
            .filter(|provider| **provider != IpProvider::Bgp)
            .map(|provider| *provider as i32)
            .collect();
        providers.sort();
        providers
    }
}

#[derive(Debug)]
struct Static;

impl Provider for Static {
    fn name(&self) -> &'static str {
        "static"
    }
    fn route_here<'a>(&'a self, _address: &'a str) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn set_rdns<'a>(
        &'a self,
        _address: &'a str,
        _name: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async {
            anyhow::bail!("a static pool has no provider to set reverse DNS through")
        })
    }
}

/// Announcing Burrow's own prefix from the node holding each address. Not
/// built: refused rather than pretended.
#[derive(Debug)]
struct Bgp;

impl Provider for Bgp {
    fn name(&self) -> &'static str {
        "bgp"
    }
    fn route_here<'a>(&'a self, _address: &'a str) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { anyhow::bail!("the bgp provider is not implemented") })
    }
    fn set_rdns<'a>(
        &'a self,
        _address: &'a str,
        _name: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { anyhow::bail!("the bgp provider is not implemented") })
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OvhConfig {
    /// e.g. `https://eu.api.ovh.com/1.0`.
    #[serde(default = "ovh_endpoint")]
    pub endpoint: String,
    pub application_key: String,
    pub application_secret: String,
    pub consumer_key: String,
    /// This node's dedicated server, as OVH names it: `ns1234567.ip-1-2-3.eu`.
    pub service_name: String,
}

fn ovh_endpoint() -> String {
    "https://eu.api.ovh.com/1.0".into()
}

/// OVH Additional IPs, moved between dedicated servers with
/// `POST /dedicated/server/{serviceName}/ipMove` and named with
/// `POST /ip/{ip}/reverse`, every call signed with the application secret
/// and consumer key.
#[derive(Debug)]
struct Ovh {
    config: OvhConfig,
    client: reqwest::Client,
}

impl Ovh {
    fn new(config: OvhConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// `$1$` and the SHA-1 of the secret, key, method, URL, body and time,
    /// joined by `+`.
    fn signature(&self, method: &str, url: &str, body: &str, timestamp: i64) -> String {
        use sha1::Digest as _;
        let joined = format!(
            "{}+{}+{method}+{url}+{body}+{timestamp}",
            self.config.application_secret, self.config.consumer_key
        );
        format!("$1${}", hex::encode(sha1::Sha1::digest(joined.as_bytes())))
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let endpoint = self.config.endpoint.trim_end_matches('/');
        let timestamp: i64 = self
            .client
            .get(format!("{endpoint}/auth/time"))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?
            .trim()
            .parse()?;
        let url = format!("{endpoint}{path}");
        let body = body.map(|value| value.to_string()).unwrap_or_default();
        let signature = self.signature(method.as_str(), &url, &body, timestamp);
        let mut request = self
            .client
            .request(method, &url)
            .header("X-Ovh-Application", &self.config.application_key)
            .header("X-Ovh-Consumer", &self.config.consumer_key)
            .header("X-Ovh-Timestamp", timestamp.to_string())
            .header("X-Ovh-Signature", signature);
        if !body.is_empty() {
            request = request
                .header("Content-Type", "application/json")
                .body(body);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "ovh {url} answered {status}: {}",
                response.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

/// An address as OVH's `/ip/{ip}` paths take it: a block, slash encoded.
fn ovh_block(address: &str) -> String {
    let prefix = if address.contains(':') { 128 } else { 32 };
    format!("{address}%2F{prefix}")
}

impl Provider for Ovh {
    fn name(&self) -> &'static str {
        "ovh"
    }
    fn route_here<'a>(&'a self, address: &'a str) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let path = format!("/dedicated/server/{}/ipMove", self.config.service_name);
            self.call(
                reqwest::Method::POST,
                &path,
                Some(serde_json::json!({ "ip": format!("{address}/32") })),
            )
            .await
        })
    }
    fn set_rdns<'a>(
        &'a self,
        address: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let path = format!("/ip/{}/reverse", ovh_block(address));
            let reverse = if name.ends_with('.') {
                name.to_string()
            } else {
                format!("{name}.")
            };
            self.call(
                reqwest::Method::POST,
                &path,
                Some(serde_json::json!({ "ipReverse": address, "reverse": reverse })),
            )
            .await
        })
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HetznerConfig {
    #[serde(default = "hetzner_endpoint")]
    pub endpoint: String,
    pub token: String,
    /// This node's Hetzner Cloud server id.
    pub server_id: i64,
}

fn hetzner_endpoint() -> String {
    "https://api.hetzner.cloud/v1".into()
}

/// Hetzner Cloud Floating IPs: found by address in `GET /floating_ips`,
/// assigned with `POST /floating_ips/{id}/actions/assign` and named with
/// `.../actions/change_dns_ptr`, under a bearer token.
#[derive(Debug)]
struct Hetzner {
    config: HetznerConfig,
    client: reqwest::Client,
}

impl Hetzner {
    fn new(config: HetznerConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.endpoint.trim_end_matches('/'))
    }

    async fn floating_ip_id(&self, address: &str) -> anyhow::Result<i64> {
        #[derive(serde::Deserialize)]
        struct Page {
            floating_ips: Vec<FloatingIp>,
        }
        #[derive(serde::Deserialize)]
        struct FloatingIp {
            id: i64,
            ip: String,
        }
        let wanted: std::net::IpAddr = address.parse()?;
        for page in 1..=50 {
            let found: Page = self
                .client
                .get(self.url(&format!("/floating_ips?page={page}&per_page=50")))
                .bearer_auth(&self.config.token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if found.floating_ips.is_empty() {
                break;
            }
            // A v6 Floating IP is listed as its /64.
            if let Some(ip) = found.floating_ips.iter().find(|ip| {
                let listed = ip.ip.split('/').next().unwrap_or_default();
                listed.parse::<std::net::IpAddr>().ok() == Some(wanted)
                    || (wanted.is_ipv6() && covers64(&ip.ip, wanted))
            }) {
                return Ok(ip.id);
            }
        }
        anyhow::bail!("no hetzner floating ip {address} on this project")
    }

    async fn action(&self, id: i64, action: &str, body: serde_json::Value) -> anyhow::Result<()> {
        let url = self.url(&format!("/floating_ips/{id}/actions/{action}"));
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.config.token)
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "hetzner {url} answered {status}: {}",
                response.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

fn covers64(listed: &str, address: std::net::IpAddr) -> bool {
    let (Some(network), std::net::IpAddr::V6(address)) = (listed.split('/').next(), address) else {
        return false;
    };
    let Ok(network) = network.parse::<std::net::Ipv6Addr>() else {
        return false;
    };
    u128::from(network) >> 64 == u128::from(address) >> 64
}

impl Provider for Hetzner {
    fn name(&self) -> &'static str {
        "hetzner"
    }
    fn route_here<'a>(&'a self, address: &'a str) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let id = self.floating_ip_id(address).await?;
            self.action(
                id,
                "assign",
                serde_json::json!({ "server": self.config.server_id }),
            )
            .await
        })
    }
    fn set_rdns<'a>(
        &'a self,
        address: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let id = self.floating_ip_id(address).await?;
            let dns_ptr = (!name.is_empty()).then_some(name);
            self.action(
                id,
                "change_dns_ptr",
                serde_json::json!({ "ip": address, "dns_ptr": dns_ptr }),
            )
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// What the fake server was asked: method, path, headers and body.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: String,
    }

    /// An HTTP/1.1 server answering each request with the first route whose
    /// path prefix matches, recording every request.
    async fn fake(
        routes: Vec<(&'static str, &'static str)>,
    ) -> (String, Arc<std::sync::Mutex<Vec<Seen>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen: Arc<std::sync::Mutex<Vec<Seen>>> = Arc::default();
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let routes = routes.clone();
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head, body) = loop {
                        let n = stream.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        buffer.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buffer).to_string();
                        if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                            let length = head
                                .lines()
                                .find_map(|line| {
                                    let (key, value) = line.split_once(':')?;
                                    key.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())?
                                })
                                .unwrap_or(0);
                            if rest.len() >= length {
                                break (head.to_string(), rest[..length].to_string());
                            }
                        }
                    };
                    let mut lines = head.lines();
                    let request = lines.next().unwrap_or_default().to_string();
                    let mut parts = request.split_whitespace();
                    let method = parts.next().unwrap_or_default().to_string();
                    let path = parts.next().unwrap_or_default().to_string();
                    let headers = lines
                        .filter_map(|line| line.split_once(':'))
                        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_string()))
                        .collect();
                    log.lock().unwrap().push(Seen {
                        method,
                        path: path.clone(),
                        headers,
                        body,
                    });
                    let answer = routes
                        .iter()
                        .find(|(prefix, _)| path.starts_with(prefix))
                        .map(|(_, answer)| *answer)
                        .unwrap_or("{}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://{address}"), seen)
    }

    fn ovh(endpoint: String) -> Ovh {
        Ovh::new(OvhConfig {
            endpoint,
            application_key: "ak".into(),
            application_secret: "as".into(),
            consumer_key: "ck".into(),
            service_name: "ns1.ip-1-2-3.eu".into(),
        })
    }

    #[tokio::test]
    async fn ovh_moves_an_address_to_this_server_with_a_signed_call() {
        let (endpoint, seen) = fake(vec![("/1.0/auth/time", "1700000000")]).await;
        let provider = ovh(format!("{endpoint}/1.0"));
        provider.route_here("203.0.113.17").await.unwrap();
        let seen = seen.lock().unwrap().clone();
        let call = seen.iter().find(|s| s.method == "POST").unwrap();
        assert_eq!(call.path, "/1.0/dedicated/server/ns1.ip-1-2-3.eu/ipMove");
        assert_eq!(call.body, r#"{"ip":"203.0.113.17/32"}"#);
        assert_eq!(call.headers["x-ovh-application"], "ak");
        assert_eq!(call.headers["x-ovh-consumer"], "ck");
        assert_eq!(call.headers["x-ovh-timestamp"], "1700000000");
        let url = format!("{endpoint}/1.0/dedicated/server/ns1.ip-1-2-3.eu/ipMove");
        assert_eq!(
            call.headers["x-ovh-signature"],
            provider.signature("POST", &url, &call.body, 1700000000)
        );
    }

    #[test]
    fn the_ovh_signature_is_sha1_over_the_joined_fields() {
        let provider = ovh("https://eu.api.ovh.com/1.0".into());
        use sha1::Digest as _;
        let expected = format!(
            "$1${}",
            hex::encode(sha1::Sha1::digest(
                b"as+ck+GET+https://eu.api.ovh.com/1.0/me++1366560945"
            ))
        );
        assert_eq!(
            provider.signature("GET", "https://eu.api.ovh.com/1.0/me", "", 1366560945),
            expected
        );
    }

    #[tokio::test]
    async fn ovh_sets_reverse_dns_on_the_block() {
        let (endpoint, seen) = fake(vec![("/auth/time", "1700000000")]).await;
        ovh(endpoint)
            .set_rdns("203.0.113.17", "mail.example.com")
            .await
            .unwrap();
        let seen = seen.lock().unwrap().clone();
        let call = seen.iter().find(|s| s.method == "POST").unwrap();
        assert_eq!(call.path, "/ip/203.0.113.17%2F32/reverse");
        let body: serde_json::Value = serde_json::from_str(&call.body).unwrap();
        assert_eq!(body["ipReverse"], "203.0.113.17");
        assert_eq!(body["reverse"], "mail.example.com.");
    }

    fn hetzner(endpoint: String) -> Hetzner {
        Hetzner::new(HetznerConfig {
            endpoint,
            token: "tok".into(),
            server_id: 42,
        })
    }

    const FLOATING: &str =
        r#"{"floating_ips":[{"id":7,"ip":"198.51.100.4"},{"id":9,"ip":"2001:db8:5::/64"}]}"#;

    #[tokio::test]
    async fn hetzner_assigns_the_floating_ip_found_by_address() {
        let (endpoint, seen) = fake(vec![
            ("/floating_ips?page=1", FLOATING),
            ("/floating_ips?page=", r#"{"floating_ips":[]}"#),
        ])
        .await;
        hetzner(endpoint).route_here("198.51.100.4").await.unwrap();
        let seen = seen.lock().unwrap().clone();
        let call = seen.iter().find(|s| s.method == "POST").unwrap();
        assert_eq!(call.path, "/floating_ips/7/actions/assign");
        assert_eq!(call.body, r#"{"server":42}"#);
        assert_eq!(call.headers["authorization"], "Bearer tok");
    }

    #[tokio::test]
    async fn hetzner_names_an_address_inside_a_v6_floating_ip() {
        let (endpoint, seen) = fake(vec![("/floating_ips?page=1", FLOATING)]).await;
        hetzner(endpoint)
            .set_rdns("2001:db8:5::1", "host.example.com")
            .await
            .unwrap();
        let seen = seen.lock().unwrap().clone();
        let call = seen.iter().find(|s| s.method == "POST").unwrap();
        assert_eq!(call.path, "/floating_ips/9/actions/change_dns_ptr");
        let body: serde_json::Value = serde_json::from_str(&call.body).unwrap();
        assert_eq!(body["ip"], "2001:db8:5::1");
        assert_eq!(body["dns_ptr"], "host.example.com");
    }

    #[tokio::test]
    async fn an_address_hetzner_does_not_list_is_an_error() {
        let (endpoint, _) = fake(vec![
            ("/floating_ips?page=1", FLOATING),
            ("/floating_ips?page=", r#"{"floating_ips":[]}"#),
        ])
        .await;
        assert!(hetzner(endpoint).route_here("192.0.2.1").await.is_err());
    }

    #[tokio::test]
    async fn static_routes_nothing_and_refuses_reverse_dns() {
        let providers = Providers::from_file(ProvidersFile::default());
        let provider = providers.get(IpProvider::Unspecified).unwrap();
        assert_eq!(provider.name(), "static");
        provider.route_here("203.0.113.17").await.unwrap();
        assert!(
            provider
                .set_rdns("203.0.113.17", "x.example")
                .await
                .is_err()
        );
        assert!(providers.get(IpProvider::Ovh).is_none());
        assert!(
            providers
                .get(IpProvider::Bgp)
                .unwrap()
                .route_here("x")
                .await
                .is_err()
        );
        assert_eq!(providers.registered(), vec![IpProvider::Static as i32]);
    }

    #[test]
    fn a_providers_file_is_strict_json() {
        let file: ProvidersFile =
            serde_json::from_str(r#"{"hetzner":{"token":"t","server_id":1}}"#).unwrap();
        assert_eq!(
            file.hetzner.unwrap().endpoint,
            "https://api.hetzner.cloud/v1"
        );
        assert!(serde_json::from_str::<ProvidersFile>(r#"{"aws":{}}"#).is_err());
    }
}
