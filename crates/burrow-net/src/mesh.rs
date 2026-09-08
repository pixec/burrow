//! The WireGuard mesh that carries traffic between sandboxes on different
//! nodes.
//!
//! Each node owns a disjoint slice of the sandbox address pool (see
//! [`crate::ipam`]), so a guest address identifies the node holding it. The
//! mesh gives every node a route to every other node's slice, and WireGuard's
//! `AllowedIPs` doubles as the authorisation rule: a peer may only send
//! packets sourced from the range it owns, enforced cryptographically rather
//! than by a firewall rule that could be misordered.
//!
//! That property is why mesh traffic is exempt from the anti-spoof chain,
//! which keys on tap devices a remote node does not have.

use std::path::Path;

use crate::error::{NetError, Result};

/// Mesh interface name. Distinct from the `bt*` tap prefix, so firewall rules
/// can tell local sandbox traffic from traffic that arrived over the mesh.
pub const MESH_INTERFACE: &str = "burrow-wg";
pub const DEFAULT_PORT: u16 = 51820;

/// One node's presence on the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub node_id: String,
    pub public_key: String,
    /// `host:port` the peer's WireGuard listens on.
    pub endpoint: String,
    /// The sandbox range this peer owns, as a CIDR.
    pub subnet: String,
}

/// A node's own mesh identity, persisted so it survives restarts.
///
/// A node that regenerated its key on every restart would have to be
/// redistributed to every peer before cross-node traffic worked again.
pub struct Identity {
    pub private_key: String,
    pub public_key: String,
}

impl Identity {
    /// Loads the node's key, generating one on first run.
    pub async fn load_or_create(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("wireguard.key");
        if let Ok(existing) = tokio::fs::read_to_string(&path).await {
            let private_key = existing.trim().to_string();
            if !private_key.is_empty() {
                let public_key = derive_public_key(&private_key).await?;
                return Ok(Self {
                    private_key,
                    public_key,
                });
            }
        }

        let private_key = run(&["wg", "genkey"], None).await?;
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        tokio::fs::write(&path, &private_key).await?;
        // The key is the node's identity on the mesh; nothing else on the host
        // has any business reading it.
        restrict(&path).await;

        let public_key = derive_public_key(&private_key).await?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

async fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(err) = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
    {
        tracing::warn!(path = %path.display(), %err, "could not restrict key permissions");
    }
}

async fn derive_public_key(private_key: &str) -> Result<String> {
    run(&["wg", "pubkey"], Some(private_key)).await
}

/// Brings up the mesh interface and replaces its peer set.
///
/// The whole configuration is reapplied on every change rather than diffed:
/// the peer list is small, and a full apply cannot drift from what the
/// orchestrator last said.
pub async fn configure(
    identity: &Identity,
    listen_port: u16,
    subnet: &str,
    peers: &[Peer],
) -> Result<()> {
    ensure_interface(subnet).await?;

    // Nothing unvalidated reaches the config or the routing table; see
    // [`valid_peer`].
    let peers: Vec<&Peer> = peers.iter().filter(|peer| valid_peer(peer)).collect();

    // `syncconf` removes peers absent from the config, which is what makes a
    // node that left the fleet stop being routable.
    let config = render_config(identity, listen_port, &peers);
    let synced = run(
        &["wg", "syncconf", MESH_INTERFACE, "/dev/stdin"],
        Some(&config),
    )
    .await;
    if let Err(err) = synced {
        tracing::warn!(%err, "syncconf failed; falling back to setconf");
        run(
            &["wg", "setconf", MESH_INTERFACE, "/dev/stdin"],
            Some(&config),
        )
        .await?;
    }

    for peer in &peers {
        add_route(&peer.subnet).await;
    }
    tracing::info!(peers = peers.len(), "mesh configured");
    Ok(())
}

/// Whether a peer may be written into the config and routed to.
///
/// Every field ends up either in a `wg setconf` file or in an `ip route`
/// argument, both parsed line by line, so a newline in any of them appends a
/// directive of the sender's choosing: an extra `[Peer]` with `AllowedIPs =
/// 0.0.0.0/0` is enough to make one node the default route for another's whole
/// sandbox range. The fields also have to mean what the mesh assumes, since
/// `AllowedIPs` is the authorisation rule and not just a route.
///
/// A peer failing any check is dropped rather than corrected: a malformed
/// record says nothing reliable about which node it describes.
fn valid_peer(peer: &Peer) -> bool {
    let reason = if !valid_subnet(&peer.subnet) {
        "subnet is not a CIDR inside the sandbox pool, or claims more than one node's slice"
    } else if !valid_public_key(&peer.public_key) {
        "public key is not 32 bytes of base64"
    } else if !valid_endpoint(&peer.endpoint) {
        "endpoint is not host:port"
    } else {
        return true;
    };
    tracing::warn!(
        node = %label(&peer.node_id),
        reason,
        "dropping a mesh peer the orchestrator described badly"
    );
    false
}

/// The peer's `AllowedIPs`: an IPv4 CIDR inside the sandbox pool, no shorter
/// than one node's slice.
///
/// Inside the pool because a peer owns sandbox addresses and nothing else; no
/// shorter than [`crate::ipam::NODE_PREFIX`] because no node legitimately owns
/// more than its slice, and a shorter prefix would authorise the peer to speak
/// for addresses another node hands out.
fn valid_subnet(subnet: &str) -> bool {
    let Some((address, prefix)) = subnet.split_once('/') else {
        return false;
    };
    // `str::parse` accepts a leading `+` for integers; a prefix is digits.
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    if !(crate::ipam::NODE_PREFIX..=32).contains(&prefix) {
        return false;
    }
    // Inside the pool: the peer's range must share the pool's prefix bits.
    let pool = u32::from(crate::ipam::POOL_ADDRESS);
    let mask = u32::MAX << (32 - crate::ipam::POOL_PREFIX);
    u32::from(address) & mask == pool & mask
}

/// A WireGuard public key: 32 raw bytes, which base64 spells as exactly 44
/// characters ending in one `=` of padding.
fn valid_public_key(key: &str) -> bool {
    use base64::Engine as _;
    key.len() == 44
        && base64::engine::general_purpose::STANDARD
            .decode(key)
            .is_ok_and(|bytes| bytes.len() == 32)
}

/// An empty endpoint, or `host:port` with nothing in it that a config file
/// would read as anything but one token.
///
/// Empty is legitimate: a peer behind NAT has no reachable endpoint until it
/// speaks first, and the line is then simply omitted.
fn valid_endpoint(endpoint: &str) -> bool {
    if endpoint.is_empty() {
        return true;
    }
    // Bracketed IPv6 included, so `[::1]:51820` is a usable endpoint. Nothing
    // outside this set can appear, whitespace and newlines above all.
    if !endpoint
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']'))
    {
        return false;
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    port.parse::<u16>().is_ok_and(|port| port != 0)
}

/// A node id reduced to what may safely appear in a log line.
fn label(node_id: &str) -> String {
    node_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '?'
            }
        })
        .take(64)
        .collect()
}

/// Renders the `wg` config for `peers`, which must already have passed
/// [`valid_peer`].
fn render_config(identity: &Identity, listen_port: u16, peers: &[&Peer]) -> String {
    use std::fmt::Write as _;
    let mut config = String::new();
    let _ = writeln!(config, "[Interface]");
    let _ = writeln!(config, "PrivateKey = {}", identity.private_key);
    let _ = writeln!(config, "ListenPort = {listen_port}");

    for peer in peers {
        let _ = writeln!(config, "\n[Peer]");
        let _ = writeln!(config, "PublicKey = {}", peer.public_key);
        if !peer.endpoint.is_empty() {
            let _ = writeln!(config, "Endpoint = {}", peer.endpoint);
        }
        // Both the route and the authorisation: WireGuard drops packets from
        // this peer whose source is outside its own range.
        let _ = writeln!(config, "AllowedIPs = {}", peer.subnet);
        // Nodes commonly sit behind NAT; a keepalive keeps the return path
        // open so a peer can be reached without having spoken first.
        let _ = writeln!(config, "PersistentKeepalive = 25");
    }
    config
}

async fn ensure_interface(subnet: &str) -> Result<()> {
    let exists = tokio::process::Command::new("ip")
        .args(["link", "show", MESH_INTERFACE])
        .output()
        .await
        .map(|out| out.status.success())
        .unwrap_or(false);

    if !exists {
        run(
            &["ip", "link", "add", MESH_INTERFACE, "type", "wireguard"],
            None,
        )
        .await?;
    }
    // The node's own slice, so mesh traffic has a source address to reply from.
    let _ = run(&["ip", "addr", "add", subnet, "dev", MESH_INTERFACE], None).await;
    run(&["ip", "link", "set", MESH_INTERFACE, "up"], None).await?;
    Ok(())
}

async fn add_route(subnet: &str) {
    // Already-present routes are the normal case on reconfiguration.
    let _ = tokio::process::Command::new("ip")
        .args(["route", "replace", subnet, "dev", MESH_INTERFACE])
        .output()
        .await;
}

/// Removes the mesh interface, for a node leaving or shutting down.
pub async fn teardown() {
    let _ = tokio::process::Command::new("ip")
        .args(["link", "del", MESH_INTERFACE])
        .output()
        .await;
}

async fn run(argv: &[&str], stdin: Option<&str>) -> Result<String> {
    let (program, args) = argv.split_first().expect("argv is never empty");
    let mut command = tokio::process::Command::new(program);
    command.args(args);

    let output = match stdin {
        None => command.output().await?,
        Some(input) => {
            use tokio::io::AsyncWriteExt;
            command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let mut child = command.spawn()?;
            if let Some(mut pipe) = child.stdin.take() {
                pipe.write_all(input.as_bytes()).await?;
                pipe.flush().await?;
            }
            child.wait_with_output().await?
        }
    };

    if !output.status.success() {
        return Err(NetError::Command {
            command: argv.join(" "),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real-shaped public key: 32 bytes, base64, seeded from the node id so
    /// peers in one test are distinguishable.
    fn key(id: &str) -> String {
        use base64::Engine as _;
        let mut bytes = [0u8; 32];
        for (slot, byte) in bytes.iter_mut().zip(id.bytes().cycle()) {
            *slot = byte;
        }
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn peer(id: &str, subnet: &str) -> Peer {
        Peer {
            node_id: id.into(),
            public_key: key(id),
            endpoint: format!("{id}.example:51820"),
            subnet: subnet.into(),
        }
    }

    /// Validates and renders, the way `configure` does.
    fn render(identity: &Identity, port: u16, peers: &[Peer]) -> String {
        let peers: Vec<&Peer> = peers.iter().filter(|peer| valid_peer(peer)).collect();
        render_config(identity, port, &peers)
    }

    fn identity() -> Identity {
        Identity {
            private_key: "private".into(),
            public_key: "public".into(),
        }
    }

    #[test]
    fn config_carries_the_interface_and_every_peer() {
        let config = render(
            &identity(),
            51820,
            &[peer("a", "10.99.4.0/22"), peer("b", "10.99.8.0/22")],
        );
        assert!(config.contains("PrivateKey = private"));
        assert!(config.contains("ListenPort = 51820"));
        assert!(config.contains(&format!("PublicKey = {}", key("a"))));
        assert!(config.contains(&format!("PublicKey = {}", key("b"))));
    }

    #[test]
    fn allowed_ips_is_the_peers_own_range_only() {
        // AllowedIPs is the authorisation rule, not just a route: widening it
        // would let one node inject traffic claiming another's addresses.
        let config = render(&identity(), 51820, &[peer("a", "10.99.4.0/22")]);
        assert!(config.contains("AllowedIPs = 10.99.4.0/22"));
        assert!(!config.contains("AllowedIPs = 0.0.0.0/0"));
    }

    #[test]
    fn a_node_with_no_peers_still_produces_a_valid_interface() {
        let config = render(&identity(), 51820, &[]);
        assert!(config.contains("[Interface]"));
        assert!(!config.contains("[Peer]"));
    }

    #[test]
    fn peers_without_a_known_endpoint_are_still_configured() {
        // A peer behind NAT may have no reachable endpoint until it speaks
        // first; it must still be accepted when it does.
        let mut unreachable = peer("a", "10.99.4.0/22");
        unreachable.endpoint = String::new();
        let config = render(&identity(), 51820, &[unreachable]);
        assert!(config.contains(&format!("PublicKey = {}", key("a"))));
        assert!(!config.contains("Endpoint ="));
    }

    /// A newline in a peer field appends a directive of the sender's choosing:
    /// an extra `[Peer]` claiming `0.0.0.0/0` would make this node route its
    /// whole world into someone else's tunnel.
    #[test]
    fn a_peer_carrying_config_directives_is_dropped_not_rendered() {
        let mut injected = peer("a", "10.99.4.0/22");
        injected.public_key = format!("{}\n[Peer]\nAllowedIPs = 0.0.0.0/0", key("a"));
        let config = render(&identity(), 51820, &[injected, peer("b", "10.99.8.0/22")]);

        assert!(!config.contains("0.0.0.0/0"), "{config}");
        // One bad record must not cost the rest of the fleet its peers.
        assert!(config.contains("AllowedIPs = 10.99.8.0/22"));
    }

    /// A peer claiming more than one node's slice is claiming the right to
    /// speak for sandboxes another node hands out.
    #[test]
    fn a_peer_may_only_claim_a_range_inside_the_pool() {
        for good in ["10.99.4.0/22", "10.99.8.0/24", "10.99.0.2/32"] {
            assert!(valid_subnet(good), "{good} should be accepted");
        }
        for bad in [
            // Wider than a node's slice: covers ranges other nodes own.
            "10.99.0.0/16",
            "10.99.0.0/21",
            // Outside the pool entirely.
            "0.0.0.0/0",
            "10.98.0.0/22",
            "192.168.0.0/22",
            // Not a CIDR at all.
            "10.99.4.0",
            "10.99.4.0/",
            "10.99.4.0/+22",
            "10.99.4.0/33",
            "10.99.4.0/22 extra",
            "10.99.4.0/22\nAllowedIPs = 0.0.0.0/0",
            "",
        ] {
            assert!(!valid_subnet(bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn a_public_key_must_be_thirty_two_bytes_of_base64() {
        assert!(valid_public_key(&key("a")));
        for bad in [
            "",
            "a-key",
            // 44 characters, but not base64.
            &"!".repeat(44),
            // Valid base64 of the wrong length.
            "AAAA",
            &{
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([0u8; 16])
            },
            &format!("{}\n", key("a")),
            &format!(" {}", key("a")),
        ] {
            assert!(!valid_public_key(bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn an_endpoint_must_be_host_and_port_and_nothing_else() {
        for good in ["a.example:51820", "10.0.0.1:1", "[::1]:51820", ""] {
            assert!(valid_endpoint(good), "{good:?} should be accepted");
        }
        for bad in [
            "a.example",
            "a.example:",
            ":51820",
            "a.example:0",
            "a.example:70000",
            "a.example:port",
            "a.example:51820 extra",
            "a.example:51820\nPersistentKeepalive = 0",
            "a.example:51820\t",
        ] {
            assert!(!valid_endpoint(bad), "{bad:?} should be refused");
        }
    }

    /// A peer with a bad endpoint is dropped whole rather than rendered with
    /// the line omitted: if one field is untrustworthy, so are the rest.
    #[test]
    fn one_bad_field_drops_the_whole_peer() {
        let mut bad = peer("a", "10.99.4.0/22");
        bad.endpoint = "a.example:51820 Endpoint = elsewhere:1".into();
        let config = render(&identity(), 51820, &[bad]);
        assert!(!config.contains("[Peer]"), "{config}");
        assert!(!config.contains("10.99.4.0/22"));
    }
}
