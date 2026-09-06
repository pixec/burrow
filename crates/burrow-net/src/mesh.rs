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

    // `syncconf` removes peers absent from the config, which is what makes a
    // node that left the fleet stop being routable.
    let config = render_config(identity, listen_port, peers);
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

    for peer in peers {
        add_route(&peer.subnet).await;
    }
    tracing::info!(peers = peers.len(), "mesh configured");
    Ok(())
}

fn render_config(identity: &Identity, listen_port: u16, peers: &[Peer]) -> String {
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

    fn peer(id: &str, subnet: &str) -> Peer {
        Peer {
            node_id: id.into(),
            public_key: format!("{id}-key"),
            endpoint: format!("{id}:51820"),
            subnet: subnet.into(),
        }
    }

    fn identity() -> Identity {
        Identity {
            private_key: "private".into(),
            public_key: "public".into(),
        }
    }

    #[test]
    fn config_carries_the_interface_and_every_peer() {
        let config = render_config(
            &identity(),
            51820,
            &[peer("a", "10.99.4.0/22"), peer("b", "10.99.8.0/22")],
        );
        assert!(config.contains("PrivateKey = private"));
        assert!(config.contains("ListenPort = 51820"));
        assert!(config.contains("PublicKey = a-key"));
        assert!(config.contains("PublicKey = b-key"));
    }

    #[test]
    fn allowed_ips_is_the_peers_own_range_only() {
        // AllowedIPs is the authorisation rule, not just a route: widening it
        // would let one node inject traffic claiming another's addresses.
        let config = render_config(&identity(), 51820, &[peer("a", "10.99.4.0/22")]);
        assert!(config.contains("AllowedIPs = 10.99.4.0/22"));
        assert!(!config.contains("AllowedIPs = 0.0.0.0/0"));
    }

    #[test]
    fn a_node_with_no_peers_still_produces_a_valid_interface() {
        let config = render_config(&identity(), 51820, &[]);
        assert!(config.contains("[Interface]"));
        assert!(!config.contains("[Peer]"));
    }

    #[test]
    fn peers_without_a_known_endpoint_are_still_configured() {
        // A peer behind NAT may have no reachable endpoint until it speaks
        // first; it must still be accepted when it does.
        let mut unreachable = peer("a", "10.99.4.0/22");
        unreachable.endpoint = String::new();
        let config = render_config(&identity(), 51820, &[unreachable]);
        assert!(config.contains("PublicKey = a-key"));
        assert!(!config.contains("Endpoint ="));
    }
}
