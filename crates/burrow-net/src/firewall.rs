//! nftables policy for sandbox traffic.
//!
//! The whole ruleset is regenerated and applied atomically on every change
//! (`nft -f -` with a leading flush), so it cannot drift from the sandbox
//! registry the way incremental edits would.
//!
//! Base chains use `policy accept` and jump sandbox traffic into burrow-owned
//! chains that end in `drop`. `policy drop` on a base hook would filter *all*
//! of the host's forwarded traffic, not just burrow's.
//!
//! Anything not selected therefore falls through to `accept`, so selection is
//! by input interface, never by source address: a guest can forge its source
//! but cannot choose which tap a packet arrives on. Every burrow tap is
//! anti-spoofed (see [`render_antispoof`]) before the address-based rules run.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::error::{NetError, Result};

/// The address range every sandbox lease comes from.
pub const SANDBOX_CIDR: &str = "10.99.0.0/16";
/// The renderer's validated form of [`SANDBOX_CIDR`]. Nothing reaches the nft
/// script that was not parsed first, a constant included, so this is built from
/// [`crate::ipam`]'s numbers rather than from the string above.
const SANDBOX_POOL: Cidr = Cidr {
    addr: crate::ipam::POOL_ADDRESS,
    prefix: crate::ipam::POOL_PREFIX,
};
/// Prefix shared by every burrow tap, used for interface wildcard matches.
pub const TAP_PREFIX: &str = "bt";

/// Link-local space, home to `169.254.169.254`: on EC2, GCP, Azure and most
/// other clouds, the instance's own credentials are an unauthenticated HTTP
/// GET away at that address. Denied to every sandbox regardless of egress
/// mode, the same way `crate::proxy`'s `is_forbidden_destination` denies it
/// on the allowlist path. Open mode has no proxy in front of it to do that,
/// so without this the metadata service is reachable from any open-mode
/// sandbox on a cloud host.
const METADATA_CIDR: Cidr = Cidr {
    addr: Ipv4Addr::new(169, 254, 0, 0),
    prefix: 16,
};

/// Mesh interface, mirrored from [`crate::mesh`] so rules can name it.
pub const MESH_INTERFACE: &str = crate::mesh::MESH_INTERFACE;

const FILTER_TABLE: &str = "burrow";
const NAT_TABLE: &str = "burrow_nat";
/// Holds nothing but per-sandbox byte counters, in a table of its own so that
/// reading usage never has to walk the policy rules.
const METER_TABLE: &str = "burrow_meter";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No traffic in or out.
    None,
    /// Egress only to the host services (proxy, DNS); everything else denied.
    Allowlist,
    /// Full NAT'd egress.
    Open,
}

#[derive(Debug, Clone)]
pub struct PortMap {
    pub host_port: u16,
    pub guest_port: u16,
}

#[derive(Debug, Clone)]
pub struct SandboxRules {
    pub sandbox_id: String,
    /// Host tap carrying this sandbox's traffic. Burrow creates it, so unlike
    /// the source address it cannot be forged from inside the guest, which is
    /// why every policy decision keys off it.
    pub tap: String,
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub mode: Mode,
    /// Extra destinations permitted at L3 regardless of mode.
    pub allow_cidrs: Vec<String>,
    /// Destinations this sandbox may never reach, whatever the mode says.
    /// Rendered before every allowance, so a denied range stays unreachable
    /// even when `allow_cidrs` or `open` would grant it.
    pub deny_cidrs: Vec<String>,
    /// Ports the CIDR allowance is limited to. Empty means every port.
    pub allow_ports: Vec<u32>,
    /// Guest addresses of peers sharing a private network with this sandbox,
    /// local and remote alike. Remote ones arrive over the mesh rather than a
    /// tap, but the policy is the same.
    pub peers: Vec<Ipv4Addr>,
    pub ports: Vec<PortMap>,
}

/// Ports on the host that sandboxes may always reach: the egress proxy and the
/// logging DNS resolver. Both are burrow's own services.
pub const PROXY_PORT: u16 = 3128;
pub const DNS_PORT: u16 = 53;

/// A validated `allow_cidrs` entry.
///
/// `nft -f -` reads a script, one command per line, so a caller's string
/// reaching it verbatim is rule injection: a newline inside a "CIDR" would
/// append rules of the attacker's choosing to burrow's own tables. Only the
/// parsed address and prefix are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    addr: Ipv4Addr,
    prefix: u8,
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Parses `a.b.c.d[/len]`, rejecting anything else.
///
/// A bare address is a /32, which is what an operator writing one means.
/// Whitespace, a second slash, `+32` and a prefix over 32 are refused rather
/// than interpreted.
fn parse_cidr(value: &str) -> Option<Cidr> {
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, len)) => {
            // `str::parse` for integers accepts a leading `+`; a prefix length
            // is digits and nothing else.
            if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let prefix: u8 = len.parse().ok()?;
            if prefix > 32 {
                return None;
            }
            (addr, prefix)
        }
        None => (value, 32),
    };
    Some(Cidr {
        addr: addr.parse::<Ipv4Addr>().ok()?,
        prefix,
    })
}

/// The validated form of a sandbox's L3 allowance, or `None` when any part of
/// it is malformed.
///
/// All-or-nothing per sandbox, failing to no allowance at all rather than to
/// the subset that happened to parse. Letting one bad record abort the render
/// would freeze the whole node's ruleset, since every sandbox is re-rendered
/// into one transactional `nft -f -` script.
fn validated_allowance(sandbox: &SandboxRules) -> Option<(Vec<Cidr>, Vec<u16>)> {
    let mut cidrs = Vec::with_capacity(sandbox.allow_cidrs.len());
    for entry in &sandbox.allow_cidrs {
        match parse_cidr(entry) {
            Some(cidr) => cidrs.push(cidr),
            None => {
                tracing::error!(
                    sandbox = sandbox.sandbox_id,
                    "rejecting a malformed allow_cidrs entry; this sandbox gets no \
                     address allowance"
                );
                return None;
            }
        }
    }

    let mut ports = Vec::with_capacity(sandbox.allow_ports.len());
    for port in &sandbox.allow_ports {
        match u16::try_from(*port) {
            Ok(port) => ports.push(port),
            Err(_) => {
                tracing::error!(
                    sandbox = sandbox.sandbox_id,
                    port,
                    "rejecting an out-of-range allow_ports entry; this sandbox gets no \
                     address allowance"
                );
                return None;
            }
        }
    }
    Some((cidrs, ports))
}

/// The validated form of a sandbox's denied ranges, or `None` when any entry
/// is malformed.
///
/// Fails the opposite way from [`validated_allowance`]: dropping an unparseable
/// denial would grant exactly the access the operator asked to withhold, so the
/// caller turns `None` into a blanket drop for the sandbox.
fn validated_denials(sandbox: &SandboxRules) -> Option<Vec<Cidr>> {
    let mut cidrs = Vec::with_capacity(sandbox.deny_cidrs.len());
    for entry in &sandbox.deny_cidrs {
        match parse_cidr(entry) {
            Some(cidr) => cidrs.push(cidr),
            None => {
                tracing::error!(
                    sandbox = sandbox.sandbox_id,
                    "rejecting a malformed deny_cidrs entry; this sandbox gets no egress \
                     at all"
                );
                return None;
            }
        }
    }
    Some(cidrs)
}

/// Renders the complete ruleset for the given sandboxes.
///
/// Equivalent to [`render_with`] with no control-plane addresses.
pub fn render(sandboxes: &[SandboxRules]) -> String {
    render_with(sandboxes, &[])
}

/// Renders the complete ruleset, with `control_plane` denied to every sandbox.
///
/// `control_plane` is this node's orchestrator and every node's edge router.
/// The orchestrator's API creates and deletes sandboxes and routes exec and
/// logs into them; an edge router proxies into any sandbox's published port,
/// addressed by sandbox id, on nothing more than the hostname. A sandbox that
/// reaches either reaches a sandbox it shares no private network with, whatever
/// the rules below say, because the packets never come near them.
///
/// Open mode is what makes them reachable at all: it has NAT'd egress to
/// anywhere the node can route.
pub fn render_with(sandboxes: &[SandboxRules], control_plane: &[Ipv4Addr]) -> String {
    let mut out = String::new();

    // Declaring before flushing makes this work on a fresh host too: `flush`
    // on a missing table is an error, `add` on an existing one is a no-op.
    let _ = writeln!(out, "add table inet {FILTER_TABLE}");
    let _ = writeln!(out, "flush table inet {FILTER_TABLE}");
    let _ = writeln!(out, "add table ip {NAT_TABLE}");
    let _ = writeln!(out, "flush table ip {NAT_TABLE}");

    render_antispoof(&mut out, sandboxes);

    // Traffic routed *through* the host: sandbox to internet, or peer to peer.
    let _ = writeln!(
        out,
        "add chain inet {FILTER_TABLE} forward {{ type filter hook forward priority 0; policy accept; }}"
    );
    let _ = writeln!(out, "add chain inet {FILTER_TABLE} sandbox");
    // Anti-spoofing runs first: after it, a packet arriving on a burrow tap is
    // guaranteed to carry that sandbox's own address, which is what makes the
    // address-based rules below trustworthy.
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} forward iifname \"{TAP_PREFIX}*\" jump antispoof"
    );
    // Selection is by interface, not by address: a guest can forge its source
    // address, but it cannot choose which tap its packets arrive on.
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} forward iifname \"{TAP_PREFIX}*\" jump sandbox"
    );
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} forward oifname \"{TAP_PREFIX}*\" jump sandbox"
    );
    // Mesh traffic is already constrained by WireGuard's AllowedIPs, which
    // drops anything sourced outside the sending node's range. That is a
    // cryptographic check the anti-spoof chain cannot improve on, so mesh
    // traffic skips it.
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} forward iifname \"{MESH_INTERFACE}\" jump sandbox"
    );
    // Ahead of everything, the established accept included, or a conntrack
    // entry would outlive the denial that replaced its policy.
    //
    // On the destination only: traffic *from* one of these addresses is how a
    // node's edge reaches a guest port.
    for address in control_plane {
        let _ = writeln!(
            out,
            "add rule inet {FILTER_TABLE} sandbox ip daddr {address} drop"
        );
    }

    // Every unconditional denial, for the same reason as the control plane
    // above: the established accept below is a hole a conntrack entry keeps
    // open, so a denial rendered after it never sees the packets of a
    // connection opened under the looser policy. Entries already in the table
    // are cleared separately; see [`flush_conntrack`].
    for sandbox in sandboxes {
        render_sandbox_denials(&mut out, sandbox);
    }

    // Return traffic for connections burrow already allowed.
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} sandbox ct state established,related accept"
    );

    for sandbox in sandboxes {
        render_sandbox_allowances(&mut out, sandbox);
    }

    // Anything in the sandbox range that no rule above accepted.
    let _ = writeln!(out, "add rule inet {FILTER_TABLE} sandbox drop");

    render_host_input(&mut out, sandboxes);
    render_nat(&mut out, sandboxes);
    render_meter(&mut out, sandboxes);
    out
}

/// Bytes each sandbox has moved in either direction, keyed by guest address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic {
    /// Delivered to the guest.
    pub rx_bytes: u64,
    /// Sent by the guest.
    pub tx_bytes: u64,
}

/// The counter names for one sandbox.
///
/// Derived from the assigned address, never from a caller's string: `nft -f -`
/// reads one command per line, and an `Ipv4Addr` can only render as four dotted
/// numbers. The address also identifies the sandbox on the wire, so mapping a
/// counter back to a sandbox is exact.
pub fn counter_names(guest_ip: Ipv4Addr) -> (String, String) {
    let key = guest_ip.octets();
    let key = format!("{}_{}_{}_{}", key[0], key[1], key[2], key[3]);
    (format!("rx_{key}"), format!("tx_{key}"))
}

/// Counts each sandbox's own traffic, in both directions.
///
/// Hooked at prerouting and postrouting rather than `forward`, because
/// allowlist-mode egress terminates at the proxy on the host and never crosses
/// the forward hook. Both see every packet on the tap whatever its destination.
///
/// Counting is by interface, like every policy decision here: a guest chooses
/// its source address and cannot choose its tap.
fn render_meter(out: &mut String, sandboxes: &[SandboxRules]) {
    let _ = writeln!(out, "add table inet {METER_TABLE}");
    let _ = writeln!(out, "flush table inet {METER_TABLE}");
    // Far ahead of the policy tables' priority 0, so a packet is counted
    // whether or not the policy goes on to drop it.
    let _ = writeln!(
        out,
        "add chain inet {METER_TABLE} rx {{ type filter hook postrouting priority -300; policy accept; }}"
    );
    let _ = writeln!(
        out,
        "add chain inet {METER_TABLE} tx {{ type filter hook prerouting priority -300; policy accept; }}"
    );
    for sandbox in sandboxes {
        let (rx, tx) = counter_names(sandbox.guest_ip);
        let _ = writeln!(out, "add counter inet {METER_TABLE} {rx}");
        let _ = writeln!(out, "add counter inet {METER_TABLE} {tx}");
        let _ = writeln!(
            out,
            "add rule inet {METER_TABLE} rx oifname \"{}\" counter name \"{rx}\"",
            sandbox.tap
        );
        let _ = writeln!(
            out,
            "add rule inet {METER_TABLE} tx iifname \"{}\" counter name \"{tx}\"",
            sandbox.tap
        );
    }
}

/// Reads the byte counters back.
///
/// Every render begins with a flush, so these are the bytes since the last
/// render, not since the sandbox was created. Accumulating them into a lasting
/// total is the caller's job, which is what lets one total span a sandbox's
/// several VMs.
pub async fn counters() -> Result<std::collections::HashMap<Ipv4Addr, Traffic>> {
    let output = tokio::process::Command::new("nft")
        .args(["list", "counters", "table", "inet", METER_TABLE])
        .output()
        .await?;
    if !output.status.success() {
        return Err(NetError::Command {
            command: "nft list counters".into(),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(parse_counters(&String::from_utf8_lossy(&output.stdout)))
}

/// Pulls `counter <name> { packets N bytes M }` out of `nft`'s listing.
///
/// Token-wise rather than line-wise: nft's layout has changed between releases
/// and the pairing of a name with the `bytes` that follows it has not. Anything
/// unrecognised is skipped, since a counter this node did not create says
/// nothing about a sandbox.
fn parse_counters(text: &str) -> std::collections::HashMap<Ipv4Addr, Traffic> {
    let mut out: std::collections::HashMap<Ipv4Addr, Traffic> = std::collections::HashMap::new();
    let mut tokens = text.split_whitespace();
    let mut current: Option<(Ipv4Addr, bool)> = None;
    while let Some(token) = tokens.next() {
        match token {
            "counter" => current = tokens.next().and_then(parse_counter_name),
            "bytes" => {
                let Some((address, is_rx)) = current.take() else {
                    continue;
                };
                let Some(bytes) = tokens.next().and_then(|value| value.parse::<u64>().ok()) else {
                    continue;
                };
                let entry = out.entry(address).or_default();
                if is_rx {
                    entry.rx_bytes = bytes;
                } else {
                    entry.tx_bytes = bytes;
                }
            }
            _ => {}
        }
    }
    out
}

/// The inverse of [`counter_names`]: the address a counter belongs to, and
/// whether it is the receive side.
fn parse_counter_name(name: &str) -> Option<(Ipv4Addr, bool)> {
    let (is_rx, rest) = match (name.strip_prefix("rx_"), name.strip_prefix("tx_")) {
        (Some(rest), _) => (true, rest),
        (_, Some(rest)) => (false, rest),
        _ => return None,
    };
    let mut octets = [0u8; 4];
    let mut parts = rest.split('_');
    for octet in &mut octets {
        *octet = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some((Ipv4Addr::from(octets), is_rx))
}

/// Drops packets arriving on a burrow tap that do not carry the address burrow
/// assigned to that tap's sandbox.
///
/// Without this every other rule here is advisory: a guest can put any source
/// address it likes on a packet, and so impersonate a peer to cross a private
/// network it does not belong to, borrow a more permissive sandbox's egress
/// policy, or fall through unmatched to the base hook's `accept`. Interface
/// identity is the only thing the guest cannot forge.
fn render_antispoof(out: &mut String, sandboxes: &[SandboxRules]) {
    let _ = writeln!(out, "add chain inet {FILTER_TABLE} antispoof");
    for sandbox in sandboxes {
        let _ = writeln!(
            out,
            "add rule inet {FILTER_TABLE} antispoof iifname \"{}\" ip saddr {} return",
            sandbox.tap, sandbox.guest_ip
        );
    }
    // Reached only by a packet on a burrow tap whose source is not that
    // sandbox's own address. Counted and logged rather than dropped in silence:
    // forging addresses is a deliberate act the operator should be able to see.
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} antispoof iifname \"{TAP_PREFIX}*\" \
         counter log prefix \"burrow-spoof \" level warn drop"
    );
}

/// Policy for traffic addressed to the host itself.
///
/// This is a separate hook from `forward`, and forgetting it is a privilege
/// escalation: the host runs burrowd's own gRPC API, and a sandbox that can
/// reach it can create, delete, and exec into its neighbours. Sandboxes get
/// nothing on the host except burrow's own proxy and resolver, and only when
/// their policy calls for them.
fn render_host_input(out: &mut String, sandboxes: &[SandboxRules]) {
    let _ = writeln!(
        out,
        "add chain inet {FILTER_TABLE} input {{ type filter hook input priority 0; policy accept; }}"
    );
    let _ = writeln!(out, "add chain inet {FILTER_TABLE} tohost");
    // By interface, and anti-spoofed first, for the same reason as `forward`:
    // an address-only match is bypassable by forging the source.
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} input iifname \"{TAP_PREFIX}*\" jump antispoof"
    );
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} input iifname \"{TAP_PREFIX}*\" jump tohost"
    );
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} tohost ct state established,related accept"
    );
    // ICMP to the gateway is how anything inside a sandbox checks whether its
    // network works at all; it carries no payload worth restricting.
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} tohost icmp type echo-request accept"
    );

    for sandbox in sandboxes {
        let (guest, host) = (sandbox.guest_ip, sandbox.host_ip);

        // The resolver is burrow's own and records every lookup, so modes with
        // *some* egress reach it. `none` does not: a name is arbitrary
        // attacker-chosen bytes leaving the sandbox, so a resolver is an exfil
        // channel like any other.
        //
        // UDP only: the resolver binds a UDP socket and nothing else, so a
        // TCP/53 accept is a hole pointed at whatever might later listen on
        // the gateway's port 53. Nothing needs the TCP fallback, because the
        // resolver never truncates (see `burrow-proxy`'s `dns` module).
        if sandbox.mode != Mode::None {
            let _ = writeln!(
                out,
                "add rule inet {FILTER_TABLE} tohost ip saddr {guest} ip daddr {host} udp dport {DNS_PORT} accept"
            );
        }

        // The proxy only serves sandboxes whose policy routes through it.
        if sandbox.mode == Mode::Allowlist {
            let _ = writeln!(
                out,
                "add rule inet {FILTER_TABLE} tohost ip saddr {guest} ip daddr {host} tcp dport {PROXY_PORT} accept"
            );
        }
    }

    let _ = writeln!(out, "add rule inet {FILTER_TABLE} tohost drop");
}

/// Matches only traffic that came from neither a sandbox tap nor the mesh,
/// that is, traffic originating outside the fleet.
fn external_only() -> String {
    format!("iifname != \"{TAP_PREFIX}*\" iifname != \"{MESH_INTERFACE}\"")
}

/// A sandbox id reduced to what may appear in the script.
///
/// Only the comment above each sandbox's rules is written from an id, and ids
/// are validated where they are chosen, but a comment is still a line of an
/// `nft -f -` script. Anything outside the id charset becomes `?`, so no record
/// can end a comment early and start a rule of its own.
fn label(sandbox_id: &str) -> String {
    sandbox_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// A sandbox's unconditional drops.
///
/// Rendered before the chain's `ct state established,related accept`, and so
/// before anything at all that accepts: nftables takes the first terminating
/// verdict, so a range named here is unreachable whatever the mode is,
/// whatever else the policy allows, and whatever conntrack remembers of a
/// connection opened under an earlier policy.
fn render_sandbox_denials(out: &mut String, sandbox: &SandboxRules) {
    let guest = sandbox.guest_ip;
    let _ = writeln!(out, "# sandbox {} denials", label(&sandbox.sandbox_id));

    // The cloud metadata address, ahead of everything else including the
    // operator's own deny_cidrs: unlike those, this is not something an
    // operator opts into, and it applies in every mode, peers included, since
    // no sandbox has a legitimate reason to have this in a private network.
    let _ = writeln!(
        out,
        "add rule inet {FILTER_TABLE} sandbox ip saddr {guest} ip daddr {METADATA_CIDR} drop"
    );

    match validated_denials(sandbox) {
        Some(denied) => {
            for cidr in &denied {
                let _ = writeln!(
                    out,
                    "add rule inet {FILTER_TABLE} sandbox ip saddr {guest} ip daddr {cidr} drop"
                );
            }
        }
        None => {
            // An unparseable denial is not ignorable: rather than render the
            // allowances it was meant to override, this sandbox gets nothing.
            let _ = writeln!(
                out,
                "add rule inet {FILTER_TABLE} sandbox ip saddr {guest} drop"
            );
        }
    }
}

/// A sandbox's accepts, and the open-mode pool drop that scopes them.
///
/// Rendered after the established accept, unlike [`render_sandbox_denials`]:
/// nothing here needs to outrank a conntrack entry, since an entry only exists
/// for a connection one of these accepts already permitted.
fn render_sandbox_allowances(out: &mut String, sandbox: &SandboxRules) {
    // A sandbox whose denials did not parse was blanket-dropped, and renders
    // no policy at all.
    if validated_denials(sandbox).is_none() {
        return;
    }

    let guest = sandbox.guest_ip;
    let external = external_only();
    let _ = writeln!(out, "# sandbox {}", label(&sandbox.sandbox_id));

    // Peers first: private-network membership is granted regardless of the
    // egress mode, since it is a separate axis of the policy.
    //
    // Both directions, because a node only renders rules for the sandboxes it
    // hosts. When a peer lives on another node the first packet of an inbound
    // connection arrives over the mesh with no conntrack entry yet, and an
    // outbound-only rule would drop it.
    for peer in &sandbox.peers {
        let _ = writeln!(
            out,
            "add rule inet {FILTER_TABLE} sandbox ip saddr {guest} ip daddr {peer} accept"
        );
        let _ = writeln!(
            out,
            "add rule inet {FILTER_TABLE} sandbox ip saddr {peer} ip daddr {guest} accept"
        );
    }

    match sandbox.mode {
        Mode::None => {}
        // Allowlist web traffic never traverses the forward hook: it is
        // redirected to the proxy, which opens its own connection outward, and
        // name resolution is answered by burrow's resolver on the host rather
        // than leaving the node. So there is nothing to allow here.
        Mode::Allowlist => {}
        Mode::Open => {
            // Open means the internet, not the fleet. Every sandbox address on
            // every node comes out of one pool, so denying the pool is what
            // stops an open sandbox reaching its neighbours here and, over the
            // mesh, on other nodes.
            //
            // Ordered after the peer accepts and before the blanket accept, or
            // private networks stop working: nftables takes the first
            // terminating verdict, so a peer is already accepted by the time
            // this is reached and everything else in the pool is not.
            //
            // The gateway is in the pool too, but that traffic is delivered
            // locally and policed by `tohost` on the input hook, which this
            // forward-path rule never sees.
            let _ = writeln!(
                out,
                "add rule inet {FILTER_TABLE} sandbox ip saddr {guest} ip daddr {SANDBOX_POOL} drop"
            );
            let _ = writeln!(
                out,
                "add rule inet {FILTER_TABLE} sandbox ip saddr {guest} accept"
            );
        }
    }

    // A CIDR allowance is a hole punched at the IP layer, bypassing the proxy.
    // Naming ports narrows it to the ones actually needed.
    //
    // Addresses and ports are rendered from parsed values, never from what the
    // caller sent, which could carry nft commands of its own.
    if let Some((cidrs, ports)) = validated_allowance(sandbox) {
        let ports = (!ports.is_empty()).then(|| {
            ports
                .iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        });
        for cidr in &cidrs {
            match &ports {
                None => {
                    let _ = writeln!(
                        out,
                        "add rule inet {FILTER_TABLE} sandbox ip saddr {guest} ip daddr {cidr} accept"
                    );
                }
                Some(list) => {
                    for protocol in ["tcp", "udp"] {
                        let _ = writeln!(
                            out,
                            "add rule inet {FILTER_TABLE} sandbox ip saddr {guest} ip daddr {cidr} {protocol} dport {{ {list} }} accept"
                        );
                    }
                }
            }
        }
    }

    // Inbound to published ports, which the NAT table has already rewritten.
    // Only for traffic that genuinely arrived from outside: matching on the
    // guest address alone would also let a neighbouring sandbox, or a mesh
    // peer, through this external door.
    for port in &sandbox.ports {
        let _ = writeln!(
            out,
            "add rule inet {FILTER_TABLE} sandbox {external} ip daddr {guest} tcp dport {} accept",
            port.guest_port
        );
    }
}

fn render_nat(out: &mut String, sandboxes: &[SandboxRules]) {
    let _ = writeln!(
        out,
        "add chain ip {NAT_TABLE} postrouting {{ type nat hook postrouting priority 100; policy accept; }}"
    );
    let _ = writeln!(
        out,
        "add chain ip {NAT_TABLE} prerouting {{ type nat hook prerouting priority -100; policy accept; }}"
    );

    for sandbox in sandboxes {
        // Allowlist mode never routes outward on its own: its web traffic is
        // redirected to the proxy, which reads the requested hostname and
        // decides. Redirect happens in prerouting, before any routing
        // decision, so the guest needs no proxy configuration.
        if sandbox.mode == Mode::Allowlist {
            // Traffic to a private-network peer is not egress and must reach
            // the peer unchanged. Without this it is swept into the egress
            // proxy along with everything else on 80/443 and denied there for
            // not being an allowlisted *domain*, so joining a network would
            // silently stop working under allowlist mode. Ordered before the
            // redirect because nftables takes the first terminating verdict.
            if !sandbox.peers.is_empty() {
                let _ = writeln!(
                    out,
                    "add rule ip {NAT_TABLE} prerouting ip saddr {} ip daddr {{ {} }} accept",
                    sandbox.guest_ip,
                    sandbox
                        .peers
                        .iter()
                        .map(|peer| peer.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let _ = writeln!(
                out,
                "add rule ip {NAT_TABLE} prerouting ip saddr {} tcp dport {{ 80, 443 }} redirect to :{PROXY_PORT}",
                sandbox.guest_ip
            );
        }
        // Only open-mode sandboxes reach the internet directly; allowlist mode
        // egresses through the proxy, which is a host-local connection.
        if sandbox.mode == Mode::Open {
            // Everywhere except the sandbox pool, for the same reason allowlist
            // mode exempts its peers from the redirect: traffic to a
            // private-network peer is not egress. Translated, it would reach a
            // local peer wearing the gateway's address, and a peer on another
            // node wearing this node's mesh address, which that node's rules do
            // not recognise as this sandbox and so drop.
            let _ = writeln!(
                out,
                "add rule ip {NAT_TABLE} postrouting ip saddr {} ip daddr != {SANDBOX_POOL} masquerade",
                sandbox.guest_ip
            );
        }
        // Published ports are doors from outside the fleet. Without the
        // interface guard the rule matches on destination port alone, so any
        // sandbox, including one in `none` mode, could hit its own gateway
        // address on a published port and be translated into a neighbour's
        // service; a mesh peer could do the same across nodes.
        let external = external_only();
        for port in &sandbox.ports {
            let _ = writeln!(
                out,
                "add rule ip {NAT_TABLE} prerouting {external} tcp dport {} dnat to {}:{}",
                port.host_port, sandbox.guest_ip, port.guest_port
            );
        }
    }
}

/// Deletes every conntrack entry with `guest_ip` on either side.
///
/// The sandbox chain accepts anything in `established` state so that replies
/// to permitted traffic get back, which is also how a connection survives the
/// policy that permitted it: tightening `deny_cidrs`, leaving `open` mode, or
/// deleting the sandbox leaves the kernel holding entries whose reply
/// direction no rule names, keeping the NAT binding alive. Both directions are
/// cleared, since a published port means inbound entries whose *destination*
/// is the guest. Recycled leases make this sharper still: the address goes to
/// the next sandbox created, which would inherit the previous tenant's open
/// connections.
///
/// `conntrack` from conntrack-tools is the only interface the kernel offers
/// for deleting selected entries; `nft` can match on conntrack state but
/// cannot delete. Its absence is logged rather than fatal, because a node
/// missing it still applies its rules to every *new* connection.
pub async fn flush_conntrack(guest_ip: Ipv4Addr) {
    let address = guest_ip.to_string();
    // One call per direction: `conntrack -D` ANDs its selectors, so a single
    // call naming both would only match entries that are from *and* to the
    // guest. It exits non-zero when it matched nothing, which is the ordinary
    // case, so only a failure to run it at all is worth reporting.
    for selector in ["--src", "--dst"] {
        let run = tokio::process::Command::new("conntrack")
            .args(["-D", selector, &address])
            .output()
            .await;
        if let Err(err) = run {
            tracing::warn!(
                guest = %address,
                %err,
                "could not flush conntrack entries; connections opened under a \
                 previous policy may outlive it until they idle out"
            );
            return;
        }
    }
}

/// Applies a rendered ruleset. `nft -f -` is transactional: either the whole
/// script commits or nothing changes.
pub async fn apply(ruleset: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(ruleset.as_bytes()).await?;
        stdin.flush().await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(NetError::Command {
            command: "nft -f -".into(),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(mode: Mode) -> SandboxRules {
        SandboxRules {
            sandbox_id: "sbx_test".into(),
            tap: "bt1".into(),
            host_ip: Ipv4Addr::new(10, 99, 0, 5),
            guest_ip: Ipv4Addr::new(10, 99, 0, 6),
            mode,
            allow_cidrs: vec![],
            deny_cidrs: vec![],
            allow_ports: vec![],
            peers: vec![],
            ports: vec![],
        }
    }

    #[test]
    fn base_chains_never_default_to_drop() {
        // A drop policy on a base hook would filter all host traffic, not just
        // burrow's, so this is a safety property worth pinning down.
        let ruleset = render(&[sandbox(Mode::Open)]);
        assert!(ruleset.contains("hook forward priority 0; policy accept"));
        assert!(!ruleset.contains("policy drop"));
    }

    #[test]
    fn sandbox_traffic_ends_in_a_drop() {
        let ruleset = render(&[]);
        assert!(ruleset.trim_end().contains("sandbox drop"));
    }

    #[test]
    fn only_open_mode_masquerades_general_traffic() {
        assert!(
            render(&[sandbox(Mode::Open)])
                .contains("ip saddr 10.99.0.6 ip daddr != 10.99.0.0/16 masquerade")
        );
        // Allowlist masquerades nothing. Everything it sends is either
        // redirected to the proxy, which opens its own upstream connection, or
        // answered by the resolver on the host; neither leaves as guest source
        // traffic.
        assert!(!render(&[sandbox(Mode::Allowlist)]).contains("masquerade"));
        assert!(!render(&[sandbox(Mode::None)]).contains("masquerade"));
    }

    #[test]
    fn dns_never_leaves_the_node_in_any_mode() {
        // The guest resolves through burrow's resolver on its own gateway, and
        // nothing else. A guest that rewrites /etc/resolv.conf to a public
        // resolver therefore emits packets matching no accept, which the
        // chain's drop catches: there is no rule that lets port 53 out.
        for mode in [Mode::None, Mode::Allowlist, Mode::Open] {
            let ruleset = render(&[sandbox(mode)]);
            for line in ruleset.lines().filter(|l| l.contains("sandbox ip saddr")) {
                assert!(
                    !line.contains(&format!("dport {DNS_PORT} accept")),
                    "{mode:?} lets DNS leave the node: {line}"
                );
            }
        }
        // Reaching arbitrary hosts is still refused in allowlist mode.
        assert!(!render(&[sandbox(Mode::Allowlist)]).contains("sandbox ip saddr 10.99.0.6 accept"));
    }

    #[test]
    fn allowlist_mode_redirects_web_traffic_to_the_proxy() {
        let ruleset = render(&[sandbox(Mode::Allowlist)]);
        assert!(ruleset.contains(&format!(
            "prerouting ip saddr 10.99.0.6 tcp dport {{ 80, 443 }} redirect to :{PROXY_PORT}"
        )));
        // Other modes must not be silently proxied.
        assert!(!render(&[sandbox(Mode::Open)]).contains("redirect to"));
        assert!(!render(&[sandbox(Mode::None)]).contains("redirect to"));
    }

    #[test]
    fn allowlist_mode_permits_only_proxy_and_dns_on_the_host() {
        let ruleset = render(&[sandbox(Mode::Allowlist)]);
        assert!(ruleset.contains(&format!(
            "tohost ip saddr 10.99.0.6 ip daddr 10.99.0.5 tcp dport {PROXY_PORT} accept"
        )));
        assert!(ruleset.contains(&format!(
            "tohost ip saddr 10.99.0.6 ip daddr 10.99.0.5 udp dport {DNS_PORT} accept"
        )));
        // No blanket egress accept for the guest address.
        assert!(!ruleset.contains("sandbox ip saddr 10.99.0.6 accept"));
    }

    #[test]
    fn mesh_traffic_is_admitted_but_not_anti_spoofed() {
        // WireGuard already refuses packets sourced outside a peer's own
        // range, and the mesh interface is not a tap, so anti-spoofing has
        // nothing to check.
        let ruleset = render(&[sandbox(Mode::Open)]);
        assert!(ruleset.contains(&format!(
            "forward iifname \"{MESH_INTERFACE}\" jump sandbox"
        )));
        assert!(!ruleset.contains(&format!(
            "forward iifname \"{MESH_INTERFACE}\" jump antispoof"
        )));
    }

    #[test]
    fn a_remote_peer_is_reachable_in_both_directions() {
        let mut s = sandbox(Mode::None);
        // An address outside this node's own slice: it lives on another node.
        s.peers = vec![Ipv4Addr::new(10, 99, 4, 6)];
        let ruleset = render(&[s]);

        assert!(ruleset.contains("ip saddr 10.99.0.6 ip daddr 10.99.4.6 accept"));
        // The inbound rule is what lets a connection *started* by the remote
        // peer through: it arrives over the mesh with no conntrack entry, so
        // the established rule does not cover it.
        assert!(ruleset.contains("ip saddr 10.99.4.6 ip daddr 10.99.0.6 accept"));
    }

    #[test]
    fn traffic_is_selected_by_interface_not_by_source_address() {
        // A guest controls its own source address, so any rule that selects
        // sandbox traffic by address alone can be stepped around by forging
        // one. Selection must key off the tap, which burrow owns.
        let ruleset = render(&[sandbox(Mode::Open)]);
        assert!(ruleset.contains(&format!("forward iifname \"{TAP_PREFIX}*\" jump sandbox")));
        assert!(ruleset.contains(&format!("input iifname \"{TAP_PREFIX}*\" jump tohost")));
        assert!(!ruleset.contains(&format!("forward ip saddr {SANDBOX_CIDR} jump")));
        assert!(!ruleset.contains(&format!("input ip saddr {SANDBOX_CIDR} jump")));
    }

    #[test]
    fn forged_source_addresses_are_dropped_on_both_hooks() {
        let ruleset = render(&[sandbox(Mode::Open)]);
        // Only this sandbox's own address is let through on its own tap...
        assert!(ruleset.contains("antispoof iifname \"bt1\" ip saddr 10.99.0.6 return"));
        // ...and anything else arriving on a burrow tap is dropped.
        assert!(ruleset.contains(&format!("antispoof iifname \"{TAP_PREFIX}*\" counter log")));
        // The check must run before policy is evaluated on either hook.
        let antispoof_fwd = ruleset
            .find(&format!("forward iifname \"{TAP_PREFIX}*\" jump antispoof"))
            .expect("forward must anti-spoof");
        let policy_fwd = ruleset
            .find(&format!("forward iifname \"{TAP_PREFIX}*\" jump sandbox"))
            .expect("forward must apply policy");
        assert!(antispoof_fwd < policy_fwd, "anti-spoof must run first");

        let antispoof_in = ruleset
            .find(&format!("input iifname \"{TAP_PREFIX}*\" jump antispoof"))
            .expect("input must anti-spoof");
        let policy_in = ruleset
            .find(&format!("input iifname \"{TAP_PREFIX}*\" jump tohost"))
            .expect("input must apply policy");
        assert!(antispoof_in < policy_in, "anti-spoof must run first");
    }

    #[test]
    fn a_sandbox_cannot_borrow_another_sandboxes_address() {
        let mut a = sandbox(Mode::Open);
        a.tap = "bt1".into();
        a.guest_ip = Ipv4Addr::new(10, 99, 0, 6);
        let mut b = sandbox(Mode::Open);
        b.sandbox_id = "sbx_other".into();
        b.tap = "bt2".into();
        b.guest_ip = Ipv4Addr::new(10, 99, 0, 10);

        let ruleset = render(&[a, b]);
        // Each address is bound to exactly one tap, so B's address arriving on
        // A's tap matches no `return` and falls to the drop.
        assert!(ruleset.contains("antispoof iifname \"bt1\" ip saddr 10.99.0.6 return"));
        assert!(ruleset.contains("antispoof iifname \"bt2\" ip saddr 10.99.0.10 return"));
        assert!(!ruleset.contains("antispoof iifname \"bt1\" ip saddr 10.99.0.10 return"));
    }

    #[test]
    fn host_services_are_denied_by_default() {
        // Reaching the host means reaching burrowd's own API, so every mode
        // must end in a drop on the input path.
        for mode in [Mode::None, Mode::Allowlist, Mode::Open] {
            let ruleset = render(&[sandbox(mode)]);
            assert!(
                ruleset.contains("hook input priority 0; policy accept"),
                "input hook must not filter non-sandbox traffic"
            );
            assert!(
                ruleset.contains(&format!("add rule inet {FILTER_TABLE} tohost drop")),
                "{mode:?} must end the host chain in a drop"
            );
        }
    }

    #[test]
    fn open_mode_reaches_the_resolver_but_not_the_proxy_or_anything_else() {
        let ruleset = render(&[sandbox(Mode::Open)]);
        // "Open" means the internet, not burrow's own control plane. The
        // resolver is the one exception, because it records what it is asked.
        assert!(ruleset.contains(&format!(
            "tohost ip saddr 10.99.0.6 ip daddr 10.99.0.5 udp dport {DNS_PORT} accept"
        )));
        assert!(!ruleset.contains(&format!(
            "tohost ip saddr 10.99.0.6 ip daddr 10.99.0.5 tcp dport {PROXY_PORT}"
        )));
    }

    /// The constant callers name and the value rules are rendered from have to
    /// be the same range, or the policy would deny something other than the
    /// pool addresses are handed out of.
    #[test]
    fn the_named_pool_and_the_rendered_one_are_the_same_range() {
        assert_eq!(parse_cidr(SANDBOX_CIDR), Some(SANDBOX_POOL));
    }

    /// "Open" is egress off the node. A blanket accept also reached every other
    /// sandbox on the node and, over the mesh, every sandbox in the fleet, so
    /// private-network membership was no longer the only way one sandbox
    /// reached another.
    #[test]
    fn open_mode_cannot_reach_another_sandbox_here_or_on_another_node() {
        let ruleset = render(&[sandbox(Mode::Open)]);

        let deny = "sandbox ip saddr 10.99.0.6 ip daddr 10.99.0.0/16 drop";
        assert!(
            ruleset.contains(deny),
            "missing the pool denial:\n{ruleset}"
        );
        // The whole pool, not this node's slice: a sandbox on another node has
        // an address from another slice and is reached over the mesh.
        assert!(!ruleset.contains("ip daddr 10.99.0.0/22 drop"));

        // Before the blanket accept, or the accept wins.
        let accept = "sandbox ip saddr 10.99.0.6 accept";
        assert!(
            ruleset.find(deny) < ruleset.find(accept),
            "the denial must precede the blanket accept"
        );
        // And peer traffic is not egress, so it is not translated either.
        assert!(!ruleset.contains("ip saddr 10.99.0.6 masquerade"));
    }

    /// Open mode has no proxy in front of it to refuse the cloud metadata
    /// address the way the allowlist path does, so the firewall must refuse
    /// it directly, ahead of the blanket accept or the accept wins.
    #[test]
    fn open_mode_cannot_reach_the_cloud_metadata_address() {
        let ruleset = render(&[sandbox(Mode::Open)]);

        let deny = "sandbox ip saddr 10.99.0.6 ip daddr 169.254.0.0/16 drop";
        assert!(
            ruleset.contains(deny),
            "missing the metadata denial:\n{ruleset}"
        );

        let accept = "sandbox ip saddr 10.99.0.6 accept";
        assert!(
            ruleset.find(deny) < ruleset.find(accept),
            "the denial must precede the blanket accept"
        );
    }

    /// The metadata denial is not something an operator opts out of: it
    /// applies even to a sandbox that names the address as a peer, since
    /// nothing on the fleet legitimately lives there.
    #[test]
    fn the_metadata_denial_outranks_a_declared_peer() {
        let mut s = sandbox(Mode::None);
        s.peers = vec!["169.254.169.254".parse().unwrap()];
        let ruleset = render(&[s]);

        let deny = "sandbox ip saddr 10.99.0.6 ip daddr 169.254.0.0/16 drop";
        let peer_accept = "sandbox ip saddr 10.99.0.6 ip daddr 169.254.169.254 accept";
        assert!(
            ruleset.contains(deny),
            "missing the metadata denial:\n{ruleset}"
        );
        assert!(
            ruleset.find(deny) < ruleset.find(peer_accept),
            "the metadata denial must precede any peer accept naming it"
        );
    }

    /// The denial sits between the peer accepts and the blanket accept, so a
    /// private network keeps working, including for a member on another node
    /// whose address is in the pool the denial names.
    #[test]
    fn a_private_network_peer_outranks_the_pool_denial() {
        let mut s = sandbox(Mode::Open);
        s.peers = vec![Ipv4Addr::new(10, 99, 0, 10), Ipv4Addr::new(10, 99, 4, 6)];
        let ruleset = render(&[s]);

        let deny = "sandbox ip saddr 10.99.0.6 ip daddr 10.99.0.0/16 drop";
        for peer in [
            "sandbox ip saddr 10.99.0.6 ip daddr 10.99.0.10 accept",
            "sandbox ip saddr 10.99.0.6 ip daddr 10.99.4.6 accept",
        ] {
            assert!(ruleset.contains(peer), "missing {peer}:\n{ruleset}");
            assert!(
                ruleset.find(peer) < ruleset.find(deny),
                "{peer} must precede the denial"
            );
        }
    }

    /// The pool holds the gateway addresses too, so a denial written without
    /// care would take the resolver and the egress proxy with it. Both are
    /// reached on the host, which is a different hook.
    #[test]
    fn the_pool_denial_leaves_the_host_services_alone() {
        let open = render(&[sandbox(Mode::Open)]);
        assert!(open.contains(&format!(
            "tohost ip saddr 10.99.0.6 ip daddr 10.99.0.5 udp dport {DNS_PORT} accept"
        )));
        // Egress itself is untouched: everything outside the pool is accepted
        // and translated.
        assert!(open.contains("sandbox ip saddr 10.99.0.6 accept"));
        assert!(open.contains("ip daddr != 10.99.0.0/16 masquerade"));

        // Allowlist is unchanged in every respect, proxy included.
        let allowlist = render(&[sandbox(Mode::Allowlist)]);
        assert!(allowlist.contains(&format!(
            "tohost ip saddr 10.99.0.6 ip daddr 10.99.0.5 tcp dport {PROXY_PORT} accept"
        )));
        assert!(!allowlist.contains("ip daddr 10.99.0.0/16 drop"));
        assert!(!render(&[sandbox(Mode::None)]).contains("ip daddr 10.99.0.0/16 drop"));
    }

    /// The rules above are only as good as the routes: the orchestrator's API
    /// creates, deletes and execs into every sandbox in the fleet, and a node's
    /// edge router proxies into any of its sandboxes' published ports for
    /// whoever asks. A sandbox that can reach either reaches other sandboxes
    /// without a packet ever being matched against a rule about them.
    #[test]
    fn the_control_plane_is_denied_to_every_sandbox() {
        let orchestrator = Ipv4Addr::new(172, 18, 0, 4);
        for mode in [Mode::None, Mode::Allowlist, Mode::Open] {
            let mut s = sandbox(mode);
            s.peers = vec![Ipv4Addr::new(10, 99, 0, 10)];
            let ruleset = render_with(&[s], &[orchestrator]);

            let deny = "sandbox ip daddr 172.18.0.4 drop";
            assert!(
                ruleset.contains(deny),
                "{mode:?} must deny the control plane"
            );
            // Before the established accept, or a connection open when the
            // policy changed would outlive it.
            assert!(
                ruleset.find(deny) < ruleset.find("sandbox ct state established,related accept"),
                "{mode:?}: the denial must precede the conntrack accept"
            );
        }
        // On the destination only: traffic *from* one of these addresses is how
        // a node's edge reaches a guest port.
        assert!(
            !render_with(&[sandbox(Mode::Open)], &[orchestrator])
                .contains("sandbox ip saddr 172.18.0.4")
        );
        // And a node with none named renders none.
        assert!(!render(&[sandbox(Mode::Open)]).contains("172.18.0.4"));
    }

    #[test]
    fn a_networkless_sandbox_cannot_even_resolve() {
        // A lookup carries attacker-chosen bytes off the host, so leaving the
        // resolver reachable would make `none` mode a working exfil channel
        // rather than no traffic at all.
        let ruleset = render(&[sandbox(Mode::None)]);
        assert!(!ruleset.contains(&format!(
            "tohost ip saddr 10.99.0.6 ip daddr 10.99.0.5 udp dport {DNS_PORT} accept"
        )));
    }

    /// The resolver binds UDP and nothing else, so a TCP/53 accept is a hole
    /// pointed at a port with no listener behind it.
    #[test]
    fn the_resolver_is_reachable_over_udp_only() {
        for mode in [Mode::None, Mode::Allowlist, Mode::Open] {
            let ruleset = render(&[sandbox(mode)]);
            assert!(
                !ruleset.contains(&format!("tcp dport {DNS_PORT}")),
                "{mode:?} opens TCP/53, which nothing on the host answers"
            );
        }
        assert!(render(&[sandbox(Mode::Allowlist)]).contains(&format!(
            "tohost ip saddr 10.99.0.6 ip daddr 10.99.0.5 udp dport {DNS_PORT} accept"
        )));
    }

    #[test]
    fn none_mode_grants_nothing() {
        let ruleset = render(&[sandbox(Mode::None)]);
        assert!(!ruleset.contains("10.99.0.6 accept"));
        assert!(!ruleset.contains("masquerade"));
    }

    #[test]
    fn peers_are_allowed_independently_of_egress_mode() {
        let mut s = sandbox(Mode::None);
        s.peers = vec![Ipv4Addr::new(10, 99, 0, 10)];
        let ruleset = render(&[s]);
        assert!(ruleset.contains("ip saddr 10.99.0.6 ip daddr 10.99.0.10 accept"));
    }

    #[test]
    fn published_ports_are_dnatted_and_accepted() {
        let mut s = sandbox(Mode::Open);
        s.ports = vec![PortMap {
            host_port: 18080,
            guest_port: 8000,
        }];
        let ruleset = render(&[s]);
        assert!(ruleset.contains("tcp dport 18080 dnat to 10.99.0.6:8000"));
        assert!(ruleset.contains("ip daddr 10.99.0.6 tcp dport 8000 accept"));
    }

    /// A published port is a door from outside. Matching on destination port
    /// alone would also open it to every other sandbox on the node, which can
    /// reach its own gateway address and be translated straight into a
    /// neighbour's service.
    #[test]
    fn a_published_port_is_not_reachable_from_another_sandbox_or_the_mesh() {
        let mut s = sandbox(Mode::Open);
        s.ports = vec![PortMap {
            host_port: 18080,
            guest_port: 8000,
        }];
        let ruleset = render(&[s]);

        let guard = format!("iifname != \"{TAP_PREFIX}*\" iifname != \"{MESH_INTERFACE}\"");
        assert!(
            ruleset.contains(&format!("prerouting {guard} tcp dport 18080 dnat")),
            "the dnat must exclude sandbox and mesh traffic:\n{ruleset}"
        );
        assert!(
            ruleset.contains(&format!(
                "sandbox {guard} ip daddr 10.99.0.6 tcp dport 8000 accept"
            )),
            "the forward accept must not grant sandbox-to-sandbox access:\n{ruleset}"
        );
    }

    /// `nft -f -` reads a script line by line, so a caller-supplied string
    /// reaching it verbatim is arbitrary rule injection, including rules that
    /// undo the isolation of every other sandbox on the node.
    #[test]
    fn a_cidr_carrying_nft_commands_is_refused_outright() {
        let mut s = sandbox(Mode::Allowlist);
        s.allow_cidrs = vec![
            "0.0.0.0/0 accept\nadd rule inet burrow sandbox accept\n# ".into(),
            "10.77.0.0/16".into(),
        ];
        let rules = render(&[s]);

        assert!(!rules.contains("add rule inet burrow sandbox accept"));
        // Fail closed for the whole record: the entry that parsed is dropped
        // too rather than half-applying a policy the caller did not write.
        assert!(!rules.contains("ip daddr 10.77.0.0/16"));
        // And the ruleset is still a ruleset: one bad record must not stop the
        // rest of the node being rendered.
        assert!(rules.contains("add rule inet burrow sandbox drop"));
    }

    #[test]
    fn malformed_cidrs_and_out_of_range_ports_are_rejected() {
        for bad in [
            "",
            "   ",
            "10.77.0.0/33",
            "10.77.0.0/+8",
            "10.77.0.0/",
            "10.77.0.0/16/8",
            "not-an-address",
            "10.77.0.0/16 accept",
            "::1/128",
        ] {
            assert!(parse_cidr(bad).is_none(), "{bad:?} must not parse");
        }
        assert_eq!(
            parse_cidr("10.77.0.0/16"),
            Some(Cidr {
                addr: Ipv4Addr::new(10, 77, 0, 0),
                prefix: 16
            })
        );
        // A bare address is the /32 the operator meant.
        assert_eq!(parse_cidr("10.77.0.1").map(|c| c.prefix), Some(32));

        // A port outside the 16-bit range would abort the transaction, which
        // re-renders every sandbox on the node: one bad record must not be
        // able to freeze the whole ruleset.
        let mut s = sandbox(Mode::Allowlist);
        s.allow_cidrs = vec!["10.77.0.0/16".into()];
        s.allow_ports = vec![70_000];
        let rules = render(&[s]);
        assert!(!rules.contains("70000"));
        assert!(!rules.contains("ip daddr 10.77.0.0/16"));
    }

    /// One malformed record must not cost every *other* sandbox its rules,
    /// since the whole node is rendered into one transactional script.
    #[test]
    fn a_bad_record_does_not_poison_another_sandboxs_rules() {
        let mut bad = sandbox(Mode::Open);
        bad.sandbox_id = "sbx_bad".into();
        bad.tap = "bt1".into();
        bad.allow_cidrs = vec!["whatever\n".into()];
        let mut good = sandbox(Mode::Open);
        good.sandbox_id = "sbx_good".into();
        good.tap = "bt2".into();
        good.guest_ip = Ipv4Addr::new(10, 99, 0, 10);
        good.allow_cidrs = vec!["10.77.0.0/16".into()];

        let rules = render(&[bad, good]);
        assert!(rules.contains("ip saddr 10.99.0.10 ip daddr 10.77.0.0/16 accept"));
        assert!(!rules.contains("whatever"));
        // Every line is a single nft command; nothing the caller wrote can add
        // one of its own.
        assert!(rules.lines().all(|line| {
            line.is_empty()
                || line.starts_with("add ")
                || line.starts_with("flush ")
                || line.starts_with('#')
        }));
    }

    /// A live policy update re-renders the whole node and the script starts
    /// with a flush, so the previous policy's allowances are gone rather than
    /// layered under the new ones.
    #[test]
    fn re_rendering_replaces_the_previous_policy() {
        let mut before = sandbox(Mode::Open);
        before.allow_cidrs = vec!["10.77.0.0/16".into()];
        let before = render(&[before]);
        assert!(before.contains("ip daddr 10.77.0.0/16 accept"));
        assert!(before.contains("sandbox ip saddr 10.99.0.6 accept"));

        let mut after = sandbox(Mode::None);
        after.deny_cidrs = vec!["10.77.0.0/16".into()];
        let after = render(&[after]);

        assert!(after.contains("flush table inet burrow"));
        assert!(!after.contains("ip daddr 10.77.0.0/16 accept"));
        assert!(!after.contains("sandbox ip saddr 10.99.0.6 accept"));
        assert!(after.contains("ip daddr 10.77.0.0/16 drop"));
    }

    #[test]
    fn render_is_idempotent_for_the_same_input() {
        let s = sandbox(Mode::Open);
        assert_eq!(render(std::slice::from_ref(&s)), render(&[s]));
    }

    /// A peer is not the internet. Redirecting peer traffic into the egress
    /// proxy would have it denied for not being an allowlisted domain, which
    /// makes private networks silently useless in allowlist mode.
    #[test]
    fn peer_traffic_is_exempt_from_the_egress_redirect() {
        let mut s = sandbox(Mode::Allowlist);
        s.peers = vec![Ipv4Addr::new(10, 99, 0, 10), Ipv4Addr::new(10, 99, 4, 6)];
        let rules = render(&[s]);

        let exempt = "prerouting ip saddr 10.99.0.6 ip daddr { 10.99.0.10, 10.99.4.6 } accept";
        assert!(rules.contains(exempt), "missing peer exemption:\n{rules}");

        // And it must come first, or the redirect wins.
        let redirect = "prerouting ip saddr 10.99.0.6 tcp dport { 80, 443 } redirect";
        assert!(
            rules.find(exempt) < rules.find(redirect),
            "the exemption must precede the redirect"
        );
    }

    #[test]
    fn a_sandbox_with_no_peers_gets_no_exemption_rule() {
        let rules = render(&[sandbox(Mode::Allowlist)]);
        assert!(!rules.contains("ip daddr {  } accept"));
        assert!(!rules.contains("prerouting ip saddr 10.99.0.6 ip daddr"));
    }

    /// A CIDR allowance is a hole at the IP layer, bypassing the proxy. Naming
    /// ports must narrow it, or `allow_ports` is a field that looks like a
    /// restriction and enforces nothing.
    #[test]
    fn named_ports_narrow_a_cidr_allowance() {
        let mut s = sandbox(Mode::Allowlist);
        s.allow_cidrs = vec!["10.77.0.0/16".into()];
        s.allow_ports = vec![5432, 6379];
        let rules = render(&[s]);

        assert!(
            rules.contains("ip daddr 10.77.0.0/16 tcp dport { 5432, 6379 } accept"),
            "tcp should be limited to the named ports:\n{rules}"
        );
        assert!(rules.contains("ip daddr 10.77.0.0/16 udp dport { 5432, 6379 } accept"));
        // The unrestricted form must not also be emitted, or it would swallow
        // the narrower one.
        assert!(
            !rules.contains("ip daddr 10.77.0.0/16 accept"),
            "the any-port rule must not survive alongside the narrowed one"
        );
    }

    #[test]
    fn a_cidr_without_named_ports_stays_unrestricted() {
        let mut s = sandbox(Mode::Allowlist);
        s.allow_cidrs = vec!["10.77.0.0/16".into()];
        let rules = render(&[s]);
        assert!(rules.contains("ip daddr 10.77.0.0/16 accept"));
        // Scoped to the CIDR rule: the ruleset legitimately has other dport
        // rules for DNS and the proxy.
        assert!(!rules.contains("ip daddr 10.77.0.0/16 tcp dport"));
    }

    /// A denial is worth nothing unless it outranks every allowance, since
    /// nftables stops at the first terminating verdict.
    #[test]
    fn a_denied_range_is_dropped_before_any_allowance() {
        for mode in [Mode::None, Mode::Allowlist, Mode::Open] {
            let mut s = sandbox(mode);
            s.deny_cidrs = vec!["169.254.169.254/32".into(), "10.77.0.0/16".into()];
            s.allow_cidrs = vec!["10.77.0.0/16".into()];
            s.peers = vec![Ipv4Addr::new(10, 99, 0, 10)];
            let rules = render(&[s]);

            let deny = "sandbox ip saddr 10.99.0.6 ip daddr 10.77.0.0/16 drop";
            assert!(rules.contains(deny), "{mode:?} must render the denial");
            assert!(rules.contains("sandbox ip saddr 10.99.0.6 ip daddr 169.254.169.254/32 drop"));

            // Every accept for this sandbox must come after it: the
            // allowance, the peer, and open mode's blanket egress.
            for accept in rules
                .lines()
                .filter(|line| line.contains("ip saddr 10.99.0.6") && line.ends_with("accept"))
            {
                assert!(
                    rules.find(deny) < rules.find(accept),
                    "{mode:?}: {accept:?} precedes the denial"
                );
            }
        }
    }

    /// Dropping an unparseable denial would grant exactly the access the
    /// operator asked to withhold, so the sandbox loses its egress instead.
    #[test]
    fn a_malformed_denial_costs_the_sandbox_its_egress() {
        let mut s = sandbox(Mode::Open);
        s.deny_cidrs = vec!["10.77.0.0/16\nadd rule inet burrow sandbox accept".into()];
        s.allow_cidrs = vec!["10.77.0.0/16".into()];
        let rules = render(&[s]);

        assert!(!rules.contains("add rule inet burrow sandbox accept"));
        assert!(rules.contains("sandbox ip saddr 10.99.0.6 drop"));
        assert!(!rules.contains("ip saddr 10.99.0.6 accept"));
        assert!(!rules.contains("ip daddr 10.77.0.0/16 accept"));
        // The rest of the node still renders.
        assert!(rules.contains("add rule inet burrow sandbox drop"));
    }

    /// A counter name is built from the address burrow assigned, so nothing a
    /// caller wrote can reach the script, and it round-trips, which is what
    /// lets a reading be attributed back to a sandbox.
    #[test]
    fn counter_names_come_from_the_assigned_address_and_round_trip() {
        let (rx, tx) = counter_names(Ipv4Addr::new(10, 99, 4, 6));
        assert_eq!((rx.as_str(), tx.as_str()), ("rx_10_99_4_6", "tx_10_99_4_6"));
        assert_eq!(
            parse_counter_name(&rx),
            Some((Ipv4Addr::new(10, 99, 4, 6), true))
        );
        assert_eq!(
            parse_counter_name(&tx),
            Some((Ipv4Addr::new(10, 99, 4, 6), false))
        );

        // Every address renders as digits and underscores and nothing else, so
        // no address can produce a name carrying nft syntax.
        for octet in [0u8, 1, 127, 255] {
            let (rx, _) = counter_names(Ipv4Addr::new(octet, octet, octet, octet));
            assert!(
                rx.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "{rx:?} must be a bare identifier"
            );
        }

        // Anything that is not one of burrow's own counters is not attributed
        // to a sandbox rather than guessed at.
        for bad in [
            "rx_",
            "counter",
            "rx_10_99_4",
            "rx_10_99_4_6_7",
            "rx_10_99_4_300",
            "zz_10_99_4_6",
            "rx_a_b_c_d",
        ] {
            assert!(parse_counter_name(bad).is_none(), "{bad:?}");
        }
    }

    /// The sandbox id never reaches a counter name: it is a caller-influenced
    /// string, and this table is rendered into the same `nft -f -` script as
    /// the policy rules. The one place an id appears, the comment above a
    /// sandbox's rules, carries only the id charset.
    #[test]
    fn a_sandbox_id_is_never_rendered_into_a_counter() {
        let mut s = sandbox(Mode::Open);
        s.sandbox_id = "sbx_evil\nadd rule inet burrow sandbox accept".into();
        let rules = render(&[s]);
        assert!(!rules.contains("add rule inet burrow sandbox accept"));
        assert!(rules.contains("# sandbox sbx_evil?add"));
        assert!(rules.contains("add counter inet burrow_meter rx_10_99_0_6"));
        assert!(rules.contains("counter name \"tx_10_99_0_6\""));
    }

    /// Allowlist egress terminates at the proxy on the host, which never
    /// crosses the forward hook, so counting there would report zero for every
    /// sandbox that is actually using its allowlist.
    #[test]
    fn traffic_is_counted_on_both_of_the_taps_directions() {
        let rules = render(&[sandbox(Mode::Allowlist)]);
        assert!(rules.contains("hook prerouting priority -300"));
        assert!(rules.contains("hook postrouting priority -300"));
        assert!(rules.contains("meter tx iifname \"bt1\" counter name \"tx_10_99_0_6\""));
        assert!(rules.contains("meter rx oifname \"bt1\" counter name \"rx_10_99_0_6\""));
    }

    /// Counters go with the rest of a sandbox's rules: the whole table is
    /// flushed and rebuilt from whoever is still running.
    #[test]
    fn a_departed_sandbox_leaves_no_counter_behind() {
        let mut gone = sandbox(Mode::Open);
        gone.guest_ip = Ipv4Addr::new(10, 99, 0, 10);
        assert!(render(&[gone]).contains("rx_10_99_0_10"));

        let after = render(&[sandbox(Mode::Open)]);
        assert!(after.contains("flush table inet burrow_meter"));
        assert!(!after.contains("10_99_0_10"));
    }

    #[test]
    fn nft_counter_output_is_read_back_per_sandbox() {
        let listing = "table inet burrow_meter {\n\
             \tcounter rx_10_99_0_6 {\n\t\tpackets 12 bytes 3456\n\t}\n\
             \tcounter tx_10_99_0_6 {\n\t\tpackets 9 bytes 780\n\t}\n\
             \tcounter rx_10_99_0_10 {\n\t\tpackets 0 bytes 0\n\t}\n\
             }\n";
        let read = parse_counters(listing);
        assert_eq!(
            read.get(&Ipv4Addr::new(10, 99, 0, 6)),
            Some(&Traffic {
                rx_bytes: 3456,
                tx_bytes: 780
            })
        );
        // A sandbox that has moved nothing reports zeroes, not nothing.
        assert_eq!(
            read.get(&Ipv4Addr::new(10, 99, 0, 10)),
            Some(&Traffic::default())
        );
        assert!(parse_counters("").is_empty());
    }

    /// A denial rendered after the `established` accept applies only to
    /// connections that are not already open, so the sandbox keeps whatever it
    /// had until the entry idles out. Every unconditional drop must precede
    /// the accept.
    #[test]
    fn every_denial_precedes_the_established_accept() {
        for mode in [Mode::None, Mode::Allowlist, Mode::Open] {
            let mut s = sandbox(mode);
            s.deny_cidrs = vec!["10.77.0.0/16".into()];
            s.allow_cidrs = vec!["10.88.0.0/16".into()];
            s.peers = vec![Ipv4Addr::new(10, 99, 0, 10)];
            let rules = render_with(&[s], &[Ipv4Addr::new(172, 18, 0, 4)]);

            let established = rules
                .find("sandbox ct state established,related accept")
                .expect("the chain must accept return traffic");
            for deny in [
                "sandbox ip daddr 172.18.0.4 drop",
                "sandbox ip saddr 10.99.0.6 ip daddr 169.254.0.0/16 drop",
                "sandbox ip saddr 10.99.0.6 ip daddr 10.77.0.0/16 drop",
            ] {
                let at = rules
                    .find(deny)
                    .unwrap_or_else(|| panic!("{mode:?} must render {deny}:\n{rules}"));
                assert!(
                    at < established,
                    "{mode:?}: {deny} must precede the established accept"
                );
            }
        }
    }

    /// The blanket drop a malformed `deny_cidrs` earns is a denial like any
    /// other, so it too outranks the established accept, and the sandbox's
    /// allowances are not rendered at all.
    #[test]
    fn a_malformed_denial_drops_ahead_of_the_established_accept() {
        let mut s = sandbox(Mode::Open);
        s.deny_cidrs = vec!["nonsense\n".into()];
        s.allow_cidrs = vec!["10.77.0.0/16".into()];
        s.peers = vec![Ipv4Addr::new(10, 99, 0, 10)];
        let rules = render(&[s]);

        let drop = rules
            .find("sandbox ip saddr 10.99.0.6 drop")
            .expect("a malformed denial must cost the sandbox its egress");
        let established = rules
            .find("sandbox ct state established,related accept")
            .expect("the chain must accept return traffic");
        assert!(drop < established);
        // Nothing of this sandbox's policy is rendered at all, so no accept
        // survives to be reached by a conntrack entry.
        assert!(!rules.contains("ip saddr 10.99.0.6 ip daddr 10.99.0.10 accept"));
        assert!(!rules.contains("ip daddr 10.77.0.0/16 accept"));
    }

    /// Everything not explicitly permitted falls to the chain's drop, which is
    /// what rejects arbitrary TCP.
    #[test]
    fn arbitrary_traffic_falls_to_the_drop() {
        let rules = render(&[sandbox(Mode::Allowlist)]);
        let sandbox_chain = rules
            .lines()
            .filter(|line| line.contains("burrow sandbox"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            sandbox_chain.trim_end().ends_with("drop"),
            "the sandbox chain must end in a drop:\n{sandbox_chain}"
        );
    }
}
