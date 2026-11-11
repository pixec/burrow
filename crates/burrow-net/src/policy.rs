//! Whether a sandbox may reach a destination, and why not.
//!
//! One decision with two enforcers. On Linux [`crate::firewall`] renders it as
//! nftables rules; on a node with no nftables, [`crate::usernet`] asks it per
//! flow. Both read the validated forms built here, and a test renders the
//! ruleset and evaluates it against [`decide`] over a table of cases, so a
//! change to one that the other does not follow fails the build rather than
//! leaving two policies that disagree about the same sandbox.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::firewall::{DNS_PORT, Mode, PROXY_PORT, Protocol};

/// The renderer's validated form of [`crate::firewall::SANDBOX_CIDR`]. Nothing
/// reaches the nft script that was not parsed first, a constant included, so
/// this is built from [`crate::ipam`]'s numbers rather than from the string.
pub(crate) const SANDBOX_POOL: Cidr = Cidr {
    addr: IpAddr::V4(crate::ipam::POOL_ADDRESS),
    prefix: crate::ipam::POOL_PREFIX,
};

/// Link-local space, home to `169.254.169.254`: on EC2, GCP, Azure and most
/// other clouds, the instance's own credentials are an unauthenticated HTTP
/// GET away at that address. Denied to every sandbox regardless of egress
/// mode, the same way `crate::proxy`'s `is_forbidden_destination` denies it
/// on the allowlist path. Open mode has no proxy in front of it to do that,
/// so without this the metadata service is reachable from any open-mode
/// sandbox on a cloud host.
pub(crate) const METADATA_CIDR: Cidr = Cidr {
    addr: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
    prefix: 16,
};

/// Ports allowlist mode hands to the egress proxy, which decides by name.
pub const PROXIED_PORTS: [u16; 2] = [80, 443];

/// Most port denials one policy may carry. Each renders a handful of rules
/// into the node's one ruleset, so the count is part of every packet's cost.
pub const MAX_PORT_DENIALS: usize = 64;
/// Most destination ranges one port denial may be narrowed to.
pub const MAX_PORT_DENIAL_CIDRS: usize = 16;

/// A validated CIDR, of either family.
///
/// `nft -f -` reads a script, one command per line, so a caller's string
/// reaching it verbatim is rule injection: a newline inside a "CIDR" would
/// append rules of the attacker's choosing to burrow's own tables. Only the
/// parsed address and prefix are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    pub(crate) addr: IpAddr,
    pub(crate) prefix: u8,
}

impl Cidr {
    /// Whether `address` is inside this range. A range only ever covers its
    /// own family, exactly as an `ip daddr` match never sees a v6 packet.
    pub(crate) fn contains(self, address: IpAddr) -> bool {
        match (self.addr, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                // A /0 covers everything, and shifting by the width is
                // undefined.
                let mask = match self.prefix {
                    0 => 0,
                    bits => u32::MAX << (32 - bits),
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = match self.prefix {
                    0 => 0,
                    bits => u128::MAX << (128 - bits),
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }

    pub(crate) fn is_v4(self) -> bool {
        self.addr.is_ipv4()
    }

    /// The nftables destination match for this range's family.
    pub(crate) fn daddr(self) -> &'static str {
        if self.is_v4() {
            "ip daddr"
        } else {
            "ip6 daddr"
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Parses `a.b.c.d[/len]` or `v6[/len]`, rejecting anything else.
///
/// A bare address is a host route, /32 or /128, which is what an operator
/// writing one means. Whitespace, a second slash, `+32`, a zone id and a
/// prefix longer than the family's are refused rather than interpreted.
pub(crate) fn parse_cidr(value: &str) -> Option<Cidr> {
    let (addr, len) = match value.split_once('/') {
        Some((addr, len)) => {
            // `str::parse` for integers accepts a leading `+`; a prefix length
            // is digits and nothing else.
            if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (addr, Some(len.parse::<u8>().ok()?))
        }
        None => (value, None),
    };
    let addr: IpAddr = addr.parse().ok()?;
    let width = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = len.unwrap_or(width);
    if prefix > width {
        return None;
    }
    Some(Cidr { addr, prefix })
}

/// One `deny_ports` entry as the caller wrote it, before validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortDenial {
    /// The transport it applies to; `None` is both TCP and UDP.
    pub protocol: Option<Protocol>,
    /// First port of the range.
    pub first: u32,
    /// Last port of the range, inclusive. 0 means `first` alone.
    pub last: u32,
    /// Destination ranges it is narrowed to, of either family. Empty is every
    /// destination.
    pub cidrs: Vec<String>,
}

impl From<&burrow_proto::common::v1::PortRule> for PortDenial {
    /// Validation happens at the ruleset, where a malformed entry costs the
    /// sandbox its egress rather than being skipped. An unknown protocol reads
    /// as both, the broader denial, for the same reason.
    fn from(rule: &burrow_proto::common::v1::PortRule) -> Self {
        use burrow_proto::common::v1::PortProtocol;
        Self {
            protocol: match PortProtocol::try_from(rule.protocol) {
                Ok(PortProtocol::Tcp) => Some(Protocol::Tcp),
                Ok(PortProtocol::Udp) => Some(Protocol::Udp),
                _ => None,
            },
            first: rule.port,
            last: rule.port_end,
            cidrs: rule.cidrs.clone(),
        }
    }
}

/// A validated [`PortDenial`]: only these numbers ever reach the ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortBlock {
    pub(crate) protocol: Option<Protocol>,
    pub(crate) first: u16,
    pub(crate) last: u16,
    pub(crate) cidrs: Vec<Cidr>,
}

impl PortBlock {
    fn validate(denial: &PortDenial) -> Option<Self> {
        let first = u16::try_from(denial.first).ok().filter(|p| *p != 0)?;
        let last = match denial.last {
            0 => first,
            last => u16::try_from(last).ok().filter(|l| *l >= first)?,
        };
        if denial.cidrs.len() > MAX_PORT_DENIAL_CIDRS {
            return None;
        }
        let cidrs = denial
            .cidrs
            .iter()
            .map(|entry| parse_cidr(entry))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            protocol: denial.protocol,
            first,
            last,
            cidrs,
        })
    }

    /// The nftables keywords of the transports this covers.
    pub(crate) fn protocols(&self) -> &'static [&'static str] {
        match self.protocol {
            None => &["tcp", "udp"],
            Some(Protocol::Tcp) => &["tcp"],
            Some(Protocol::Udp) => &["udp"],
        }
    }

    /// The ports as an nftables value: `25`, or the range `465-587`.
    pub(crate) fn ports(&self) -> String {
        if self.first == self.last {
            self.first.to_string()
        } else {
            format!("{}-{}", self.first, self.last)
        }
    }

    fn matches(&self, destination: IpAddr, transport: Transport, port: u16) -> bool {
        let protocol = match transport {
            Transport::Tcp => Protocol::Tcp,
            Transport::Udp => Protocol::Udp,
            Transport::Icmp => return false,
        };
        self.protocol.is_none_or(|p| p == protocol)
            && (self.first..=self.last).contains(&port)
            && (self.cidrs.is_empty() || self.cidrs.iter().any(|c| c.contains(destination)))
    }
}

/// A sandbox's validated denials: ranges and ports refused ahead of every
/// allowance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Denials {
    pub(crate) cidrs: Vec<Cidr>,
    pub(crate) ports: Vec<PortBlock>,
}

impl Denials {
    fn refusal(
        &self,
        destination: IpAddr,
        transport: Transport,
        port: u16,
    ) -> Option<&'static str> {
        if self.cidrs.iter().any(|cidr| cidr.contains(destination)) {
            Some("destination is in a denied range")
        } else if self
            .ports
            .iter()
            .any(|block| block.matches(destination, transport, port))
        {
            Some("destination port is denied")
        } else {
            None
        }
    }
}

/// The validated form of a sandbox's L3 allowance, or `None` when any part of
/// it is malformed.
///
/// All-or-nothing per sandbox, failing to no allowance at all rather than to
/// the subset that happened to parse. Letting one bad record abort the render
/// would freeze the whole node's ruleset, since every sandbox is re-rendered
/// into one transactional `nft -f -` script.
pub(crate) fn validated_allowance(
    sandbox_id: &str,
    allow_cidrs: &[String],
    allow_ports: &[u32],
) -> Option<(Vec<Cidr>, Vec<u16>)> {
    let mut cidrs = Vec::with_capacity(allow_cidrs.len());
    for entry in allow_cidrs {
        // IPv4 only: an allowance is forwarded at L3, and nothing but open
        // mode forwards IPv6.
        match parse_cidr(entry).filter(|cidr| cidr.is_v4()) {
            Some(cidr) => cidrs.push(cidr),
            None => {
                tracing::error!(
                    sandbox = sandbox_id,
                    "rejecting a malformed allow_cidrs entry; this sandbox gets no \
                     address allowance"
                );
                return None;
            }
        }
    }

    let mut ports = Vec::with_capacity(allow_ports.len());
    for port in allow_ports {
        match u16::try_from(*port) {
            Ok(port) => ports.push(port),
            Err(_) => {
                tracing::error!(
                    sandbox = sandbox_id,
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

/// The validated form of a sandbox's denied ranges and ports, or `None` when
/// any entry is malformed.
///
/// Fails the opposite way from [`validated_allowance`]: dropping an unparseable
/// denial would grant exactly the access the operator asked to withhold, so the
/// caller turns `None` into a blanket drop for the sandbox.
pub(crate) fn validated_denials(
    sandbox_id: &str,
    deny_cidrs: &[String],
    deny_ports: &[PortDenial],
) -> Option<Denials> {
    let mut cidrs = Vec::with_capacity(deny_cidrs.len());
    for entry in deny_cidrs {
        match parse_cidr(entry) {
            Some(cidr) => cidrs.push(cidr),
            None => {
                tracing::error!(
                    sandbox = sandbox_id,
                    "rejecting a malformed deny_cidrs entry; this sandbox gets no egress \
                     at all"
                );
                return None;
            }
        }
    }
    if deny_ports.len() > MAX_PORT_DENIALS {
        tracing::error!(
            sandbox = sandbox_id,
            count = deny_ports.len(),
            "rejecting an oversized deny_ports list; this sandbox gets no egress at all"
        );
        return None;
    }
    let mut ports = Vec::with_capacity(deny_ports.len());
    for denial in deny_ports {
        match PortBlock::validate(denial) {
            Some(block) => ports.push(block),
            None => {
                tracing::error!(
                    sandbox = sandbox_id,
                    "rejecting a malformed deny_ports entry; this sandbox gets no egress \
                     at all"
                );
                return None;
            }
        }
    }
    Some(Denials { cidrs, ports })
}

/// Most ingress rules one policy may carry, and most ports or sources one rule
/// may name.
pub const MAX_INGRESS_RULES: usize = 64;
pub const MAX_INGRESS_ENTRIES: usize = 16;

/// What an ingress rule admits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IngressProtocol {
    /// TCP and UDP.
    #[default]
    Both,
    Tcp,
    Udp,
    /// Echo requests, in the family each source names.
    Icmp,
}

/// One `NetworkPolicy.ingress` entry as the caller wrote it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngressRule {
    pub protocol: IngressProtocol,
    /// `(first, last)`, with 0 as `last` meaning `first` alone. Empty is every
    /// port.
    pub ports: Vec<(u32, u32)>,
    /// Source ranges of either family. Empty is anyone.
    pub sources: Vec<String>,
}

impl From<&burrow_proto::common::v1::IngressRule> for IngressRule {
    fn from(rule: &burrow_proto::common::v1::IngressRule) -> Self {
        use burrow_proto::common::v1::IngressProtocol as Proto;
        Self {
            protocol: match Proto::try_from(rule.protocol) {
                Ok(Proto::Tcp) => IngressProtocol::Tcp,
                Ok(Proto::Udp) => IngressProtocol::Udp,
                Ok(Proto::Icmp) => IngressProtocol::Icmp,
                _ => IngressProtocol::Both,
            },
            ports: rule.ports.iter().map(|r| (r.port, r.port_end)).collect(),
            sources: rule.sources.clone(),
        }
    }
}

/// A validated [`IngressRule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Door {
    pub(crate) protocol: IngressProtocol,
    pub(crate) ports: Vec<(u16, u16)>,
    pub(crate) sources: Vec<Cidr>,
}

impl Door {
    fn validate(rule: &IngressRule) -> Option<Self> {
        if rule.ports.len() > MAX_INGRESS_ENTRIES || rule.sources.len() > MAX_INGRESS_ENTRIES {
            return None;
        }
        if rule.protocol == IngressProtocol::Icmp && !rule.ports.is_empty() {
            return None;
        }
        let ports = rule
            .ports
            .iter()
            .map(|(first, last)| {
                let first = u16::try_from(*first).ok().filter(|p| *p != 0)?;
                let last = match last {
                    0 => first,
                    last => u16::try_from(*last).ok().filter(|l| *l >= first)?,
                };
                Some((first, last))
            })
            .collect::<Option<Vec<_>>>()?;
        let sources = rule
            .sources
            .iter()
            .map(|entry| parse_cidr(entry))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            protocol: rule.protocol,
            ports,
            sources,
        })
    }

    /// The ports as an nftables value, `{ 25, 465-587 }`, or `None` for every
    /// port.
    pub(crate) fn port_set(&self) -> Option<String> {
        if self.ports.is_empty() {
            return None;
        }
        let ports: Vec<String> = self
            .ports
            .iter()
            .map(|(first, last)| match first == last {
                true => first.to_string(),
                false => format!("{first}-{last}"),
            })
            .collect();
        Some(format!("{{ {} }}", ports.join(", ")))
    }

    /// The sources of one family, `None` when the rule admits anyone and an
    /// empty list when it names only the other family's.
    pub(crate) fn sources_of(&self, is_v4: bool) -> Option<Vec<Cidr>> {
        if self.sources.is_empty() {
            return None;
        }
        Some(
            self.sources
                .iter()
                .copied()
                .filter(|cidr| cidr.is_v4() == is_v4)
                .collect(),
        )
    }

    /// Whether this admits `transport` from `source` on `port`.
    #[cfg(test)]
    pub(crate) fn admits(&self, source: IpAddr, transport: Transport, port: u16) -> bool {
        let is_protocol = matches!(
            (self.protocol, transport),
            (IngressProtocol::Both, Transport::Tcp | Transport::Udp)
                | (IngressProtocol::Tcp, Transport::Tcp)
                | (IngressProtocol::Udp, Transport::Udp)
                | (IngressProtocol::Icmp, Transport::Icmp)
        );
        is_protocol
            && (self.ports.is_empty()
                || self
                    .ports
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(&port)))
            && (self.sources.is_empty() || self.sources.iter().any(|cidr| cidr.contains(source)))
    }
}

/// A sandbox's validated ingress, or `None` when any rule is malformed, which
/// admits nothing at all rather than the rules that happened to parse.
pub(crate) fn validated_ingress(sandbox_id: &str, rules: &[IngressRule]) -> Option<Vec<Door>> {
    if rules.len() > MAX_INGRESS_RULES {
        tracing::error!(
            sandbox = sandbox_id,
            "rejecting an oversized ingress list; nothing is admitted"
        );
        return None;
    }
    let doors = rules.iter().map(Door::validate).collect::<Option<Vec<_>>>();
    if doors.is_none() {
        tracing::error!(
            sandbox = sandbox_id,
            "rejecting a malformed ingress rule; nothing is admitted"
        );
    }
    doors
}

/// What a sandbox's policy refuses ahead of every allowance, as the caller
/// wrote it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Deny<'a> {
    pub cidrs: &'a [String],
    pub ports: &'a [PortDenial],
    /// Refuse every IPv6 destination beyond the sandbox's own gateway.
    pub is_ipv6_denied: bool,
}

/// One sandbox's L3 policy, validated once rather than per flow.
#[derive(Debug, Clone)]
pub struct Rules {
    mode: Mode,
    allowance: Option<(Vec<Cidr>, Vec<u16>)>,
    denials: Option<Denials>,
    is_ipv6_denied: bool,
    peers: Vec<Ipv4Addr>,
}

impl Rules {
    /// Validates a sandbox's policy fields, logging (once, here) any entry
    /// that costs the sandbox its allowance or its egress.
    pub fn new(
        sandbox_id: &str,
        mode: Mode,
        allow_cidrs: &[String],
        allow_ports: &[u32],
        deny: Deny<'_>,
        peers: &[Ipv4Addr],
    ) -> Self {
        Self {
            mode,
            allowance: validated_allowance(sandbox_id, allow_cidrs, allow_ports),
            denials: validated_denials(sandbox_id, deny.cidrs, deny.ports),
            is_ipv6_denied: deny.is_ipv6_denied,
            peers: peers.to_vec(),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }
}

/// Addresses denied to every sandbox on a node, whatever its policy.
#[derive(Debug, Clone, Default)]
pub struct NodeDenials {
    /// The orchestrator, every edge router and every node's API and Access
    /// endpoints. See [`crate::firewall::render_with`].
    pub control_plane: Vec<IpAddr>,
    /// This node's own addresses. On Linux a packet for one is delivered
    /// locally and meets the host input chain, which admits nothing but the
    /// gateway's services; a userspace stack dials outward from the node, so
    /// it must refuse these itself, loopback included.
    pub node: Vec<IpAddr>,
}

impl NodeDenials {
    fn is_node(&self, address: IpAddr) -> bool {
        address.is_loopback() || self.node.contains(&address)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    /// An echo request. Carries no port.
    Icmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// One of the gateway's own services: the resolver, or ICMP echo.
    Host,
    /// Through the egress proxy, which decides by name.
    Proxy,
    /// Straight to the destination.
    Direct,
    /// Refused, with a reason suitable for an audit record.
    Deny(&'static str),
}

/// Decides one new flow from a sandbox whose gateway is `host`.
///
/// Ordered exactly as the ruleset is evaluated: the allowlist redirect in NAT
/// prerouting first, then the host input chain for anything addressed to the
/// node, then the sandbox chain with its unconditional denials ahead of every
/// accept.
pub fn decide(
    rules: &Rules,
    host: Ipv4Addr,
    node: &NodeDenials,
    destination: IpAddr,
    transport: Transport,
    port: u16,
) -> Verdict {
    let is_peer = matches!(destination, IpAddr::V4(v4) if rules.peers.contains(&v4));
    // A sandbox denied IPv6 gets no v6 redirect: the proxy is egress too.
    let is_redirected_family = destination.is_ipv4() || !rules.is_ipv6_denied;
    // Denied ports on 80 and 443 are not exempt from the redirect. The proxy
    // refuses them, as it refuses a denied range, and records the refusal.
    if rules.mode == Mode::Allowlist
        && transport == Transport::Tcp
        && PROXIED_PORTS.contains(&port)
        && !is_peer
        && is_redirected_family
    {
        return Verdict::Proxy;
    }

    if destination == IpAddr::V4(host) || node.is_node(destination) {
        return match transport {
            Transport::Icmp => Verdict::Host,
            Transport::Udp
                if destination == IpAddr::V4(host)
                    && port == DNS_PORT
                    && !matches!(rules.mode, Mode::None | Mode::Unspecified) =>
            {
                Verdict::Host
            }
            Transport::Tcp
                if destination == IpAddr::V4(host)
                    && port == PROXY_PORT
                    && rules.mode == Mode::Allowlist =>
            {
                Verdict::Proxy
            }
            _ => Verdict::Deny("destination is this node"),
        };
    }

    if node.control_plane.contains(&destination) {
        return Verdict::Deny("destination is a control-plane address");
    }

    let v4 = match destination {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => return decide_v6(rules, v6, transport, port),
    };
    if METADATA_CIDR.contains(destination) {
        return Verdict::Deny("destination is an internal or metadata address");
    }
    let Some(denials) = &rules.denials else {
        return Verdict::Deny("policy has a malformed denial");
    };
    if let Some(reason) = denials.refusal(destination, transport, port) {
        return Verdict::Deny(reason);
    }
    let destination = v4;
    if is_peer {
        return Verdict::Direct;
    }
    if rules.mode == Mode::Open {
        if SANDBOX_POOL.contains(IpAddr::V4(destination)) {
            return Verdict::Deny("destination is another sandbox");
        }
        return Verdict::Direct;
    }
    if let Some((cidrs, ports)) = &rules.allowance
        && cidrs
            .iter()
            .any(|cidr| cidr.contains(IpAddr::V4(destination)))
        && (ports.is_empty() || (transport != Transport::Icmp && ports.contains(&port)))
    {
        return Verdict::Direct;
    }
    Verdict::Deny(match rules.mode {
        Mode::None | Mode::Unspecified => "sandbox has no egress",
        _ => "destination not in allowlist",
    })
}

/// Decides a new flow arriving for the sandbox with `rules` from `source`,
/// another sandbox's address: the `ip saddr {peer} ip daddr {guest} accept`
/// its sandbox chain renders, which is all a flow arriving over the mesh meets
/// on Linux.
pub fn decide_ingress(rules: &Rules, source: Ipv4Addr) -> Verdict {
    if rules.peers.contains(&source) {
        Verdict::Direct
    } else {
        Verdict::Deny("source shares no private network with this sandbox")
    }
}

/// Decides a new flow from one sandbox to another sandbox's address, on a
/// node that forwards between them itself.
///
/// `sender` is the sending sandbox's own [`decide`] when it is on this node,
/// and `None` when the flow arrived over the mesh, already admitted by the
/// sender's node. `receiver` is the receiving sandbox's rules when it is on
/// this node, and `None` when the flow leaves over the mesh for the
/// receiver's node to admit. Anything but `Direct` from the sender stands, so
/// allowlist web traffic to a non-member still goes to the proxy.
pub fn decide_peer(sender: Option<Verdict>, receiver: Option<&Rules>, source: Ipv4Addr) -> Verdict {
    if let Some(verdict) = sender
        && verdict != Verdict::Direct
    {
        return verdict;
    }
    match receiver {
        Some(rules) => decide_ingress(rules, source),
        None => Verdict::Direct,
    }
}

/// The sandbox chain's v6 rules: link-local denied in every mode, then the
/// policy's own denials, and only open mode forwarding at all, never into the
/// fleet's v6 pool.
fn decide_v6(rules: &Rules, destination: Ipv6Addr, transport: Transport, port: u16) -> Verdict {
    if (destination.segments()[0] & 0xffc0) == 0xfe80 {
        return Verdict::Deny("destination is an internal or metadata address");
    }
    if rules.is_ipv6_denied {
        return Verdict::Deny("ipv6 egress is denied");
    }
    let Some(denials) = &rules.denials else {
        return Verdict::Deny("policy has a malformed denial");
    };
    if let Some(reason) = denials.refusal(IpAddr::V6(destination), transport, port) {
        return Verdict::Deny(reason);
    }
    if rules.mode != Mode::Open {
        return Verdict::Deny("ipv6 egress is open mode only");
    }
    if destination.segments()[..3] == crate::ipam::POOL6_ADDRESS.segments()[..3] {
        return Verdict::Deny("destination is another sandbox");
    }
    Verdict::Direct
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{SandboxRules, render_with};

    const HOST: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 5);
    const GUEST: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 6);
    const NODE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    const CONTROL: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    fn sandbox(mode: Mode) -> SandboxRules {
        SandboxRules {
            sandbox_id: "sbx_test".into(),
            tap: "bt1".into(),
            host_ip: HOST,
            guest_ip: GUEST,
            host_ip6: "fd99:b070:0:1::1".parse().unwrap(),
            guest_ip6: "fd99:b070:0:1::2".parse().unwrap(),
            mode,
            allow_cidrs: vec![],
            deny_cidrs: vec![],
            deny_ports: vec![],
            is_ipv6_denied: false,
            allow_ports: vec![],
            peers: vec![],
            ports: vec![],
            inspected: None,
            public: Default::default(),
        }
    }

    fn rules_of(sandbox: &SandboxRules) -> Rules {
        Rules::new(
            &sandbox.sandbox_id,
            sandbox.mode,
            &sandbox.allow_cidrs,
            &sandbox.allow_ports,
            Deny {
                cidrs: &sandbox.deny_cidrs,
                ports: &sandbox.deny_ports,
                is_ipv6_denied: sandbox.is_ipv6_denied,
            },
            &sandbox.peers,
        )
    }

    /// The `<proto> dport <ports>` match of a rule, if it has one, as
    /// inclusive ranges: a port is `25` or `465-587`.
    fn dport(rule: &str) -> Option<(&str, Vec<(u16, u16)>)> {
        let (head, rest) = rule.split_once(" dport ")?;
        let proto = head.rsplit(' ').next()?;
        let list = match rest.strip_prefix("{ ") {
            Some(set) => set.split(" }").next()?,
            None => rest.split(' ').next()?,
        };
        Some((
            proto,
            list.split(", ")
                .map(|p| match p.split_once('-') {
                    Some((a, b)) => (a.parse().unwrap(), b.parse().unwrap()),
                    None => (p.parse().unwrap(), p.parse().unwrap()),
                })
                .collect(),
        ))
    }

    /// Whether a rule's `ip daddr` match, a CIDR or a `{ set }` of them,
    /// covers `to`.
    fn daddr(rule: &str, to: Ipv4Addr) -> bool {
        let Some((_, rest)) = rule.split_once("ip daddr ") else {
            return true;
        };
        let covers = |entry: &str| parse_cidr(entry).is_some_and(|c| c.contains(IpAddr::V4(to)));
        match rest.strip_prefix("{ ") {
            Some(set) => set.split(" }").next().unwrap().split(", ").any(covers),
            None => covers(rest.split(' ').next().unwrap()),
        }
    }

    /// What the rendered ruleset does with the first packet of a new v4 flow
    /// from the guest: a small evaluator over exactly the rule shapes the
    /// renderer emits for one sandbox. Returns the verdict kind only, since
    /// nftables carries no reasons.
    fn evaluate(ruleset: &str, to: Ipv4Addr, transport: Transport, port: u16) -> Verdict {
        let guest = format!("ip saddr {GUEST}");
        let proto = match transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Icmp => "icmp",
        };
        let matches = |rule: &str, to: Ipv4Addr, port: u16| {
            daddr(rule, to)
                && dport(rule).is_none_or(|(p, ports)| {
                    p == proto && ports.iter().any(|(a, b)| (*a..=*b).contains(&port))
                })
        };
        let chain = |name: &str| {
            let prefix = format!("add rule {name} ");
            ruleset
                .lines()
                .filter_map(move |line| line.strip_prefix(prefix.as_str()).map(str::to_string))
                .collect::<Vec<_>>()
        };

        // NAT prerouting, where a peer accept skips the redirect.
        let redirected = chain("ip burrow_nat prerouting")
            .iter()
            .find(|rule| rule.starts_with(&guest) && matches(rule, to, port))
            .is_some_and(|rule| rule.contains("redirect to"));
        let (to, port) = if redirected {
            (HOST, PROXY_PORT)
        } else {
            (to, port)
        };

        if to == HOST || IpAddr::V4(to) == NODE {
            for rule in chain("inet burrow tohost") {
                if rule == "icmp type echo-request accept" {
                    if transport == Transport::Icmp {
                        return Verdict::Host;
                    }
                } else if rule == "drop" {
                    return Verdict::Deny("");
                } else if rule.starts_with(&guest) && matches(&rule, to, port) {
                    return if port == PROXY_PORT {
                        Verdict::Proxy
                    } else {
                        Verdict::Host
                    };
                }
            }
            unreachable!("tohost ends in a drop");
        }

        for rule in chain("inet burrow sandbox") {
            if rule.starts_with("ct state") || rule.contains("ip6 ") {
                continue;
            }
            let applies = rule == "drop"
                || ((rule.starts_with(&guest) || rule.starts_with("ip daddr "))
                    && matches(&rule, to, port));
            if !applies {
                continue;
            }
            return match rule.rsplit(' ').next() {
                Some("drop") => Verdict::Deny(""),
                _ => Verdict::Direct,
            };
        }
        unreachable!("the sandbox chain ends in a drop");
    }

    fn same_kind(a: Verdict, b: Verdict) -> bool {
        std::mem::discriminant(&a) == std::mem::discriminant(&b)
    }

    #[test]
    fn the_ruleset_and_the_decision_agree() {
        let public = Ipv4Addr::new(93, 184, 216, 34);
        let lan = Ipv4Addr::new(10, 2, 3, 4);
        let denied_in_lan = Ipv4Addr::new(10, 2, 9, 9);
        let peer = Ipv4Addr::new(10, 99, 4, 6);
        let neighbour = Ipv4Addr::new(10, 99, 0, 10);
        let metadata = Ipv4Addr::new(169, 254, 169, 254);
        let control = match CONTROL {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!(),
        };
        let node = match NODE {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!(),
        };

        let mut allow = sandbox(Mode::Allowlist);
        allow.allow_cidrs = vec!["10.2.0.0/16".into()];
        allow.deny_cidrs = vec!["10.2.9.0/24".into()];
        let mut allow_ports = allow.clone();
        allow_ports.allow_ports = vec![5432];
        let mut open = sandbox(Mode::Open);
        open.deny_cidrs = vec!["10.2.9.0/24".into()];
        open.peers = vec![peer];
        let mut broken = sandbox(Mode::Open);
        broken.deny_cidrs = vec!["not a cidr".into()];
        let mut allow_with_peer = sandbox(Mode::Allowlist);
        allow_with_peer.peers = vec![peer];
        // Port denials: everywhere, a range, one transport, and one scoped to
        // a range, in both modes that have egress to deny.
        let smtp = vec![
            PortDenial {
                protocol: Some(Protocol::Tcp),
                first: 25,
                ..Default::default()
            },
            PortDenial {
                protocol: Some(Protocol::Tcp),
                first: 465,
                last: 587,
                ..Default::default()
            },
            PortDenial {
                protocol: None,
                first: 5432,
                cidrs: vec!["10.2.0.0/16".into(), "2001:db8::/32".into()],
                ..Default::default()
            },
        ];
        let mut open_ports = sandbox(Mode::Open);
        open_ports.deny_ports = smtp.clone();
        open_ports.peers = vec![peer];
        let mut allow_ports_denied = sandbox(Mode::Allowlist);
        allow_ports_denied.allow_cidrs = vec!["10.2.0.0/16".into()];
        allow_ports_denied.deny_ports = smtp.clone();
        allow_ports_denied.deny_ports.push(PortDenial {
            protocol: Some(Protocol::Tcp),
            first: 443,
            ..Default::default()
        });
        let mut broken_ports = sandbox(Mode::Open);
        broken_ports.deny_ports = vec![PortDenial {
            first: 600,
            last: 599,
            ..Default::default()
        }];

        let destinations = [
            public,
            lan,
            denied_in_lan,
            peer,
            neighbour,
            metadata,
            control,
            node,
            HOST,
        ];
        let probes = [
            (Transport::Tcp, 443),
            (Transport::Tcp, 80),
            (Transport::Tcp, 5432),
            (Transport::Tcp, 22),
            (Transport::Udp, 53),
            (Transport::Udp, 5432),
            (Transport::Tcp, PROXY_PORT),
            (Transport::Tcp, 25),
            (Transport::Udp, 25),
            (Transport::Tcp, 500),
            (Transport::Icmp, 0),
        ];
        let node_denials = NodeDenials {
            control_plane: vec![CONTROL],
            node: vec![NODE],
        };
        let mut checked = 0;
        for sandbox in [
            sandbox(Mode::None),
            sandbox(Mode::Allowlist),
            sandbox(Mode::Open),
            allow,
            allow_ports,
            open,
            broken,
            allow_with_peer,
            open_ports,
            allow_ports_denied,
            broken_ports,
        ] {
            let ruleset = render_with(std::slice::from_ref(&sandbox), &[CONTROL]);
            let rules = rules_of(&sandbox);
            for to in destinations {
                for (transport, port) in probes {
                    let decided =
                        decide(&rules, HOST, &node_denials, IpAddr::V4(to), transport, port);
                    let rendered = evaluate(&ruleset, to, transport, port);
                    assert!(
                        same_kind(decided, rendered),
                        "{:?} {:?} {to} {transport:?}/{port}: decide says {decided:?}, \
                         nftables says {rendered:?}",
                        sandbox.mode,
                        sandbox.allow_cidrs,
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 11 * 9 * 11);
    }

    /// What the rendered ruleset does with the first packet of a new flow
    /// from one sandbox address to another, whichever of them the ruleset
    /// names: the NAT redirect for a local sender, then the sandbox chain.
    fn evaluate_between(
        ruleset: &str,
        from: Ipv4Addr,
        to: Ipv4Addr,
        transport: Transport,
        port: u16,
    ) -> Verdict {
        let proto = match transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Icmp => "icmp",
        };
        let applies = |rule: &str| {
            let source = rule
                .strip_prefix("ip saddr ")
                .map(|rest| rest.split(' ').next().unwrap());
            !rule.contains("iifname")
                && source.is_none_or(|source| source == from.to_string())
                && daddr(rule, to)
                && dport(rule).is_none_or(|(p, ports)| {
                    p == proto && ports.iter().any(|(a, b)| (*a..=*b).contains(&port))
                })
        };
        let chain = |name: &str| {
            let prefix = format!("add rule {name} ");
            ruleset
                .lines()
                .filter_map(move |line| line.strip_prefix(prefix.as_str()).map(str::to_string))
                .collect::<Vec<_>>()
        };
        let redirected = chain("ip burrow_nat prerouting")
            .iter()
            .find(|rule| rule.starts_with(&format!("ip saddr {from} ")) && applies(rule))
            .is_some_and(|rule| rule.contains("redirect to"));
        if redirected {
            return Verdict::Proxy;
        }
        for rule in chain("inet burrow sandbox") {
            if rule.starts_with("ct state") || rule.contains("ip6 ") {
                continue;
            }
            if rule == "drop" || applies(&rule) {
                return match rule.rsplit(' ').next() {
                    Some("drop") => Verdict::Deny(""),
                    _ => Verdict::Direct,
                };
            }
        }
        unreachable!("the sandbox chain ends in a drop");
    }

    /// A node with no ruleset forwards between sandboxes itself, deciding
    /// each new flow with [`decide_peer`]. Rendered for the same pair, the
    /// ruleset must agree, both for two sandboxes on one node and for either
    /// half of a flow crossing the mesh.
    #[test]
    fn the_ruleset_and_the_peer_decision_agree() {
        let local = (Ipv4Addr::new(10, 99, 0, 5), Ipv4Addr::new(10, 99, 0, 6));
        let neighbour = (Ipv4Addr::new(10, 99, 0, 9), Ipv4Addr::new(10, 99, 0, 10));
        let remote = Ipv4Addr::new(10, 99, 4, 6);
        let member = |(host, guest): (Ipv4Addr, Ipv4Addr), mode, peer: Option<Ipv4Addr>| {
            let mut s = sandbox(mode);
            s.sandbox_id = format!("sbx_{guest}");
            s.host_ip = host;
            s.guest_ip = guest;
            s.peers = peer.into_iter().collect();
            s
        };
        let probes = [
            (Transport::Tcp, 80),
            (Transport::Tcp, 443),
            (Transport::Tcp, 22),
            (Transport::Udp, 5432),
            (Transport::Icmp, 0),
        ];
        let mut checked = 0;
        for sender_mode in [Mode::None, Mode::Allowlist, Mode::Open] {
            for receiver_mode in [Mode::None, Mode::Allowlist, Mode::Open] {
                for is_member in [true, false] {
                    // A denied range covering the peer, or denied ports
                    // narrowed to nothing else: either is egress, and holds
                    // between peers as it does towards the internet.
                    for denial in [None, Some(false), Some(true)] {
                        let is_denied = denial.is_some();
                        let deny = |sandbox: &mut SandboxRules, cidr: &str| match denial {
                            Some(false) => sandbox.deny_cidrs = vec![cidr.into()],
                            Some(true) => {
                                sandbox.deny_ports = vec![
                                    PortDenial {
                                        protocol: Some(Protocol::Tcp),
                                        first: 22,
                                        cidrs: vec![cidr.into()],
                                        ..Default::default()
                                    },
                                    PortDenial {
                                        protocol: None,
                                        first: 5000,
                                        last: 6000,
                                        ..Default::default()
                                    },
                                ]
                            }
                            None => {}
                        };
                        for (transport, port) in probes {
                            // Both on this node.
                            let mut sender =
                                member(local, sender_mode, is_member.then_some(neighbour.1));
                            deny(&mut sender, "10.99.0.8/29");
                            let receiver =
                                member(neighbour, receiver_mode, is_member.then_some(local.1));
                            let ruleset = render_with(&[sender.clone(), receiver.clone()], &[]);
                            let decided = decide_peer(
                                Some(decide(
                                    &rules_of(&sender),
                                    local.0,
                                    &NodeDenials::default(),
                                    IpAddr::V4(neighbour.1),
                                    transport,
                                    port,
                                )),
                                Some(&rules_of(&receiver)),
                                local.1,
                            );
                            let rendered =
                                evaluate_between(&ruleset, local.1, neighbour.1, transport, port);
                            assert!(
                                same_kind(decided, rendered),
                                "local {sender_mode:?} -> {receiver_mode:?} member={is_member} \
                                 denied={is_denied} {transport:?}/{port}: {decided:?} vs {rendered:?}"
                            );

                            // Leaving for a peer on another node.
                            let mut sender =
                                member(local, sender_mode, is_member.then_some(remote));
                            deny(&mut sender, "10.99.4.0/24");
                            let ruleset = render_with(std::slice::from_ref(&sender), &[]);
                            let decided = decide_peer(
                                Some(decide(
                                    &rules_of(&sender),
                                    local.0,
                                    &NodeDenials::default(),
                                    IpAddr::V4(remote),
                                    transport,
                                    port,
                                )),
                                None,
                                local.1,
                            );
                            let rendered =
                                evaluate_between(&ruleset, local.1, remote, transport, port);
                            assert!(
                                same_kind(decided, rendered),
                                "outbound {sender_mode:?} member={is_member} denied={is_denied} \
                                 {transport:?}/{port}: {decided:?} vs {rendered:?}"
                            );

                            // Arriving over the mesh from a peer on another node.
                            let mut receiver =
                                member(neighbour, receiver_mode, is_member.then_some(remote));
                            deny(&mut receiver, "10.99.4.0/24");
                            let ruleset = render_with(std::slice::from_ref(&receiver), &[]);
                            let decided = decide_peer(None, Some(&rules_of(&receiver)), remote);
                            let rendered =
                                evaluate_between(&ruleset, remote, neighbour.1, transport, port);
                            assert!(
                                same_kind(decided, rendered),
                                "inbound {receiver_mode:?} member={is_member} denied={is_denied} \
                                 {transport:?}/{port}: {decided:?} vs {rendered:?}"
                            );
                            checked += 3;
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 3 * 3 * 2 * 3 * 5 * 3);
    }

    #[test]
    fn a_denied_range_beats_an_allowed_one() {
        let rules = Rules::new(
            "sbx",
            Mode::Allowlist,
            &["10.2.0.0/16".into()],
            &[],
            Deny {
                cidrs: &["10.2.9.0/24".into()],
                ..Default::default()
            },
            &[],
        );
        let at = |a: [u8; 4]| {
            decide(
                &rules,
                HOST,
                &NodeDenials::default(),
                IpAddr::from(a),
                Transport::Tcp,
                5432,
            )
        };
        assert_eq!(at([10, 2, 3, 4]), Verdict::Direct);
        assert_eq!(
            at([10, 2, 9, 9]),
            Verdict::Deny("destination is in a denied range")
        );
    }

    #[test]
    fn loopback_is_the_node() {
        let rules = Rules::new("sbx", Mode::Open, &[], &[], Deny::default(), &[]);
        assert_eq!(
            decide(
                &rules,
                HOST,
                &NodeDenials::default(),
                IpAddr::from([127, 0, 0, 1]),
                Transport::Tcp,
                22
            ),
            Verdict::Deny("destination is this node")
        );
    }

    #[test]
    fn port_restrictions_narrow_the_allowance() {
        let rules = Rules::new(
            "sbx",
            Mode::Allowlist,
            &["10.2.0.0/16".into()],
            &[5432],
            Deny::default(),
            &[],
        );
        let to = IpAddr::from([10, 2, 3, 4]);
        let node = NodeDenials::default();
        assert_eq!(
            decide(&rules, HOST, &node, to, Transport::Udp, 5432),
            Verdict::Direct
        );
        assert!(matches!(
            decide(&rules, HOST, &node, to, Transport::Tcp, 22),
            Verdict::Deny(_)
        ));
        assert!(matches!(
            decide(&rules, HOST, &node, to, Transport::Icmp, 0),
            Verdict::Deny(_)
        ));
    }

    fn decide_v6(rules: &Rules, to: &str, transport: Transport, port: u16) -> Verdict {
        decide(
            rules,
            HOST,
            &NodeDenials::default(),
            to.parse().unwrap(),
            transport,
            port,
        )
    }

    #[test]
    fn a_denied_port_beats_open_mode_and_peers_in_both_families() {
        let peer = Ipv4Addr::new(10, 99, 4, 6);
        let rules = Rules::new(
            "sbx",
            Mode::Open,
            &[],
            &[],
            Deny {
                ports: &[PortDenial {
                    protocol: Some(Protocol::Tcp),
                    first: 25,
                    ..Default::default()
                }],
                ..Default::default()
            },
            &[peer],
        );
        let node = NodeDenials::default();
        let at = |to: IpAddr, transport, port| decide(&rules, HOST, &node, to, transport, port);
        let public = IpAddr::from([93, 184, 216, 34]);
        assert_eq!(
            at(public, Transport::Tcp, 25),
            Verdict::Deny("destination port is denied")
        );
        assert_eq!(
            at(IpAddr::V4(peer), Transport::Tcp, 25),
            Verdict::Deny("destination port is denied")
        );
        // Only the transport and port named.
        assert_eq!(at(public, Transport::Udp, 25), Verdict::Direct);
        assert_eq!(at(public, Transport::Tcp, 26), Verdict::Direct);
        assert_eq!(
            decide_v6(&rules, "2001:db8::25", Transport::Tcp, 25),
            Verdict::Deny("destination port is denied")
        );
        assert_eq!(
            decide_v6(&rules, "2001:db8::25", Transport::Tcp, 443),
            Verdict::Direct
        );
    }

    #[test]
    fn a_scoped_port_denial_applies_only_to_its_ranges_and_family() {
        let rules = Rules::new(
            "sbx",
            Mode::Open,
            &[],
            &[],
            Deny {
                ports: &[PortDenial {
                    protocol: None,
                    first: 5000,
                    last: 5999,
                    cidrs: vec!["10.2.0.0/16".into()],
                }],
                ..Default::default()
            },
            &[],
        );
        let node = NodeDenials::default();
        let at = |to: [u8; 4], transport, port| {
            decide(&rules, HOST, &node, IpAddr::from(to), transport, port)
        };
        assert!(matches!(
            at([10, 2, 3, 4], Transport::Udp, 5432),
            Verdict::Deny(_)
        ));
        assert!(matches!(
            at([10, 2, 3, 4], Transport::Tcp, 5999),
            Verdict::Deny(_)
        ));
        assert_eq!(at([10, 3, 3, 4], Transport::Tcp, 5432), Verdict::Direct);
        assert_eq!(at([10, 2, 3, 4], Transport::Tcp, 6000), Verdict::Direct);
        // A v4-only scope says nothing about v6.
        assert_eq!(
            decide_v6(&rules, "2001:db8::1", Transport::Tcp, 5432),
            Verdict::Direct
        );
    }

    #[test]
    fn allowlist_hands_a_denied_web_port_to_the_proxy_to_refuse() {
        let rules = Rules::new(
            "sbx",
            Mode::Allowlist,
            &["10.2.0.0/16".into()],
            &[],
            Deny {
                ports: &[PortDenial {
                    protocol: Some(Protocol::Tcp),
                    first: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
            &[],
        );
        let node = NodeDenials::default();
        // The proxy refuses it, and records the refusal.
        assert_eq!(
            decide(
                &rules,
                HOST,
                &node,
                IpAddr::from([1, 2, 3, 4]),
                Transport::Tcp,
                443
            ),
            Verdict::Proxy
        );
        // Off the proxied ports, the firewall refuses it ahead of allow_cidrs.
        let rules = Rules::new(
            "sbx",
            Mode::Allowlist,
            &["10.2.0.0/16".into()],
            &[],
            Deny {
                ports: &[PortDenial {
                    protocol: Some(Protocol::Tcp),
                    first: 5432,
                    ..Default::default()
                }],
                ..Default::default()
            },
            &[],
        );
        assert_eq!(
            decide(
                &rules,
                HOST,
                &node,
                IpAddr::from([10, 2, 3, 4]),
                Transport::Tcp,
                5432
            ),
            Verdict::Deny("destination port is denied")
        );
    }

    #[test]
    fn ipv6_follows_the_mode_unless_denied() {
        let rules = |mode, is_ipv6_denied, cidrs: &[String]| {
            Rules::new(
                "sbx",
                mode,
                &[],
                &[],
                Deny {
                    cidrs,
                    is_ipv6_denied,
                    ..Default::default()
                },
                &[],
            )
        };
        let public = "2606:2800:220:1::1";
        // The defaults, unchanged: open forwards, allowlist proxies the web
        // ports, none forwards nothing.
        assert_eq!(
            decide_v6(&rules(Mode::Open, false, &[]), public, Transport::Tcp, 22),
            Verdict::Direct
        );
        assert_eq!(
            decide_v6(
                &rules(Mode::Allowlist, false, &[]),
                public,
                Transport::Tcp,
                443
            ),
            Verdict::Proxy
        );
        assert!(matches!(
            decide_v6(&rules(Mode::None, false, &[]), public, Transport::Tcp, 443),
            Verdict::Deny(_)
        ));
        // Denied: nothing, in any mode, the proxy included.
        for mode in [Mode::Open, Mode::Allowlist, Mode::None] {
            for (transport, port) in [
                (Transport::Tcp, 443),
                (Transport::Udp, 53),
                (Transport::Icmp, 0),
            ] {
                assert!(
                    matches!(
                        decide_v6(&rules(mode, true, &[]), public, transport, port),
                        Verdict::Deny(_)
                    ),
                    "{mode:?} {transport:?}/{port}"
                );
            }
        }
        // IPv4 is untouched by the v6 denial.
        assert_eq!(
            decide(
                &rules(Mode::Open, true, &[]),
                HOST,
                &NodeDenials::default(),
                IpAddr::from([93, 184, 216, 34]),
                Transport::Tcp,
                443
            ),
            Verdict::Direct
        );
        // A v6 range in deny_cidrs is a denial on the v6 path.
        let ranged = rules(Mode::Open, false, &["2606:2800::/32".into()]);
        assert_eq!(
            decide_v6(&ranged, public, Transport::Tcp, 22),
            Verdict::Deny("destination is in a denied range")
        );
        assert_eq!(
            decide_v6(&ranged, "2001:db8::1", Transport::Tcp, 22),
            Verdict::Direct
        );
    }

    #[test]
    fn a_malformed_port_denial_costs_the_sandbox_its_egress() {
        let rules = Rules::new(
            "sbx",
            Mode::Open,
            &[],
            &[],
            Deny {
                ports: &[PortDenial {
                    first: 0,
                    ..Default::default()
                }],
                ..Default::default()
            },
            &[],
        );
        assert!(matches!(
            decide(
                &rules,
                HOST,
                &NodeDenials::default(),
                IpAddr::from([93, 184, 216, 34]),
                Transport::Tcp,
                443
            ),
            Verdict::Deny(_)
        ));
        assert!(matches!(
            decide_v6(&rules, "2001:db8::1", Transport::Tcp, 443),
            Verdict::Deny(_)
        ));
    }
}
