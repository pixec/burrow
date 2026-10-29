//! Whether a sandbox may reach a destination, and why not.
//!
//! One decision with two enforcers. On Linux [`crate::firewall`] renders it as
//! nftables rules; on a node with no nftables, [`crate::usernet`] asks it per
//! flow. Both read the validated forms built here, and a test renders the
//! ruleset and evaluates it against [`decide`] over a table of cases, so a
//! change to one that the other does not follow fails the build rather than
//! leaving two policies that disagree about the same sandbox.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::firewall::{DNS_PORT, Mode, PROXY_PORT};

/// The renderer's validated form of [`crate::firewall::SANDBOX_CIDR`]. Nothing
/// reaches the nft script that was not parsed first, a constant included, so
/// this is built from [`crate::ipam`]'s numbers rather than from the string.
pub(crate) const SANDBOX_POOL: Cidr = Cidr {
    addr: crate::ipam::POOL_ADDRESS,
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
    addr: Ipv4Addr::new(169, 254, 0, 0),
    prefix: 16,
};

/// Ports allowlist mode hands to the egress proxy, which decides by name.
pub const PROXIED_PORTS: [u16; 2] = [80, 443];

/// A validated `allow_cidrs` entry.
///
/// `nft -f -` reads a script, one command per line, so a caller's string
/// reaching it verbatim is rule injection: a newline inside a "CIDR" would
/// append rules of the attacker's choosing to burrow's own tables. Only the
/// parsed address and prefix are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    pub(crate) addr: Ipv4Addr,
    pub(crate) prefix: u8,
}

impl Cidr {
    pub(crate) fn contains(self, address: Ipv4Addr) -> bool {
        // A /0 covers everything, and shifting a u32 by 32 is undefined.
        let mask = match self.prefix {
            0 => 0,
            bits => u32::MAX << (32 - bits),
        };
        u32::from(self.addr) & mask == u32::from(address) & mask
    }
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
pub(crate) fn parse_cidr(value: &str) -> Option<Cidr> {
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
pub(crate) fn validated_allowance(
    sandbox_id: &str,
    allow_cidrs: &[String],
    allow_ports: &[u32],
) -> Option<(Vec<Cidr>, Vec<u16>)> {
    let mut cidrs = Vec::with_capacity(allow_cidrs.len());
    for entry in allow_cidrs {
        match parse_cidr(entry) {
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

/// The validated form of a sandbox's denied ranges, or `None` when any entry
/// is malformed.
///
/// Fails the opposite way from [`validated_allowance`]: dropping an unparseable
/// denial would grant exactly the access the operator asked to withhold, so the
/// caller turns `None` into a blanket drop for the sandbox.
pub(crate) fn validated_denials(sandbox_id: &str, deny_cidrs: &[String]) -> Option<Vec<Cidr>> {
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
    Some(cidrs)
}

/// One sandbox's L3 policy, validated once rather than per flow.
#[derive(Debug, Clone)]
pub struct Rules {
    mode: Mode,
    allowance: Option<(Vec<Cidr>, Vec<u16>)>,
    denials: Option<Vec<Cidr>>,
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
        deny_cidrs: &[String],
        peers: &[Ipv4Addr],
    ) -> Self {
        Self {
            mode,
            allowance: validated_allowance(sandbox_id, allow_cidrs, allow_ports),
            denials: validated_denials(sandbox_id, deny_cidrs),
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
    if rules.mode == Mode::Allowlist
        && transport == Transport::Tcp
        && PROXIED_PORTS.contains(&port)
        && !is_peer
    {
        return Verdict::Proxy;
    }

    if destination == IpAddr::V4(host) || node.is_node(destination) {
        return match transport {
            Transport::Icmp => Verdict::Host,
            Transport::Udp
                if destination == IpAddr::V4(host)
                    && port == DNS_PORT
                    && rules.mode != Mode::None =>
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

    let destination = match destination {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => return decide_v6(rules, v6),
    };
    if METADATA_CIDR.contains(destination) {
        return Verdict::Deny("destination is an internal or metadata address");
    }
    let Some(denials) = &rules.denials else {
        return Verdict::Deny("policy has a malformed deny_cidrs entry");
    };
    if denials.iter().any(|cidr| cidr.contains(destination)) {
        return Verdict::Deny("destination is in a denied range");
    }
    if is_peer {
        return Verdict::Direct;
    }
    if rules.mode == Mode::Open {
        if SANDBOX_POOL.contains(destination) {
            return Verdict::Deny("destination is another sandbox");
        }
        return Verdict::Direct;
    }
    if let Some((cidrs, ports)) = &rules.allowance
        && cidrs.iter().any(|cidr| cidr.contains(destination))
        && (ports.is_empty() || (transport != Transport::Icmp && ports.contains(&port)))
    {
        return Verdict::Direct;
    }
    Verdict::Deny(match rules.mode {
        Mode::None => "sandbox has no egress",
        _ => "destination not in allowlist",
    })
}

/// The sandbox chain's v6 rules: link-local denied in every mode, and only
/// open mode forwarding at all, never into the fleet's v6 pool.
fn decide_v6(rules: &Rules, destination: Ipv6Addr) -> Verdict {
    if (destination.segments()[0] & 0xffc0) == 0xfe80 {
        return Verdict::Deny("destination is an internal or metadata address");
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
            allow_ports: vec![],
            peers: vec![],
            ports: vec![],
        }
    }

    fn rules_of(sandbox: &SandboxRules) -> Rules {
        Rules::new(
            &sandbox.sandbox_id,
            sandbox.mode,
            &sandbox.allow_cidrs,
            &sandbox.allow_ports,
            &sandbox.deny_cidrs,
            &sandbox.peers,
        )
    }

    /// The `<proto> dport <ports>` match of a rule, if it has one.
    fn dport(rule: &str) -> Option<(&str, Vec<u16>)> {
        let (head, rest) = rule.split_once(" dport ")?;
        let proto = head.rsplit(' ').next()?;
        let list = match rest.strip_prefix("{ ") {
            Some(set) => set.split(" }").next()?,
            None => rest.split(' ').next()?,
        };
        Some((
            proto,
            list.split(", ").map(|p| p.parse().unwrap()).collect(),
        ))
    }

    /// Whether a rule's `ip daddr` match, a CIDR or a `{ set }`, covers `to`.
    fn daddr(rule: &str, to: Ipv4Addr) -> bool {
        let Some((_, rest)) = rule.split_once("ip daddr ") else {
            return true;
        };
        match rest.strip_prefix("{ ") {
            Some(set) => set
                .split(" }")
                .next()
                .unwrap()
                .split(", ")
                .any(|a| a == to.to_string()),
            None => parse_cidr(rest.split(' ').next().unwrap()).is_some_and(|c| c.contains(to)),
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
                && dport(rule).is_none_or(|(p, ports)| p == proto && ports.contains(&port))
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
        assert_eq!(checked, 8 * 9 * 8);
    }

    #[test]
    fn a_denied_range_beats_an_allowed_one() {
        let rules = Rules::new(
            "sbx",
            Mode::Allowlist,
            &["10.2.0.0/16".into()],
            &[],
            &["10.2.9.0/24".into()],
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
        let rules = Rules::new("sbx", Mode::Open, &[], &[], &[], &[]);
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
            &[],
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
}
