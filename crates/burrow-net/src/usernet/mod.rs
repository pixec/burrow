//! A userspace network stack for sandboxes on nodes without nftables.
//!
//! A macOS sandbox (a Virtualization.framework guest) has one NIC, attached
//! with `VZFileHandleNetworkDeviceAttachment` to one end of a `SOCK_DGRAM`
//! socket pair. Every Ethernet frame the guest sends arrives as one datagram
//! on the other end, which [`UserNet::attach`] takes. Nothing else connects the
//! guest to anything, so the guest reaches exactly what this stack forwards:
//! anti-spoofing is a property of the link, and the node is unreachable unless
//! a flow is dialled outward on the guest's behalf.
//!
//! # What the guest sees
//!
//! - **L2/L3.** ARP for the gateway (and the resolver address, when it
//!   differs) is answered; ARP for any other address, the guest's own
//!   included, is not. DHCPv4 hands out the sandbox's fixed address, gateway,
//!   resolver and MTU. Frames whose source MAC is not the guest's, and IPv4
//!   whose source is not the guest's address (DHCP from `0.0.0.0` aside), are
//!   dropped. IPv6 is dropped: there is no router advertisement, so a guest
//!   keeps only its link-local address, as on Linux where v6 is never
//!   forwarded outside open mode either.
//! - **DNS** on the resolver address, port 53, is answered by burrow-proxy's
//!   [`Resolver`] with this sandbox's policy: the same allowlist, the same
//!   `.internal` directory, the same pinning of answers that the proxy later
//!   checks connections against, the same audit records.
//! - **TCP** is terminated in smoltcp. A SYN creates a socket whose SYN-ACK is
//!   held back until the flow is decided, so a refused or unreachable
//!   destination answers with a reset, as a real one would, and the guest
//!   never sees a handshake complete for a connection nothing will carry.
//! - **UDP** other than DHCP and DNS is relayed per flow through a host
//!   socket, when the policy allows the destination.
//! - **ICMP** echo to the gateway is answered. Echo anywhere else is dropped:
//!   unprivileged ICMP sockets differ too much between hosts to relay.
//!
//! # Policy
//!
//! Each new flow is decided by [`crate::policy::decide`], the same function
//! the Linux ruleset is tested against, so the two enforce one policy:
//!
//! | Verdict | Here | On Linux |
//! | --- | --- | --- |
//! | `Proxy` (allowlist, TCP 80/443) | [`Proxy::serve_stream`]: SNI/Host allowlist, pinning, TLS inspection, request rules, credentials | nftables redirect to the same proxy |
//! | `Direct` (open mode, `allow_cidrs`/`allow_ports`, peers) | a host socket dialled to the destination, spliced | forward chain accept, masquerade |
//! | `Host` (the resolver, gateway ping) | answered in the stack | `tohost` accept |
//! | `Deny` | reset (TCP) or dropped (UDP), audited | chain drop |
//!
//! The node's own addresses and loopback are denied like the control plane,
//! because a flow from here is dialled from the node: on Linux the same
//! packets meet the host input chain, which admits nothing but the gateway's
//! services.
//!
//! The policy is a [`watch`] channel; a new value applies to the next flow,
//! and a direct flow the new policy denies is reset there and then, the way
//! the Linux path flushes conntrack after re-rendering.
//!
//! # Audit
//!
//! Records go to the node's [`AuditLog`] as [`EgressEvent`]s. Proxied flows
//! and DNS write exactly what they write on Linux, since the same code writes
//! them. Direct flows and refusals decided here write one record per flow,
//! allowed or not, with bytes in each direction: on Linux nftables decides
//! those and records nothing, so these are extra rather than different.
//! [`AuditLog::observed`] shows every record to a callback too.
//!
//! Two consequences of following the ruleset rather than FIREWALL.md's prose,
//! both of which the Linux path has too: in `none` mode the resolver is not
//! reachable at all, `.internal` names included, because `tohost` admits
//! UDP/53 only for modes with egress; and in allowlist mode TCP 80/443 goes to
//! the proxy even when an `allow_cidrs` entry covers the destination, because
//! the NAT redirect runs before the filter that would accept it.
//!
//! # Wiring it into a node
//!
//! - Build one [`Node`] from the pieces `serve.rs` already makes for the
//!   Linux proxy and resolver: the [`AuditLog`], [`Resolutions`],
//!   [`DeniedAddresses`] (kept current from the control-plane set), the
//!   inspection [`Authority`], the [`Directory`] and `--dns-upstream`.
//! - Per sandbox: a `SOCK_DGRAM` socketpair; one end, with `SO_SNDBUF` 1 MiB
//!   and `SO_RCVBUF` 4 MiB, goes to `burrow_vmm::vz::Network::Datagram`, the
//!   other to [`UserNet::attach`] with [`SandboxNet::from_lease`] (the VM's
//!   MAC must then be [`Lease::guest_mac`]).
//! - The policy is a `watch::Sender<Policy>` per sandbox: build
//!   [`Policy::new`] from the same `SandboxPolicy` the daemon puts in the
//!   proxy's table, plus the record's `allow_cidrs`, `allow_ports` and peers,
//!   and `send_replace` it wherever the daemon re-syncs the firewall.
//! - `ExposePort` is [`Handle::publish`] with a listener on the host port.
//! - Drop the [`Handle`] when the VM stops. Nothing of the stack is saved in
//!   a VM snapshot: attach a fresh one on restore. The guest keeps its lease,
//!   since the address is the same, and its open connections are reset.
//!
//! `examples/vz-usernet.rs` boots a macOS guest this way, with the policy
//! switchable from a control socket.
//!
//! # Not supported yet
//!
//! - IPv6 of any kind beyond dropping it, so open-mode v6 egress is missing.
//! - Private networks between sandboxes: each stack is its own island, so
//!   `peers` can only reach addresses the node itself routes to.
//! - ICMP beyond echo to the gateway, and IP fragments from the guest.
//! - TCP to the resolver: Linux does not admit it either.
//! - Link-local destinations (the metadata address among them) never reach
//!   the stack: a guest treats them as on-link and ARPs for them, which goes
//!   unanswered. Denied either way, but unaudited.

mod conn;
mod stack;
mod udp;
mod wire;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::Arc;

use burrow_proxy::directory::Directory;
use burrow_proxy::inspect::Authority;
use burrow_proxy::policy::NetworkMode;
use burrow_proxy::{AuditLog, DeniedAddresses, EgressEvent, Proxy, Resolutions, Resolver};
use tokio::sync::watch;

use crate::firewall::Mode;
use crate::ipam::Lease;
use crate::policy::Rules;

pub use conn::GuestConn;
pub use stack::Handle;
pub use wire::GATEWAY_MAC;

/// The guest's side of its link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxNet {
    pub mac: [u8; 6],
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub prefix: u8,
    /// Where the guest is told to resolve. Usually the gateway.
    pub dns_ip: Ipv4Addr,
    /// IP MTU, offered over DHCP and used to size TCP segments.
    pub mtu: u16,
}

impl SandboxNet {
    /// The link a Linux sandbox with this lease would have, with the MAC
    /// [`Lease::guest_mac`] gives it.
    pub fn from_lease(lease: &Lease) -> Self {
        let o = lease.guest_ip.octets();
        Self {
            mac: [0x02, 0x00, o[0], o[1], o[2], o[3]],
            guest_ip: lease.guest_ip,
            gateway_ip: lease.host_ip,
            prefix: lease.prefix_len,
            dns_ip: lease.host_ip,
            mtu: 1500,
        }
    }
}

/// One sandbox's egress policy, as both halves of the enforcement read it.
#[derive(Clone)]
pub struct Policy {
    /// What the proxy and the resolver decide by. Built the way the daemon
    /// builds it for the Linux proxy's table.
    pub proxy: burrow_proxy::SandboxPolicy,
    /// The L3 half, validated: mode and `deny_cidrs` from `proxy`, with the
    /// fields only nftables reads on Linux.
    pub rules: Rules,
}

impl Policy {
    pub fn new(
        proxy: burrow_proxy::SandboxPolicy,
        allow_cidrs: &[String],
        allow_ports: &[u32],
        peers: &[Ipv4Addr],
    ) -> Self {
        let mode = match proxy.mode {
            NetworkMode::None => Mode::None,
            NetworkMode::Allowlist => Mode::Allowlist,
            NetworkMode::Open => Mode::Open,
        };
        let rules = Rules::new(
            &proxy.sandbox_id,
            mode,
            allow_cidrs,
            allow_ports,
            &proxy.deny_cidrs,
            peers,
        );
        Self { proxy, rules }
    }
}

/// The node's share of egress, the same pieces the Linux daemon gives its
/// proxy and resolver, shared by every sandbox's stack.
pub struct Node {
    pub audit: AuditLog,
    /// What the resolver told each sandbox, keyed by sandbox id, which the
    /// proxy checks connections against.
    pub resolutions: Arc<Resolutions>,
    /// Control-plane addresses, kept current by the daemon.
    pub denied: Arc<DeniedAddresses>,
    /// Signs inspected sessions' certificates. `None` disables inspection.
    pub authority: Option<Arc<Authority>>,
    pub directory: Arc<Directory>,
    /// Where allowed queries are forwarded.
    pub dns_upstream: SocketAddr,
}

/// The stack itself; see the module docs.
pub struct UserNet;

impl UserNet {
    /// Starts serving the guest on `fd`, the daemon's end of the socket pair
    /// whose other end is the guest's NIC. Must be called inside a tokio
    /// runtime. Everything stops when the returned handle is dropped.
    pub fn attach(
        fd: OwnedFd,
        net: SandboxNet,
        policy: watch::Receiver<Policy>,
        node: Arc<Node>,
    ) -> std::io::Result<Handle> {
        stack::attach(fd, net, policy, node)
    }
}

/// The proxy and resolver one sandbox's flows are handed to.
///
/// Their policy table holds this sandbox alone, keyed by its guest address:
/// each stack is its own link, so two sandboxes could even share an address
/// without one being judged by the other's policy.
pub(crate) struct Services {
    pub proxy: Proxy,
    pub resolver: Resolver,
}

impl Services {
    fn new(node: &Node, policies: Arc<burrow_proxy::PolicyTable>) -> Self {
        Self {
            proxy: Proxy {
                policies: Arc::clone(&policies),
                audit: node.audit.clone(),
                resolutions: Arc::clone(&node.resolutions),
                authority: node.authority.clone(),
                denied: Arc::clone(&node.denied),
            },
            resolver: Resolver {
                policies,
                audit: node.audit.clone(),
                upstream: node.dns_upstream,
                resolutions: Arc::clone(&node.resolutions),
                directory: Arc::clone(&node.directory),
            },
        }
    }
}

/// One record for a flow this stack decided itself.
pub(crate) struct Flow<'a> {
    pub sandbox_id: &'a str,
    pub source: Ipv4Addr,
    pub destination: SocketAddr,
    pub is_allowed: bool,
    pub reason: String,
    pub sent: u64,
    pub received: u64,
}

impl Flow<'_> {
    pub fn record(self, audit: &AuditLog) {
        audit.record(EgressEvent {
            at: burrow_proxy::now_rfc3339(),
            sandbox_id: self.sandbox_id.to_string(),
            source_ip: self.source.to_string(),
            destination: self.destination.to_string(),
            host: None,
            port: self.destination.port(),
            is_allowed: self.is_allowed,
            reason: self.reason,
            bytes_sent: self.sent,
            bytes_received: self.received,
            dropped_records: 0,
        });
    }
}

/// This host's own addresses, loopback included.
///
/// Read per decision rather than once, because a node's addresses change
/// under it (DHCP, VPNs, a new interface), and a stale list is an address a
/// sandbox could reach the node on.
pub(crate) fn node_addresses() -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list freed below, and every
    // entry is read only while that list is alive.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return addresses;
        }
        let mut at = head;
        while let Some(entry) = at.as_ref() {
            if let Some(addr) = entry.ifa_addr.as_ref() {
                match i32::from(addr.sa_family) {
                    libc::AF_INET => {
                        let v4 = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                        addresses
                            .push(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))));
                    }
                    libc::AF_INET6 => {
                        let v6 = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                        addresses.push(IpAddr::V6(v6.sin6_addr.s6_addr.into()));
                    }
                    _ => {}
                }
            }
            at = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    addresses
}
