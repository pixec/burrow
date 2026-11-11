//! What a node supports beyond the original set, named on its
//! `NodeInfo.policy_features`.
//!
//! A node that predates a field decodes a policy carrying it and drops it
//! without a word, so a port denial or a rule's expiry would quietly not
//! apply. The orchestrator places and updates a policy only on a node that
//! names every feature it uses, and places a sandbox's state only on a node
//! that can restore its disk layout.

pub const DENY_PORTS: &str = "deny_ports";
pub const IPV6_DENIED: &str = "ipv6_denied";
pub const RULE_EXPIRY: &str = "rule_expiry";
pub const RULE_BINDING: &str = "rule_binding";
pub const OPEN_INSPECTION: &str = "open_inspection";
/// `NetworkPolicy.ingress`, enforced on a sandbox's public addresses.
pub const INGRESS: &str = "ingress";
/// Dedicated public addresses routed to a sandbox's tap.
pub const PUBLIC_IPS: &str = "public_ips";
/// One writable root disk per sandbox, cloned from its image, in place of the
/// overlay; state written on it is restored, adopted and grown only here.
pub const ROOT_DISK: &str = "root_disk";
/// `UpdateResources` reshaping a sandbox (vCPUs, memory, a root disk grown
/// live or shrunk offline) and `UpdateLifetime` moving its clocks.
pub const UPDATE_RESOURCES: &str = "update_resources";

/// Every feature this build enforces.
pub const ALL: &[&str] = &[
    DENY_PORTS,
    IPV6_DENIED,
    RULE_EXPIRY,
    RULE_BINDING,
    OPEN_INSPECTION,
    INGRESS,
    PUBLIC_IPS,
    ROOT_DISK,
    UPDATE_RESOURCES,
];

/// What a node on this platform enforces. A macOS node's sandboxes sit behind
/// a userspace stack with no route a public address could arrive on, so it
/// names neither ingress nor public addresses and is refused both.
pub fn enforced() -> Vec<&'static str> {
    ALL.iter()
        .copied()
        .filter(|feature| cfg!(target_os = "linux") || !matches!(*feature, INGRESS | PUBLIC_IPS))
        .collect()
}
