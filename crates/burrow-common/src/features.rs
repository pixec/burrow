//! What a node's platform enforces, named on its `NodeInfo.policy_features`.
//!
//! The orchestrator places and updates a policy only on a node that names
//! every feature it uses.

/// `NetworkPolicy.ingress`, enforced on a sandbox's public addresses.
pub const INGRESS: &str = "ingress";
/// Dedicated public addresses routed to a sandbox's tap.
pub const PUBLIC_IPS: &str = "public_ips";

/// Every feature this build enforces.
pub const ALL: &[&str] = &[INGRESS, PUBLIC_IPS];

/// What a node on this platform enforces. A macOS node's sandboxes sit behind
/// a userspace stack with no route a public address could arrive on, so it
/// names neither ingress nor public addresses and is refused both.
pub fn enforced() -> Vec<&'static str> {
    ALL.iter()
        .copied()
        .filter(|feature| cfg!(target_os = "linux") || !matches!(*feature, INGRESS | PUBLIC_IPS))
        .collect()
}
