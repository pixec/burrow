//! Policy fields a node enforces beyond the original set, named on its
//! `NodeInfo.policy_features`.
//!
//! A node that predates a field decodes a policy carrying it and drops it
//! without a word, so a port denial or a rule's expiry would quietly not
//! apply. The orchestrator places and updates a policy only on a node that
//! names every feature it uses.

pub const DENY_PORTS: &str = "deny_ports";
pub const IPV6_DENIED: &str = "ipv6_denied";
pub const RULE_EXPIRY: &str = "rule_expiry";
pub const RULE_BINDING: &str = "rule_binding";
pub const OPEN_INSPECTION: &str = "open_inspection";

/// Every feature this build enforces.
pub const ALL: &[&str] = &[
    DENY_PORTS,
    IPV6_DENIED,
    RULE_EXPIRY,
    RULE_BINDING,
    OPEN_INSPECTION,
];
