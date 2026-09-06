//! Names for sandboxes on a private network.
//!
//! An address is a placement detail that changes every time a sandbox is
//! recreated, so private-network members need names to reach each other by.
//!
//! Every member is reachable at `<alias>.<network>.internal`, and at
//! `<sandbox-id>.<network>.internal` whether or not it was given an alias,
//! since an id always exists. The shorter `<alias>.internal` resolves against
//! the networks the *caller* belongs to.
//!
//! Membership is the authorisation, and it is checked on the query rather than
//! only on the packet: a sandbox that is not in a network cannot resolve its
//! members, so names cannot be used to enumerate the fleet even where the
//! firewall would have dropped the traffic anyway.

use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::RwLock;

/// The suffix that marks a name as burrow's to answer.
///
/// RFC 8375 reserves it as a locally-served zone that must never be resolved
/// upstream, so an internal name the directory does not know cannot silently
/// leak into a public lookup.
pub const INTERNAL_SUFFIX: &str = ".internal";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub sandbox_id: String,
    /// What this member answers to. Falls back to the sandbox id.
    pub alias: String,
    pub address: Ipv4Addr,
}

impl Member {
    /// Whether this member answers to `name`, by alias or by id.
    fn answers_to(&self, name: &str) -> bool {
        self.alias.eq_ignore_ascii_case(name) || self.sandbox_id.eq_ignore_ascii_case(name)
    }
}

/// Who is on which private network, across the whole fleet.
///
/// Ordered by network name so a name that is ambiguous across two networks
/// resolves the same way every time rather than by hash order.
#[derive(Default)]
pub struct Directory {
    networks: RwLock<BTreeMap<String, Vec<Member>>>,
}

impl Directory {
    /// Replaces the whole directory. Membership changes are delivered whole
    /// rather than as deltas, so this is the only way it is updated.
    pub fn replace(&self, networks: BTreeMap<String, Vec<Member>>) {
        *self.networks.write().unwrap() = networks;
    }

    /// Networks `client` belongs to.
    fn networks_of(&self, client: Ipv4Addr) -> HashSet<String> {
        self.networks
            .read()
            .unwrap()
            .iter()
            .filter(|(_, members)| members.iter().any(|m| m.address == client))
            .map(|(network, _)| network.clone())
            .collect()
    }

    /// Resolves an internal name on behalf of `client`.
    ///
    /// `None` means "no such name *for you*", which is deliberately
    /// indistinguishable from "no such name": a caller outside a network
    /// should not be able to learn that one exists.
    pub fn resolve(&self, client: Ipv4Addr, name: &str) -> Option<Ipv4Addr> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let stem = name.strip_suffix(INTERNAL_SUFFIX)?;
        if stem.is_empty() {
            return None;
        }
        let joined = self.networks_of(client);
        if joined.is_empty() {
            return None;
        }
        let networks = self.networks.read().unwrap();

        // "<alias>.<network>.internal": the only form that can disambiguate a
        // name used on more than one network.
        if let Some((alias, network)) = stem.rsplit_once('.')
            && joined.contains(network)
            && let Some(members) = networks.get(network)
            && let Some(member) = members.iter().find(|m| m.answers_to(alias))
        {
            return Some(member.address);
        }

        // "<alias>.internal": searched across the caller's own networks only.
        networks
            .iter()
            .filter(|(network, _)| joined.contains(*network))
            .find_map(|(_, members)| {
                members
                    .iter()
                    .find(|m| m.answers_to(stem))
                    .map(|m| m.address)
            })
    }

    /// Every address `client` shares a network with, for the firewall.
    pub fn peers_of(&self, client: Ipv4Addr) -> Vec<Ipv4Addr> {
        let joined = self.networks_of(client);
        let networks = self.networks.read().unwrap();
        let mut peers: Vec<_> = networks
            .iter()
            .filter(|(network, _)| joined.contains(*network))
            .flat_map(|(_, members)| members.iter())
            .map(|m| m.address)
            .filter(|address| *address != client)
            .collect();
        peers.sort();
        peers.dedup();
        peers
    }
}

/// Whether a name is burrow's to answer rather than the upstream resolver's.
pub fn is_internal(name: &str) -> bool {
    name.trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(INTERNAL_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 99, 0, last)
    }

    fn member(id: &str, alias: &str, last: u8) -> Member {
        Member {
            sandbox_id: id.into(),
            alias: alias.into(),
            address: ip(last),
        }
    }

    fn directory(entries: &[(&str, Vec<Member>)]) -> Directory {
        let directory = Directory::default();
        directory.replace(
            entries
                .iter()
                .map(|(network, members)| ((*network).to_string(), members.clone()))
                .collect(),
        );
        directory
    }

    #[test]
    fn a_member_resolves_a_peer_by_alias() {
        let d = directory(&[(
            "team",
            vec![member("sbx_a", "alpha", 6), member("sbx_b", "beta", 10)],
        )]);
        assert_eq!(d.resolve(ip(6), "beta.team.internal"), Some(ip(10)));
        assert_eq!(d.resolve(ip(10), "alpha.team.internal"), Some(ip(6)));
    }

    /// An id always exists, so a sandbox is addressable without anyone having
    /// named it.
    #[test]
    fn a_member_resolves_a_peer_by_sandbox_id() {
        let d = directory(&[(
            "team",
            vec![member("sbx_a", "alpha", 6), member("sbx_b", "beta", 10)],
        )]);
        assert_eq!(d.resolve(ip(6), "sbx_b.team.internal"), Some(ip(10)));
        assert_eq!(d.resolve(ip(6), "sbx_b.internal"), Some(ip(10)));
    }

    #[test]
    fn the_short_form_searches_the_callers_own_networks() {
        let d = directory(&[(
            "team",
            vec![member("sbx_a", "alpha", 6), member("sbx_b", "beta", 10)],
        )]);
        assert_eq!(d.resolve(ip(6), "beta.internal"), Some(ip(10)));
    }

    /// Membership is the authorisation. A non-member must not even learn that
    /// the name exists.
    #[test]
    fn a_non_member_resolves_nothing() {
        let d = directory(&[(
            "team",
            vec![member("sbx_a", "alpha", 6), member("sbx_b", "beta", 10)],
        )]);
        let outsider = ip(14);
        assert_eq!(d.resolve(outsider, "beta.team.internal"), None);
        assert_eq!(d.resolve(outsider, "beta.internal"), None);
        assert_eq!(d.resolve(outsider, "sbx_b.internal"), None);
    }

    /// Being in *a* network does not grant visibility into another one.
    #[test]
    fn a_member_of_one_network_cannot_resolve_another() {
        let d = directory(&[
            ("red", vec![member("sbx_a", "alpha", 6)]),
            ("blue", vec![member("sbx_b", "beta", 10)]),
        ]);
        assert_eq!(d.resolve(ip(6), "beta.blue.internal"), None);
        assert_eq!(d.resolve(ip(6), "beta.internal"), None);
    }

    #[test]
    fn a_sandbox_can_resolve_itself() {
        let d = directory(&[("team", vec![member("sbx_a", "alpha", 6)])]);
        assert_eq!(d.resolve(ip(6), "alpha.team.internal"), Some(ip(6)));
    }

    #[test]
    fn names_are_case_insensitive_and_tolerate_a_trailing_dot() {
        let d = directory(&[(
            "team",
            vec![member("sbx_a", "alpha", 6), member("sbx_b", "Beta", 10)],
        )]);
        assert_eq!(d.resolve(ip(6), "BETA.Team.internal."), Some(ip(10)));
    }

    #[test]
    fn only_internal_names_are_ours_to_answer() {
        assert!(is_internal("beta.team.internal"));
        assert!(is_internal("beta.team.internal."));
        assert!(is_internal("BETA.TEAM.INTERNAL"));
        assert!(!is_internal("example.com"));
        assert!(!is_internal("internal"));
        assert!(!is_internal("notinternal"));
    }

    #[test]
    fn an_unknown_internal_name_resolves_to_nothing() {
        let d = directory(&[("team", vec![member("sbx_a", "alpha", 6)])]);
        assert_eq!(d.resolve(ip(6), "nobody.team.internal"), None);
        assert_eq!(d.resolve(ip(6), "nobody.internal"), None);
        assert_eq!(d.resolve(ip(6), ".internal"), None);
    }

    #[test]
    fn peers_exclude_the_caller_and_span_its_networks() {
        let d = directory(&[
            (
                "red",
                vec![member("sbx_a", "alpha", 6), member("sbx_b", "beta", 10)],
            ),
            (
                "blue",
                vec![member("sbx_a", "alpha", 6), member("sbx_c", "gamma", 14)],
            ),
        ]);
        assert_eq!(d.peers_of(ip(6)), vec![ip(10), ip(14)]);
        // Someone in only one of them sees only that one.
        assert_eq!(d.peers_of(ip(10)), vec![ip(6)]);
        assert!(d.peers_of(ip(200)).is_empty());
    }
}
