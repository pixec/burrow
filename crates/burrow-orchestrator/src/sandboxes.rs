//! The orchestrator's sandbox registry: which sandbox lives on which node.
//!
//! Nodes stay authoritative: whatever a node reports replaces what is held
//! here. The sqlite store behind it covers only the case nodes cannot, a whole
//! fleet restarting at once.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use burrow_proto::common::v1 as common;

/// Placements are stored as encoded protobuf, so the record on disk is the
/// same shape as the one on the wire and cannot drift from it.
fn encode(sandbox: &common::Sandbox) -> Vec<u8> {
    use prost::Message as _;
    sandbox.encode_to_vec()
}

fn decode(bytes: &[u8]) -> Option<common::Sandbox> {
    use prost::Message as _;
    common::Sandbox::decode(bytes).ok()
}

/// The name a member answers to, defaulting to its sandbox id.
///
/// An id always works, so a sandbox is addressable without anyone having
/// chosen a name for it; an alias is what makes the address memorable.
fn alias_of(membership: &common::NetworkMembership, sandbox_id: &str) -> String {
    if membership.alias.is_empty() {
        sandbox_id.to_string()
    } else {
        membership.alias.clone()
    }
}

/// How long a freshly created sandbox is immune to being forgotten by a
/// heartbeat.
///
/// It covers a report sampled before the sandbox existed and only now
/// arriving: one heartbeat interval of sampling lag plus flight time. Wide,
/// because being wrong the other way only keeps a deleted sandbox's record for
/// one more heartbeat.
const SETTLING_GRACE: Duration = Duration::from_secs(30);

/// What a heartbeat's state report changed. See [`SandboxRegistry::apply_states`].
#[derive(Debug, Default)]
pub struct Applied {
    /// Sandboxes whose state the node moved on its own.
    pub restated: usize,
    /// Placements dropped because the node no longer lists them.
    pub forgotten: usize,
    /// Ids the node lists that this registry holds no placement for.
    pub unknown: Vec<String>,
}

/// How long a tombstone is kept before it is assumed no longer needed.
///
/// A node that comes back inside this window has its copy of the sandbox
/// destroyed; one that never comes back would otherwise leave the record here
/// forever.
pub const TOMBSTONE_TTL_SECS: i64 = 30 * 86_400;

/// A delete that was accepted while the hosting node was unreachable.
#[derive(Debug, Clone)]
pub struct Tombstone {
    pub node_id: String,
    /// Unix seconds the delete was accepted.
    pub at: i64,
}

/// What a reconcile did with a node's reported inventory.
#[derive(Debug, Default)]
pub struct Reconciled {
    pub adopted: usize,
    pub forgotten: usize,
    /// Reported sandboxes a caller already deleted while this node was down.
    /// Not adopted; the caller destroys them on the node instead.
    pub tombstoned: Vec<String>,
}

#[derive(Default)]
pub struct SandboxRegistry {
    sandboxes: Mutex<HashMap<String, common::Sandbox>>,
    /// Sandboxes deleted while their node was unreachable, by sandbox id.
    ///
    /// The delete could not reach the node, so the placement was dropped on
    /// the orchestrator's word alone. This is what stops the node re-asserting
    /// the sandbox into existence if it ever comes back.
    tombstones: Mutex<HashMap<String, Tombstone>>,
    /// Ids whose create is in flight.
    ///
    /// A record only enters `sandboxes` once its node has built the sandbox,
    /// which leaves a window of a second or two where a second create of the
    /// same caller-chosen id sees nothing and is placed too, on another node
    /// where the node's own duplicate check cannot see it either. Claiming the
    /// id here closes that window.
    creating: Mutex<HashSet<String>>,
    /// Names whose create is in flight, held for the same reason as `creating`.
    naming: Mutex<HashSet<String>>,
    /// Ids whose create finished too recently to trust a heartbeat about them.
    ///
    /// A node samples its inventory and then sends it, so a sandbox created
    /// after the sample is simply not in the report. Reading that as "the node
    /// no longer has it" destroys the record of a sandbox that is running, and
    /// whose id the caller already holds. The id sits here for a grace window
    /// instead, after which the node has had a chance to list it.
    settling: Mutex<HashMap<String, Instant>>,
    /// Survives a restart of the whole fleet, the one case nodes cannot cover.
    store: Option<Arc<burrow_store::Store>>,
}

impl SandboxRegistry {
    /// Opens a registry backed by durable storage, restoring what it holds.
    pub fn with_store(store: Arc<burrow_store::Store>) -> Self {
        let mut sandboxes = HashMap::new();
        match store.list_placements() {
            Ok(rows) => {
                for row in rows {
                    match decode(&row.record) {
                        Some(sandbox) => {
                            sandboxes.insert(sandbox.id.clone(), sandbox);
                        }
                        None => tracing::warn!(
                            sandbox = row.id,
                            "discarding an unreadable placement record"
                        ),
                    }
                }
                if !sandboxes.is_empty() {
                    tracing::info!(count = sandboxes.len(), "restored placements from disk");
                }
            }
            Err(err) => tracing::error!(%err, "could not read stored placements"),
        }

        let mut tombstones = HashMap::new();
        match store.list_tombstones() {
            Ok(rows) => {
                for row in rows {
                    tombstones.insert(
                        row.sandbox_id,
                        Tombstone {
                            node_id: row.node_id,
                            at: row.at,
                        },
                    );
                }
                if !tombstones.is_empty() {
                    tracing::info!(
                        count = tombstones.len(),
                        "restored tombstones for sandboxes deleted while their node was down"
                    );
                }
            }
            Err(err) => tracing::error!(%err, "could not read stored tombstones"),
        }

        Self {
            sandboxes: Mutex::new(sandboxes),
            tombstones: Mutex::new(tombstones),
            creating: Mutex::new(HashSet::new()),
            naming: Mutex::new(HashSet::new()),
            settling: Mutex::new(HashMap::new()),
            store: Some(store),
        }
    }

    /// Claims an id, a name, or both for a create that is about to run.
    ///
    /// Either may be empty, meaning there is nothing to claim: a generated id
    /// cannot collide, and a sandbox need not be named at all. `Err` carries
    /// the reason, which is what a caller turns into ALREADY_EXISTS.
    ///
    /// Claiming rather than merely checking is what closes the window between a
    /// create being accepted and its record arriving; see `creating`.
    pub fn reserve(&self, id: &str, name: &str) -> Result<Reservation<'_>, String> {
        let sandboxes = self.sandboxes.lock().unwrap();
        let mut creating = self.creating.lock().unwrap();
        let mut naming = self.naming.lock().unwrap();

        if !id.is_empty() && (sandboxes.contains_key(id) || creating.contains(id)) {
            return Err(format!("sandbox {id} exists"));
        }
        if !name.is_empty() && (sandboxes.values().any(|s| s.name == name) || naming.contains(name))
        {
            return Err(format!("a sandbox named {name} exists"));
        }
        if !id.is_empty() {
            creating.insert(id.to_string());
        }
        if !name.is_empty() {
            naming.insert(name.to_string());
        }
        Ok(Reservation {
            registry: self,
            id: id.to_string(),
            name: name.to_string(),
        })
    }

    /// The id of the sandbox carrying this name, if one does.
    ///
    /// Names are unique, so a scan returns at most one. The map is small
    /// enough that indexing it would buy nothing a list already pays for.
    pub fn id_by_name(&self, name: &str) -> Option<String> {
        if name.is_empty() {
            return None;
        }
        self.sandboxes
            .lock()
            .unwrap()
            .values()
            .find(|s| s.name == name)
            .map(|s| s.id.clone())
    }

    /// Map and store are both written under the registry lock, here and
    /// everywhere below.
    ///
    /// Persisting outside it lets a delete's row removal and an insert's row
    /// write interleave, and nothing re-reads the store until the next restart,
    /// so the divergence is permanent. The store is sqlite behind its own mutex
    /// and these methods are synchronous, so holding one lock across the other
    /// is a short critical section, not a deadlock.
    pub fn insert(&self, sandbox: common::Sandbox) {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        self.persist(&sandbox);
        self.settling
            .lock()
            .unwrap()
            .insert(sandbox.id.clone(), Instant::now());
        sandboxes.insert(sandbox.id.clone(), sandbox);
    }

    fn persist(&self, sandbox: &common::Sandbox) {
        let Some(store) = &self.store else { return };
        // Best effort: a registry that cannot write to disk is still correct
        // for as long as it is running, and nodes rebuild it on registration.
        if let Err(err) = store.put_placement(&burrow_store::PlacementRow {
            id: sandbox.id.clone(),
            node_id: sandbox.node_id.clone(),
            record: encode(sandbox),
        }) {
            tracing::warn!(sandbox = sandbox.id, %err, "could not persist a placement");
        }
    }

    /// Ages every settling entry out, as if `SETTLING_GRACE` had passed.
    ///
    /// Tests that are about what a heartbeat forgets have to get past the
    /// grace window without sleeping through it.
    #[cfg(test)]
    fn settled(&self) {
        self.settling.lock().unwrap().clear();
    }

    fn forget(&self, id: &str) {
        let Some(store) = &self.store else { return };
        if let Err(err) = store.delete_placement(id) {
            tracing::warn!(sandbox = id, %err, "could not remove a stored placement");
        }
    }

    pub fn get(&self, id: &str) -> Option<common::Sandbox> {
        self.sandboxes.lock().unwrap().get(id).cloned()
    }

    /// The node currently hosting a sandbox.
    pub fn node_of(&self, id: &str) -> Option<String> {
        self.sandboxes
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.node_id.clone())
    }

    pub fn remove(&self, id: &str) -> Option<common::Sandbox> {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        let removed = sandboxes.remove(id);
        self.forget(id);
        removed
    }

    /// Drops a sandbox whose node could not be told, and remembers that it was.
    ///
    /// For a node that has missed its heartbeats and cannot be asked. The
    /// placement is removed anyway, or a permanently dead node would leave an
    /// undeletable sandbox holding its name and capacity; the tombstone records
    /// the intent, so a node that does come back has its copy destroyed rather
    /// than adopted.
    pub fn forget_deleted(&self, id: &str) -> Option<common::Sandbox> {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        let removed = sandboxes.remove(id);
        self.forget(id);

        let node_id = removed
            .as_ref()
            .map(|s| s.node_id.clone())
            .unwrap_or_default();
        let at = burrow_core::unix_now();
        self.tombstones.lock().unwrap().insert(
            id.to_string(),
            Tombstone {
                node_id: node_id.clone(),
                at,
            },
        );
        if let Some(store) = &self.store
            && let Err(err) = store.put_tombstone(&burrow_store::TombstoneRow {
                sandbox_id: id.to_string(),
                node_id,
                at,
            })
        {
            // Loud rather than fatal: the delete has already happened as far as
            // the caller is concerned, and losing the tombstone only means a
            // returning node's copy is re-adopted instead of destroyed.
            tracing::error!(sandbox = id, %err, "could not persist a tombstone");
        }
        removed
    }

    pub fn is_tombstoned(&self, id: &str) -> bool {
        self.tombstones.lock().unwrap().contains_key(id)
    }

    /// Forgets a tombstone: the node no longer holds the sandbox, or never will.
    pub fn clear_tombstone(&self, id: &str) {
        if self.tombstones.lock().unwrap().remove(id).is_none() {
            return;
        }
        if let Some(store) = &self.store
            && let Err(err) = store.delete_tombstone(id)
        {
            tracing::warn!(sandbox = id, %err, "could not remove a stored tombstone");
        }
    }

    /// Drops tombstones older than `ttl_secs`, returning how many.
    ///
    /// A node that never returns would otherwise accumulate them for the life
    /// of the cluster.
    pub fn prune_tombstones(&self, ttl_secs: i64) -> usize {
        let cutoff = burrow_core::unix_now().saturating_sub(ttl_secs);
        let mut tombstones = self.tombstones.lock().unwrap();
        let expired: Vec<String> = tombstones
            .iter()
            .filter(|(_, t)| t.at < cutoff)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            tombstones.remove(id);
        }
        drop(tombstones);
        if !expired.is_empty()
            && let Some(store) = &self.store
            && let Err(err) = store.prune_tombstones(cutoff)
        {
            tracing::warn!(%err, "could not prune stored tombstones");
        }
        expired.len()
    }

    /// Drops every placement recorded against a node, returning what was held.
    ///
    /// For a node written off entirely, so the names and the capacity its
    /// sandboxes held come back. Deliberately leaves *no* tombstones: nothing
    /// was deleted here, the node was simply given up on, and if it ever does
    /// return its own inventory should be adopted as usual.
    pub fn forget_node(&self, node_id: &str) -> Vec<common::Sandbox> {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        if let Some(store) = &self.store
            && let Err(err) = store.delete_placements_for_node(node_id)
        {
            tracing::warn!(node_id, %err, "could not clear stored placements for a node");
        }
        let mut dropped = Vec::new();
        sandboxes.retain(|_, sandbox| {
            let keep = sandbox.node_id != node_id;
            if !keep {
                dropped.push(sandbox.clone());
            }
            keep
        });
        dropped
    }

    /// Replaces everything recorded against a node with what that node
    /// actually reports.
    ///
    /// Nodes own their sandboxes and persist them, so a node, not this cache,
    /// is the authority on what exists there. Adopting its list on every
    /// re-registration lets an orchestrator restart rebuild its whole view from
    /// the fleet.
    ///
    /// A sandbox a caller already deleted is the exception: the node was
    /// unreachable at the time, so adopting its copy back would undo a delete
    /// the caller was told had succeeded. Those ids come back in
    /// [`Reconciled::tombstoned`] to be destroyed on the node instead.
    pub fn reconcile_node(&self, node_id: &str, reported: Vec<common::Sandbox>) -> Reconciled {
        // Under the same lock as the map update: clearing the node's rows
        // first and taking the lock afterwards leaves a window in which an
        // insert writes a row this call has already decided to drop.
        let mut sandboxes = self.sandboxes.lock().unwrap();
        if let Some(store) = &self.store
            && let Err(err) = store.delete_placements_for_node(node_id)
        {
            tracing::warn!(node_id, %err, "could not clear stored placements for a node");
        }

        let before = sandboxes.len();
        sandboxes.retain(|_, s| s.node_id != node_id);
        let dropped = before - sandboxes.len();

        let tombstones = self.tombstones.lock().unwrap();
        let mut still_held = HashSet::new();
        let mut out = Reconciled::default();
        for mut sandbox in reported {
            if tombstones.contains_key(&sandbox.id) {
                still_held.insert(sandbox.id.clone());
                out.tombstoned.push(sandbox.id);
                continue;
            }
            // The node may not know its own id before registering; the
            // orchestrator is authoritative for that one field.
            sandbox.node_id = node_id.to_string();
            // A name is unique across the fleet, and this one may have been
            // reused while the node was away. The record is still adopted, but
            // the newer claim on the name keeps it.
            if !sandbox.name.is_empty() && self.name_taken(&sandboxes, &sandbox.name, &sandbox.id) {
                tracing::warn!(
                    node_id,
                    sandbox = sandbox.id,
                    name = sandbox.name,
                    "adopting a returning sandbox without its name; the name was \
                     reused while the node was away"
                );
                sandbox.name.clear();
            }
            self.persist(&sandbox);
            sandboxes.insert(sandbox.id.clone(), sandbox);
            out.adopted += 1;
        }
        drop(tombstones);

        // Whatever the node no longer lists is gone from it for good, so the
        // tombstone has nothing left to guard against.
        let settled: Vec<String> = self
            .tombstones
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, t)| t.node_id == node_id && !still_held.contains(id.as_str()))
            .map(|(id, _)| id.clone())
            .collect();
        drop(sandboxes);
        for id in settled {
            self.clear_tombstone(&id);
        }

        out.forgotten = dropped.saturating_sub(out.adopted);
        out
    }

    /// Whether some *other* sandbox, or a create in flight, holds this name.
    fn name_taken(
        &self,
        sandboxes: &HashMap<String, common::Sandbox>,
        name: &str,
        except: &str,
    ) -> bool {
        sandboxes.values().any(|s| s.name == name && s.id != except)
            || self.naming.lock().unwrap().contains(name)
    }

    /// Applies a node's own view of the sandboxes it holds.
    ///
    /// Unlike [`reconcile_node`](Self::reconcile_node) this carries only ids and
    /// states, because it runs on every heartbeat. Anything the node no longer
    /// lists is gone: a sandbox that outlived its policy is destroyed there, and
    /// continuing to list it would be inventing one.
    ///
    /// Two things a report is *not* evidence of, both of them ordering rather
    /// than disagreement:
    ///
    /// * A sandbox created after the node sampled its inventory is missing from
    ///   the report because it did not exist yet, not because it is gone. Ids
    ///   still being created, and ids created inside [`SETTLING_GRACE`], are
    ///   therefore never dropped by a heartbeat.
    /// * An id the node lists that this registry has never heard of is a real
    ///   sandbox whose placement record was lost, by a restart without a store
    ///   or otherwise. It is returned in [`Applied::unknown`] so the caller can
    ///   pull the node's full listing; a state report carries no name, policy
    ///   or address, so there is nothing here to rebuild a record from.
    pub fn apply_states(
        &self,
        node_id: &str,
        reported: &[burrow_proto::node::v1::SandboxStateReport],
    ) -> Applied {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        let mut out = Applied::default();

        // Only what actually moved is written back. A heartbeat arrives every
        // few seconds and almost always says nothing new; rewriting every
        // placement on the node each time is a disk write per sandbox per
        // heartbeat for no change at all.
        let tombstoned = self.tombstones.lock().unwrap();
        let mut changed = Vec::new();
        for report in reported {
            // A node that was down when a delete arrived keeps reporting the
            // sandbox until its registration reconciles. Nothing here may put
            // it back: the delete already succeeded for the caller.
            if tombstoned.contains_key(&report.sandbox_id) {
                continue;
            }
            let Some(sandbox) = sandboxes.get_mut(&report.sandbox_id) else {
                // Not ours yet: a create in flight is inserted only once the
                // node answers, and this report may have overtaken it.
                if !self.creating.lock().unwrap().contains(&report.sandbox_id) {
                    out.unknown.push(report.sandbox_id.clone());
                }
                continue;
            };
            if sandbox.node_id != node_id {
                continue;
            }
            // Usage is taken on every heartbeat but never persisted here: it
            // moves constantly, the node holds the durable copy, and a
            // registry rebuilt from a node's reconcile gets it back anyway.
            sandbox.cpu_usage_usec = report.cpu_usage_usec;
            sandbox.rx_bytes = report.rx_bytes;
            sandbox.tx_bytes = report.tx_bytes;
            // Not persisted, and not a `changed` entry: it describes the VM the
            // node is running now, and a recovered or resumed sandbox
            // handshakes again. It is here for the durable case of a guest that
            // never came up, which nothing else would correct.
            sandbox.agent_unconfirmed = report.agent_unconfirmed;
            if sandbox.state != report.state {
                sandbox.state = report.state;
                changed.push(sandbox.clone());
            }
        }
        out.restated = changed.len();

        let mut gone = Vec::new();
        if reported.is_empty() {
            // "Lists nothing" is not the same claim as "held nothing": a node
            // that just restarted heartbeats before recover() has repopulated
            // its inventory, and erasing on that would destroy the record of
            // every sandbox it is about to bring back. Real deletions arrive
            // through DeleteSandbox, and a genuinely empty node is corrected
            // by the reconcile that follows its registration.
            if sandboxes.values().any(|s| s.node_id == node_id) {
                tracing::warn!(
                    node_id,
                    "heartbeat listed no sandboxes; keeping the recorded placements \
                     rather than forgetting them"
                );
            }
        } else {
            let known: std::collections::HashSet<&str> =
                reported.iter().map(|r| r.sandbox_id.as_str()).collect();
            // Expired entries are dropped here rather than on a timer: this is
            // the only reader, and it runs every few seconds per node.
            let mut settling = self.settling.lock().unwrap();
            settling.retain(|_, at| at.elapsed() < SETTLING_GRACE);
            let creating = self.creating.lock().unwrap();
            sandboxes.retain(|id, sandbox| {
                let keep = sandbox.node_id != node_id
                    || known.contains(id.as_str())
                    // Too new for this report to have seen; see the doc comment.
                    || creating.contains(id)
                    || settling.contains_key(id);
                if !keep {
                    gone.push(id.clone());
                }
                keep
            });
        }

        // Still under the lock: a delete racing this call must not have its
        // row rewritten by a snapshot taken before it ran.
        for sandbox in &changed {
            self.persist(sandbox);
        }
        for id in &gone {
            self.forget(id);
        }
        out.forgotten = gone.len();
        out
    }

    /// The node already hosting members of any of `networks`.
    ///
    /// Private-network membership is enforced per node, so a new member has to
    /// land where the existing ones are. Returns `None` when the networks are
    /// empty or have no members yet, which leaves placement unconstrained.
    pub fn node_hosting_networks(&self, networks: &[String]) -> Option<String> {
        if networks.is_empty() {
            return None;
        }
        let sandboxes = self.sandboxes.lock().unwrap();
        sandboxes.values().find_map(|sandbox| {
            let joined = sandbox
                .policy
                .iter()
                .flat_map(|p| p.networks.iter())
                .any(|m| networks.contains(&m.network));
            joined.then(|| sandbox.node_id.clone())
        })
    }

    /// Guest addresses on each private network that live on *other* nodes.
    ///
    /// A node already knows its own members; what it cannot know is which
    /// remote addresses share a network with them, which is exactly what its
    /// firewall needs in order to let mesh traffic through.
    pub fn network_members(&self, for_node: &str) -> Vec<burrow_proto::node::v1::NetworkMembers> {
        let sandboxes = self.sandboxes.lock().unwrap();
        let mut by_network: std::collections::BTreeMap<
            String,
            Vec<burrow_proto::node::v1::NetworkMember>,
        > = std::collections::BTreeMap::new();

        for sandbox in sandboxes.values() {
            if sandbox.node_id == for_node || sandbox.guest_ip.is_empty() {
                continue;
            }
            for membership in sandbox.policy.iter().flat_map(|p| p.networks.iter()) {
                if membership.network.is_empty() {
                    continue;
                }
                by_network
                    .entry(membership.network.clone())
                    .or_default()
                    .push(burrow_proto::node::v1::NetworkMember {
                        sandbox_id: sandbox.id.clone(),
                        alias: alias_of(membership, &sandbox.id),
                        guest_ip: sandbox.guest_ip.clone(),
                    });
            }
        }

        by_network
            .into_iter()
            .map(|(network, members)| burrow_proto::node::v1::NetworkMembers { network, members })
            .collect()
    }

    /// Every sandbox, or only those carrying an exact `key=value` tag.
    ///
    /// Filtered here rather than fanned out: nodes reconcile this registry on
    /// registration and restate it on every heartbeat, so one map already holds
    /// the fleet.
    pub fn list_tagged(&self, tag: Option<(&str, &str)>) -> Vec<common::Sandbox> {
        let mut out: Vec<_> = self
            .sandboxes
            .lock()
            .unwrap()
            .values()
            .filter(|sandbox| match tag {
                Some((key, value)) => sandbox.metadata.get(key).is_some_and(|held| held == value),
                None => true,
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}

/// A claim on a sandbox id and name, held for as long as its create is running.
pub struct Reservation<'a> {
    registry: &'a SandboxRegistry,
    id: String,
    name: String,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.registry.creating.lock().unwrap().remove(&self.id);
        self.registry.naming.lock().unwrap().remove(&self.name);
    }
}

#[cfg(test)]
mod reservation_tests {
    use super::*;

    fn registry() -> SandboxRegistry {
        SandboxRegistry::default()
    }

    #[test]
    fn an_id_being_created_cannot_be_claimed_twice() {
        let registry = registry();
        let first = registry.reserve("build-1", "").expect("first claim");
        assert!(registry.reserve("build-1", "").is_err());
        drop(first);
        // The create failed, so the id is free again.
        assert!(registry.reserve("build-1", "").is_ok());
    }

    #[test]
    fn an_id_that_belongs_to_a_sandbox_cannot_be_claimed() {
        let registry = registry();
        registry.insert(common::Sandbox {
            id: "build-1".into(),
            node_id: "node1".into(),
            ..Default::default()
        });
        assert!(registry.reserve("build-1", "").is_err());
        assert!(registry.reserve("build-2", "").is_ok());
    }

    #[test]
    fn a_name_is_claimed_for_as_long_as_its_create_runs() {
        let registry = registry();
        let claim = registry.reserve("", "api").expect("first claim");
        assert!(registry.reserve("", "api").is_err());
        // A different name, and a create with no name at all, are unaffected.
        assert!(registry.reserve("", "worker").is_ok());
        assert!(registry.reserve("", "").is_ok());
        drop(claim);
        assert!(registry.reserve("", "api").is_ok());
    }

    #[test]
    fn a_name_in_use_is_refused_and_resolves_to_its_sandbox() {
        let registry = registry();
        registry.insert(common::Sandbox {
            id: "sbx_1".into(),
            node_id: "node1".into(),
            name: "api".into(),
            ..Default::default()
        });
        assert_eq!(registry.id_by_name("api").as_deref(), Some("sbx_1"));
        assert_eq!(registry.id_by_name("worker"), None);
        // An empty name is not a name: unnamed sandboxes must not answer to it.
        assert_eq!(registry.id_by_name(""), None);

        let Err(taken) = registry.reserve("", "api") else {
            panic!("a name already in use must be refused");
        };
        assert!(taken.contains("api"), "{taken}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burrow_proto::node::v1::SandboxStateReport;

    fn sandbox(id: &str, node: &str, state: common::SandboxState) -> common::Sandbox {
        common::Sandbox {
            id: id.into(),
            node_id: node.into(),
            state: state as i32,
            ..Default::default()
        }
    }

    fn report(id: &str, state: common::SandboxState) -> SandboxStateReport {
        SandboxStateReport {
            sandbox_id: id.into(),
            state: state as i32,
            ..Default::default()
        }
    }

    /// A node suspends idle sandboxes without being asked, so the orchestrator
    /// must learn the new state from the node rather than assume the one it
    /// last caused.
    #[test]
    fn a_node_initiated_suspension_is_adopted() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Running));

        let applied =
            registry.apply_states("node1", &[report("a", common::SandboxState::Suspended)]);
        let (restated, forgotten) = (applied.restated, applied.forgotten);

        assert_eq!((restated, forgotten), (1, 0));
        assert_eq!(
            registry.get("a").unwrap().state,
            common::SandboxState::Suspended as i32
        );
    }

    /// A heartbeat is a snapshot of a moment, and that moment may be older
    /// than the sandbox. Reading "not in the report" as "gone" then erases the
    /// record of a sandbox the caller has already been handed the id of.
    #[test]
    fn a_just_created_sandbox_survives_a_heartbeat_that_predates_it() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("old", "node1", common::SandboxState::Running));
        registry.settled();
        // Created after the node sampled the report below.
        registry.insert(sandbox("brand-new", "node1", common::SandboxState::Running));

        let applied =
            registry.apply_states("node1", &[report("old", common::SandboxState::Running)]);

        assert_eq!(applied.forgotten, 0);
        assert!(registry.get("brand-new").is_some());
        // And once the grace window is over, a report that still omits it is
        // taken at its word.
        registry.settled();
        let applied =
            registry.apply_states("node1", &[report("old", common::SandboxState::Running)]);
        assert_eq!(applied.forgotten, 1);
        assert!(registry.get("brand-new").is_none());
    }

    /// The id is claimed before the node is asked to build the sandbox, so a
    /// heartbeat can arrive while the create is still in flight.
    #[test]
    fn an_id_still_being_created_is_not_forgotten() {
        let registry = SandboxRegistry::default();
        let reserved = registry.reserve("in-flight", "").expect("free id");
        registry.insert(sandbox("in-flight", "node1", common::SandboxState::Running));
        // Not `settled()`: the point is that `creating` alone is enough.
        registry.settling.lock().unwrap().clear();

        let applied = registry.apply_states("node1", &[]);
        assert_eq!(applied.forgotten, 0);
        assert!(registry.get("in-flight").is_some());
        drop(reserved);
    }

    /// An orchestrator that lost its store still has a fleet full of running
    /// sandboxes. Ignoring the ids it does not recognise would leave them
    /// unreachable through the API for as long as the node stays registered.
    #[test]
    fn a_reported_sandbox_with_no_record_is_reported_for_reconciling() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("known", "node1", common::SandboxState::Running));
        registry.settled();

        let applied = registry.apply_states(
            "node1",
            &[
                report("known", common::SandboxState::Running),
                report("stranger", common::SandboxState::Running),
            ],
        );

        assert_eq!(applied.unknown, vec!["stranger".to_string()]);
        // Nothing is invented from a state report: it carries no name, policy
        // or address, so the caller pulls the node's full listing instead.
        assert!(registry.get("stranger").is_none());
    }

    /// A delete that could not reach its node stays deleted. The tombstone is
    /// the record of that, and it must not read as a sandbox to go adopt.
    #[test]
    fn a_tombstoned_id_is_not_reported_as_unknown() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("deleted", "node1", common::SandboxState::Running));
        registry.forget_deleted("deleted");
        registry.settled();

        let applied =
            registry.apply_states("node1", &[report("deleted", common::SandboxState::Running)]);
        assert!(applied.unknown.is_empty());
    }

    /// A sandbox that outlived its policy is destroyed on the node; continuing
    /// to list it would be inventing one.
    #[test]
    fn a_sandbox_the_node_no_longer_holds_is_forgotten() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("gone", "node1", common::SandboxState::Running));
        registry.insert(sandbox("kept", "node1", common::SandboxState::Running));
        registry.settled();

        let forgotten = registry
            .apply_states("node1", &[report("kept", common::SandboxState::Running)])
            .forgotten;

        assert_eq!(forgotten, 1);
        assert!(registry.get("gone").is_none());
        assert!(registry.get("kept").is_some());
    }

    /// One node's heartbeat says nothing about another node's sandboxes.
    #[test]
    fn another_nodes_sandboxes_are_left_alone() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("mine", "node1", common::SandboxState::Running));
        registry.insert(sandbox("theirs", "node2", common::SandboxState::Running));

        let forgotten = registry
            .apply_states("node1", &[report("mine", common::SandboxState::Running)])
            .forgotten;

        assert_eq!(forgotten, 0);
        assert!(registry.get("theirs").is_some());
    }

    /// A node cannot claim a sandbox the registry says lives somewhere else.
    #[test]
    fn a_node_cannot_restate_a_sandbox_it_does_not_host() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("elsewhere", "node2", common::SandboxState::Running));

        let restated = registry
            .apply_states(
                "node1",
                &[report("elsewhere", common::SandboxState::Suspended)],
            )
            .restated;

        assert_eq!(restated, 0);
        assert_eq!(
            registry.get("elsewhere").unwrap().state,
            common::SandboxState::Running as i32
        );
    }

    /// A node that has restarted heartbeats before it has finished recovering
    /// its sandboxes. Taking that empty list literally would erase the record
    /// of everything it is about to bring back.
    #[test]
    fn an_empty_report_is_not_read_as_an_empty_node() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Running));

        let applied = registry.apply_states("node1", &[]);
        let (restated, forgotten) = (applied.restated, applied.forgotten);

        assert_eq!((restated, forgotten), (0, 0));
        assert!(registry.get("a").is_some());
    }

    fn tagged(id: &str, pairs: &[(&str, &str)]) -> common::Sandbox {
        common::Sandbox {
            id: id.into(),
            node_id: "node1".into(),
            metadata: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_tag_filter_matches_the_whole_pair() {
        let registry = SandboxRegistry::default();
        registry.insert(tagged("a", &[("env", "staging"), ("team", "infra")]));
        registry.insert(tagged("b", &[("env", "prod")]));
        registry.insert(tagged("c", &[]));

        let staging = registry.list_tagged(Some(("env", "staging")));
        assert_eq!(staging.len(), 1);
        assert_eq!(staging[0].id, "a");

        // The key alone is not a match, and neither is the value alone.
        assert!(registry.list_tagged(Some(("env", "stag"))).is_empty());
        assert!(registry.list_tagged(Some(("team", "prod"))).is_empty());
        assert_eq!(registry.list_tagged(Some(("team", "infra"))).len(), 1);
        assert_eq!(registry.list_tagged(None).len(), 3);
    }

    #[test]
    fn an_unchanged_inventory_reports_no_churn() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Running));
        let applied = registry.apply_states("node1", &[report("a", common::SandboxState::Running)]);
        let (restated, forgotten) = (applied.restated, applied.forgotten);
        assert_eq!((restated, forgotten), (0, 0));
    }

    fn named(id: &str, node: &str, name: &str) -> common::Sandbox {
        common::Sandbox {
            name: name.into(),
            ..sandbox(id, node, common::SandboxState::Running)
        }
    }

    /// The whole point of accepting a delete the node never heard: the name and
    /// the id come back immediately, rather than when the node does.
    #[test]
    fn a_delete_against_a_dead_node_frees_the_name() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));

        assert!(registry.reserve("b", "web").is_err());
        let forgotten = registry.forget_deleted("a").expect("the record");

        assert_eq!(forgotten.name, "web");
        assert!(registry.get("a").is_none());
        assert!(registry.reserve("b", "web").is_ok());
    }

    /// A node that was down for the delete still holds the sandbox, and says so
    /// the moment it returns. Adopting that would undo a delete the caller was
    /// already told had succeeded.
    #[test]
    fn a_tombstoned_sandbox_is_not_adopted_back() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_deleted("a");

        let outcome = registry.reconcile_node("node1", vec![named("a", "node1", "web")]);

        assert_eq!(outcome.adopted, 0);
        assert_eq!(outcome.tombstoned, vec!["a".to_string()]);
        assert!(registry.get("a").is_none());
        // Still held, so the tombstone stays until the node has destroyed it.
        assert!(registry.is_tombstoned("a"));
    }

    /// Heartbeats arrive every few seconds, long before the registration that
    /// reconciles. None of them may put a deleted sandbox back.
    #[test]
    fn a_heartbeat_cannot_resurrect_a_tombstoned_sandbox() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_deleted("a");

        registry.apply_states("node1", &[report("a", common::SandboxState::Running)]);

        assert!(registry.get("a").is_none());
    }

    /// Once the node stops listing it, the delete has actually happened and
    /// there is nothing left for the tombstone to guard against.
    #[test]
    fn a_tombstone_is_cleared_once_the_node_lets_go() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_deleted("a");

        let outcome = registry.reconcile_node("node1", vec![]);

        assert!(outcome.tombstoned.is_empty());
        assert!(!registry.is_tombstoned("a"));
    }

    /// Writing a node off is not a delete. Nobody asked for its sandboxes to be
    /// destroyed, so if it ever comes back its own inventory is the truth.
    #[test]
    fn a_written_off_node_leaves_no_tombstones() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.insert(named("b", "node2", "api"));

        let dropped = registry.forget_node("node1");

        assert_eq!(dropped.len(), 1);
        assert!(registry.get("a").is_none());
        assert!(registry.get("b").is_some(), "another node is untouched");
        assert!(!registry.is_tombstoned("a"));
        assert!(registry.reserve("c", "web").is_ok(), "the name comes back");

        // And the sandbox is really still there, so a return re-adopts it.
        let outcome = registry.reconcile_node("node1", vec![named("a", "node1", "web")]);
        assert_eq!(outcome.adopted, 1);
        assert!(registry.get("a").is_some());
    }

    /// A name freed by writing the node off may already belong to someone else
    /// by the time the node returns. The sandbox is real and is adopted; the
    /// newer claim on the name is the one that holds.
    #[test]
    fn a_returning_sandbox_gives_up_a_name_that_was_reused() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_node("node1");
        registry.insert(named("b", "node2", "web"));

        let outcome = registry.reconcile_node("node1", vec![named("a", "node1", "web")]);

        assert_eq!(outcome.adopted, 1);
        assert_eq!(registry.get("a").expect("adopted").name, "");
        assert_eq!(registry.id_by_name("web").as_deref(), Some("b"));
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    fn sandbox(id: &str, node: &str) -> common::Sandbox {
        common::Sandbox {
            id: id.into(),
            node_id: node.into(),
            template: "python".into(),
            state: common::SandboxState::Running as i32,
            guest_ip: "10.99.0.6".into(),
            ..Default::default()
        }
    }

    fn store() -> (Arc<burrow_store::Store>, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "burrow-placements-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&path);
        (Arc::new(burrow_store::Store::open(&path).unwrap()), path)
    }

    /// The whole point: a fleet that restarts together should not lose the
    /// mapping from sandbox to node.
    #[test]
    fn placements_survive_a_restart() {
        let (store, path) = store();
        {
            let registry = SandboxRegistry::with_store(Arc::clone(&store));
            registry.insert(sandbox("sbx_a", "node1"));
            registry.insert(sandbox("sbx_b", "node2"));
        }

        let restored = SandboxRegistry::with_store(Arc::clone(&store));
        assert_eq!(restored.node_of("sbx_a").as_deref(), Some("node1"));
        assert_eq!(restored.node_of("sbx_b").as_deref(), Some("node2"));
        assert_eq!(restored.get("sbx_a").unwrap().template, "python");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_removed_sandbox_does_not_come_back() {
        let (store, path) = store();
        {
            let registry = SandboxRegistry::with_store(Arc::clone(&store));
            registry.insert(sandbox("sbx_a", "node1"));
            registry.remove("sbx_a");
        }
        assert!(
            SandboxRegistry::with_store(Arc::clone(&store))
                .get("sbx_a")
                .is_none()
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Nodes stay authoritative: what a node reports replaces what was stored
    /// for it, including sandboxes it no longer has.
    #[test]
    fn reconciling_a_node_rewrites_what_was_stored_for_it() {
        let (store, path) = store();
        {
            let registry = SandboxRegistry::with_store(Arc::clone(&store));
            registry.insert(sandbox("gone", "node1"));
            registry.insert(sandbox("kept", "node1"));
            registry.insert(sandbox("elsewhere", "node2"));
            registry.reconcile_node("node1", vec![sandbox("kept", "node1")]);
        }

        let restored = SandboxRegistry::with_store(Arc::clone(&store));
        assert!(restored.get("gone").is_none(), "a node's word is final");
        assert!(restored.get("kept").is_some());
        assert!(
            restored.get("elsewhere").is_some(),
            "another node's sandboxes are untouched"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A node-initiated state change has to reach disk too, or a restart
    /// resurrects the state the orchestrator last caused.
    #[test]
    fn adopted_states_are_persisted() {
        use burrow_proto::node::v1::SandboxStateReport;
        let (store, path) = store();
        {
            let registry = SandboxRegistry::with_store(Arc::clone(&store));
            registry.insert(sandbox("sbx_a", "node1"));
            registry.insert(sandbox("dropped", "node1"));
            registry.settled();
            registry.apply_states(
                "node1",
                &[SandboxStateReport {
                    sandbox_id: "sbx_a".into(),
                    state: common::SandboxState::Suspended as i32,
                    ..Default::default()
                }],
            );
        }

        let restored = SandboxRegistry::with_store(Arc::clone(&store));
        assert_eq!(
            restored.get("sbx_a").unwrap().state,
            common::SandboxState::Suspended as i32
        );
        assert!(restored.get("dropped").is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// Heartbeats arrive every few seconds and usually say nothing new;
    /// rewriting every placement each time is a write per sandbox per
    /// heartbeat for no change at all.
    #[test]
    fn an_unchanged_heartbeat_writes_nothing() {
        use burrow_proto::node::v1::SandboxStateReport;
        let (store, path) = store();
        let registry = SandboxRegistry::with_store(Arc::clone(&store));
        registry.insert(sandbox("sbx_a", "node1"));

        // Removed behind the registry's back, so a needless rewrite is
        // visible: only a persist would put the row back.
        store.delete_placement("sbx_a").unwrap();
        registry.apply_states(
            "node1",
            &[SandboxStateReport {
                sandbox_id: "sbx_a".into(),
                state: common::SandboxState::Running as i32,
                ..Default::default()
            }],
        );
        assert!(store.list_placements().unwrap().is_empty());

        // A state that did move is still written.
        registry.apply_states(
            "node1",
            &[SandboxStateReport {
                sandbox_id: "sbx_a".into(),
                state: common::SandboxState::Suspended as i32,
                ..Default::default()
            }],
        );
        assert_eq!(store.list_placements().unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_registry_without_a_store_still_works() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("sbx_a", "node1"));
        assert_eq!(registry.node_of("sbx_a").as_deref(), Some("node1"));
        registry.remove("sbx_a");
        assert!(registry.get("sbx_a").is_none());
    }
}
