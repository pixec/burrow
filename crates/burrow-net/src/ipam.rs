//! Address allocation for sandbox networking.
//!
//! Every sandbox gets its own /30 on its own tap device rather than sharing a
//! bridge. Two reasons: sandboxes restored from one snapshot share a MAC
//! address, and a shared L2 domain would make them collide; and per-sandbox
//! subnets make nftables rules match on address alone, with no need to
//! correlate interfaces.
//!
//! A /30 holds four addresses: network, host, guest, broadcast.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use crate::error::{NetError, Result};

/// Host-side base network. Each sandbox takes one /30 from it.
const BASE: [u8; 4] = [10, 99, 0, 0];
/// /30s available inside a /16: skips block 0 so the first host address is
/// never the base network address.
const MAX_BLOCKS: u32 = 16_382;

/// The whole pool, which every node's slice is carved out of.
///
/// Every sandbox address on every node in the fleet is in here, which is what
/// makes it the range a policy has to name when it means "any sandbox
/// anywhere" rather than "a sandbox on this node".
pub const POOL_ADDRESS: Ipv4Addr = Ipv4Addr::new(BASE[0], BASE[1], BASE[2], BASE[3]);
/// Prefix covering all [`MAX_BLOCKS`] /30s.
pub const POOL_PREFIX: u8 = 16;

/// /30 blocks each node may allocate from.
///
/// Nodes allocate independently and never coordinate, so their ranges must not
/// overlap: two nodes handing out the same guest address would make cross-node
/// routing ambiguous and let one node's sandbox impersonate another's. Slicing
/// the pool by node index makes that impossible by construction, at the cost
/// of a fixed ceiling per node.
pub const BLOCKS_PER_NODE: u32 = 256;
/// Nodes addressable within the pool.
pub const MAX_NODES: u32 = MAX_BLOCKS / BLOCKS_PER_NODE;
/// Prefix of one node's slice: [`BLOCKS_PER_NODE`] /30s is 1024 addresses.
///
/// A mesh peer claiming a range shorter than this is claiming more than a node
/// can own, so [`crate::mesh`] refuses it.
pub const NODE_PREFIX: u8 = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// Index of the /30 block, which is what makes the lease releasable.
    pub block: u32,
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub prefix_len: u8,
}

impl Lease {
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::new(255, 255, 255, 252)
    }

    /// Deterministic locally-administered MAC. The low bytes come from the
    /// guest address, so a sandbox keeps its MAC across restarts.
    pub fn guest_mac(&self) -> String {
        let o = self.guest_ip.octets();
        format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
    }

    /// Kernel command line fragment that configures the guest NIC at boot,
    /// avoiding any need for DHCP inside the sandbox.
    pub fn kernel_ip_arg(&self) -> String {
        format!(
            "ip={}::{}:{}::eth0:off",
            self.guest_ip,
            self.host_ip,
            self.netmask()
        )
    }
}

#[derive(Debug, Default)]
pub struct Ipam {
    /// sandbox id -> allocated block
    allocated: Mutex<HashMap<String, u32>>,
    /// First block this node owns.
    base_block: u32,
}

impl Ipam {
    /// Creates an allocator confined to one node's slice of the pool.
    ///
    /// `node_index` is assigned by the orchestrator and stable for a node's
    /// lifetime, so a node keeps its addresses across restarts.
    ///
    /// An index at or past [`MAX_NODES`] is an error rather than something to
    /// clamp: clamping would put it on the same slice as the last legitimate
    /// node, so both would hand out the same guest addresses and cross-node
    /// routing would be ambiguous.
    pub fn for_node(node_index: u32) -> Result<Self> {
        if node_index >= MAX_NODES {
            return Err(NetError::NodeIndexOutOfRange {
                index: node_index,
                max: MAX_NODES,
            });
        }
        Ok(Self {
            allocated: Mutex::new(HashMap::new()),
            base_block: node_index * BLOCKS_PER_NODE,
        })
    }

    /// The slice of the pool this allocator owns.
    pub fn node_index(&self) -> u32 {
        self.base_block / BLOCKS_PER_NODE
    }

    /// The address range this node allocates from, as a CIDR.
    ///
    /// Peers route this range to the node over the mesh.
    pub fn subnet(&self) -> String {
        let base = u32::from_be_bytes(BASE) + self.base_block * 4;
        format!("{}/{NODE_PREFIX}", std::net::Ipv4Addr::from(base))
    }

    /// Allocates the lowest free /30. Re-allocating for a sandbox that already
    /// holds one returns the same lease, so resume keeps a stable address.
    pub fn allocate(&self, sandbox_id: &str) -> Result<Lease> {
        let mut allocated = self.allocated.lock().unwrap();
        if let Some(block) = allocated.get(sandbox_id) {
            return Ok(lease_for(*block));
        }
        let used: std::collections::HashSet<u32> = allocated.values().copied().collect();
        // Block 0 of the whole pool is skipped so the first host address is
        // never the network address; later nodes may use their first block.
        let first = self.base_block.max(1);
        let block = (first..self.base_block + BLOCKS_PER_NODE)
            .find(|b| !used.contains(b))
            .ok_or(NetError::AddressPoolExhausted)?;
        allocated.insert(sandbox_id.to_string(), block);
        Ok(lease_for(block))
    }

    pub fn release(&self, sandbox_id: &str) {
        self.allocated.lock().unwrap().remove(sandbox_id);
    }

    pub fn get(&self, sandbox_id: &str) -> Option<Lease> {
        self.allocated
            .lock()
            .unwrap()
            .get(sandbox_id)
            .map(|b| lease_for(*b))
    }

    /// Restores a lease recorded elsewhere (e.g. loaded from disk at startup),
    /// so recovered sandboxes do not have their addresses handed to others.
    pub fn reserve(&self, sandbox_id: &str, block: u32) {
        self.allocated
            .lock()
            .unwrap()
            .insert(sandbox_id.to_string(), block);
    }
}

/// A fixed lease for the transient VM used to build a warm snapshot.
///
/// Taken from the top of the pool so it cannot collide with an allocated
/// block, and never registered with the allocator: the warm VM exists only
/// long enough to be snapshotted.
pub fn warm_lease() -> Lease {
    lease_for(MAX_BLOCKS)
}

fn lease_for(block: u32) -> Lease {
    // Block N occupies 10.99.x.y/30 starting at offset N*4.
    let offset = block * 4;
    let base = u32::from_be_bytes(BASE);
    let host = base + offset + 1;
    let guest = base + offset + 2;
    Lease {
        block,
        host_ip: Ipv4Addr::from(host),
        guest_ip: Ipv4Addr::from(guest),
        prefix_len: 30,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodes_allocate_from_disjoint_ranges() {
        // Two nodes never coordinate, so overlapping addresses would be
        // undetectable until traffic went to the wrong sandbox.
        let a = Ipam::for_node(0).unwrap();
        let b = Ipam::for_node(1).unwrap();
        let from_a = a.allocate("x").unwrap();
        let from_b = b.allocate("y").unwrap();
        assert_ne!(from_a.guest_ip, from_b.guest_ip);
        assert_eq!(from_b.guest_ip, Ipv4Addr::new(10, 99, 4, 2));
    }

    #[test]
    fn a_node_subnet_covers_exactly_its_blocks() {
        assert_eq!(Ipam::for_node(0).unwrap().subnet(), "10.99.0.0/22");
        assert_eq!(Ipam::for_node(1).unwrap().subnet(), "10.99.4.0/22");
        assert_eq!(Ipam::for_node(2).unwrap().subnet(), "10.99.8.0/22");
    }

    #[test]
    fn a_node_cannot_allocate_past_its_slice() {
        let ipam = Ipam::for_node(0).unwrap();
        // Block 0 is skipped, so a node gets one fewer than its full share.
        for i in 0..BLOCKS_PER_NODE - 1 {
            ipam.allocate(&format!("s{i}")).unwrap();
        }
        assert!(ipam.allocate("one-too-many").is_err());
    }

    /// An index the pool cannot hold is refused, since clamping it would put
    /// the node on a slice another node already owns.
    #[test]
    fn an_out_of_range_node_index_is_refused_rather_than_clamped() {
        // The bound is exclusive, so the last index is still legitimate.
        assert_eq!(
            Ipam::for_node(MAX_NODES - 1).unwrap().node_index(),
            MAX_NODES - 1
        );
        for index in [MAX_NODES, u32::MAX] {
            let err = Ipam::for_node(index).unwrap_err();
            assert!(
                matches!(err, NetError::NodeIndexOutOfRange { index: got, .. } if got == index),
                "{index} must be refused, got {err}"
            );
        }
    }

    #[test]
    fn blocks_are_adjacent_and_distinct() {
        let ipam = Ipam::default();
        let a = ipam.allocate("a").unwrap();
        let b = ipam.allocate("b").unwrap();
        assert_eq!(a.host_ip, Ipv4Addr::new(10, 99, 0, 5));
        assert_eq!(a.guest_ip, Ipv4Addr::new(10, 99, 0, 6));
        assert_eq!(b.host_ip, Ipv4Addr::new(10, 99, 0, 9));
        assert_ne!(a.guest_ip, b.guest_ip);
    }

    #[test]
    fn allocation_is_idempotent_per_sandbox() {
        let ipam = Ipam::default();
        let first = ipam.allocate("a").unwrap();
        assert_eq!(first, ipam.allocate("a").unwrap());
    }

    #[test]
    fn released_blocks_are_reused() {
        let ipam = Ipam::default();
        let a = ipam.allocate("a").unwrap();
        ipam.release("a");
        let b = ipam.allocate("b").unwrap();
        assert_eq!(a.guest_ip, b.guest_ip);
    }

    #[test]
    fn mac_is_derived_from_the_guest_address() {
        let ipam = Ipam::default();
        let lease = ipam.allocate("a").unwrap();
        assert_eq!(lease.guest_mac(), "02:00:0a:63:00:06");
    }
}
