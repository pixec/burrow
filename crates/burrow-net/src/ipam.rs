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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use crate::error::{NetError, Result};

/// The fleet's sandbox address pool, and how it is sliced between nodes.
///
/// Every sandbox address on every node in the fleet is in here, which is what
/// makes it the range a policy has to name when it means "any sandbox
/// anywhere" rather than "a sandbox on this node". The orchestrator owns it and
/// hands it to each node at registration, because everything that routes
/// between nodes assumes they agree on it: the mesh's routes and its refusal
/// of a peer claiming more than a slice, the firewall's pool-wide rules, and
/// the route a guest takes to every other sandbox.
///
/// The pool is cut into /30 blocks. Nodes allocate independently and never
/// coordinate, so their ranges must not overlap: two nodes handing out the
/// same guest address would make cross-node routing ambiguous and let one
/// node's sandbox impersonate another's. Slicing the pool by node index into
/// `blocks_per_node` blocks each makes that impossible by construction, at the
/// cost of a fixed ceiling per node.
///
/// The v6 pool mirrors it: one /64 per block, indexed by the same block, so a
/// sandbox's two families always name the same sandbox. A ULA rather than a
/// routed prefix: a sandbox's egress goes through the host exactly as it does
/// over IPv4, so nothing here needs to be globally routable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressPool {
    v4: Ipv4Addr,
    v4_prefix: u8,
    v6: Ipv6Addr,
    v6_prefix: u8,
    blocks_per_node: u32,
}

pub const DEFAULT_POOL: &str = "10.99.0.0/16";
pub const DEFAULT_POOL6: &str = "fd99:b070::/48";
pub const DEFAULT_BLOCKS_PER_NODE: u32 = 256;

/// The shortest v4 pool: a /10 holds 2^20 blocks, as many as
/// [`crate::firewall::egress_mark`] has room for.
const MIN_PREFIX: u8 = 10;
/// One `/64` per sandbox, which is the smallest prefix anything in IPv6 land
/// expects to be handed.
const GUEST6_PREFIX: u8 = 64;

/// What a v4 pool may be carved from: RFC 1918 and the CGNAT range.
const PRIVATE: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
];

impl Default for AddressPool {
    fn default() -> Self {
        Self {
            v4: Ipv4Addr::new(10, 99, 0, 0),
            v4_prefix: 16,
            v6: Ipv6Addr::new(0xfd99, 0xb070, 0, 0, 0, 0, 0, 0),
            v6_prefix: 48,
            blocks_per_node: DEFAULT_BLOCKS_PER_NODE,
        }
    }
}

impl AddressPool {
    /// A pool of the v4 and v6 CIDRs given, each node taking
    /// `blocks_per_node` /30s of it.
    ///
    /// The v4 pool must be private, no larger than a /10, and hold at least
    /// one node's slice; the slice a power of two of at least 4 blocks; the v6
    /// pool a ULA with room for a /64 per v4 block.
    pub fn new(v4: &str, v6: &str, blocks_per_node: u32) -> std::result::Result<Self, String> {
        let (address, v4_prefix) = parse_cidr(v4)?;
        let IpAddr::V4(address4) = address else {
            return Err(format!("{v4} is not an IPv4 CIDR"));
        };
        let (address, v6_prefix) = parse_cidr(v6)?;
        let IpAddr::V6(address6) = address else {
            return Err(format!("{v6} is not an IPv6 CIDR"));
        };
        if v4_prefix > 30 || u32::from(address4) & !mask4(v4_prefix) != 0 {
            return Err(format!(
                "{v4} is not a network address with a prefix of /30 or shorter"
            ));
        }
        if !PRIVATE
            .iter()
            .any(|&(range, prefix)| prefix <= v4_prefix && within4(address4, range, prefix))
        {
            return Err(format!(
                "{v4} is not private: a pool goes inside 10.0.0.0/8, 172.16.0.0/12, \
                 192.168.0.0/16 or 100.64.0.0/10"
            ));
        }
        if v4_prefix < MIN_PREFIX {
            return Err(format!(
                "{v4} is larger than a /{MIN_PREFIX}, the most blocks a sandbox's egress mark \
                 can name"
            ));
        }
        if blocks_per_node < 4 || !blocks_per_node.is_power_of_two() {
            return Err(format!(
                "{blocks_per_node} blocks per node is not a power of two of at least 4"
            ));
        }
        let pool = Self {
            v4: address4,
            v4_prefix,
            v6: address6,
            v6_prefix,
            blocks_per_node,
        };
        if pool.max_nodes() == 0 {
            return Err(format!(
                "{v4} holds {} /30 blocks, too few for one node's {blocks_per_node} and the two \
                 a warm build takes",
                pool.blocks()
            ));
        }
        if v6_prefix > GUEST6_PREFIX
            || u128::from(address6) & !mask6(v6_prefix) != 0
            || address6.segments()[0] & 0xfe00 != 0xfc00
        {
            return Err(format!(
                "{v6} is not a unique local (fc00::/7) network address"
            ));
        }
        let room = GUEST6_PREFIX - pool.block_bits();
        if v6_prefix > room {
            return Err(format!(
                "{v6} cannot give each of {v4}'s {} blocks a /64: the v6 pool must be a /{room} \
                 or shorter",
                pool.blocks()
            ));
        }
        Ok(pool)
    }

    /// The v4 pool as a CIDR.
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.v4, self.v4_prefix)
    }

    /// The v6 pool as a CIDR.
    pub fn cidr6(&self) -> String {
        format!("{}/{}", self.v6, self.v6_prefix)
    }

    pub fn network(&self) -> (Ipv4Addr, u8) {
        (self.v4, self.v4_prefix)
    }

    pub fn network6(&self) -> (Ipv6Addr, u8) {
        (self.v6, self.v6_prefix)
    }

    pub fn blocks_per_node(&self) -> u32 {
        self.blocks_per_node
    }

    fn block_bits(&self) -> u8 {
        30 - self.v4_prefix
    }

    /// Every /30 in the pool.
    fn blocks(&self) -> u32 {
        1 << self.block_bits()
    }

    /// Nodes the pool has a slice for. The top two blocks are left out of
    /// every slice for [`Self::warm_lease`] and [`Self::profiling_lease`].
    pub fn max_nodes(&self) -> u32 {
        (self.blocks() - 2) / self.blocks_per_node
    }

    /// Prefix of one node's slice.
    ///
    /// A mesh peer claiming a range shorter than this is claiming more than a
    /// node can own, so [`crate::mesh`] refuses it.
    pub fn node_prefix(&self) -> u8 {
        30 - self.blocks_per_node.trailing_zeros() as u8
    }

    /// Node `index`'s slice as a CIDR. Peers route it to the node over the
    /// mesh.
    pub fn node_subnet(&self, index: u32) -> String {
        let base = u32::from(self.v4) + index * self.blocks_per_node * 4;
        format!("{}/{}", Ipv4Addr::from(base), self.node_prefix())
    }

    /// Whether `address` is a sandbox address of either family.
    pub fn contains(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(v4) => within4(v4, self.v4, self.v4_prefix),
            IpAddr::V6(v6) => u128::from(v6) & mask6(self.v6_prefix) == u128::from(self.v6),
        }
    }

    /// The first of `addresses` inside the pool, which a node holding it
    /// would route into its sandboxes instead of to wherever it is.
    pub fn overlap(&self, addresses: impl IntoIterator<Item = IpAddr>) -> Option<IpAddr> {
        addresses
            .into_iter()
            .find(|address| self.contains(*address))
    }

    /// A fixed lease for the transient VM used to build a warm snapshot.
    ///
    /// Taken from the top of the pool so it cannot collide with an allocated
    /// block, and never registered with the allocator: the warm VM exists only
    /// long enough to be snapshotted.
    pub fn warm_lease(&self) -> Lease {
        self.lease(self.blocks() - 2)
    }

    /// A fixed lease for the restore that profiles a warm snapshot: another
    /// than [`Self::warm_lease`], so its guest is re-addressed as every
    /// clone's is.
    pub fn profiling_lease(&self) -> Lease {
        self.lease(self.blocks() - 1)
    }

    fn lease(&self, block: u32) -> Lease {
        let base = u32::from(self.v4) + block * 4;
        Lease {
            block,
            host_ip: Ipv4Addr::from(base + 1),
            guest_ip: Ipv4Addr::from(base + 2),
            prefix_len: 30,
            pool: *self,
        }
    }
}

/// `v4 v6 blocks_per_node`, as a node records the pool it was given.
impl std::fmt::Display for AddressPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.cidr(),
            self.cidr6(),
            self.blocks_per_node
        )
    }
}

impl std::str::FromStr for AddressPool {
    type Err = String;

    fn from_str(text: &str) -> std::result::Result<Self, String> {
        let fields: Vec<&str> = text.split_whitespace().collect();
        let [v4, v6, blocks] = fields[..] else {
            return Err(format!("{text:?} is not `v4 v6 blocks_per_node`"));
        };
        let blocks = blocks
            .parse()
            .map_err(|_| format!("{blocks:?} is not a number of blocks"))?;
        Self::new(v4, v6, blocks)
    }
}

fn parse_cidr(text: &str) -> std::result::Result<(IpAddr, u8), String> {
    let (address, prefix) = text
        .split_once('/')
        .ok_or_else(|| format!("{text} is not a CIDR"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("{text} is not a CIDR"))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|prefix| *prefix <= if address.is_ipv4() { 32 } else { 128 })
        .ok_or_else(|| format!("{text} is not a CIDR"))?;
    Ok((address, prefix))
}

fn mask4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

fn within4(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    u32::from(address) & mask4(prefix) == u32::from(network)
}

/// This host's addresses outside burrow's own taps and mesh, which the pool
/// must not overlap.
pub fn host_addresses() -> Vec<IpAddr> {
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
            let name = std::ffi::CStr::from_ptr(entry.ifa_name).to_string_lossy();
            let is_ours = name.starts_with(crate::firewall::TAP_PREFIX)
                || name == crate::mesh::MESH_INTERFACE;
            if let Some(addr) = entry.ifa_addr.as_ref().filter(|_| !is_ours) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// Index of the /30 block, which is what makes the lease releasable.
    pub block: u32,
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub prefix_len: u8,
    pool: AddressPool,
}

impl Lease {
    /// The pool the lease is from.
    pub fn pool(&self) -> AddressPool {
        self.pool
    }

    /// The sandbox's `/64`, indexed by the same block as its `/30` so the two
    /// families name the same sandbox and neither can drift from the other.
    fn subnet6(&self) -> u128 {
        u128::from(self.pool.v6) | u128::from(self.block) << 64
    }

    /// Host side of the link, `::1` in the sandbox's `/64`.
    pub fn host_ip6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.subnet6() | 1)
    }

    /// Guest side, `::2`, mirroring the v4 layout where the host takes the
    /// first usable address and the guest the second.
    pub fn guest_ip6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.subnet6() | 2)
    }

    pub fn prefix_len6(&self) -> u8 {
        GUEST6_PREFIX
    }

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
    pub fn kernel_ip_arg(&self, hostname: &str) -> String {
        format!(
            "ip={}::{}:{}:{hostname}:eth0:off",
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
    pool: AddressPool,
    /// First block this node owns.
    base_block: u32,
}

impl Ipam {
    /// Creates an allocator confined to one node's slice of `pool`.
    ///
    /// `node_index` is assigned by the orchestrator and stable for a node's
    /// lifetime, so a node keeps its addresses across restarts.
    ///
    /// An index at or past [`AddressPool::max_nodes`] is an error rather than
    /// something to clamp: clamping would put it on the same slice as the last
    /// legitimate node, so both would hand out the same guest addresses and
    /// cross-node routing would be ambiguous.
    pub fn for_node(pool: AddressPool, node_index: u32) -> Result<Self> {
        if node_index >= pool.max_nodes() {
            return Err(NetError::NodeIndexOutOfRange {
                index: node_index,
                max: pool.max_nodes(),
            });
        }
        Ok(Self {
            allocated: Mutex::new(HashMap::new()),
            pool,
            base_block: node_index * pool.blocks_per_node,
        })
    }

    pub fn pool(&self) -> AddressPool {
        self.pool
    }

    /// The slice of the pool this allocator owns.
    pub fn node_index(&self) -> u32 {
        self.base_block / self.pool.blocks_per_node
    }

    /// The address range this node allocates from, as a CIDR.
    ///
    /// Peers route this range to the node over the mesh.
    pub fn subnet(&self) -> String {
        self.pool.node_subnet(self.node_index())
    }

    /// Allocates the lowest free /30. Re-allocating for a sandbox that already
    /// holds one returns the same lease, so resume keeps a stable address.
    pub fn allocate(&self, sandbox_id: &str) -> Result<Lease> {
        let mut allocated = self.allocated.lock().unwrap();
        if let Some(block) = allocated.get(sandbox_id) {
            return Ok(self.pool.lease(*block));
        }
        let used: std::collections::HashSet<u32> = allocated.values().copied().collect();
        let block = self
            .blocks()
            .find(|b| !used.contains(b))
            .ok_or(NetError::AddressPoolExhausted)?;
        allocated.insert(sandbox_id.to_string(), block);
        Ok(self.pool.lease(block))
    }

    pub fn release(&self, sandbox_id: &str) {
        self.allocated.lock().unwrap().remove(sandbox_id);
    }

    pub fn get(&self, sandbox_id: &str) -> Option<Lease> {
        self.allocated
            .lock()
            .unwrap()
            .get(sandbox_id)
            .map(|b| self.pool.lease(*b))
    }

    /// Restores a lease recorded elsewhere (e.g. loaded from disk at startup),
    /// so recovered sandboxes do not have their addresses handed to others.
    ///
    /// A block outside this node's slice, or one another sandbox holds, is
    /// refused and nothing changes.
    pub fn reserve(&self, sandbox_id: &str, block: u32) -> Result<()> {
        let blocks = self.blocks();
        if !blocks.contains(&block) {
            return Err(NetError::LeaseBlockOutOfRange {
                block,
                first: blocks.start,
                end: blocks.end,
            });
        }
        let mut allocated = self.allocated.lock().unwrap();
        if let Some((holder, _)) = allocated
            .iter()
            .find(|(id, held)| **held == block && id.as_str() != sandbox_id)
        {
            return Err(NetError::LeaseBlockInUse {
                block,
                sandbox_id: holder.clone(),
            });
        }
        allocated.insert(sandbox_id.to_string(), block);
        Ok(())
    }

    /// The blocks this node may lease. Block 0 of the whole pool is skipped so
    /// the first host address is never the network address; later nodes may
    /// use their first block.
    fn blocks(&self) -> std::ops::Range<u32> {
        self.base_block.max(1)..self.base_block + self.pool.blocks_per_node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both families are indexed by the same block, so a sandbox's v4 and v6
    /// addresses always name the same sandbox and a released block frees
    /// both.
    #[test]
    fn a_lease_carries_a_matching_v6_link() {
        let ipam = Ipam::for_node(AddressPool::default(), 0).unwrap();
        let lease = ipam.allocate("sbx_a").unwrap();
        assert_eq!(lease.prefix_len6(), 64);
        assert_eq!(
            lease.host_ip6(),
            format!("fd99:b070:0:{:x}::1", lease.block)
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(
            lease.guest_ip6(),
            format!("fd99:b070:0:{:x}::2", lease.block)
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        // Distinct sandboxes never share a /64.
        let other = ipam.allocate("sbx_b").unwrap();
        assert_ne!(lease.guest_ip6(), other.guest_ip6());
        assert_ne!(lease.host_ip6(), other.host_ip6());
    }

    #[test]
    fn nodes_allocate_from_disjoint_ranges() {
        // Two nodes never coordinate, so overlapping addresses would be
        // undetectable until traffic went to the wrong sandbox.
        let a = Ipam::for_node(AddressPool::default(), 0).unwrap();
        let b = Ipam::for_node(AddressPool::default(), 1).unwrap();
        let from_a = a.allocate("x").unwrap();
        let from_b = b.allocate("y").unwrap();
        assert_ne!(from_a.guest_ip, from_b.guest_ip);
        assert_eq!(from_b.guest_ip, Ipv4Addr::new(10, 99, 4, 2));
    }

    #[test]
    fn a_node_subnet_covers_exactly_its_blocks() {
        assert_eq!(
            Ipam::for_node(AddressPool::default(), 0).unwrap().subnet(),
            "10.99.0.0/22"
        );
        assert_eq!(
            Ipam::for_node(AddressPool::default(), 1).unwrap().subnet(),
            "10.99.4.0/22"
        );
        assert_eq!(
            Ipam::for_node(AddressPool::default(), 2).unwrap().subnet(),
            "10.99.8.0/22"
        );
    }

    #[test]
    fn a_node_cannot_allocate_past_its_slice() {
        let ipam = Ipam::for_node(AddressPool::default(), 0).unwrap();
        // Block 0 is skipped, so a node gets one fewer than its full share.
        for i in 0..DEFAULT_BLOCKS_PER_NODE - 1 {
            ipam.allocate(&format!("s{i}")).unwrap();
        }
        assert!(ipam.allocate("one-too-many").is_err());
    }

    /// An index the pool cannot hold is refused, since clamping it would put
    /// the node on a slice another node already owns.
    #[test]
    fn an_out_of_range_node_index_is_refused_rather_than_clamped() {
        let max_nodes = || AddressPool::default().max_nodes();
        // The bound is exclusive, so the last index is still legitimate.
        assert_eq!(
            Ipam::for_node(AddressPool::default(), max_nodes() - 1)
                .unwrap()
                .node_index(),
            max_nodes() - 1
        );
        for index in [max_nodes(), u32::MAX] {
            let err = Ipam::for_node(AddressPool::default(), index).unwrap_err();
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
    fn a_restored_block_held_by_another_sandbox_is_refused() {
        let ipam = Ipam::for_node(AddressPool::default(), 0).unwrap();
        ipam.reserve("sbx_a", 1).unwrap();
        let err = ipam.reserve("sbx_b", 1).unwrap_err();
        assert!(
            matches!(&err, NetError::LeaseBlockInUse { block: 1, sandbox_id } if sandbox_id == "sbx_a"),
            "got {err}"
        );
        assert_eq!(ipam.get("sbx_a").unwrap().block, 1);
        assert!(ipam.get("sbx_b").is_none());
    }

    #[test]
    fn a_restored_block_from_another_node_is_refused() {
        let ipam = Ipam::for_node(AddressPool::default(), 1).unwrap();
        for block in [1, DEFAULT_BLOCKS_PER_NODE - 1, 2 * DEFAULT_BLOCKS_PER_NODE] {
            let err = ipam.reserve("sbx", block).unwrap_err();
            assert!(
                matches!(err, NetError::LeaseBlockOutOfRange { block: got, first, end }
                    if got == block && first == DEFAULT_BLOCKS_PER_NODE && end == 2 * DEFAULT_BLOCKS_PER_NODE),
                "{block} must be refused, got {err}"
            );
        }
        assert!(ipam.get("sbx").is_none());
    }

    #[test]
    fn block_zero_cannot_be_restored() {
        let ipam = Ipam::for_node(AddressPool::default(), 0).unwrap();
        for block in [0, u32::MAX] {
            assert!(matches!(
                ipam.reserve("", block),
                Err(NetError::LeaseBlockOutOfRange { first: 1, .. })
            ));
        }
    }

    #[test]
    fn restoring_a_held_block_again_is_a_no_op() {
        let ipam = Ipam::for_node(AddressPool::default(), 0).unwrap();
        ipam.reserve("sbx", 7).unwrap();
        ipam.reserve("sbx", 7).unwrap();
        assert_eq!(ipam.get("sbx"), Some(AddressPool::default().lease(7)));
        assert_ne!(ipam.allocate("other").unwrap().block, 7);
    }

    #[test]
    fn every_allocated_block_can_be_restored() {
        let ipam = Ipam::for_node(AddressPool::default(), 2).unwrap();
        let restored = Ipam::for_node(AddressPool::default(), 2).unwrap();
        while let Ok(lease) = ipam.allocate(&format!("s{}", lease_count(&ipam))) {
            restored.reserve("sbx", lease.block).unwrap();
        }
        assert_eq!(lease_count(&ipam), DEFAULT_BLOCKS_PER_NODE as usize);
    }

    fn lease_count(ipam: &Ipam) -> usize {
        ipam.allocated.lock().unwrap().len()
    }

    #[test]
    fn mac_is_derived_from_the_guest_address() {
        let ipam = Ipam::default();
        let lease = ipam.allocate("a").unwrap();
        assert_eq!(lease.guest_mac(), "02:00:0a:63:00:06");
    }

    /// The defaults are the pool every deployment had before it was
    /// configurable, so upgrading changes no address.
    #[test]
    fn the_default_pool_is_the_one_before_it_was_configurable() {
        let pool = AddressPool::default();
        assert_eq!(
            pool,
            AddressPool::new(DEFAULT_POOL, DEFAULT_POOL6, DEFAULT_BLOCKS_PER_NODE).unwrap()
        );
        assert_eq!(pool.max_nodes(), 63);
        assert_eq!(pool.node_prefix(), 22);
        assert_eq!(pool.cidr(), "10.99.0.0/16");
        assert_eq!(pool.cidr6(), "fd99:b070::/48");
        let warm = pool.warm_lease();
        assert_eq!(
            (warm.block, warm.guest_ip),
            (16_382, Ipv4Addr::new(10, 99, 255, 250))
        );
        assert_eq!(pool.profiling_lease().block, 16_383);
        assert_eq!(
            warm.guest_ip6(),
            "fd99:b070:0:3ffe::2".parse::<Ipv6Addr>().unwrap()
        );
    }

    /// A CGNAT pool sliced 1024 blocks a node: slices are disjoint and
    /// adjacent, each a /20, and v6 follows the same blocks.
    #[test]
    fn a_custom_pool_slices_by_its_own_numbers() {
        let pool = AddressPool::new("100.64.0.0/16", "fd00:b070::/48", 1024).unwrap();
        assert_eq!(pool.max_nodes(), 15);
        assert_eq!(pool.node_prefix(), 20);
        assert_eq!(pool.node_subnet(0), "100.64.0.0/20");
        assert_eq!(pool.node_subnet(1), "100.64.16.0/20");
        let a = Ipam::for_node(pool, 0).unwrap();
        let b = Ipam::for_node(pool, 1).unwrap();
        let (from_a, from_b) = (a.allocate("x").unwrap(), b.allocate("y").unwrap());
        assert_eq!(from_a.guest_ip, Ipv4Addr::new(100, 64, 0, 6));
        assert_eq!(from_b.guest_ip, Ipv4Addr::new(100, 64, 16, 2));
        assert_eq!(from_b.block, 1024);
        assert_eq!(
            from_b.guest_ip6(),
            "fd00:b070:0:400::2".parse::<Ipv6Addr>().unwrap()
        );
        // Block 0 is skipped, so node 0 holds 1023, "x" among them.
        for i in 0..1022 {
            a.allocate(&format!("s{i}")).unwrap();
        }
        assert!(a.allocate("one-too-many").is_err());
        assert!(Ipam::for_node(pool, 15).is_err());
        assert!(pool.contains(IpAddr::V4(Ipv4Addr::new(100, 64, 255, 255))));
        assert!(!pool.contains(IpAddr::V4(Ipv4Addr::new(100, 65, 0, 1))));
        assert!(pool.contains("fd00:b070:0:ffff::2".parse().unwrap()));
        assert!(!pool.contains("fd00:b071::2".parse().unwrap()));
    }

    /// The largest pool: a /10 of 2^20 blocks, thousands of sandboxes a node
    /// over hundreds of nodes, with tap names inside the kernel's 15 bytes.
    #[test]
    fn the_largest_pool_holds_thousands_a_node_over_hundreds_of_nodes() {
        let pool = AddressPool::new("100.64.0.0/10", "fd99:b070::/44", 4096).unwrap();
        assert_eq!(pool.max_nodes(), 255);
        let last = Ipam::for_node(pool, 254).unwrap();
        let lease = last.allocate("x").unwrap();
        assert_eq!(lease.block, 254 * 4096);
        assert!(format!("bt{}", pool.profiling_lease().block).len() <= 15);
        assert!(crate::firewall::egress_mark(pool.profiling_lease().block) >> 20 == 0xb7);
        assert_eq!(
            pool.profiling_lease().guest_ip6(),
            "fd99:b070:f:ffff::2".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn a_pool_that_cannot_work_is_refused() {
        let refused = |v4: &str, v6: &str, blocks: u32| {
            AddressPool::new(v4, v6, blocks).expect_err(&format!("{v4} {v6} {blocks}"))
        };
        assert!(refused("8.8.0.0/16", DEFAULT_POOL6, 256).contains("not private"));
        assert!(refused("172.32.0.0/16", DEFAULT_POOL6, 256).contains("not private"));
        assert!(refused("100.128.0.0/16", DEFAULT_POOL6, 256).contains("not private"));
        assert!(refused("10.0.0.0/8", "fd99::/32", 256).contains("larger than a /10"));
        assert!(refused("10.99.0.1/16", DEFAULT_POOL6, 256).contains("network address"));
        assert!(refused("10.99.0.0", DEFAULT_POOL6, 256).contains("not a CIDR"));
        assert!(refused("fd99::/48", DEFAULT_POOL6, 256).contains("not an IPv4"));
        assert!(refused(DEFAULT_POOL, DEFAULT_POOL6, 300).contains("power of two"));
        assert!(refused(DEFAULT_POOL, DEFAULT_POOL6, 2).contains("power of two"));
        assert!(refused("10.99.0.0/24", DEFAULT_POOL6, 64).contains("too few"));
        assert!(refused(DEFAULT_POOL, "2001:db8::/48", 256).contains("unique local"));
        assert!(refused(DEFAULT_POOL, "fd99:b070::1/48", 256).contains("unique local"));
        assert!(refused("10.96.0.0/12", DEFAULT_POOL6, 256).contains("/46 or shorter"));
        AddressPool::new("10.96.0.0/12", "fd99:b070::/46", 256).unwrap();
        AddressPool::new("192.168.0.0/24", "fd99:b070::/56", 4).unwrap();
    }

    /// A node records its pool as text and reads the same pool back.
    #[test]
    fn a_pool_survives_its_text_form() {
        let pool = AddressPool::new("100.64.0.0/16", "fd00:b070::/48", 1024).unwrap();
        assert_eq!(pool.to_string(), "100.64.0.0/16 fd00:b070::/48 1024");
        assert_eq!(pool.to_string().parse::<AddressPool>(), Ok(pool));
        assert!(
            "100.64.0.0/16 fd00:b070::/48"
                .parse::<AddressPool>()
                .is_err()
        );
    }

    #[test]
    fn overlap_finds_an_address_inside_either_family() {
        let pool = AddressPool::default();
        let host = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 5, 15)),
            "fd99:b070:0:1::5".parse().unwrap(),
        ];
        assert_eq!(pool.overlap(host), Some(host[1]));
        assert_eq!(pool.overlap(host[..1].iter().copied()), None);
    }
}
