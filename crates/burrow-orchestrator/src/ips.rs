//! Dedicated public IPs: pools, allocation within a caller's quota,
//! attachment to a sandbox on a node a pool reaches, and quarantine on
//! release.
//!
//! The orchestrator holds the records; the node holding a sandbox routes the
//! address to it and is the only party that calls a provider, with the
//! credentials in its own configuration.

#![allow(clippy::result_large_err)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use prost::Message as _;
use tonic::Status;
use tonic::metadata::MetadataMap;

use burrow_proto::common::v1 as common;
use burrow_proto::node::v1 as nodepb;

use super::{ApiService, NodeClient};

/// How addresses are handed out: who may manage pools, how many a caller may
/// hold, and how long a released one sits out.
#[derive(Debug, Clone)]
pub struct IpConfig {
    /// Tokens that may create, change and remove pools. Empty makes every
    /// accepted token an operator's, which is a single-tenant deployment.
    pub operator_tokens: Vec<String>,
    pub quota: u32,
    pub quarantine_secs: i64,
}

impl Default for IpConfig {
    fn default() -> Self {
        Self {
            operator_tokens: Vec::new(),
            quota: 4,
            quarantine_secs: 24 * 60 * 60,
        }
    }
}

/// The most addresses one pool may enumerate.
const MAX_POOL_ADDRESSES: u64 = 65_536;
const ALLOCATED: i32 = common::PublicIpState::Allocated as i32;
const QUARANTINED: i32 = common::PublicIpState::Quarantined as i32;

/// Who is calling: a digest of the bearer token, never the token.
#[derive(Debug, Clone)]
pub struct Caller {
    pub owner: String,
    pub is_operator: bool,
}

/// The caller presenting `metadata`'s bearer token.
pub fn caller(metadata: &MetadataMap, config: &IpConfig) -> Caller {
    use sha2::Digest as _;
    let token = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .unwrap_or_default();
    let owner = match token.is_empty() {
        true => "anonymous".to_string(),
        false => hex::encode(&sha2::Sha256::digest(token.as_bytes())[..8]),
    };
    let is_operator = config.operator_tokens.is_empty()
        || config.operator_tokens.iter().any(|operator| {
            burrow_common::auth::constant_time_eq(operator.as_bytes(), token.as_bytes())
        });
    Caller { owner, is_operator }
}

fn store_error(err: burrow_store::StoreError) -> Status {
    Status::internal(format!("ip store: {err}"))
}

/// Every address a v4 pool holds, in order, or the subnets a v6 one carves,
/// each as the address the guest takes and the prefix routed to it.
fn enumerate(pool: &common::IpPool) -> Result<Vec<(IpAddr, u8)>, String> {
    if !pool.prefix6.is_empty() {
        let (base, len) = parse_prefix6(&pool.prefix6)?;
        let per = pool.per_sandbox as u8;
        if !(len..=128).contains(&per) || per == 0 {
            return Err(format!(
                "per_sandbox /{} must be between the prefix's /{len} and /128",
                pool.per_sandbox
            ));
        }
        let count = 1u128 << u32::from(per - len).min(17);
        let count = count.min(MAX_POOL_ADDRESSES as u128);
        return Ok((0..count)
            .map(|index| {
                let subnet = u128::from(base) | (index << (128 - u32::from(per)));
                let address = if per < 128 { subnet | 1 } else { subnet };
                (IpAddr::V6(Ipv6Addr::from(address)), per)
            })
            .collect());
    }
    let mut out = Vec::new();
    for range in &pool.ranges {
        let (first, last) = range
            .split_once('-')
            .ok_or_else(|| format!("range {range:?} is not first-last"))?;
        let first: Ipv4Addr = first
            .trim()
            .parse()
            .map_err(|_| format!("range {range:?} does not start with an IPv4 address"))?;
        let last: Ipv4Addr = last
            .trim()
            .parse()
            .map_err(|_| format!("range {range:?} does not end with an IPv4 address"))?;
        let (first, last) = (u32::from(first), u32::from(last));
        if last < first || u64::from(last - first) >= MAX_POOL_ADDRESSES {
            return Err(format!("range {range:?} is backwards or too large"));
        }
        out.extend((first..=last).map(|n| (IpAddr::V4(Ipv4Addr::from(n)), 32)));
    }
    for address in &pool.addresses {
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| format!("{address:?} is not an IPv4 address"))?;
        out.push((IpAddr::V4(address), 32));
    }
    let mut seen = HashSet::new();
    out.retain(|(address, _)| seen.insert(*address));
    if out.len() as u64 > MAX_POOL_ADDRESSES {
        return Err(format!("at most {MAX_POOL_ADDRESSES} addresses per pool"));
    }
    Ok(out)
}

fn parse_prefix6(prefix: &str) -> Result<(Ipv6Addr, u8), String> {
    let (address, len) = prefix
        .split_once('/')
        .ok_or_else(|| format!("prefix6 {prefix:?} is not address/len"))?;
    let address: Ipv6Addr = address
        .parse()
        .map_err(|_| format!("prefix6 {prefix:?} is not an IPv6 prefix"))?;
    let len: u8 = len
        .parse()
        .ok()
        .filter(|len| *len <= 128)
        .ok_or_else(|| format!("prefix6 {prefix:?} has no valid length"))?;
    let mask = match len {
        0 => 0,
        bits => u128::MAX << (128 - u32::from(bits)),
    };
    Ok((Ipv6Addr::from(u128::from(address) & mask), len))
}

/// Checks a pool an operator wrote, and fills in its derived fields.
pub fn validate_pool(pool: &mut common::IpPool) -> Result<(), Status> {
    let invalid = |message: String| Status::invalid_argument(message);
    super::validate_name(&pool.name)?;
    match common::IpProvider::try_from(pool.provider) {
        Ok(common::IpProvider::Unspecified) => pool.provider = common::IpProvider::Static as i32,
        Ok(_) => {}
        Err(_) => {
            return Err(invalid(format!(
                "provider {} is not a known provider",
                pool.provider
            )));
        }
    }
    burrow_common::tags::validate_labels(&pool.node_labels)?;
    if pool.node_id.is_empty() == pool.node_labels.is_empty() {
        return Err(invalid(
            "a pool covers one node (node_id) or the nodes carrying node_labels, exactly one"
                .into(),
        ));
    }
    let is_v6 = !pool.prefix6.is_empty();
    if is_v6 && !(pool.ranges.is_empty() && pool.addresses.is_empty()) {
        return Err(invalid(
            "a pool is IPv4 ranges and addresses or an IPv6 prefix6, not both".into(),
        ));
    }
    let addresses = enumerate(pool).map_err(invalid)?;
    if addresses.is_empty() {
        return Err(invalid("the pool holds no addresses".into()));
    }
    if !pool.gateway.is_empty() {
        let gateway: IpAddr = pool
            .gateway
            .parse()
            .map_err(|_| invalid(format!("gateway {:?} is not an address", pool.gateway)))?;
        if gateway.is_ipv6() != is_v6 {
            return Err(invalid(
                "the gateway is of the other family from the pool".into(),
            ));
        }
        let width = if is_v6 { 128 } else { 32 };
        if !(1..=width).contains(&pool.prefix_len) {
            return Err(invalid(format!(
                "prefix_len {} is not a prefix of the gateway's network",
                pool.prefix_len
            )));
        }
    }
    for nameserver in &pool.nameservers {
        nameserver
            .parse::<IpAddr>()
            .map_err(|_| invalid(format!("nameserver {nameserver:?} is not an address")))?;
    }
    if pool.quarantine_secs < 0 {
        return Err(invalid("quarantine_secs is never negative".into()));
    }
    pool.total = addresses.len() as u32;
    Ok(())
}

/// Whether `info` is a node `pool` reaches.
fn covers(pool: &common::IpPool, info: &common::NodeInfo) -> bool {
    match pool.node_id.is_empty() {
        false => pool.node_id == info.id,
        true => pool
            .node_labels
            .iter()
            .all(|(key, value)| info.labels.get(key) == Some(value)),
    }
}

impl ApiService {
    fn ip_store(&self) -> Result<&std::sync::Arc<burrow_store::Store>, Status> {
        self.0.store.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "public IPs need the orchestrator's store, which did not open",
            )
        })
    }

    fn require_operator(&self, metadata: &MetadataMap) -> Result<(), Status> {
        if caller(metadata, &self.0.ips).is_operator {
            Ok(())
        } else {
            Err(Status::permission_denied(
                "address pools are operator configuration; this credential is not an operator's",
            ))
        }
    }

    async fn pools(&self) -> Result<Vec<common::IpPool>, Status> {
        let rows = self
            .ip_store()?
            .list_ip_pools()
            .await
            .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|(_, record)| common::IpPool::decode(record.as_slice()).ok())
            .collect())
    }

    async fn pool(&self, name: &str) -> Result<common::IpPool, Status> {
        self.pools()
            .await?
            .into_iter()
            .find(|pool| pool.name == name)
            .ok_or_else(|| Status::not_found(format!("no ip pool {name}")))
    }

    async fn ip_row(
        &self,
        address: &str,
    ) -> Result<(burrow_store::IpRow, common::PublicIp), Status> {
        let normalized = address
            .parse::<IpAddr>()
            .map(|a| a.to_string())
            .map_err(|_| Status::invalid_argument(format!("{address:?} is not an address")))?;
        let row = self
            .ip_store()?
            .get_ip(&normalized)
            .await
            .map_err(store_error)?
            .filter(|row| row.state == ALLOCATED)
            .ok_or_else(|| Status::not_found(format!("{normalized} is not allocated")))?;
        let ip = common::PublicIp::decode(row.record.as_slice())
            .map_err(|err| Status::internal(format!("ip record {normalized}: {err}")))?;
        Ok((row, ip))
    }

    /// The row for `address`, refused unless `caller` owns it or operates.
    async fn owned_ip(
        &self,
        address: &str,
        caller: &Caller,
    ) -> Result<(burrow_store::IpRow, common::PublicIp), Status> {
        let (row, ip) = self.ip_row(address).await?;
        if row.owner != caller.owner && !caller.is_operator {
            return Err(Status::not_found(format!(
                "{} is not allocated",
                ip.address
            )));
        }
        Ok((row, ip))
    }

    async fn save_ip(
        &self,
        row: &burrow_store::IpRow,
        ip: &common::PublicIp,
    ) -> Result<(), Status> {
        let row = burrow_store::IpRow {
            record: ip.encode_to_vec(),
            ..row.clone()
        };
        self.ip_store()?.put_ip(&row).await.map_err(store_error)
    }

    pub(super) async fn node_client(&self, node_id: &str) -> Result<NodeClient, Status> {
        let endpoint = self
            .0
            .nodes
            .endpoint(node_id)
            .ok_or_else(|| Status::unavailable(format!("node {node_id} is unreachable")))?;
        self.0
            .channels
            .get(&endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach node {node_id}: {err}")))
    }

    pub(super) async fn create_ip_pool_inner(
        &self,
        metadata: &MetadataMap,
        mut pool: common::IpPool,
        is_update: bool,
    ) -> Result<common::IpPool, Status> {
        self.require_operator(metadata)?;
        validate_pool(&mut pool)?;
        let pools = self.pools().await?;
        let exists = pools.iter().any(|held| held.name == pool.name);
        match (exists, is_update) {
            (true, false) => {
                return Err(Status::already_exists(format!(
                    "ip pool {} exists",
                    pool.name
                )));
            }
            (false, true) => return Err(Status::not_found(format!("no ip pool {}", pool.name))),
            _ => {}
        }
        let mine: HashSet<IpAddr> = enumerate(&pool)
            .unwrap_or_default()
            .into_iter()
            .map(|(address, _)| address)
            .collect();
        for other in pools.iter().filter(|held| held.name != pool.name) {
            if let Some((address, _)) = enumerate(other)
                .unwrap_or_default()
                .into_iter()
                .find(|(address, _)| mine.contains(address))
            {
                return Err(Status::already_exists(format!(
                    "{address} is already in pool {}",
                    other.name
                )));
            }
        }
        if is_update {
            let held: Vec<_> = self
                .ip_store()?
                .list_ips()
                .await
                .map_err(store_error)?
                .into_iter()
                .filter(|row| row.pool == pool.name)
                .collect();
            if let Some(row) = held.iter().find(|row| {
                row.address
                    .parse::<IpAddr>()
                    .is_ok_and(|address| !mine.contains(&address))
            }) {
                return Err(Status::failed_precondition(format!(
                    "{} is allocated from pool {} and would no longer be in it; release it first",
                    row.address, pool.name
                )));
            }
        }
        pool.allocated = 0;
        self.ip_store()?
            .put_ip_pool(&pool.name, &pool.encode_to_vec())
            .await
            .map_err(store_error)?;
        tracing::info!(pool = pool.name, total = pool.total, "ip pool saved");
        Ok(pool)
    }

    pub(super) async fn delete_ip_pool_inner(
        &self,
        metadata: &MetadataMap,
        name: &str,
    ) -> Result<(), Status> {
        self.require_operator(metadata)?;
        let held = self
            .ip_store()?
            .list_ips()
            .await
            .map_err(store_error)?
            .into_iter()
            .filter(|row| row.pool == name && row.state == ALLOCATED)
            .count();
        if held > 0 {
            return Err(Status::failed_precondition(format!(
                "ip pool {name} has {held} allocated addresses; release them first"
            )));
        }
        if !self
            .ip_store()?
            .delete_ip_pool(name)
            .await
            .map_err(store_error)?
        {
            return Err(Status::not_found(format!("no ip pool {name}")));
        }
        Ok(())
    }

    pub(super) async fn list_ip_pools_inner(&self) -> Result<Vec<common::IpPool>, Status> {
        let rows = self.ip_store()?.list_ips().await.map_err(store_error)?;
        let mut counts: HashMap<String, u32> = HashMap::new();
        for row in rows.iter().filter(|row| row.state == ALLOCATED) {
            *counts.entry(row.pool.clone()).or_default() += 1;
        }
        let mut pools = self.pools().await?;
        for pool in &mut pools {
            pool.allocated = counts.get(&pool.name).copied().unwrap_or(0);
        }
        Ok(pools)
    }

    pub(super) async fn allocate_ip_inner(
        &self,
        metadata: &MetadataMap,
        req: burrow_proto::api::v1::AllocateIpRequest,
    ) -> Result<common::PublicIp, Status> {
        let caller = caller(metadata, &self.0.ips);
        let store = self.ip_store()?;
        let rows = store.list_ips().await.map_err(store_error)?;
        let held = rows
            .iter()
            .filter(|row| row.owner == caller.owner && row.state == ALLOCATED)
            .count() as u32;
        if held >= self.0.ips.quota && !caller.is_operator {
            return Err(Status::resource_exhausted(format!(
                "this credential holds {held} public IPs, its quota; release one first"
            )));
        }
        let family = match req.family {
            0 | 4 => 4,
            6 => 6,
            other => {
                return Err(Status::invalid_argument(format!(
                    "family {other} is not 4 or 6"
                )));
            }
        };
        let sandbox = match req.sandbox_id.is_empty() {
            true => None,
            false => {
                let id = self.resolve(&req.sandbox_id).await;
                let node = self.node_of(&id)?;
                Some((id, node))
            }
        };
        let node_info = sandbox
            .as_ref()
            .and_then(|(_, node)| self.0.nodes.info(node));
        let pools: Vec<common::IpPool> = self
            .pools()
            .await?
            .into_iter()
            .filter(|pool| req.pool.is_empty() || pool.name == req.pool)
            .filter(|pool| (pool.prefix6.is_empty()) == (family == 4))
            .filter(|pool| node_info.as_ref().is_none_or(|info| covers(pool, info)))
            .collect();
        if pools.is_empty() {
            return Err(match (&req.pool, &sandbox) {
                (name, _) if !name.is_empty() => Status::not_found(format!(
                    "no IPv{family} pool {name}{}",
                    sandbox
                        .as_ref()
                        .map(|(_, node)| format!(" covering node {node}"))
                        .unwrap_or_default()
                )),
                (_, Some((_, node))) => {
                    Status::failed_precondition(format!("no IPv{family} pool covers node {node}"))
                }
                _ => Status::failed_precondition(format!("no IPv{family} pool is configured")),
            });
        }
        let now = burrow_common::unix_now_ms();
        let taken: HashSet<String> = rows
            .iter()
            .filter(|row| row.state == ALLOCATED || row.available_at_ms > now)
            .map(|row| row.address.clone())
            .collect();
        for pool in &pools {
            for (address, prefix) in enumerate(pool).map_err(Status::internal)? {
                let address = address.to_string();
                if taken.contains(&address) {
                    continue;
                }
                let ip = common::PublicIp {
                    address: address.clone(),
                    family,
                    prefix_len: u32::from(prefix),
                    pool: pool.name.clone(),
                    provider: pool.provider,
                    is_movable: pool.provider().is_movable(),
                    node_id: pool.node_id.clone(),
                    allocated_at_unix_ms: now,
                    owner: caller.owner.clone(),
                    gateway: pool.gateway.clone(),
                    gateway_prefix_len: pool.prefix_len,
                    is_on_link: pool.is_on_link,
                    is_smtp_allowed: pool.is_smtp_allowed,
                    is_wake_on_traffic: pool.is_wake_on_traffic,
                    nameservers: pool.nameservers.clone(),
                    state: ALLOCATED,
                    ..Default::default()
                };
                let row = burrow_store::IpRow {
                    address: address.clone(),
                    pool: pool.name.clone(),
                    owner: caller.owner.clone(),
                    state: ALLOCATED,
                    available_at_ms: 0,
                    record: ip.encode_to_vec(),
                };
                if !store.claim_ip(&row, now).await.map_err(store_error)? {
                    continue;
                }
                tracing::info!(
                    address,
                    pool = pool.name,
                    owner = caller.owner,
                    "public ip allocated"
                );
                if let Some((id, _)) = &sandbox {
                    return self.attach_to(row, ip, id).await;
                }
                return Ok(ip);
            }
        }
        Err(Status::resource_exhausted(format!(
            "every IPv{family} address in {} is allocated or quarantined",
            pools
                .iter()
                .map(|pool| pool.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    pub(super) async fn attach_ip_inner(
        &self,
        metadata: &MetadataMap,
        address: &str,
        sandbox: &str,
    ) -> Result<common::PublicIp, Status> {
        let caller = caller(metadata, &self.0.ips);
        let (row, ip) = self.owned_ip(address, &caller).await?;
        let id = self.resolve(sandbox).await;
        self.attach_to(row, ip, &id).await
    }

    /// The node a sandbox holding `ip` must be on, when it is pinned: a
    /// static address that has reached a node keeps it, and a pool scoped to
    /// one node gives every address that node.
    pub(super) fn pinned_node(ip: &common::PublicIp) -> Option<String> {
        (!ip.is_movable && !ip.node_id.is_empty()).then(|| ip.node_id.clone())
    }

    /// Checks that a sandbox on `node` can hold `ip`.
    async fn require_reachable(&self, ip: &common::PublicIp, node: &str) -> Result<(), Status> {
        let info = self
            .0
            .nodes
            .info(node)
            .ok_or_else(|| Status::unavailable(format!("node {node} is unknown")))?;
        let missing =
            crate::registry::missing_features(&info, &[burrow_common::features::PUBLIC_IPS]);
        if !missing.is_empty() {
            return Err(Status::failed_precondition(format!(
                "node {node} cannot route a public IP to a sandbox: a macOS node's userspace \
                 network has no route one could arrive on, and an older burrowd has none"
            )));
        }
        if let Some(pinned) = Self::pinned_node(ip)
            && pinned != node
        {
            return Err(Status::failed_precondition(format!(
                "{} is a static address that reaches only node {pinned}, and the sandbox is on \
                 node {node}",
                ip.address
            )));
        }
        let pool = self.pool(&ip.pool).await?;
        if !covers(&pool, &info) {
            return Err(Status::failed_precondition(format!(
                "pool {} does not cover node {node}",
                pool.name
            )));
        }
        if ip.is_movable && !info.ip_providers.contains(&ip.provider) {
            return Err(Status::failed_precondition(format!(
                "node {node} holds no {} credentials, so it cannot have {} routed to it",
                ip.provider().label(),
                ip.address
            )));
        }
        Ok(())
    }

    async fn attach_to(
        &self,
        row: burrow_store::IpRow,
        mut ip: common::PublicIp,
        sandbox_id: &str,
    ) -> Result<common::PublicIp, Status> {
        if ip.sandbox_id == sandbox_id {
            return Ok(ip);
        }
        if !ip.sandbox_id.is_empty() {
            return Err(Status::failed_precondition(format!(
                "{} is attached to sandbox {}; detach it first",
                ip.address, ip.sandbox_id
            )));
        }
        let node = self.holder(sandbox_id).await?;
        if node.is_empty() {
            return Err(Status::failed_precondition(format!(
                "sandbox {sandbox_id} is on no node; start it first"
            )));
        }
        self.require_reachable(&ip, &node).await?;
        let mut client = self.node_client(&node).await?;
        if ip.is_movable && ip.node_id != node {
            client
                .route_public_ip(nodepb::NodeProviderRequest {
                    ip: Some(ip.clone()),
                    rdns: String::new(),
                })
                .await?;
        }
        ip.sandbox_id = sandbox_id.to_string();
        ip.node_id = node.clone();
        ip.attached_at_unix_ms = burrow_common::unix_now_ms();
        let sandbox = client
            .attach_public_ip(nodepb::NodeAttachIpRequest {
                sandbox_id: sandbox_id.to_string(),
                ip: Some(ip.clone()),
            })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox);
        self.save_ip(&row, &ip).await?;
        tracing::info!(
            address = ip.address,
            sandbox = sandbox_id,
            node,
            "public ip attached"
        );
        Ok(ip)
    }

    pub(super) async fn detach_ip_inner(
        &self,
        metadata: &MetadataMap,
        address: &str,
    ) -> Result<common::PublicIp, Status> {
        let caller = caller(metadata, &self.0.ips);
        let (row, ip) = self.owned_ip(address, &caller).await?;
        self.detach(row, ip).await
    }

    async fn detach(
        &self,
        row: burrow_store::IpRow,
        mut ip: common::PublicIp,
    ) -> Result<common::PublicIp, Status> {
        if ip.sandbox_id.is_empty() {
            return Ok(ip);
        }
        match self.node_for(&ip.sandbox_id).await {
            Ok(mut client) => {
                let sandbox = client
                    .detach_public_ip(nodepb::NodeDetachIpRequest {
                        sandbox_id: ip.sandbox_id.clone(),
                        address: ip.address.clone(),
                    })
                    .await?
                    .into_inner();
                self.0.sandboxes.insert(sandbox);
            }
            // A sandbox that no longer exists holds nothing to take back.
            Err(err) if err.code() == tonic::Code::NotFound => {}
            Err(err) => return Err(err),
        }
        tracing::info!(
            address = ip.address,
            sandbox = ip.sandbox_id,
            "public ip detached"
        );
        ip.sandbox_id.clear();
        ip.attached_at_unix_ms = 0;
        self.save_ip(&row, &ip).await?;
        Ok(ip)
    }

    pub(super) async fn release_ip_inner(
        &self,
        metadata: &MetadataMap,
        address: &str,
    ) -> Result<(), Status> {
        let caller = caller(metadata, &self.0.ips);
        let (row, ip) = self.owned_ip(address, &caller).await?;
        let mut ip = self.detach(row.clone(), ip).await?;
        let quarantine = self
            .pool(&ip.pool)
            .await
            .ok()
            .map(|pool| pool.quarantine_secs)
            .filter(|secs| *secs > 0)
            .unwrap_or(self.0.ips.quarantine_secs);
        let now = burrow_common::unix_now_ms();
        ip.released_at_unix_ms = now;
        ip.quarantined_until_unix_ms = now + quarantine * 1000;
        ip.state = QUARANTINED;
        ip.rdns.clear();
        let row = burrow_store::IpRow {
            state: QUARANTINED,
            available_at_ms: ip.quarantined_until_unix_ms,
            ..row
        };
        self.save_ip(&row, &ip).await?;
        tracing::info!(
            address = ip.address,
            quarantine_secs = quarantine,
            "public ip released into quarantine"
        );
        Ok(())
    }

    pub(super) async fn list_ips_inner(
        &self,
        metadata: &MetadataMap,
        req: burrow_proto::api::v1::ListIpsRequest,
    ) -> Result<Vec<common::PublicIp>, Status> {
        let caller = caller(metadata, &self.0.ips);
        let sandbox = match req.sandbox_id.is_empty() {
            true => None,
            false => Some(self.resolve(&req.sandbox_id).await),
        };
        let now = burrow_common::unix_now_ms();
        let rows = self.ip_store()?.list_ips().await.map_err(store_error)?;
        Ok(rows
            .into_iter()
            .filter(|row| match row.state {
                ALLOCATED => caller.is_operator || row.owner == caller.owner,
                _ => req.is_quarantine_included && caller.is_operator && row.available_at_ms > now,
            })
            .filter(|row| req.pool.is_empty() || row.pool == req.pool)
            .filter_map(|row| common::PublicIp::decode(row.record.as_slice()).ok())
            .filter(|ip| sandbox.as_ref().is_none_or(|id| &ip.sandbox_id == id))
            .collect())
    }

    pub(super) async fn set_ip_rdns_inner(
        &self,
        metadata: &MetadataMap,
        address: &str,
        name: &str,
    ) -> Result<common::PublicIp, Status> {
        let caller = caller(metadata, &self.0.ips);
        let (row, mut ip) = self.owned_ip(address, &caller).await?;
        if !name.is_empty() && !is_host_name(name) {
            return Err(Status::invalid_argument(format!(
                "{name:?} is not a host name"
            )));
        }
        if !ip.provider().is_movable() {
            return Err(Status::failed_precondition(format!(
                "{} is from a static pool, whose provider offers no reverse DNS; set its PTR \
                 record with whoever routes the range",
                ip.address
            )));
        }
        let pool = self.pool(&ip.pool).await?;
        let node = match ip.node_id.is_empty() {
            false => ip.node_id.clone(),
            true => self
                .0
                .nodes
                .healthy_ids()
                .into_iter()
                .filter_map(|id| self.0.nodes.info(&id))
                .find(|info| covers(&pool, info) && info.ip_providers.contains(&ip.provider))
                .map(|info| info.id)
                .ok_or_else(|| {
                    Status::failed_precondition(format!(
                        "no healthy node in pool {} holds {} credentials",
                        pool.name,
                        ip.provider().label()
                    ))
                })?,
        };
        self.node_client(&node)
            .await?
            .set_public_ip_rdns(nodepb::NodeProviderRequest {
                ip: Some(ip.clone()),
                rdns: name.to_string(),
            })
            .await?;
        ip.rdns = name.to_string();
        self.save_ip(&row, &ip).await?;
        Ok(ip)
    }

    /// The addresses attached to `sandbox_id`, by the orchestrator's records.
    pub(super) async fn ips_of(
        &self,
        sandbox_id: &str,
    ) -> Vec<(burrow_store::IpRow, common::PublicIp)> {
        let Ok(store) = self.ip_store() else {
            return Vec::new();
        };
        store
            .list_ips()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.state == ALLOCATED)
            .filter_map(|row| {
                let ip = common::PublicIp::decode(row.record.as_slice()).ok()?;
                (ip.sandbox_id == sandbox_id).then_some((row, ip))
            })
            .collect()
    }

    /// A deleted sandbox gives its addresses back to their owners, still
    /// allocated, so an address in someone's DNS is never handed on.
    pub(super) async fn forget_attachments(&self, sandbox_id: &str) {
        for (row, mut ip) in self.ips_of(sandbox_id).await {
            ip.sandbox_id.clear();
            ip.attached_at_unix_ms = 0;
            if let Err(err) = self.save_ip(&row, &ip).await {
                tracing::warn!(
                    address = ip.address,
                    err = err.message(),
                    "could not detach a deleted sandbox's address"
                );
            }
        }
    }

    /// Resolves the addresses a create asks for: each the caller's and
    /// detached, and the node a static one pins the sandbox to.
    pub(super) async fn ips_for_create(
        &self,
        metadata: &MetadataMap,
        addresses: &[String],
    ) -> Result<
        (
            Vec<(burrow_store::IpRow, common::PublicIp)>,
            Option<String>,
            HashMap<String, String>,
        ),
        Status,
    > {
        let caller = caller(metadata, &self.0.ips);
        let mut out = Vec::new();
        let mut pinned: Option<String> = None;
        let mut labels = HashMap::new();
        for address in addresses {
            let (row, ip) = self.owned_ip(address, &caller).await?;
            if !ip.sandbox_id.is_empty() {
                return Err(Status::failed_precondition(format!(
                    "{} is attached to sandbox {}; detach it first",
                    ip.address, ip.sandbox_id
                )));
            }
            let pool = self.pool(&ip.pool).await?;
            let node = Self::pinned_node(&ip)
                .or_else(|| (!pool.node_id.is_empty()).then(|| pool.node_id.clone()));
            if let Some(node) = node {
                if pinned.as_ref().is_some_and(|held| *held != node) {
                    return Err(Status::failed_precondition(format!(
                        "{} reaches only node {node}, and another requested address another node",
                        ip.address
                    )));
                }
                pinned = Some(node);
            }
            labels.extend(pool.node_labels.clone());
            out.push((row, ip));
        }
        Ok((out, pinned, labels))
    }

    /// Attaches what a create asked for, deleting the sandbox if any fails so
    /// the caller is not left holding one without its addresses.
    pub(super) async fn attach_for_create(
        &self,
        sandbox_id: &str,
        ips: Vec<(burrow_store::IpRow, common::PublicIp)>,
    ) -> Result<(), Status> {
        for (row, ip) in ips {
            if let Err(err) = self.attach_to(row, ip, sandbox_id).await {
                if let Ok(mut client) = self.node_for(sandbox_id).await {
                    let _ = client
                        .delete_sandbox(nodepb::NodeSandboxRef {
                            sandbox_id: sandbox_id.to_string(),
                        })
                        .await;
                }
                self.forget_attachments(sandbox_id).await;
                self.0.sandboxes.remove(sandbox_id);
                return Err(err);
            }
        }
        Ok(())
    }

    /// Refuses a move that would leave a static address behind, and checks a
    /// target can take every movable one.
    pub(super) async fn require_movable(
        &self,
        sandbox_id: &str,
        target: Option<&str>,
    ) -> Result<(), Status> {
        for (_, ip) in self.ips_of(sandbox_id).await {
            if !ip.is_movable {
                return Err(Status::failed_precondition(format!(
                    "sandbox {sandbox_id} holds {}, a static address that reaches only node {}; \
                     detach it first, or keep the sandbox where it is",
                    ip.address, ip.node_id
                )));
            }
            if let Some(target) = target {
                self.require_reachable(&ip, target).await?;
            }
        }
        Ok(())
    }

    /// Has each movable address the sandbox holds routed to `target`, between
    /// the source letting go and the target restoring it.
    pub(super) async fn route_to(&self, sandbox_id: &str, target: &str) -> Result<(), Status> {
        let ips = self.ips_of(sandbox_id).await;
        if ips.is_empty() {
            return Ok(());
        }
        let mut client = self.node_client(target).await?;
        for (row, mut ip) in ips {
            self.require_reachable(&ip, target).await?;
            client
                .route_public_ip(nodepb::NodeProviderRequest {
                    ip: Some(ip.clone()),
                    rdns: String::new(),
                })
                .await?;
            ip.node_id = target.to_string();
            self.save_ip(&row, &ip).await?;
            tracing::info!(
                address = ip.address,
                sandbox = sandbox_id,
                node = target,
                "public ip routed for a move"
            );
        }
        Ok(())
    }
}

/// A DNS host name: labels of letters, digits and hyphens, dot-separated.
fn is_host_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> common::IpPool {
        common::IpPool {
            name: "rack-a".into(),
            node_id: "node-a".into(),
            ranges: vec!["203.0.113.16-203.0.113.30".into()],
            gateway: "203.0.113.1".into(),
            prefix_len: 24,
            ..Default::default()
        }
    }

    #[test]
    fn a_pool_enumerates_its_ranges_and_addresses_once() {
        let mut pool = pool();
        pool.addresses = vec!["203.0.113.16".into(), "198.51.100.7".into()];
        validate_pool(&mut pool).unwrap();
        assert_eq!(pool.total, 16);
        assert_eq!(pool.provider(), common::IpProvider::Static);
    }

    #[test]
    fn a_v6_pool_carves_a_subnet_per_sandbox() {
        let pool = common::IpPool {
            prefix6: "2001:db8:100::/48".into(),
            per_sandbox: 64,
            ..Default::default()
        };
        let all = enumerate(&pool).unwrap();
        assert_eq!(all[0], ("2001:db8:100::1".parse().unwrap(), 64));
        assert_eq!(all[1], ("2001:db8:100:1::1".parse().unwrap(), 64));
        assert_eq!(all.len(), 65_536);
    }

    #[test]
    fn a_pool_is_refused_when_it_is_malformed() {
        let cases: [fn(&mut common::IpPool); 9] = [
            |p| p.node_id.clear(),
            |p| p.node_labels = [("rack".to_string(), "b7".to_string())].into(),
            |p| p.provider = 99,
            |p| p.ranges = vec!["203.0.113.30-203.0.113.16".into()],
            |p| p.ranges = vec!["10.0.0.0-10.2.0.0".into()],
            |p| p.gateway = "2001:db8::1".into(),
            |p| p.prefix_len = 0,
            |p| p.prefix6 = "2001:db8::/48".into(),
            |p| p.name = "Not A Name".into(),
        ];
        for (index, case) in cases.iter().enumerate() {
            let mut pool = pool();
            case(&mut pool);
            assert!(
                validate_pool(&mut pool).is_err(),
                "case {index} should be refused"
            );
        }
    }

    #[test]
    fn a_caller_is_a_digest_of_its_token() {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", "Bearer secret-token".parse().unwrap());
        let config = IpConfig {
            operator_tokens: vec!["operator-token".into()],
            ..Default::default()
        };
        let who = caller(&metadata, &config);
        assert_eq!(who.owner.len(), 16);
        assert!(!who.owner.contains("secret"));
        assert!(!who.is_operator);
        metadata.insert("authorization", "Bearer operator-token".parse().unwrap());
        assert!(caller(&metadata, &config).is_operator);
        assert!(caller(&MetadataMap::new(), &IpConfig::default()).is_operator);
    }

    #[test]
    fn coverage_follows_the_pools_scope() {
        let mut info = common::NodeInfo {
            id: "node-b".into(),
            labels: [("rack".to_string(), "b7".to_string())].into(),
            ..Default::default()
        };
        assert!(!covers(&pool(), &info));
        let labelled = common::IpPool {
            node_id: String::new(),
            node_labels: [("rack".to_string(), "b7".to_string())].into(),
            ..pool()
        };
        assert!(covers(&labelled, &info));
        info.labels.clear();
        assert!(!covers(&labelled, &info));
    }

    #[test]
    fn reverse_dns_names_are_host_names() {
        assert!(is_host_name("mail.example.com"));
        assert!(is_host_name("mail.example.com."));
        assert!(!is_host_name("-bad.example"));
        assert!(!is_host_name("a b"));
        assert!(!is_host_name(""));
    }
}
