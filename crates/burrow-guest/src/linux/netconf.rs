//! Reconfiguring the guest's interface after a snapshot restore.
//!
//! Done over netlink rather than by shelling out to `ip`. Five process spawns
//! were the dominant cost of a warm create: each one pays a fork, an exec, a
//! dynamic-linker run and, under nested virtualisation, doubled vmexit costs,
//! for work that is a handful of netlink messages.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use futures::TryStreamExt;
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder};

const INTERFACE: &str = "eth0";

/// A netlink connection and the interface index, resolved once at boot.
///
/// Both were being paid for on every restore, on the critical path of a warm
/// create: opening the socket and asking the kernel for `eth0`'s index cost
/// more than the reconfiguration itself. Neither answer changes across a
/// snapshot, since the socket and the interface are both inside the guest and
/// are captured and restored with it, so both are established before the
/// snapshot is ever taken.
struct Netlink {
    handle: Handle,
    index: u32,
}

static NETLINK: OnceLock<Netlink> = OnceLock::new();

/// Held across a reapply, so two handshakes of one guest cannot interleave
/// their flushes and adds.
static APPLYING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Opens the netlink connection and resolves the interface, so a later restore
/// does not have to. Call once, at startup.
pub async fn prepare() {
    if NETLINK.get().is_some() {
        return;
    }
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(parts) => parts,
        Err(err) => {
            tracing::warn!(%err, "no netlink connection at boot; restores will open one");
            return;
        }
    };
    // Deliberately never joined: it drives the socket for the agent's life.
    tokio::spawn(connection);

    match link_index(&handle).await {
        Ok(index) => {
            let _ = NETLINK.set(Netlink { handle, index });
            tracing::debug!(index, "netlink ready");
        }
        Err(err) => tracing::warn!(%err, "could not resolve {INTERFACE} at boot"),
    }
}

/// Adds an IPv6 address to the guest's interface, leaving everything else
/// alone.
///
/// Separate from [`apply`] because a cold boot has already been addressed by
/// the kernel over IPv4 and only wants the v6 half; flushing and reapplying
/// would tear down a working interface to add to it.
pub async fn add_ipv6(
    address: Ipv6Addr,
    prefix_len: u8,
    gateway: Option<Ipv6Addr>,
) -> anyhow::Result<()> {
    match NETLINK.get() {
        Some(netlink) => {
            add_one_ipv6(&netlink.handle, netlink.index, address, prefix_len, gateway).await
        }
        None => {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            let connection = tokio::spawn(connection);
            let index = link_index(&handle).await?;
            let result = add_one_ipv6(&handle, index, address, prefix_len, gateway).await;
            drop(handle);
            connection.abort();
            result
        }
    }
}

async fn add_one_ipv6(
    handle: &Handle,
    index: u32,
    address: Ipv6Addr,
    prefix_len: u8,
    gateway: Option<Ipv6Addr>,
) -> anyhow::Result<()> {
    // Replaced rather than added, as in `configure`.
    handle
        .address()
        .add(index, std::net::IpAddr::V6(address), prefix_len)
        .replace()
        .execute()
        .await?;
    // Without a default route the address is decorative: every destination
    // outside the sandbox's own /64 is unreachable before a rule sees it.
    if let Some(gateway) = gateway {
        // A clone wakes holding the warm snapshot's v6 default route, whose
        // gateway sits in a /64 this sandbox does not have an address in. The
        // kernel keeps the first default route it has and the add below is a
        // no-op, so the guest keeps routing at an address that is not its
        // gateway and every v6 destination is unreachable.
        remove_default_routes6(handle).await;
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .gateway(gateway)
            .output_interface(index)
            .build();
        if let Err(err) = handle.route().add(route).replace().execute().await {
            tracing::warn!(%gateway, %err, "could not add the guest's IPv6 default route");
        }
    }
    Ok(())
}

/// Applies an address, gateway, and resolver to the guest's interface.
///
/// Existing addresses are removed first: a clone wakes holding whatever the
/// warm snapshot had, and leaving that in place would let it answer on an
/// address that belongs to another sandbox.
pub async fn apply(
    ip: Ipv4Addr,
    prefix_len: u8,
    gateway: Option<Ipv4Addr>,
    dns: Option<&str>,
    ip6: Option<(Ipv6Addr, u8, Option<Ipv6Addr>)>,
) -> anyhow::Result<()> {
    // The resolver is a file write with no kernel round trip, so it is done
    // first and costs nothing against the netlink work.
    if let Some(dns) = dns {
        std::fs::write("/etc/resolv.conf", format!("nameserver {dns}\n"))?;
    }

    match NETLINK.get() {
        Some(netlink) => {
            configure(&netlink.handle, netlink.index, ip, prefix_len, gateway, ip6).await
        }
        // Fall back to opening one: a guest that failed to prepare at boot
        // should still be re-addressable, just more slowly.
        None => {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            let connection = tokio::spawn(connection);
            let index = link_index(&handle).await?;
            let result = configure(&handle, index, ip, prefix_len, gateway, ip6).await;
            drop(handle);
            connection.abort();
            result
        }
    }
}

async fn configure(
    handle: &Handle,
    index: u32,
    ip: Ipv4Addr,
    prefix_len: u8,
    gateway: Option<Ipv4Addr>,
    ip6: Option<(Ipv6Addr, u8, Option<Ipv6Addr>)>,
) -> anyhow::Result<()> {
    let _applying = APPLYING.lock().await;
    flush_addresses(handle, index).await?;
    // Replaced rather than added: a reapply that finds the address or the
    // default route already in place, from a handshake repeated or one the
    // snapshot caught half done, must still succeed. An add answers EEXIST.
    handle
        .address()
        .add(index, std::net::IpAddr::V4(ip), prefix_len)
        .replace()
        .execute()
        .await?;
    handle
        .link()
        .set(
            LinkMessageBuilder::<LinkUnspec>::new()
                .index(index)
                .up()
                .build(),
        )
        .execute()
        .await?;

    // After the link is up, and never fatal: a guest whose kernel has IPv6
    // disabled still wants the v4 address it just got.
    if let Some((address, prefix, gateway6)) = ip6
        && let Err(err) = add_one_ipv6(handle, index, address, prefix, gateway6).await
    {
        tracing::warn!(%address, %err, "could not add the guest's IPv6 address");
    }

    if let Some(gateway) = gateway {
        // The snapshot's default route points through a gateway that is not
        // this sandbox's, so it has to go before the new one is added.
        remove_default_routes(handle).await;
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .gateway(gateway)
            .output_interface(index)
            .build();
        handle.route().add(route).replace().execute().await?;
    }
    Ok(())
}

/// The private addresses and gateways the public ones sit beside.
pub struct Private {
    pub ip: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub ip6: Option<Ipv6Addr>,
    pub gateway6: Option<Ipv6Addr>,
}

/// The fleet's sandbox pools, kept on the private addresses: a peer or the
/// node knows this sandbox by its lease, not by a public address.
const POOL: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 99, 0, 0), 16);
const POOL6: (Ipv6Addr, u8) = (Ipv6Addr::new(0xfd99, 0xb070, 0, 0, 0, 0, 0, 0), 48);

/// Makes the interface hold exactly `public` beside the private addresses,
/// and the first public address of each family the source of its default
/// route.
pub async fn apply_public(
    private: Private,
    public: &[(std::net::IpAddr, u8)],
) -> anyhow::Result<()> {
    match NETLINK.get() {
        Some(netlink) => configure_public(&netlink.handle, netlink.index, &private, public).await,
        None => {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            let connection = tokio::spawn(connection);
            let index = link_index(&handle).await?;
            let result = configure_public(&handle, index, &private, public).await;
            drop(handle);
            connection.abort();
            result
        }
    }
}

async fn configure_public(
    handle: &Handle,
    index: u32,
    private: &Private,
    public: &[(std::net::IpAddr, u8)],
) -> anyhow::Result<()> {
    use netlink_packet_route::address::AddressAttribute;
    use std::net::IpAddr;

    let _applying = APPLYING.lock().await;
    let held: Vec<_> = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect()
        .await?;
    for message in held {
        let address = message.attributes.iter().find_map(|attr| match attr {
            AddressAttribute::Address(address) => Some(*address),
            _ => None,
        });
        let Some(address) = address else {
            continue;
        };
        let is_kept = match address {
            IpAddr::V4(v4) => v4 == private.ip,
            IpAddr::V6(v6) => Some(v6) == private.ip6 || v6.is_unicast_link_local(),
        } || public.iter().any(|(held, _)| *held == address);
        if !is_kept && let Err(err) = handle.address().del(message).execute().await {
            tracing::warn!(%address, %err, "could not remove a public address");
        }
    }
    for (address, prefix) in public {
        let mut add = handle.address().add(index, *address, *prefix).replace();
        // No duplicate detection: the host routes this address to this link
        // alone, and a tentative address cannot be the source of a route.
        if address.is_ipv6() {
            use netlink_packet_route::address::{AddressFlags, AddressHeaderFlags};
            let message = add.message_mut();
            message.header.flags |= AddressHeaderFlags::Nodad;
            message
                .attributes
                .push(AddressAttribute::Flags(AddressFlags::Nodad));
        }
        add.execute().await?;
    }

    let source4 = public.iter().find_map(|(address, _)| match address {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(_) => None,
    });
    if let Some(gateway) = private.gateway {
        remove_default_routes(handle).await;
        let mut route = RouteMessageBuilder::<Ipv4Addr>::new()
            .gateway(gateway)
            .output_interface(index);
        if let Some(source) = source4 {
            route = route.pref_source(source);
        }
        handle
            .route()
            .add(route.build())
            .replace()
            .execute()
            .await?;
        let pool = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(POOL.0, POOL.1)
            .gateway(gateway)
            .pref_source(private.ip)
            .output_interface(index)
            .build();
        handle.route().add(pool).replace().execute().await?;
    }

    let source6 = public.iter().find_map(|(address, _)| match address {
        IpAddr::V6(v6) => Some(*v6),
        IpAddr::V4(_) => None,
    });
    if let Some(gateway6) = private.gateway6 {
        remove_default_routes6(handle).await;
        let mut route = RouteMessageBuilder::<Ipv6Addr>::new()
            .gateway(gateway6)
            .output_interface(index);
        if let Some(source) = source6 {
            route = route.pref_source(source);
        }
        if let Err(err) = handle.route().add(route.build()).replace().execute().await {
            tracing::warn!(%err, "could not set the guest's IPv6 default route");
        }
        // Source selection prefers the lease's ULA for the pool by itself.
        if private.ip6.is_some() {
            let pool = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(POOL6.0, POOL6.1)
                .gateway(gateway6)
                .output_interface(index)
                .build();
            if let Err(err) = handle.route().add(pool).replace().execute().await {
                tracing::warn!(%err, "could not route the sandbox pool over the private IPv6 address");
            }
        }
    }
    Ok(())
}

async fn link_index(handle: &Handle) -> anyhow::Result<u32> {
    let mut links = handle
        .link()
        .get()
        .match_name(INTERFACE.to_string())
        .execute();
    let link = links
        .try_next()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no {INTERFACE} interface in the guest"))?;
    Ok(link.header.index)
}

async fn flush_addresses(handle: &Handle, index: u32) -> anyhow::Result<()> {
    let existing: Vec<_> = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect()
        .await?;

    for address in existing {
        // A failure here is worth knowing about but not worth abandoning the
        // reconfiguration for: the add below is what actually matters.
        if let Err(err) = handle.address().del(address).execute().await {
            tracing::warn!(%err, "could not remove a stale address");
        }
    }
    Ok(())
}

async fn remove_default_routes6(handle: &Handle) {
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};

    let query = RouteMessageBuilder::<Ipv6Addr>::new().build();
    let routes: Vec<_> = match handle.route().get(query).execute().try_collect().await {
        Ok(routes) => routes,
        Err(err) => {
            tracing::warn!(%err, "could not list IPv6 routes");
            return;
        }
    };

    for route in routes {
        let is_default = route.header.destination_prefix_length == 0
            && !route
                .attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Destination(RouteAddress::Inet6(_))))
            && route
                .attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Gateway(RouteAddress::Inet6(_))));
        if is_default && let Err(err) = handle.route().del(route).execute().await {
            tracing::warn!(%err, "could not remove the stale IPv6 default route");
        }
    }
}

async fn remove_default_routes(handle: &Handle) {
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};

    let query = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let routes: Vec<_> = match handle.route().get(query).execute().try_collect().await {
        Ok(routes) => routes,
        Err(err) => {
            tracing::warn!(%err, "could not list routes");
            return;
        }
    };

    for route in routes {
        // A default route is one with no destination prefix.
        let is_default = route.header.destination_prefix_length == 0
            && !route
                .attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Destination(RouteAddress::Inet(_))));
        if is_default && let Err(err) = handle.route().del(route).execute().await {
            tracing::warn!(%err, "could not remove the stale default route");
        }
    }
}
