//! Reconfiguring the guest's interface after a snapshot restore.
//!
//! Done over netlink rather than by shelling out to `ip`. Five process spawns
//! were the dominant cost of a warm create: each one pays a fork, an exec, a
//! dynamic-linker run and, under nested virtualisation, doubled vmexit costs,
//! for work that is a handful of netlink messages.

use std::net::Ipv4Addr;
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
) -> anyhow::Result<()> {
    // The resolver is a file write with no kernel round trip, so it is done
    // first and costs nothing against the netlink work.
    if let Some(dns) = dns {
        std::fs::write("/etc/resolv.conf", format!("nameserver {dns}\n"))?;
    }

    match NETLINK.get() {
        Some(netlink) => configure(&netlink.handle, netlink.index, ip, prefix_len, gateway).await,
        // Fall back to opening one: a guest that failed to prepare at boot
        // should still be re-addressable, just more slowly.
        None => {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            let connection = tokio::spawn(connection);
            let index = link_index(&handle).await?;
            let result = configure(&handle, index, ip, prefix_len, gateway).await;
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
) -> anyhow::Result<()> {
    flush_addresses(handle, index).await?;
    handle
        .address()
        .add(index, std::net::IpAddr::V4(ip), prefix_len)
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

    if let Some(gateway) = gateway {
        // The snapshot's default route points through a gateway that is not
        // this sandbox's, so it has to go before the new one is added.
        remove_default_routes(handle).await;
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .gateway(gateway)
            .output_interface(index)
            .build();
        handle.route().add(route).execute().await?;
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
