//! Reconfiguring the guest's interface after a snapshot restore.
//!
//! Done over netlink rather than by shelling out to `ip`. Five process spawns
//! were the dominant cost of a warm create: each one pays a fork, an exec, a
//! dynamic-linker run and, under nested virtualisation, doubled vmexit costs,
//! for work that is a handful of netlink messages.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use futures::{FutureExt as _, TryStreamExt};
use netlink_packet_route::address::{
    AddressAttribute, AddressFlags, AddressHeaderFlags, AddressMessage,
};
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
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

/// The addresses and gateways a handshake names.
pub struct Network {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub ip6: Option<(Ipv6Addr, u8)>,
    pub gateway6: Option<Ipv6Addr>,
    /// Held beside the private addresses, the first of each family the source
    /// of its default route.
    pub public: Vec<(IpAddr, u8)>,
}

/// The fleet's sandbox pools, kept on the private addresses: a peer or the
/// node knows this sandbox by its lease, not by a public address.
const POOL: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 99, 0, 0), 16);
const POOL6: (Ipv6Addr, u8) = (Ipv6Addr::new(0xfd99, 0xb070, 0, 0, 0, 0, 0, 0), 48);

/// Makes the interface hold exactly `network`, changing only what differs.
///
/// With `is_private` the private addresses are set as well, for a guest woken
/// from a snapshot taken under another lease: a clone holds whatever the warm
/// snapshot had, and keeping it would let it answer on an address that
/// belongs to another sandbox. Without it they are left as they are, and only
/// the public side and the routes are made to match.
///
/// Everything is read first, in one round trip, and a guest that already
/// matches is not written to at all. What does differ goes out in two
/// batches: the addresses and the link, then the routes that depend on them.
pub async fn apply(network: &Network, is_private: bool, dns: Option<&str>) -> anyhow::Result<()> {
    // The resolver is a file write with no kernel round trip, so it is done
    // first and costs nothing against the netlink work.
    if is_private && let Some(dns) = dns {
        crate::linux::init::set_resolver(dns)?;
    }

    match NETLINK.get() {
        Some(netlink) => reconcile(&netlink.handle, netlink.index, network, is_private).await,
        // Fall back to opening one: a guest that failed to prepare at boot
        // should still be re-addressable, just more slowly.
        None => {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            let connection = tokio::spawn(connection);
            let index = link_index(&handle).await?;
            let result = reconcile(&handle, index, network, is_private).await;
            drop(handle);
            connection.abort();
            result
        }
    }
}

/// An address as the interface holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    address: IpAddr,
    prefix_len: u8,
}

/// A route through the interface, as held or as wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Route {
    /// None for a default route.
    destination: Option<(IpAddr, u8)>,
    gateway: Option<IpAddr>,
    oif: Option<u32>,
    source: Option<IpAddr>,
}

/// What the interface holds now.
#[derive(Debug, Default)]
struct Current {
    addresses: Vec<Held>,
    routes: Vec<Route>,
    is_up: bool,
}

/// What has to change, as indices into [`Current`] for what goes and values
/// for what comes.
#[derive(Debug, Default, PartialEq)]
struct Plan {
    dropped_routes: Vec<usize>,
    dropped_addresses: Vec<usize>,
    added_addresses: Vec<Held>,
    is_raised: bool,
    added_routes: Vec<Route>,
}

impl Plan {
    fn is_empty(&self) -> bool {
        *self == Plan::default()
    }
}

fn plan(current: &Current, network: &Network, index: u32, is_private: bool) -> Plan {
    let mut wanted: Vec<Held> = Vec::new();
    if is_private {
        wanted.push(Held {
            address: IpAddr::V4(network.ip),
            prefix_len: network.prefix_len,
        });
        if let Some((ip6, prefix_len)) = network.ip6 {
            wanted.push(Held {
                address: IpAddr::V6(ip6),
                prefix_len,
            });
        }
    }
    for &(address, prefix_len) in &network.public {
        wanted.push(Held {
            address,
            prefix_len,
        });
    }
    let is_private_address = |address: IpAddr| match address {
        IpAddr::V4(v4) => v4 == network.ip,
        IpAddr::V6(v6) => network.ip6.is_some_and(|(ip6, _)| ip6 == v6),
    };

    let mut plan = Plan::default();
    for (at, held) in current.addresses.iter().enumerate() {
        let is_kept = wanted.contains(held)
            || matches!(held.address, IpAddr::V6(v6) if v6.is_unicast_link_local())
            || (!is_private && is_private_address(held.address));
        if !is_kept {
            plan.dropped_addresses.push(at);
        }
    }
    plan.added_addresses = wanted
        .into_iter()
        .filter(|address| !current.addresses.contains(address))
        .collect();
    plan.is_raised = is_private && !current.is_up;

    // An address that comes or goes can take routes with it, so a family
    // whose addresses change has its routes put back whatever they look like.
    let is_touched = |v4: bool| {
        plan.added_addresses
            .iter()
            .map(|held| held.address)
            .chain(
                plan.dropped_addresses
                    .iter()
                    .map(|&at| current.addresses[at].address),
            )
            .any(|address| address.is_ipv4() == v4)
    };
    let (touched4, touched6) = (is_touched(true), is_touched(false));

    let source = |v4: bool| {
        network
            .public
            .iter()
            .map(|&(address, _)| address)
            .find(|address| address.is_ipv4() == v4)
    };
    let mut wanted_routes = Vec::new();
    if let Some(gateway) = network.gateway {
        wanted_routes.push(Route {
            destination: None,
            gateway: Some(IpAddr::V4(gateway)),
            oif: Some(index),
            source: source(true),
        });
        wanted_routes.push(Route {
            destination: Some((IpAddr::V4(POOL.0), POOL.1)),
            gateway: Some(IpAddr::V4(gateway)),
            oif: Some(index),
            source: Some(IpAddr::V4(network.ip)),
        });
    }
    if let Some(gateway6) = network.gateway6 {
        wanted_routes.push(Route {
            destination: None,
            gateway: Some(IpAddr::V6(gateway6)),
            oif: Some(index),
            source: source(false),
        });
        // Source selection prefers the lease's ULA for the pool by itself.
        if network.ip6.is_some() {
            wanted_routes.push(Route {
                destination: Some((IpAddr::V6(POOL6.0), POOL6.1)),
                gateway: Some(IpAddr::V6(gateway6)),
                oif: Some(index),
                source: None,
            });
        }
    }

    let is_v4 = |route: &Route| route.gateway.is_some_and(|gateway| gateway.is_ipv4());
    // Only a default route through a gateway is removed: the kernel keeps the
    // first default it has, so one through a gateway that is not this
    // sandbox's would win over the one added. The kernel's own have none.
    for (at, route) in current.routes.iter().enumerate() {
        if route.destination.is_none()
            && route.gateway.is_some()
            && (!wanted_routes.contains(route) || if is_v4(route) { touched4 } else { touched6 })
        {
            plan.dropped_routes.push(at);
        }
    }
    plan.added_routes = wanted_routes
        .into_iter()
        .filter(|route| {
            !current.routes.contains(route) || if is_v4(route) { touched4 } else { touched6 }
        })
        .collect();
    plan
}

/// The interface's state, with the messages it was read from for removing
/// what a plan drops.
async fn current(
    handle: &Handle,
    index: u32,
) -> anyhow::Result<(Current, Vec<RouteMessage>, Vec<AddressMessage>)> {
    let addresses = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect::<Vec<_>>();
    let routes4 = handle
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute()
        .try_collect::<Vec<_>>();
    let routes6 = handle
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute()
        .try_collect::<Vec<_>>();
    let link = handle
        .link()
        .get()
        .match_index(index)
        .execute()
        .try_collect::<Vec<_>>();
    let (addresses, routes4, routes6, link) = futures::join!(addresses, routes4, routes6, link);
    let (held, addresses): (Vec<_>, Vec<_>) = addresses?
        .into_iter()
        .filter_map(|message| Some((held_of(&message)?, message)))
        .unzip();
    let routes: Vec<RouteMessage> = routes4?.into_iter().chain(routes6?).collect();
    let current = Current {
        addresses: held,
        routes: routes.iter().map(route_of).collect(),
        is_up: link?
            .first()
            .is_some_and(|link| link.header.flags.contains(LinkFlags::Up)),
    };
    Ok((current, routes, addresses))
}

fn held_of(message: &AddressMessage) -> Option<Held> {
    message.attributes.iter().find_map(|attr| match attr {
        AddressAttribute::Address(address) => Some(Held {
            address: *address,
            prefix_len: message.header.prefix_len,
        }),
        _ => None,
    })
}

fn route_of(message: &RouteMessage) -> Route {
    let address = |address: &RouteAddress| match address {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    };
    let mut route = Route {
        destination: None,
        gateway: None,
        oif: None,
        source: None,
    };
    for attr in &message.attributes {
        match attr {
            RouteAttribute::Destination(destination) => {
                route.destination =
                    address(destination).map(|at| (at, message.header.destination_prefix_length));
            }
            RouteAttribute::Gateway(gateway) => route.gateway = address(gateway),
            RouteAttribute::Oif(oif) => route.oif = Some(*oif),
            RouteAttribute::PrefSource(source) => route.source = address(source),
            _ => {}
        }
    }
    route
}

/// One netlink request in a batch, and what its failure means.
struct Request {
    what: String,
    is_fatal: bool,
    sent: futures::future::BoxFuture<'static, Result<(), rtnetlink::Error>>,
}

/// Sends every request before waiting on any, so a batch costs one round trip
/// rather than one per request. The kernel takes them in the order sent.
async fn send(requests: Vec<Request>) -> anyhow::Result<()> {
    let (labels, sent): (Vec<_>, Vec<_>) = requests
        .into_iter()
        .map(|request| ((request.what, request.is_fatal), request.sent))
        .unzip();
    let mut fatal = None;
    for ((what, is_fatal), result) in labels
        .into_iter()
        .zip(futures::future::join_all(sent).await)
    {
        match result {
            Err(err) if is_fatal => {
                fatal.get_or_insert_with(|| anyhow::anyhow!("{what}: {err}"));
            }
            // Worth knowing about but not worth abandoning the reconfiguration
            // for: what is added is what actually matters.
            Err(err) => tracing::warn!(%err, "could not {what}"),
            Ok(()) => {}
        }
    }
    fatal.map_or(Ok(()), Err)
}

async fn reconcile(
    handle: &Handle,
    index: u32,
    network: &Network,
    is_private: bool,
) -> anyhow::Result<()> {
    let _applying = APPLYING.lock().await;
    let (current, routes, addresses) = current(handle, index).await?;
    let plan = plan(&current, network, index, is_private);
    if plan.is_empty() {
        return Ok(());
    }

    // Routes before addresses: removing an address takes the routes sourced
    // from it, and a route removed twice is an error.
    let mut first = Vec::new();
    for &at in &plan.dropped_routes {
        first.push(Request {
            what: "remove a stale default route".into(),
            is_fatal: false,
            sent: handle.route().del(routes[at].clone()).execute().boxed(),
        });
    }
    for &at in &plan.dropped_addresses {
        first.push(Request {
            what: format!("remove {}", current.addresses[at].address),
            is_fatal: false,
            sent: handle
                .address()
                .del(addresses[at].clone())
                .execute()
                .boxed(),
        });
    }
    for held in &plan.added_addresses {
        // Replaced rather than added: a reapply that finds the address already
        // in place, from a handshake the snapshot caught half done, must still
        // succeed. An add answers EEXIST.
        let mut add = handle
            .address()
            .add(index, held.address, held.prefix_len)
            .replace();
        let is_public = network
            .public
            .iter()
            .any(|&(address, _)| address == held.address);
        // No duplicate detection: the host routes this address to this link
        // alone, and a tentative address cannot be the source of a route.
        if is_public && held.address.is_ipv6() {
            let message = add.message_mut();
            message.header.flags |= AddressHeaderFlags::Nodad;
            message
                .attributes
                .push(AddressAttribute::Flags(AddressFlags::Nodad));
        }
        first.push(Request {
            what: format!("add {}", held.address),
            // A guest whose kernel has IPv6 disabled still wants its v4
            // address.
            is_fatal: is_public || held.address.is_ipv4(),
            sent: add.execute().boxed(),
        });
    }
    if plan.is_raised {
        first.push(Request {
            what: format!("bring {INTERFACE} up"),
            is_fatal: true,
            sent: handle
                .link()
                .set(
                    LinkMessageBuilder::<LinkUnspec>::new()
                        .index(index)
                        .up()
                        .build(),
                )
                .execute()
                .boxed(),
        });
    }
    send(first).await?;

    let mut second = Vec::new();
    for route in &plan.added_routes {
        let message = match (route.gateway, route.destination) {
            (Some(IpAddr::V4(gateway)), destination) => {
                let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                    .gateway(gateway)
                    .output_interface(index);
                if let Some((IpAddr::V4(at), prefix_len)) = destination {
                    builder = builder.destination_prefix(at, prefix_len);
                }
                if let Some(IpAddr::V4(source)) = route.source {
                    builder = builder.pref_source(source);
                }
                builder.build()
            }
            (Some(IpAddr::V6(gateway)), destination) => {
                let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                    .gateway(gateway)
                    .output_interface(index);
                if let Some((IpAddr::V6(at), prefix_len)) = destination {
                    builder = builder.destination_prefix(at, prefix_len);
                }
                if let Some(IpAddr::V6(source)) = route.source {
                    builder = builder.pref_source(source);
                }
                builder.build()
            }
            (None, _) => continue,
        };
        let is_v4 = route.gateway.is_some_and(|gateway| gateway.is_ipv4());
        second.push(Request {
            what: match route.destination {
                None => format!(
                    "set the default route via {}",
                    route.gateway.expect("matched")
                ),
                Some((at, prefix_len)) => format!("route {at}/{prefix_len}"),
            },
            is_fatal: is_v4,
            sent: handle.route().add(message).replace().execute().boxed(),
        });
    }
    send(second).await
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

async fn remove_default_routes6(handle: &Handle) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: u32 = 2;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(last: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xfd99, 0xb070, 0, 1, 0, 0, 0, last))
    }

    fn network(third: u8, public: Vec<(IpAddr, u8)>) -> Network {
        Network {
            ip: Ipv4Addr::new(10, 99, third, 2),
            prefix_len: 30,
            gateway: Some(Ipv4Addr::new(10, 99, third, 1)),
            ip6: Some((
                Ipv6Addr::new(0xfd99, 0xb070, 0, third.into(), 0, 0, 0, 2),
                64,
            )),
            gateway6: Some(Ipv6Addr::new(0xfd99, 0xb070, 0, third.into(), 0, 0, 0, 1)),
            public,
        }
    }

    fn held(address: IpAddr, prefix_len: u8) -> Held {
        Held {
            address,
            prefix_len,
        }
    }

    /// The interface as a handshake of `network` leaves it.
    fn applied(network: &Network) -> Current {
        let empty = Current {
            is_up: true,
            ..Default::default()
        };
        let plan = plan(&empty, network, INDEX, true);
        Current {
            addresses: std::iter::once(held(
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                64,
            ))
            .chain(plan.added_addresses)
            .collect(),
            routes: plan.added_routes,
            is_up: true,
        }
    }

    #[test]
    fn a_guest_that_already_matches_is_left_alone() {
        let network = network(1, vec![(v4(203, 0, 113, 7), 32), (v6(9), 128)]);
        let current = applied(&network);
        assert!(plan(&current, &network, INDEX, true).is_empty());
        assert!(plan(&current, &network, INDEX, false).is_empty());
    }

    #[test]
    fn a_clone_drops_the_snapshot_address_for_its_own() {
        let warm = applied(&network(1, vec![]));
        let clone = network(2, vec![]);
        let plan = plan(&warm, &clone, INDEX, true);

        let dropped: Vec<_> = plan
            .dropped_addresses
            .iter()
            .map(|&at| warm.addresses[at].address)
            .collect();
        assert!(dropped.contains(&v4(10, 99, 1, 2)));
        assert!(
            !dropped
                .iter()
                .any(|a| matches!(a, IpAddr::V6(v) if v.is_unicast_link_local()))
        );
        assert!(plan.added_addresses.contains(&held(v4(10, 99, 2, 2), 30)));
        // The snapshot's default routes go, and every route is put back
        // through the clone's own gateways.
        let dropped_routes: Vec<_> = plan
            .dropped_routes
            .iter()
            .map(|&at| warm.routes[at])
            .collect();
        assert!(
            dropped_routes
                .iter()
                .all(|route| route.destination.is_none())
        );
        assert_eq!(dropped_routes.len(), 2);
        assert_eq!(plan.added_routes.len(), 4);
        assert!(plan.added_routes.contains(&Route {
            destination: None,
            gateway: Some(v4(10, 99, 2, 1)),
            oif: Some(INDEX),
            source: None,
        }));
        assert!(plan.added_routes.contains(&Route {
            destination: Some((IpAddr::V4(POOL.0), POOL.1)),
            gateway: Some(v4(10, 99, 2, 1)),
            oif: Some(INDEX),
            source: Some(v4(10, 99, 2, 2)),
        }));
    }

    #[test]
    fn a_changed_public_address_moves_the_default_route_source() {
        let before = applied(&network(1, vec![(v4(203, 0, 113, 7), 32)]));
        let after = network(1, vec![(v4(203, 0, 113, 8), 32)]);
        let plan = plan(&before, &after, INDEX, false);

        assert_eq!(
            plan.dropped_addresses
                .iter()
                .map(|&at| before.addresses[at])
                .collect::<Vec<_>>(),
            vec![held(v4(203, 0, 113, 7), 32)]
        );
        assert_eq!(plan.added_addresses, vec![held(v4(203, 0, 113, 8), 32)]);
        assert!(plan.added_routes.contains(&Route {
            destination: None,
            gateway: Some(v4(10, 99, 1, 1)),
            oif: Some(INDEX),
            source: Some(v4(203, 0, 113, 8)),
        }));
        // v6 had nothing change, so its routes stay.
        assert!(
            plan.added_routes
                .iter()
                .all(|route| route.gateway.is_some_and(|gateway| gateway.is_ipv4()))
        );
    }

    #[test]
    fn a_kept_address_is_neither_added_nor_removed() {
        let mut current = applied(&network(1, vec![]));
        current
            .addresses
            .retain(|held| held.address != v4(10, 99, 1, 2));
        current.addresses.push(held(v4(10, 99, 1, 2), 24));
        let plan = plan(&current, &network(1, vec![]), INDEX, false);
        assert!(plan.dropped_addresses.is_empty());
        assert!(plan.added_addresses.is_empty());
        assert!(!plan.is_raised);
    }

    #[test]
    fn a_stray_address_and_default_route_are_removed() {
        let network = network(1, vec![]);
        let mut current = applied(&network);
        current.addresses.push(held(v4(192, 0, 2, 5), 24));
        current.routes.push(Route {
            destination: None,
            gateway: Some(v4(192, 0, 2, 1)),
            oif: Some(INDEX),
            source: None,
        });
        let plan = plan(&current, &network, INDEX, false);
        assert_eq!(plan.dropped_addresses, vec![current.addresses.len() - 1]);
        assert!(plan.dropped_routes.contains(&(current.routes.len() - 1)));
    }

    #[test]
    fn a_link_found_down_is_raised() {
        let network = network(1, vec![]);
        let mut current = applied(&network);
        current.is_up = false;
        let plan = plan(&current, &network, INDEX, true);
        assert!(plan.is_raised);
        assert!(plan.added_addresses.is_empty());
    }
}
