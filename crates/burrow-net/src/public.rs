//! Host routes that bring a sandbox's public addresses down its tap.
//!
//! Declarative like the ruleset: the daemon hands over every route it wants
//! after each render, and only the difference from what was last applied is
//! run, with the `ip` command as [`crate::tap`] does.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::error::{NetError, Result};

/// Policy-routing priorities: one for addresses the guest sources from, one
/// for the proxy's marked upstream sockets.
const SOURCE_PRIORITY: &str = "7100";
const MARK_PRIORITY: &str = "7101";
/// First routing table handed to a gateway.
const FIRST_TABLE: u32 = 0x7b00_0001;

/// One public address or prefix routed to one tap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    pub tap: String,
    pub address: IpAddr,
    pub prefix: u8,
    /// The uplink to answer ARP or NDP on for this address, when the
    /// upstream looks it up there rather than routing it to the node.
    pub on_link: Option<String>,
    /// Where traffic from this address leaves, when it is not the node's
    /// default route.
    pub egress: Option<Egress>,
    /// The proxy's mark for this sandbox, routed the same way.
    pub mark: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Egress {
    pub gateway: IpAddr,
    /// The prefix of the network the gateway is on.
    pub prefix: u8,
    pub dev: String,
}

impl Route {
    fn network(&self) -> String {
        format!("{}/{}", masked(self.address, self.prefix), self.prefix)
    }

    fn family(&self) -> &'static str {
        if self.address.is_ipv4() { "-4" } else { "-6" }
    }
}

fn masked(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = match prefix {
                0 => 0,
                bits => u32::MAX << (32 - u32::from(bits.min(32))),
            };
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) => {
            let mask = match prefix {
                0 => 0,
                bits => u128::MAX << (128 - u32::from(bits.min(128))),
            };
            IpAddr::V6((u128::from(v6) & mask).into())
        }
    }
}

/// What is applied now, so a sync runs only the difference.
#[derive(Debug, Default)]
pub struct HostRoutes {
    applied: tokio::sync::Mutex<HashSet<Route>>,
    tables: std::sync::Mutex<HashMap<Egress, u32>>,
}

impl HostRoutes {
    /// Clears rules a previous run left at burrow's priorities. Routes and
    /// neighbour entries went with the taps they named.
    pub async fn reset(&self) {
        for priority in [SOURCE_PRIORITY, MARK_PRIORITY] {
            for family in ["-4", "-6"] {
                for _ in 0..4096 {
                    if run(&[family, "rule", "del", "priority", priority])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    }

    fn table(&self, egress: &Egress) -> u32 {
        let mut tables = self.tables.lock().unwrap();
        let next = FIRST_TABLE + tables.len() as u32;
        *tables.entry(egress.clone()).or_insert(next)
    }

    /// Makes the applied routes `desired`, returning the first failure. A
    /// route that failed is not recorded, so the next sync tries it again.
    pub async fn sync(&self, desired: &[Route]) -> Result<()> {
        let mut applied = self.applied.lock().await;
        let wanted: HashSet<Route> = desired.iter().cloned().collect();
        let gone: Vec<Route> = applied.difference(&wanted).cloned().collect();
        for route in gone {
            self.remove(&route).await;
            applied.remove(&route);
        }
        let mut first = None;
        for route in desired {
            if applied.contains(route) {
                continue;
            }
            match self.add(route).await {
                Ok(()) => {
                    applied.insert(route.clone());
                }
                Err(err) => {
                    tracing::error!(address = %route.address, tap = route.tap, %err, "could not route a public address");
                    self.remove(route).await;
                    first.get_or_insert(err);
                }
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Whether a route to `address` is in place.
    pub async fn is_applied(&self, address: IpAddr) -> bool {
        self.applied
            .lock()
            .await
            .iter()
            .any(|route| route.address == address)
    }

    async fn add(&self, route: &Route) -> Result<()> {
        let family = route.family();
        let network = route.network();
        run(&[family, "route", "replace", &network, "dev", &route.tap]).await?;
        if let Some(uplink) = &route.on_link {
            if route.address.is_ipv6() {
                let knob = format!("/proc/sys/net/ipv6/conf/{uplink}/proxy_ndp");
                let _ = tokio::fs::write(knob, "1").await;
            }
            let address = route.address.to_string();
            run(&[family, "neigh", "replace", "proxy", &address, "dev", uplink]).await?;
        }
        if let Some(egress) = &route.egress {
            let table = self.table(egress).to_string();
            let gateway = egress.gateway.to_string();
            let link = format!(
                "{}/{}",
                masked(egress.gateway, egress.prefix),
                egress.prefix
            );
            run(&[
                family,
                "route",
                "replace",
                &link,
                "dev",
                &egress.dev,
                "table",
                &table,
            ])
            .await?;
            run(&[
                family,
                "route",
                "replace",
                "default",
                "via",
                &gateway,
                "dev",
                &egress.dev,
                "table",
                &table,
            ])
            .await?;
            let _ = run(&[
                family,
                "rule",
                "del",
                "from",
                &network,
                "priority",
                SOURCE_PRIORITY,
            ])
            .await;
            run(&[
                family,
                "rule",
                "add",
                "from",
                &network,
                "lookup",
                &table,
                "priority",
                SOURCE_PRIORITY,
            ])
            .await?;
            if route.mark != 0 {
                let mark = format!("{:#x}", route.mark);
                let _ = run(&[
                    family,
                    "rule",
                    "del",
                    "fwmark",
                    &mark,
                    "priority",
                    MARK_PRIORITY,
                ])
                .await;
                run(&[
                    family,
                    "rule",
                    "add",
                    "fwmark",
                    &mark,
                    "lookup",
                    &table,
                    "priority",
                    MARK_PRIORITY,
                ])
                .await?;
            }
        }
        Ok(())
    }

    async fn remove(&self, route: &Route) {
        let family = route.family();
        let network = route.network();
        let _ = run(&[family, "route", "del", &network, "dev", &route.tap]).await;
        if let Some(uplink) = &route.on_link {
            let address = route.address.to_string();
            let _ = run(&[family, "neigh", "del", "proxy", &address, "dev", uplink]).await;
        }
        if route.egress.is_some() {
            let _ = run(&[
                family,
                "rule",
                "del",
                "from",
                &network,
                "priority",
                SOURCE_PRIORITY,
            ])
            .await;
            if route.mark != 0 {
                let mark = format!("{:#x}", route.mark);
                let _ = run(&[
                    family,
                    "rule",
                    "del",
                    "fwmark",
                    &mark,
                    "priority",
                    MARK_PRIORITY,
                ])
                .await;
            }
        }
    }
}

/// The interface the node reaches `destination` through. A sandbox's tap is
/// never one: the address is routed there once it is attached.
pub async fn uplink_for(destination: IpAddr) -> Option<String> {
    let family = if destination.is_ipv4() { "-4" } else { "-6" };
    let output = tokio::process::Command::new("ip")
        .args([family, "-o", "route", "get", &destination.to_string()])
        .output()
        .await
        .ok()?;
    parse_dev(&String::from_utf8_lossy(&output.stdout))
        .filter(|dev| !dev.starts_with(crate::firewall::TAP_PREFIX))
}

fn parse_dev(text: &str) -> Option<String> {
    let mut tokens = text.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(str::to_string);
        }
    }
    None
}

async fn run(args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        return Err(NetError::Command {
            command: format!("ip {}", args.join(" ")),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_names_its_network_not_its_address() {
        let route = Route {
            tap: "bt3".into(),
            address: "2001:db8:100:3::1".parse().unwrap(),
            prefix: 64,
            on_link: None,
            egress: None,
            mark: 0,
        };
        assert_eq!(route.network(), "2001:db8:100:3::/64");
        let route = Route {
            address: "203.0.113.17".parse().unwrap(),
            prefix: 32,
            ..route
        };
        assert_eq!(route.network(), "203.0.113.17/32");
    }

    #[test]
    fn the_uplink_is_read_from_route_get() {
        assert_eq!(
            parse_dev("1.1.1.1 via 172.30.0.1 dev eth1 src 172.30.0.2 uid 0 \\    cache"),
            Some("eth1".into())
        );
        assert_eq!(parse_dev(""), None);
    }
}
