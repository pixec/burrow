//! The `netsh` invocations that give the guest the address the host chose.
//!
//! netsh rather than the IP Helper API because `set address source=static`
//! is the one call that also turns DHCP off on the adapter: an address added
//! beside a running DHCP client is one the client may take away again.
//! Building the argv is kept apart from running it so it can be tested here.

use std::net::{Ipv4Addr, Ipv6Addr};

use burrow_proto::guest::v1::NetworkConfig;

/// One netsh call, and whether its failure fails the handshake. Removing
/// something that may not be there is allowed to fail.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    pub args: Vec<String>,
    pub is_required: bool,
}

fn step(is_required: bool, args: &[&str]) -> Step {
    Step {
        args: args.iter().map(|arg| arg.to_string()).collect(),
        is_required,
    }
}

pub fn mask(prefix_len: u32) -> Ipv4Addr {
    let prefix = prefix_len.clamp(1, 32);
    Ipv4Addr::from(u32::MAX << (32 - prefix))
}

/// Everything that moves interface `index` onto `config`, given the global
/// IPv6 addresses it holds now.
///
/// Every address is parsed before it reaches an argv: the values come from
/// the host, and netsh would read a stray `name=` inside one as its own.
pub fn steps(
    index: u32,
    config: &NetworkConfig,
    held_v6: &[Ipv6Addr],
) -> anyhow::Result<Vec<Step>> {
    let ip: Ipv4Addr = config.ip.parse()?;
    let interface = index.to_string();
    let mut out = Vec::new();

    let address = format!("address={ip}");
    let mask = format!("mask={}", mask(config.prefix_len));
    let gateway = if config.gateway.is_empty() {
        "gateway=none".to_string()
    } else {
        format!("gateway={}", config.gateway.parse::<Ipv4Addr>()?)
    };
    let name = format!("name={interface}");
    out.push(step(
        true,
        &[
            "interface",
            "ipv4",
            "set",
            "address",
            &name,
            "source=static",
            &address,
            &mask,
            &gateway,
        ],
    ));

    let dns = if config.dns.is_empty() {
        "address=none".to_string()
    } else {
        format!("address={}", config.dns.parse::<std::net::IpAddr>()?)
    };
    out.push(step(
        true,
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &name,
            "source=static",
            &dns,
            "register=none",
            "validate=no",
        ],
    ));

    let iface = format!("interface={interface}");
    for held in held_v6 {
        let address = format!("address={held}");
        out.push(step(
            false,
            &["interface", "ipv6", "delete", "address", &iface, &address],
        ));
    }
    out.push(step(
        false,
        &[
            "interface",
            "ipv6",
            "delete",
            "route",
            "prefix=::/0",
            &iface,
        ],
    ));
    if !config.ip6.is_empty() {
        let ip6: Ipv6Addr = config.ip6.parse()?;
        let address = format!("address={ip6}/{}", config.prefix_len6.clamp(1, 128));
        out.push(step(
            true,
            &["interface", "ipv6", "add", "address", &iface, &address],
        ));
        if !config.gateway6.is_empty() {
            let nexthop = format!("nexthop={}", config.gateway6.parse::<Ipv6Addr>()?);
            out.push(step(
                true,
                &[
                    "interface",
                    "ipv6",
                    "add",
                    "route",
                    "prefix=::/0",
                    &iface,
                    &nexthop,
                ],
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NetworkConfig {
        NetworkConfig {
            ip: "10.0.0.2".into(),
            prefix_len: 30,
            gateway: "10.0.0.1".into(),
            dns: "10.0.0.1".into(),
            ..Default::default()
        }
    }

    #[test]
    fn prefixes_become_masks() {
        assert_eq!(mask(30), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(mask(0), Ipv4Addr::new(128, 0, 0, 0));
    }

    #[test]
    fn ipv4_is_set_static_with_its_gateway_and_dns() {
        let steps = steps(7, &config(), &[]).unwrap();
        assert_eq!(
            steps[0].args.join(" "),
            "interface ipv4 set address name=7 source=static address=10.0.0.2 mask=255.255.255.252 gateway=10.0.0.1"
        );
        assert_eq!(
            steps[1].args.join(" "),
            "interface ipv4 set dnsservers name=7 source=static address=10.0.0.1 register=none validate=no"
        );
        // No v6 link: only the stale default route goes.
        assert_eq!(steps.len(), 3);
        assert!(!steps[2].is_required);
    }

    #[test]
    fn ipv6_replaces_what_the_snapshot_held() {
        let config = NetworkConfig {
            ip6: "fd00::2".into(),
            prefix_len6: 64,
            gateway6: "fd00::1".into(),
            ..config()
        };
        let held: Ipv6Addr = "fd00::99".parse().unwrap();
        let steps = steps(3, &config, &[held]).unwrap();
        let lines: Vec<String> = steps.iter().map(|step| step.args.join(" ")).collect();
        assert!(
            lines.contains(&"interface ipv6 delete address interface=3 address=fd00::99".into())
        );
        assert!(
            lines.contains(&"interface ipv6 add address interface=3 address=fd00::2/64".into())
        );
        assert!(
            lines.contains(
                &"interface ipv6 add route prefix=::/0 interface=3 nexthop=fd00::1".into()
            )
        );
    }

    #[test]
    fn a_value_that_is_not_an_address_is_refused() {
        let config = NetworkConfig {
            dns: "1.1.1.1 name=x".into(),
            ..config()
        };
        assert!(steps(1, &config, &[]).is_err());
    }
}
