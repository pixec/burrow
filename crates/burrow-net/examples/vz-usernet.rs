//! Boots a macOS guest with [`burrow_net::usernet`] as its only network, for
//! checking the stack against a real guest.
//!
//! ```text
//! vz-usernet <dir> [--cpus N] [--memory-mib N] [--ssh-port P]
//! ```
//!
//! `<dir>` is a machine made by `vz new` (see deploy/macos/README.md). The
//! binary needs the virtualization entitlement, as the `vz` driver does:
//!
//! ```sh
//! cargo build -p burrow-net --features usernet --example vz-usernet
//! cp target/debug/examples/vz-usernet target/vz-signed/vz-usernet
//! codesign --force --sign - --entitlements deploy/macos/vz.entitlements target/vz-signed/vz-usernet
//! ```
//!
//! The guest gets 10.99.0.6/30 behind gateway 10.99.0.5, which resolves
//! through 1.1.1.1. Its port 22 is published on `127.0.0.1:<ssh-port>`
//! (default 2222). The policy starts as `none` and is replaced by writing one
//! line to `<dir>/usernet.sock`:
//!
//! ```text
//! none | open | allowlist <domain>... [cidr=<a.b.c.d/n>]... [port=<n>]... [deny=<a.b.c.d/n>]...
//! ```
//!
//! Every audit record is printed as a JSON line, and written to
//! `<dir>/egress.jsonl`. Ctrl-C stops the guest.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    return macos::main();
    #[cfg(not(target_os = "macos"))]
    Err("Virtualization.framework is macOS only".into())
}

#[cfg(target_os = "macos")]
mod macos {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::path::Path;
    use std::sync::Arc;

    use burrow_net::usernet::{Node, Policy, SandboxNet, UserNet};
    use burrow_proxy::policy::NetworkMode;
    use burrow_proxy::{AuditLog, EgressEvent, SandboxPolicy};
    use burrow_vmm::vz::{self, VzConfig};
    use burrow_vmm::{Backend, Boot, GuestOs, NetSpec, Vm, VmSpec};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::watch;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    pub fn main() -> Result<()> {
        let mut args = std::env::args().skip(1);
        let dir = args
            .next()
            .ok_or("usage: vz-usernet <dir> [--cpus N] [--memory-mib N] [--ssh-port P]")?;
        let (mut cpus, mut mem_mib, mut ssh_port) = (None, None, 2222u16);
        while let Some(flag) = args.next() {
            let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--cpus" => cpus = Some(value.parse()?),
                "--memory-mib" => mem_mib = Some(value.parse()?),
                "--ssh-port" => ssh_port = value.parse()?,
                _ => return Err(format!("unknown flag {flag}").into()),
            }
        }
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run(Path::new(&dir), cpus, mem_mib, ssh_port))
    }

    async fn run(dir: &Path, cpus: Option<u32>, mem_mib: Option<u32>, ssh_port: u16) -> Result<()> {
        let mut fds = [0; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let (guest_end, host_end) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let guest_end = Arc::new(guest_end);
        for (opt, size) in [(libc::SO_SNDBUF, 1 << 20), (libc::SO_RCVBUF, 4 << 20)] {
            let size: libc::c_int = size;
            unsafe {
                libc::setsockopt(
                    std::os::fd::AsRawFd::as_raw_fd(&*guest_end),
                    libc::SOL_SOCKET,
                    opt,
                    (&size as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
        }

        let mac = derived_mac(dir)?;
        let net = SandboxNet {
            mac,
            guest_ip: Ipv4Addr::new(10, 99, 0, 6),
            gateway_ip: Ipv4Addr::new(10, 99, 0, 5),
            prefix: 30,
            dns_ip: Ipv4Addr::new(10, 99, 0, 5),
            mtu: 1500,
        };
        let audit = AuditLog::new(dir.join("egress.jsonl"), None).observed(Arc::new(
            |event: &EgressEvent| {
                println!("{}", serde_json::to_string(event).unwrap_or_default());
            },
        ));
        let node = Arc::new(Node {
            audit,
            resolutions: Arc::default(),
            denied: Arc::default(),
            authority: None,
            directory: Arc::default(),
            dns_upstream: SocketAddr::from(([1, 1, 1, 1], 53)),
        });
        let (policy_tx, policy_rx) = watch::channel(parse_policy("none")?);
        let handle = UserNet::attach(host_end, net, policy_rx, node)?;
        handle.publish(
            tokio::net::TcpListener::bind(("127.0.0.1", ssh_port)).await?,
            22,
        );

        let boot = vz::MacOsBoot::read(dir)?;
        let config = VzConfig {
            network: vz::Network::Datagram(guest_end),
            ..VzConfig::default()
        };
        let mut spec = VmSpec::new("usernet", dir, Backend::Vz(config));
        spec.guest_os = GuestOs::MacOs;
        spec.vcpus = cpus.unwrap_or(boot.requirements.min_vcpus);
        spec.mem_mib = mem_mib.unwrap_or(boot.requirements.min_mem_mib);
        spec.boot = Boot::MacOs(boot);
        spec.drives = vec![vz::root_drive()];
        spec.net = Some(NetSpec {
            tap: String::new(),
            guest_mac: Some(
                mac.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            ),
        });
        spec.is_vsock_enabled = true;
        let vm = Vm::boot(spec).await?;
        println!(
            "started in {:?}; ssh -p {ssh_port} burrow@127.0.0.1",
            vm.boot_latency()
        );

        let ctl = dir.join("usernet.sock");
        let _ = std::fs::remove_file(&ctl);
        let listener = tokio::net::UnixListener::bind(&ctl)?;
        let mut leased = false;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = ticker.tick() => {
                    if !leased && handle.is_leased() {
                        leased = true;
                        println!("guest holds its dhcp lease");
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let (read, mut write) = stream.into_split();
                    let mut lines = BufReader::new(read).lines();
                    while let Some(line) = lines.next_line().await? {
                        let reply = match parse_policy(&line) {
                            Ok(policy) => {
                                policy_tx.send_replace(policy);
                                format!("ok {line}\n")
                            }
                            Err(err) => format!("err {err}\n"),
                        };
                        print!("policy: {reply}");
                        write.write_all(reply.as_bytes()).await?;
                    }
                }
            }
        }
        vm.kill().await?;
        drop(handle);
        Ok(())
    }

    fn parse_policy(line: &str) -> Result<Policy> {
        let mut words = line.split_whitespace();
        let mode = match words.next() {
            Some("none") => NetworkMode::None,
            Some("open") => NetworkMode::Open,
            Some("allowlist") => NetworkMode::Allowlist,
            other => return Err(format!("unknown mode {other:?}").into()),
        };
        let (mut domains, mut cidrs, mut ports, mut deny) = (vec![], vec![], vec![], vec![]);
        for word in words {
            if let Some(cidr) = word.strip_prefix("cidr=") {
                cidrs.push(cidr.to_string());
            } else if let Some(port) = word.strip_prefix("port=") {
                ports.push(port.parse()?);
            } else if let Some(cidr) = word.strip_prefix("deny=") {
                deny.push(cidr.to_string());
            } else {
                domains.push(word.to_string());
            }
        }
        Ok(Policy::new(
            SandboxPolicy {
                sandbox_id: "sbx_usernet".into(),
                mode,
                allow_domains: domains,
                deny_cidrs: deny,
                ..Default::default()
            },
            &cidrs,
            &ports,
            &[],
        ))
    }

    /// The MAC the `vz` driver derives from the machine identifier.
    fn derived_mac(dir: &Path) -> Result<[u8; 6]> {
        let id = std::fs::read(dir.join(vz::MACHINE_ID_FILE))?;
        let hash = id.iter().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
        });
        let b = hash.to_be_bytes();
        Ok([0x02, b[0], b[1], b[2], b[3], b[4]])
    }
}
