//! Serves local TCP ports through a tailcat address, like `tailcat serve`.
//!
//!     cargo run -p tailcat-rs --example serve -- 8080,8443
//!     cargo run -p tailcat-rs --example serve -- --exit-node all
//!
//! Against a local `derper --dev` (plaintext on port 3340), which the stock
//! client reaches with `TS_DEBUG_USE_DERP_HTTP=1`:
//!
//!     cargo run -p tailcat-rs --example serve -- --dev-derp 127.0.0.1:3340 --stun-port 3478 8080

use std::net::SocketAddr;

use clap::Parser;
use tailcat_rs::{Config, DerpNode, DerpRegion, NodePublic, Ports, Region, Server, TcpConn};
use tokio::net::TcpStream;

#[derive(Parser)]
struct Args {
    /// DERP region ID to listen through; the nearest is picked otherwise.
    #[arg(long)]
    region: Option<i64>,
    /// A plaintext dev relay, as HOST:PORT, instead of a public region.
    #[arg(long)]
    dev_derp: Option<String>,
    /// The dev relay's STUN port.
    #[arg(long)]
    stun_port: Option<u16>,
    /// Client node keys allowed to connect; everyone if none are given.
    #[arg(long)]
    allow: Vec<NodePublic>,
    /// Also forward connections to any destination the client names.
    #[arg(long)]
    exit_node: bool,
    /// Comma-separated ports forwarded to 127.0.0.1, or "all".
    ports: String,
}

fn parse_ports(spec: &str) -> Result<Ports, String> {
    if spec == "all" {
        return Ok(Ports::All);
    }
    let mut ranges = Vec::new();
    for part in spec.split(',') {
        let range = match part.split_once('-') {
            Some((a, b)) => {
                let a: u16 = a.parse().map_err(|_| format!("bad port {a:?}"))?;
                let b: u16 = b.parse().map_err(|_| format!("bad port {b:?}"))?;
                a..=b
            }
            None => {
                let p: u16 = part.parse().map_err(|_| format!("bad port {part:?}"))?;
                p..=p
            }
        };
        ranges.push(range);
    }
    Ok(Ports::Ranges(ranges))
}

fn dev_region(hostport: &str, stun_port: Option<u16>) -> Result<DerpRegion, String> {
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| format!("{hostport:?} is not HOST:PORT"))?;
    let port: i32 = port.parse().map_err(|_| format!("bad port {port:?}"))?;
    Ok(DerpRegion {
        region_id: 1,
        region_code: "dev".into(),
        nodes: vec![DerpNode {
            name: "dev".into(),
            region_id: 1,
            host_name: host.into(),
            ipv4: match host.parse::<std::net::Ipv4Addr>() {
                Ok(_) => host.into(),
                Err(_) => String::new(),
            },
            derp_port: port,
            stun_port: stun_port.map(i32::from).unwrap_or(-1),
            insecure_for_tests: true,
            ..Default::default()
        }],
        ..Default::default()
    })
}

async fn handle(mut conn: TcpConn) {
    let target = if conn.is_forward() {
        conn.local_addr()
    } else {
        SocketAddr::from(([127, 0, 0, 1], conn.local_addr().port()))
    };
    let mut local = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("# error proxying to {target}: {err}");
            return;
        }
    };
    let _ = tokio::io::copy_bidirectional(&mut conn, &mut local).await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let mut config = Config {
        tcp_ports: parse_ports(&args.ports)?,
        forward_tcp: args.exit_node,
        ..Default::default()
    };
    if !args.allow.is_empty() {
        config.allowed_clients = Some(args.allow);
    }
    if let Some(dev) = &args.dev_derp {
        config.region = Region::Embedded(dev_region(dev, args.stun_port)?);
        config.insecure_derp_http = true;
    } else if let Some(id) = args.region {
        config.region = Region::Id(id);
    }

    let server = Server::start(config).await?;
    let region = server.region();
    eprintln!(
        "# Selected bootstrap relay region {}, {}",
        region.region_id,
        if region.region_name.is_empty() {
            region.region_code.as_str()
        } else {
            region.region_name.as_str()
        }
    );
    eprintln!(
        "# 🐈 Server listening with new address: {}",
        server.tailcat_addr()
    );

    while let Some(conn) = server.accept_tcp().await {
        eprintln!(
            "# connection from {} to {}",
            conn.remote_addr(),
            conn.local_addr()
        );
        tokio::spawn(handle(conn));
    }
    Ok(())
}
