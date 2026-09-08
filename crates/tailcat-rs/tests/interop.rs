//! Interoperability with the Go tailcat client, through a local dev relay.
//!
//! Needs two binaries, named by environment variables, so the test is
//! ignored by default:
//!
//!   TAILCAT_GO  the `tailcat` CLI (go build ./cmd/tailcat in tailscale/tailcat)
//!   DERPER      `derper` (go build tailscale.com/cmd/derper)
//!
//!   TAILCAT_GO=... DERPER=... cargo test -p tailcat-rs --test interop -- --ignored

use std::process::Stdio;
use std::time::Duration;

use tailcat_rs::{Config, DerpNode, DerpRegion, Ports, Region, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

const DERP_PORT: u16 = 3340;
const STUN_PORT: u16 = 33478;

fn binaries() -> (String, String) {
    let go = std::env::var("TAILCAT_GO").expect("TAILCAT_GO must name the Go tailcat binary");
    let derper = std::env::var("DERPER").expect("DERPER must name the derper binary");
    (go, derper)
}

async fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("nothing listening on port {port}");
}

fn dev_region() -> DerpRegion {
    DerpRegion {
        region_id: 1,
        region_code: "dev".into(),
        nodes: vec![DerpNode {
            name: "dev".into(),
            region_id: 1,
            host_name: "127.0.0.1".into(),
            ipv4: "127.0.0.1".into(),
            derp_port: DERP_PORT.into(),
            stun_port: STUN_PORT.into(),
            insecure_for_tests: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

async fn echo_listener() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

#[tokio::test]
#[ignore]
async fn go_client_pipes_through_rust_server() {
    let (go, derper) = binaries();
    let mut relay = Command::new(&derper)
        .args(["-dev", "-stun-port", &STUN_PORT.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn derper");
    wait_for_port(DERP_PORT).await;

    let echo_port = echo_listener().await;
    let server = std::sync::Arc::new(
        Server::start(Config {
            region: Region::Embedded(dev_region()),
            insecure_derp_http: true,
            tcp_ports: Ports::list([echo_port]),
            ..Default::default()
        })
        .await
        .expect("start server"),
    );
    {
        let server = server.clone();
        tokio::spawn(async move {
            while let Some(mut conn) = server.accept_tcp().await {
                assert!(
                    conn.peer_key().is_some(),
                    "accepted connection has no peer key"
                );
                tokio::spawn(async move {
                    let mut local = TcpStream::connect(("127.0.0.1", conn.local_addr().port()))
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut conn, &mut local).await;
                });
            }
        });
    }
    let addr = server.tailcat_addr().to_string();

    // Pipe mode: stdin goes to the server's port, the echo comes back.
    let mut client = Command::new(&go)
        .env("TS_DEBUG_USE_DERP_HTTP", "1")
        .args([&addr, &echo_port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn tailcat client");
    let mut stdin = client.stdin.take().unwrap();
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let writer = {
        let payload = payload.clone();
        tokio::spawn(async move {
            stdin.write_all(&payload).await.unwrap();
            stdin.shutdown().await.unwrap();
            drop(stdin);
        })
    };
    let mut stdout = client.stdout.take().unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), stdout.read_to_end(&mut echoed))
        .await
        .expect("client timed out")
        .unwrap();
    writer.await.unwrap();
    assert_eq!(echoed.len(), payload.len());
    assert!(echoed == payload, "echoed data differs");
    let status = client.wait().await.unwrap();
    assert!(status.success(), "client exited with {status}");
    assert_eq!(server.peers().len(), 1);

    // Path discovery: the client keeps pinging until a direct path answers.
    let ping = tokio::time::timeout(
        Duration::from_secs(40),
        Command::new(&go)
            .env("TS_DEBUG_USE_DERP_HTTP", "1")
            .args(["ping", "--until-direct", "--timeout", "30s", &addr])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("ping timed out")
    .unwrap();
    let out = String::from_utf8_lossy(&ping.stdout);
    eprintln!("ping output:\n{out}");
    assert!(ping.status.success(), "ping exited with {}", ping.status);
    let last = out.lines().last().unwrap_or_default();
    assert!(
        last.contains("via") && !last.contains("DERP"),
        "no direct path: {last}"
    );
    assert!(
        server.peers().iter().any(|p| p.direct.is_some()),
        "server side never trusted a direct path: {:?}",
        server.peers()
    );

    server.close();
    let _ = relay.kill().await;
}
