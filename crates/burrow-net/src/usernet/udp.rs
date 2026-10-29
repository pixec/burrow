//! UDP from the guest: DNS to the resolver, and other flows the policy
//! allows, each relayed through a host socket of its own.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smoltcp::wire::UdpPacket;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use super::stack::{FlowKey, Inner, Shared};
use super::{Policy, wire};
use crate::firewall::DNS_PORT;
use crate::policy::{Transport, Verdict};

/// A flow with no datagram either way for this long is over.
const IDLE: Duration = Duration::from_secs(60);
/// How long a refused flow's datagrams are dropped without another record,
/// so a guest retrying a denied destination is recorded once, not per packet.
const REFUSAL_MEMORY: Duration = Duration::from_secs(60);
/// Relayed flows one sandbox may hold at once. Each is a host socket.
const MAX_FLOWS: usize = 256;
/// Datagrams queued toward one flow's host socket before more are dropped.
const QUEUE: usize = 64;

enum Entry {
    Open {
        to_host: mpsc::Sender<Vec<u8>>,
        task: AbortHandle,
    },
    Refused {
        until: Instant,
    },
}

#[derive(Default)]
pub(super) struct Flows {
    entries: HashMap<FlowKey, Entry>,
}

/// One datagram from the guest to `dst`.
pub(super) fn ingest(
    shared: &Arc<Shared>,
    inner: &mut Inner,
    dst: Ipv4Addr,
    datagram: &UdpPacket<&[u8]>,
) {
    let (src_port, dst_port) = (datagram.src_port(), datagram.dst_port());
    let net = &shared.net;

    if (dst == net.dns_ip || dst == net.gateway_ip) && dst_port == DNS_PORT {
        if shared.decide(IpAddr::V4(dst), Transport::Udp, dst_port) != Verdict::Host {
            return;
        }
        let query = datagram.payload().to_vec();
        let task_shared = Arc::clone(shared);
        let task = tokio::spawn(async move {
            let shared = task_shared;
            if let Some(answer) = shared
                .services
                .resolver
                .answer(&query, IpAddr::V4(shared.net.guest_ip), &shared.budget)
                .await
            {
                deliver(&shared, (dst, DNS_PORT), src_port, &answer);
            }
        });
        inner.track(task.abort_handle());
        return;
    }
    // Not something a router forwards, on Linux or here: link-scoped
    // discovery chatter, which is most of what an idle guest sends.
    let subnet_broadcast = u32::from(net.gateway_ip) | (u32::MAX >> net.prefix);
    if dst.is_broadcast() || dst.is_multicast() || u32::from(dst) == subnet_broadcast {
        return;
    }

    let key = (src_port, SocketAddr::new(IpAddr::V4(dst), dst_port));
    match inner.udp.entries.get(&key) {
        Some(Entry::Open { to_host, .. }) => match to_host.try_send(datagram.payload().to_vec()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => return,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                inner.udp.entries.remove(&key);
            }
        },
        Some(Entry::Refused { until }) if *until > Instant::now() => return,
        _ => {}
    }

    match shared.decide(key.1.ip(), Transport::Udp, dst_port) {
        Verdict::Direct if inner.udp.entries.len() < MAX_FLOWS => {
            let (to_host, from_guest) = mpsc::channel(QUEUE);
            let first = datagram.payload().to_vec();
            let task = tokio::spawn(relay(Arc::clone(shared), key, from_guest, first));
            inner.udp.entries.insert(
                key,
                Entry::Open {
                    to_host,
                    task: task.abort_handle(),
                },
            );
        }
        Verdict::Direct => {}
        verdict => {
            inner.udp.entries.insert(
                key,
                Entry::Refused {
                    until: Instant::now() + REFUSAL_MEMORY,
                },
            );
            let reason = match verdict {
                Verdict::Deny(reason) => reason,
                _ => "destination is this node",
            };
            shared.record(key.1, false, reason.to_string(), (0, 0));
        }
    }
}

/// Sends `data` to the guest's `port` from `from`.
fn deliver(shared: &Shared, from: (Ipv4Addr, u16), port: u16, data: &[u8]) {
    let ident = shared.lock().ident();
    let frames = wire::udp(&shared.net, ident, from, (shared.net.guest_ip, port), data);
    shared.send_frames(frames);
}

async fn relay(
    shared: Arc<Shared>,
    key: FlowKey,
    mut from_guest: mpsc::Receiver<Vec<u8>>,
    first: Vec<u8>,
) {
    let (guest_port, destination) = key;
    let SocketAddr::V4(to) = destination else {
        return;
    };
    let opened = async {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
        socket.connect(shared.dial_address(destination)).await?;
        socket.send(&first).await?;
        Ok::<_, std::io::Error>(socket)
    }
    .await;
    let socket = match opened {
        Ok(socket) => socket,
        Err(err) => {
            shared.lock().udp.entries.remove(&key);
            shared.record(
                destination,
                true,
                format!("upstream send failed: {err}"),
                (0, 0),
            );
            return;
        }
    };

    let mut sent = first.len() as u64;
    let mut received = 0u64;
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            datagram = from_guest.recv() => {
                let Some(datagram) = datagram else { break };
                if socket.send(&datagram).await.is_ok() {
                    sent += datagram.len() as u64;
                }
            }
            reply = socket.recv(&mut buf) => {
                // An ICMP error from the destination surfaces here; the
                // flow is over either way.
                let Ok(n) = reply else { break };
                received += n as u64;
                deliver(&shared, (*to.ip(), to.port()), guest_port, &buf[..n]);
            }
            _ = tokio::time::sleep(IDLE) => break,
        }
    }
    shared.lock().udp.entries.remove(&key);
    shared.record(
        destination,
        true,
        "allowed (direct)".into(),
        (sent, received),
    );
}

/// Forgets refusals that have aged out.
pub(super) fn expire(inner: &mut Inner, now: Instant) {
    inner.udp.entries.retain(|_, entry| match entry {
        Entry::Open { task, .. } => !task.is_finished(),
        Entry::Refused { until } => *until > now,
    });
}

/// Ends the flows a new policy denies. Refusals are forgotten, so a
/// destination the new policy allows works on the guest's next try.
pub(super) fn reapply(shared: &Shared, inner: &mut Inner, policy: &Policy) {
    inner
        .udp
        .entries
        .retain(|(_, destination), entry| match entry {
            Entry::Open { task, .. } => {
                let keep = shared.decide_with(
                    policy,
                    destination.ip(),
                    Transport::Udp,
                    destination.port(),
                ) == Verdict::Direct;
                if !keep {
                    task.abort();
                }
                keep
            }
            Entry::Refused { .. } => false,
        });
}

pub(super) fn close(inner: &mut Inner) {
    for (_, entry) in inner.udp.entries.drain() {
        if let Entry::Open { task, .. } = entry {
            task.abort();
        }
    }
}
