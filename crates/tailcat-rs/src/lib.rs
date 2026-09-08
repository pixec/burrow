//! A tailcat server: a control-plane-free WireGuard listener reachable
//! through a DERP relay.
//!
//! This server speaks the tailcat wire protocols, so the stock `tailcat`
//! client connects to it unchanged. A [`Server`] publishes a
//! compact [`Addr`] that encodes its WireGuard and path-discovery public
//! keys, a pre-shared key, and the DERP region it listens through. Clients
//! register over the relay with a "meow" handshake, after which both sides
//! carry WireGuard over DERP and, once disco has found a working UDP path,
//! directly.
//!
//! Traffic inside the tunnel terminates in a userspace TCP/UDP stack, so no
//! TUN device, routing table change, or privilege is needed. Connections
//! addressed to the server surface through [`Server::accept_tcp`] and
//! [`Server::accept_udp`]; the caller decides what to do with them.
//!
//! Tailscale's magicsock does far more than tailcat uses. Only the parts
//! tailcat depends on are here: the DERP client,
//! the meow and disco messages, STUN for learning our own endpoints, and a
//! deliberately small path selector. Peer relays, portmapping and the like
//! are absent, and a client that cannot reach us directly simply stays on
//! the relay.

pub mod addr;
pub mod derp;
pub mod derpmap;
pub mod disco;
mod error;
pub mod key;
pub mod meow;
mod netstack;
mod server;
pub mod stun;
mod transport;

pub use addr::{Addr, ConnInfo};
pub use derpmap::{DerpMap, DerpNode, DerpRegion, ExpandOptions};
pub use error::{Error, Result};
pub use key::{DiscoPublic, NodePrivate, NodePublic, PresharedKey};
pub use netstack::{Ports, TcpConn, UdpFlow};
pub use server::{Config, DEFAULT_UDP_IDLE_TIMEOUT, Region, Server};
pub use transport::PeerStatus;

/// The URL of the JSON DERP map fetched when a server or address names a
/// region by ID only.
pub const DEFAULT_DERP_MAP_URL: &str = "https://tailcat.dev/derpmap.json";
