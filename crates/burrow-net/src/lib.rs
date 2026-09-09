//! Sandbox networking: address allocation, tap devices, and firewall policy.
//!
//! The topology is one routed /30 per sandbox on its own tap, with no shared
//! bridge; see [`ipam`] for why.

mod error;
pub mod firewall;
pub mod ipam;
pub mod mesh;
pub mod pinning;
pub mod tap;
pub mod transparent;

pub use error::{NetError, Result};
pub use firewall::{Mode, PortMap, Protocol, SandboxRules};
pub use ipam::{Ipam, Lease};
pub use mesh::{MESH_INTERFACE, Peer};
