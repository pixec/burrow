//! Request/response bodies for the Firecracker HTTP API.
//!
//! Every host path here is expressed **relative to the VM's working
//! directory**. Snapshot restore requires the resource paths to match what
//! they were at snapshot time, so keeping them relative and identical across
//! sandboxes (`vmlinux`, `rootfs.ext4`, `fc.sock`) makes restore work by
//! construction rather than by bookkeeping.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smt: Option<bool>,
    /// Required for diff snapshots; costs a little write performance.
    pub track_dirty_pages: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub host_dev_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_mac: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Vsock {
    /// Guest context id; 3 is the conventional first usable value.
    pub guest_cid: u32,
    pub uds_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Logger {
    pub log_path: String,
    pub level: String,
    pub show_level: bool,
    pub show_log_origin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum SnapshotType {
    Full,
    Diff,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateSnapshot {
    pub snapshot_type: SnapshotType,
    pub snapshot_path: String,
    pub mem_file_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemBackend {
    /// `File` maps the memory file directly; `Uffd` hands page faults to a
    /// userfaultfd handler (the lazy-paging path for fast restores).
    pub backend_type: String,
    pub backend_path: String,
}

/// Remaps a snapshotted network interface onto a different host device.
///
/// A snapshot records the tap it was taken with, and Firecracker refuses to
/// restore onto a different one. This is what lets many sandboxes restore from
/// a single warm snapshot: each gets its own tap, named whatever burrow
/// allocated, without the snapshot knowing.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkOverride {
    pub iface_id: String,
    pub host_dev_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadSnapshot {
    pub snapshot_path: String,
    pub mem_backend: MemBackend,
    pub enable_diff_snapshots: bool,
    pub resume_vm: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_overrides: Vec<NetworkOverride>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstanceInfo {
    pub id: String,
    /// One of `Not started`, `Running`, `Paused`.
    pub state: String,
    pub vmm_version: String,
    #[serde(default)]
    pub app_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Paused,
    Resumed,
}

impl VmState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            VmState::Paused => "Paused",
            VmState::Resumed => "Resumed",
        }
    }
}
