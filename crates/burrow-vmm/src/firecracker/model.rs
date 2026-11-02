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
    #[serde(rename = "track_dirty_pages")]
    pub is_dirty_pages_tracked: bool,
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
    /// Always sent. Firecracker's default, `Unsafe`, tells the guest the disk
    /// has no write cache, so the guest never sends a flush and its `fsync`
    /// stops in the host page cache: a power cut loses writes the guest was
    /// told were durable.
    pub cache_type: CacheType,
}

impl Drive {
    /// The drive Firecracker is given for `spec`, the one place a drive is
    /// rendered, so a boot and a hotplug cannot disagree on its cache mode.
    pub fn from_spec(spec: &crate::DriveSpec) -> Self {
        Self {
            drive_id: spec.id.clone(),
            path_on_host: spec.path.clone(),
            is_root_device: spec.is_root,
            is_read_only: spec.is_read_only,
            cache_type: CacheType::Writeback,
        }
    }
}

/// How a drive's writes reach the host.
///
/// `Writeback` advertises a volatile write cache (`VIRTIO_BLK_F_FLUSH`): the
/// guest sends a flush when it needs durability, and Firecracker answers it by
/// `fsync`ing the backing file. Ordinary writes cost the same as under
/// Firecracker's default, `Unsafe`, which Burrow never asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CacheType {
    Writeback,
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
    #[serde(rename = "show_level")]
    pub is_level_shown: bool,
    #[serde(rename = "show_log_origin")]
    pub is_log_origin_shown: bool,
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
    #[serde(rename = "enable_diff_snapshots")]
    pub is_diff_snapshots_enabled: bool,
    #[serde(rename = "resume_vm")]
    pub is_vm_resumed: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every drive, the read-only root and a volume as much as the scratch
    /// disk, goes to Firecracker with a write cache it flushes.
    #[test]
    fn every_drive_is_rendered_writeback() {
        let volume = crate::DriveSpec {
            id: "volume0".into(),
            path: "volume0.ext4".into(),
            is_root: false,
            is_read_only: false,
        };
        let read_only_volume = crate::DriveSpec {
            is_read_only: true,
            ..volume.clone()
        };
        for spec in [
            crate::DriveSpec::root_ro("rootfs.ext4"),
            crate::DriveSpec::scratch_rw("scratch.ext4"),
            volume,
            read_only_volume,
        ] {
            let body = serde_json::to_value(Drive::from_spec(&spec)).unwrap();
            assert_eq!(body["cache_type"], "Writeback", "{}", spec.id);
            assert_eq!(body["drive_id"], spec.id.as_str());
            assert_eq!(body["path_on_host"], spec.path.as_str());
            assert_eq!(body["is_read_only"], spec.is_read_only);
            assert_eq!(body["is_root_device"], spec.is_root);
        }
    }
}
