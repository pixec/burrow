//! The Firecracker API, over [`UnixHttp`].

use std::path::{Path, PathBuf};

use hyper::Method;

use super::model::*;
use crate::error::Result;
use crate::http::UnixHttp;

pub struct FcApi {
    http: UnixHttp,
}

impl FcApi {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            http: UnixHttp::new(socket),
        }
    }

    pub fn socket_path(&self) -> &Path {
        self.http.socket_path()
    }

    pub async fn instance_info(&self) -> Result<InstanceInfo> {
        self.http.get_json("/").await
    }

    pub async fn set_machine_config(&self, cfg: &MachineConfig) -> Result<()> {
        self.http.put("/machine-config", cfg).await
    }

    pub async fn set_boot_source(&self, src: &BootSource) -> Result<()> {
        self.http.put("/boot-source", src).await
    }

    pub async fn add_drive(&self, drive: &Drive) -> Result<()> {
        self.http
            .put(&format!("/drives/{}", drive.drive_id), drive)
            .await
    }

    pub async fn add_network_interface(&self, iface: &NetworkInterface) -> Result<()> {
        self.http
            .put(&format!("/network-interfaces/{}", iface.iface_id), iface)
            .await
    }

    pub async fn set_vsock(&self, vsock: &Vsock) -> Result<()> {
        self.http.put("/vsock", vsock).await
    }

    pub async fn set_logger(&self, logger: &Logger) -> Result<()> {
        self.http.put("/logger", logger).await
    }

    pub async fn start_instance(&self) -> Result<()> {
        self.http
            .put(
                "/actions",
                &serde_json::json!({ "action_type": "InstanceStart" }),
            )
            .await
    }

    /// Pauses or resumes the vCPUs of an already-booted VM.
    pub async fn set_vm_state(&self, state: VmState) -> Result<()> {
        self.http
            .call(
                Method::PATCH,
                "/vm",
                Some(&serde_json::json!({ "state": state.as_str() })),
            )
            .await
            .map(|_| ())
    }

    /// The VM must be paused first.
    pub async fn create_snapshot(&self, req: &CreateSnapshot) -> Result<()> {
        self.http.put("/snapshot/create", req).await
    }

    /// Only valid before `InstanceStart` on a fresh VMM process.
    pub async fn load_snapshot(&self, req: &LoadSnapshot) -> Result<()> {
        self.http.put("/snapshot/load", req).await
    }
}
