//! Minimal HTTP client for the Firecracker API socket.
//!
//! Firecracker speaks plain HTTP/1.1 over a Unix socket. A whole VM boot is
//! under a dozen requests, so each call opens its own connection: no pooling,
//! no keep-alive bookkeeping, and no ambiguity about connection state across
//! pause/resume.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

use crate::error::{Result, VmmError};
use crate::model::*;

pub struct FcApi {
    socket: PathBuf,
}

impl FcApi {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    async fn send(&self, method: Method, path: &str, body: Bytes) -> Result<(StatusCode, Bytes)> {
        let stream = UnixStream::connect(&self.socket).await?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        // The connection task ends when the response is fully read.
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::debug!(%err, "firecracker api connection closed");
            }
        });

        let req = Request::builder()
            .method(method)
            .uri(path)
            // Required for HTTP/1.1 origin-form requests; the value is ignored.
            .header(hyper::header::HOST, "localhost")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::ACCEPT, "application/json")
            .body(Full::new(body))?;

        let resp = sender.send_request(req).await?;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();
        Ok((status, body))
    }

    async fn call<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
    ) -> Result<Bytes> {
        let payload = match body {
            Some(b) => Bytes::from(serde_json::to_vec(b)?),
            None => Bytes::new(),
        };
        let method_name = method.to_string();
        let (status, body) = self.send(method, path, payload).await?;
        if !status.is_success() {
            return Err(VmmError::Api {
                method: method_name,
                path: path.to_string(),
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(body)
    }

    async fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        self.call(Method::PUT, path, Some(body)).await.map(|_| ())
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let body = self.call::<()>(Method::GET, path, None).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    pub async fn instance_info(&self) -> Result<InstanceInfo> {
        self.get_json("/").await
    }

    pub async fn set_machine_config(&self, cfg: &MachineConfig) -> Result<()> {
        self.put("/machine-config", cfg).await
    }

    pub async fn set_boot_source(&self, src: &BootSource) -> Result<()> {
        self.put("/boot-source", src).await
    }

    pub async fn add_drive(&self, drive: &Drive) -> Result<()> {
        self.put(&format!("/drives/{}", drive.drive_id), drive)
            .await
    }

    pub async fn add_network_interface(&self, iface: &NetworkInterface) -> Result<()> {
        self.put(&format!("/network-interfaces/{}", iface.iface_id), iface)
            .await
    }

    pub async fn set_vsock(&self, vsock: &Vsock) -> Result<()> {
        self.put("/vsock", vsock).await
    }

    pub async fn set_logger(&self, logger: &Logger) -> Result<()> {
        self.put("/logger", logger).await
    }

    pub async fn start_instance(&self) -> Result<()> {
        self.put(
            "/actions",
            &serde_json::json!({ "action_type": "InstanceStart" }),
        )
        .await
    }

    /// Pauses or resumes the vCPUs of an already-booted VM.
    pub async fn set_vm_state(&self, state: VmState) -> Result<()> {
        self.call(
            Method::PATCH,
            "/vm",
            Some(&serde_json::json!({ "state": state.as_str() })),
        )
        .await
        .map(|_| ())
    }

    /// The VM must be paused first.
    pub async fn create_snapshot(&self, req: &CreateSnapshot) -> Result<()> {
        self.put("/snapshot/create", req).await
    }

    /// Only valid before `InstanceStart` on a fresh VMM process.
    pub async fn load_snapshot(&self, req: &LoadSnapshot) -> Result<()> {
        self.put("/snapshot/load", req).await
    }
}
