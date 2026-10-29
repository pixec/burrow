//! Minimal HTTP client for a VMM's API socket.
//!
//! Firecracker and Cloud Hypervisor both speak plain HTTP/1.1 over a Unix
//! socket. A whole VM boot is under a dozen requests, so each call opens its
//! own connection: no pooling, no keep-alive bookkeeping, and no ambiguity
//! about connection state across pause/resume.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

use crate::error::{Error, Result};

pub(crate) struct UnixHttp {
    socket: PathBuf,
}

impl UnixHttp {
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
                tracing::debug!(%err, "vmm api connection closed");
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

    pub async fn call<T: Serialize>(
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
            return Err(Error::Api {
                method: method_name,
                path: path.to_string(),
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(body)
    }

    pub async fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        self.call(Method::PUT, path, Some(body)).await.map(|_| ())
    }

    /// A PUT with no body, which Cloud Hypervisor's actions require: it
    /// refuses an empty JSON object where it expects nothing.
    pub async fn put_empty(&self, path: &str) -> Result<()> {
        self.call::<()>(Method::PUT, path, None).await.map(|_| ())
    }

    /// A PUT that hands the VMM file descriptors with it, as Cloud
    /// Hypervisor takes a NIC's tap: in the ancillary data of the request's
    /// first write, which hyper has no way to send, so the request is written
    /// and its response read here by hand.
    #[cfg(target_os = "linux")]
    pub async fn put_with_fds<T: Serialize>(
        &self,
        path: &str,
        body: &T,
        fds: &[std::os::fd::RawFd],
    ) -> Result<()> {
        use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
        use std::os::fd::AsRawFd as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let body = serde_json::to_vec(body)?;
        let mut request = format!(
            "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Accept: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);
        let mut stream = UnixStream::connect(&self.socket).await?;
        let sent = loop {
            stream.writable().await?;
            match stream.try_io(tokio::io::Interest::WRITABLE, || {
                sendmsg::<()>(
                    stream.as_raw_fd(),
                    &[std::io::IoSlice::new(&request)],
                    &[ControlMessage::ScmRights(fds)],
                    MsgFlags::empty(),
                    None,
                )
                .map_err(std::io::Error::from)
            }) {
                Ok(sent) => break sent,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(err) => return Err(err.into()),
            }
        };
        stream.write_all(&request[sent..]).await?;

        let mut response = Vec::new();
        let (head, length) = loop {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("{path}: the vmm closed the connection without answering"),
                )));
            }
            response.extend_from_slice(&chunk[..n]);
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&response[..end]).into_owned();
                let length = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                response.drain(..end + 4);
                break (head, length);
            }
        };
        while response.len() < length {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..n]);
        }
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(Error::Api {
                method: "PUT".into(),
                path: path.to_string(),
                status,
                body: String::from_utf8_lossy(&response).into_owned(),
            });
        }
        Ok(())
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let body = self.call::<()>(Method::GET, path, None).await?;
        Ok(serde_json::from_slice(&body)?)
    }
}
