//! Serving gRPC over virtio-vsock.
//!
//! tonic needs its transport to implement `Connected`, which `VsockStream`
//! does not, so connections are wrapped in a newtype that delegates the IO
//! traits and reports no connection metadata.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

pub struct VsockConn {
    pub stream: tokio_vsock::VsockStream,
    /// How this connection got here, carried into the request extensions so a
    /// handler can say how much of a warm create was spent before it ran.
    pub arrival: Arrival,
}

/// Timing of the accept that produced a connection.
#[derive(Clone, Copy)]
pub struct Arrival {
    /// When `accept()` returned.
    pub accepted_at: std::time::Instant,
    /// How long the accepting task had been blocked in `accept()`.
    ///
    /// Measured on the guest's monotonic clock, which does not advance while
    /// the VM is paused, so on the first connection after a restore this is the
    /// guest-side cost of waking, not the wall time the host waited.
    pub parked: std::time::Duration,
}

impl Connected for VsockConn {
    type ConnectInfo = Arrival;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.arrival
    }
}

impl AsyncRead for VsockConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for VsockConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
