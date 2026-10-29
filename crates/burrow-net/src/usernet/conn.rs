//! A TCP connection terminated in the stack, as an ordinary async stream.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::stack::Shared;

/// The guest's half of one TCP connection.
///
/// Reads return what the guest sent and end at its FIN; a reset from the
/// guest is an error. Shutting down sends a FIN after whatever is buffered.
/// Dropping it closes the connection gracefully.
pub struct GuestConn {
    shared: Arc<Shared>,
    handle: SocketHandle,
}

impl GuestConn {
    pub(super) fn new(shared: Arc<Shared>, handle: SocketHandle) -> Self {
        Self { shared, handle }
    }

    /// Resets the connection rather than closing it.
    pub fn abort(&self) {
        let mut inner = self.shared.lock();
        if !inner.is_closed {
            inner.sockets.get_mut::<tcp::Socket>(self.handle).abort();
        }
        drop(inner);
        self.shared.wake.notify_one();
    }

    /// Waits for a connection this side opened to be accepted.
    pub(super) async fn established(&self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut inner = self.shared.lock();
            let socket = inner.sockets.get_mut::<tcp::Socket>(self.handle);
            match socket.state() {
                tcp::State::SynSent => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                tcp::State::Closed => Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into())),
                _ => Poll::Ready(Ok(())),
            }
        })
        .await
    }
}

/// Whether a socket is still waiting for its handshake to complete, in which
/// state smoltcp reports it neither readable nor writable.
fn is_opening(state: tcp::State) -> bool {
    matches!(
        state,
        tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
    )
}

impl AsyncRead for GuestConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.shared.lock();
        let socket = inner.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.can_recv() {
            let n = socket
                .recv_slice(buf.initialize_unfilled())
                .map_err(|err| io::Error::other(err.to_string()))?;
            buf.advance(n);
            drop(inner);
            // The window just opened; smoltcp only says so when polled.
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !socket.may_recv() && !is_opening(socket.state()) {
            // Closed without the guest's FIN having been read is a reset;
            // anything else past the handshake is the end of its data.
            return Poll::Ready(match socket.state() {
                tcp::State::Closed => Err(io::ErrorKind::ConnectionReset.into()),
                _ => Ok(()),
            });
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for GuestConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.shared.lock();
        let socket = inner.sockets.get_mut::<tcp::Socket>(self.handle);
        if !socket.may_send() && !is_opening(socket.state()) {
            return Poll::Ready(Err(match socket.state() {
                tcp::State::Closed => io::ErrorKind::ConnectionReset.into(),
                _ => io::ErrorKind::BrokenPipe.into(),
            }));
        }
        if socket.can_send() {
            let n = socket
                .send_slice(data)
                .map_err(|err| io::Error::other(err.to_string()))?;
            drop(inner);
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(n));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.shared.lock();
        inner.sockets.get_mut::<tcp::Socket>(self.handle).close();
        drop(inner);
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for GuestConn {
    fn drop(&mut self) {
        let mut inner = self.shared.lock();
        if inner.is_closed {
            return;
        }
        inner.sockets.get_mut::<tcp::Socket>(self.handle).close();
        inner.released.insert(self.handle);
        drop(inner);
        self.shared.wake.notify_one();
    }
}

/// Carries bytes both ways until both sides have finished, passing each
/// side's FIN on as a half-close and a reset on either side as a reset on the
/// other. Returns the bytes sent by the guest and received by it.
pub(super) async fn splice(guest: GuestConn, upstream: TcpStream) -> (u64, u64) {
    let sent = AtomicU64::new(0);
    let received = AtomicU64::new(0);
    let (mut guest_read, mut guest_write) = tokio::io::split(guest);
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let up = async {
        pump(&mut guest_read, &mut upstream_write, &sent).await?;
        upstream_write.shutdown().await
    };
    let down = async {
        pump(&mut upstream_read, &mut guest_write, &received).await?;
        guest_write.shutdown().await
    };
    if tokio::try_join!(up, down).is_err() {
        // One side reset, so the other is told the same rather than left
        // waiting for bytes that will never come.
        let guest = guest_read.unsplit(guest_write);
        guest.abort();
        if let Ok(upstream) = upstream_read.reunite(upstream_write) {
            let _ = socket2::SockRef::from(&upstream).set_linger(Some(std::time::Duration::ZERO));
        }
    }
    (sent.into_inner(), received.into_inner())
}

async fn pump<R, W>(from: &mut R, to: &mut W, moved: &AtomicU64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
        moved.fetch_add(n as u64, Ordering::Relaxed);
    }
}
