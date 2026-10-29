//! Serving gRPC over AF_VSOCK in a macOS guest.
//!
//! The SDK has `<sys/vsock.h>` and the guest kernel has the family (40) for a
//! virtio-socket device such as Virtualization.framework's; `tokio-vsock` is
//! Linux-only, so the socket is made with `libc` and driven through tokio's
//! `AsyncFd`, which on macOS is kqueue.

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use nix::libc;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

use crate::unix::asyncfd::AsyncPipe;

/// Timing of the accept that produced a connection, as on Linux.
#[derive(Clone, Copy)]
pub struct Arrival {
    pub accepted_at: std::time::Instant,
    /// How long the accepting task had been blocked in `accept()`. The guest's
    /// monotonic clock stops while the machine is paused, so after a restore
    /// this is the guest's cost of waking.
    pub parked: std::time::Duration,
}

pub struct VsockConn {
    pub stream: AsyncPipe,
    pub arrival: Arrival,
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
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for VsockConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// Close-on-exec, which macOS's socket(2) and accept(2) cannot ask for: an
/// upgrade execs the new agent, which binds the port itself.
fn cloexec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor the caller holds.
    check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) }).map(drop)
}

pub struct Listener(AsyncFd<OwnedFd>);

impl Listener {
    /// Listens on `port` of every cid: the guest's own is the hypervisor's to
    /// assign, so the peer is checked after accept instead.
    pub fn bind(port: u32) -> io::Result<Self> {
        // SAFETY: a plain socket(2); the descriptor is owned at once.
        let fd = unsafe {
            OwnedFd::from_raw_fd(check(libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0))?)
        };
        cloexec(&fd)?;
        let addr = libc::sockaddr_vm {
            svm_len: std::mem::size_of::<libc::sockaddr_vm>() as u8,
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: libc::VMADDR_CID_ANY,
        };
        // SAFETY: `addr` is a sockaddr_vm of the length passed.
        check(unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        })?;
        // SAFETY: as above.
        check(unsafe { libc::listen(fd.as_raw_fd(), 128) })?;
        // SAFETY: as above.
        let flags = check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })?;
        // SAFETY: as above.
        check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
        Ok(Self(AsyncFd::new(fd)?))
    }

    /// The next connection and the cid it came from.
    pub async fn accept(&self) -> io::Result<(AsyncPipe, u32)> {
        loop {
            let mut guard = self.0.readable().await?;
            let accepted = guard.try_io(|listener| {
                // SAFETY: all zeroes is a valid sockaddr_vm.
                let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
                let mut len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
                // SAFETY: `peer` is as long as `len` says.
                let fd = check(unsafe {
                    libc::accept(
                        listener.get_ref().as_raw_fd(),
                        (&raw mut peer).cast(),
                        &mut len,
                    )
                })?;
                // SAFETY: accept(2) just returned it to nobody else.
                Ok((unsafe { OwnedFd::from_raw_fd(fd) }, peer.svm_cid))
            });
            match accepted {
                Ok(Ok((fd, cid))) => {
                    cloexec(&fd)?;
                    return Ok((AsyncPipe::new(fd)?, cid));
                }
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }
}
