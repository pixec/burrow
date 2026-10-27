//! An async byte stream over a raw file descriptor.
//!
//! Child stdio and pty masters both arrive as bare descriptors. Tokio has no
//! constructor that adopts one directly, so they are made non-blocking and
//! driven through `AsyncFd`.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct AsyncPipe(AsyncFd<OwnedFd>);

impl AsyncPipe {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        // AsyncFd requires non-blocking, or readiness notifications deadlock.
        let raw = fd.as_raw_fd();
        let flags = unsafe { nix::libc::fcntl(raw, nix::libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { nix::libc::fcntl(raw, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(AsyncFd::new(fd)?))
    }

    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.0.get_ref().as_raw_fd()
    }
}

impl AsyncRead for AsyncPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            let result = guard.try_io(|inner| {
                let n = unsafe {
                    nix::libc::read(
                        inner.get_ref().as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // Linux reports EIO on a pty master once the last slave closes,
                // i.e. when the child exits. That is EOF, not a failure.
                Ok(Err(err)) if err.raw_os_error() == Some(nix::libc::EIO) => {
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            let result = guard.try_io(|inner| {
                let n = unsafe {
                    nix::libc::write(inner.get_ref().as_raw_fd(), buf.as_ptr().cast(), buf.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Ok(res) => return Poll::Ready(res),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
