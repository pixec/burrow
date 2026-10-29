//! Serving gRPC over virtio-vsock on Windows.
//!
//! Windows has no AF_VSOCK of its own. virtio-win's viosock driver adds one:
//! a kernel driver for the virtio-vsock device and a Winsock service provider
//! (installed with `viosocklib`) that registers an address family for it.
//! The family's number is not fixed: the provider is given one when it is
//! installed, and the driver reports it through `IOCTL_GET_AF` on the
//! `\\.\Viosock` device, which is what viosock's own `ViosockGetAF()` in
//! `vio_sockets.h` does. The agent asks the same way. Addresses are
//! viosock's `SOCKADDR_VM`: family, a reserved u16, then port and cid as
//! u32s in host order, the same layout as Linux's `sockaddr_vm`.
//!
//! Sockets are used blocking, each on threads of its own, and bridged into
//! tokio through an in-memory duplex: tokio's reactor on Windows polls sockets
//! through AFD, which only works for the base providers Windows ships, and a
//! third-party provider's sockets are not guaranteed to be among them. The
//! host makes one or two connections per sandbox, so a thread pair each is
//! cheap.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf,
};
use tokio::sync::mpsc;
use tonic::transport::server::Connected;
use windows_sys::Win32::Networking::WinSock::{
    INVALID_SOCKET, SD_SEND, SOCK_STREAM, SOCKADDR, SOCKET, SOCKET_ERROR,
    WSA_FLAG_NO_HANDLE_INHERIT, WSADATA, WSASocketW, WSAStartup, accept, bind, closesocket, listen,
    recv, send, shutdown,
};

use crate::windows::win;

/// viosock's device, as `\??\Viosock` is named from user mode.
const DEVICE: &str = "\\\\.\\Viosock";
/// viosock's `IOCTL_GET_AF`, from `vio_sockets.h`.
const IOCTL_GET_AF: u32 = 0x0801_300C;
const VMADDR_CID_ANY: u32 = u32::MAX;
/// The only peer the agent talks to, as on Linux: the host side of the
/// device is cid 2, and a process in the guest dialling its own cid arrives
/// as something else.
const HOST_CID: u32 = 2;
/// Bytes buffered between a socket's threads and tonic, each way.
const BRIDGE_BYTES: usize = 256 * 1024;

/// viosock's `SOCKADDR_VM`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SockaddrVm {
    family: u16,
    reserved: u16,
    port: u32,
    cid: u32,
}

/// The address family viosock's provider was registered under.
fn address_family() -> std::io::Result<u16> {
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, OPEN_EXISTING};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let name = win::wide(DEVICE);
    // SAFETY: `name` is NUL-terminated; the handle is owned below.
    let device = win::owned(unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    })
    .map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("opening {DEVICE} (is viosock installed?): {err}"),
        )
    })?;
    // Four bytes, of which the family is the low two: `ADDRESS_FAMILY` is a
    // u16, and a buffer larger than the driver writes is still accepted.
    let mut family = 0u32;
    let mut returned = 0u32;
    use std::os::windows::io::AsRawHandle as _;
    // SAFETY: `family` is the output buffer, sized as passed.
    win::check(unsafe {
        DeviceIoControl(
            device.as_raw_handle(),
            IOCTL_GET_AF,
            std::ptr::null(),
            0,
            (&raw mut family).cast(),
            4,
            &mut returned,
            std::ptr::null_mut(),
        )
    })?;
    let family = family as u16;
    if family == 0 {
        return Err(std::io::Error::other("viosock reports no address family"));
    }
    Ok(family)
}

fn wsa_error() -> std::io::Error {
    // SAFETY: reads thread-local state.
    std::io::Error::from_raw_os_error(unsafe {
        windows_sys::Win32::Networking::WinSock::WSAGetLastError()
    })
}

/// A socket, closed when the last thread using it lets go.
struct Socket(SOCKET);

impl Drop for Socket {
    fn drop(&mut self) {
        // SAFETY: the socket is owned and not used after this.
        unsafe { closesocket(self.0) };
    }
}

/// When a connection arrived, as burrow-guest reports it in a handshake.
#[derive(Clone, Copy)]
pub struct Arrival {
    pub accepted_at: std::time::Instant,
    pub parked: std::time::Duration,
}

pub struct VsockConn {
    stream: DuplexStream,
    arrival: Arrival,
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

/// Binds `port` on every cid and hands over each connection from the host.
pub fn listen_on(port: u32) -> std::io::Result<mpsc::Receiver<VsockConn>> {
    let mut data: WSADATA = unsafe { std::mem::zeroed() };
    // SAFETY: `data` is written by the call.
    let rc = unsafe { WSAStartup(0x0202, &mut data) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc));
    }
    let family = address_family()?;
    // SAFETY: plain socket creation; the result is checked.
    let raw = unsafe {
        WSASocketW(
            i32::from(family),
            SOCK_STREAM,
            0,
            std::ptr::null(),
            0,
            WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if raw == INVALID_SOCKET {
        return Err(wsa_error());
    }
    let listener = Socket(raw);
    let addr = SockaddrVm {
        family,
        reserved: 0,
        port,
        cid: VMADDR_CID_ANY,
    };
    // SAFETY: `addr` is a SOCKADDR_VM of the size passed.
    if unsafe {
        bind(
            listener.0,
            (&raw const addr).cast::<SOCKADDR>(),
            std::mem::size_of::<SockaddrVm>() as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(wsa_error());
    }
    // SAFETY: a bound socket.
    if unsafe { listen(listener.0, 16) } == SOCKET_ERROR {
        return Err(wsa_error());
    }
    tracing::debug!(port, family, "listening on vsock");

    let runtime = tokio::runtime::Handle::current();
    let (tx, rx) = mpsc::channel(4);
    std::thread::Builder::new()
        .name("vsock-accept".into())
        .spawn(move || {
            loop {
                let parked_since = std::time::Instant::now();
                let mut peer = SockaddrVm::default();
                let mut len = std::mem::size_of::<SockaddrVm>() as i32;
                // SAFETY: `peer` has room for `len` bytes.
                let raw =
                    unsafe { accept(listener.0, (&raw mut peer).cast::<SOCKADDR>(), &mut len) };
                if raw == INVALID_SOCKET {
                    tracing::warn!(err = %wsa_error(), "vsock accept failed");
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                let socket = Socket(raw);
                // A process inside the guest dialling the agent: the API is
                // unauthenticated because only the host is meant to reach it.
                if peer.cid != HOST_CID {
                    tracing::warn!(
                        cid = peer.cid,
                        "refusing a vsock connection that did not come from the host"
                    );
                    continue;
                }
                let arrival = Arrival {
                    accepted_at: std::time::Instant::now(),
                    parked: parked_since.elapsed(),
                };
                let stream = bridge(Arc::new(socket), &runtime);
                if tx.blocking_send(VsockConn { stream, arrival }).is_err() {
                    return;
                }
            }
        })?;
    Ok(rx)
}

/// Connects a blocking socket to an in-memory stream tonic can poll.
fn bridge(socket: Arc<Socket>, runtime: &tokio::runtime::Handle) -> DuplexStream {
    let (agent, near) = tokio::io::duplex(BRIDGE_BYTES);
    let (mut from_agent, mut to_agent) = tokio::io::split(near);

    let inbound = Arc::clone(&socket);
    let handle = runtime.clone();
    let _ = std::thread::Builder::new()
        .name("vsock-rx".into())
        .spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                // SAFETY: `buf` has room for the length passed.
                let n = unsafe { recv(inbound.0, buf.as_mut_ptr(), buf.len() as i32, 0) };
                if n <= 0 {
                    break;
                }
                if handle
                    .block_on(to_agent.write_all(&buf[..n as usize]))
                    .is_err()
                {
                    break;
                }
            }
            // Dropping the writer is the EOF tonic sees.
            let _ = handle.block_on(to_agent.shutdown());
        });

    let handle = runtime.clone();
    let _ = std::thread::Builder::new()
        .name("vsock-tx".into())
        .spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match handle.block_on(from_agent.read(&mut buf)) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut sent = 0;
                while sent < n {
                    // SAFETY: the range is within `buf`.
                    let rc = unsafe { send(socket.0, buf[sent..n].as_ptr(), (n - sent) as i32, 0) };
                    if rc <= 0 {
                        return;
                    }
                    sent += rc as usize;
                }
            }
            // SAFETY: half-closes a socket this thread still holds.
            unsafe { shutdown(socket.0, SD_SEND) };
        });
    agent
}
