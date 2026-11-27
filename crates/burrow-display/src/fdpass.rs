//! Bytes and file descriptors over a Unix stream socket.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

const MAX_FDS: usize = 4;

/// Writes all of `bytes`, with `fd` as `SCM_RIGHTS` on the first segment.
pub(crate) fn send(
    sock: &UnixStream,
    mut bytes: &[u8],
    mut fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
        let mut control = vec![0u8; space];
        // SAFETY: msghdr is plain data; zeroed is a valid empty header.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = fd.take() {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            // SAFETY: the control buffer is CMSG_SPACE for one int, so the
            // first header and its data fit in it.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(cmsg).cast::<libc::c_int>(),
                    fd.as_raw_fd(),
                );
            }
        }
        // SAFETY: msg points at live buffers for the duration of the call.
        let sent = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, SEND_FLAGS) };
        if sent < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        bytes = &bytes[sent as usize..];
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: libc::c_int = 0;

#[cfg(target_os = "linux")]
const RECV_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECV_FLAGS: libc::c_int = 0;

/// Reads what has arrived into `buf`, queueing any descriptors that came
/// with it. Returns 0 at end of stream.
pub(crate) fn recv(
    sock: &UnixStream,
    buf: &mut [u8],
    fds: &mut VecDeque<OwnedFd>,
) -> io::Result<usize> {
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE((MAX_FDS * size_of::<libc::c_int>()) as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: as in `send`.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    let n = loop {
        // SAFETY: msg points at live buffers for the duration of the call.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, RECV_FLAGS) };
        if n >= 0 {
            break n as usize;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    };
    // SAFETY: the kernel filled `control` and set msg_controllen; the CMSG
    // macros walk only what it wrote.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                let count = ((*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                    / size_of::<libc::c_int>();
                for i in 0..count {
                    fds.push_back(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};

    #[test]
    fn a_descriptor_travels_with_its_bytes() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut file = tempfile();
        file.write_all(b"frame").unwrap();
        send(&a, b"hello", None).unwrap();
        send(&a, b"mode", Some(std::os::fd::AsFd::as_fd(&file))).unwrap();
        let mut fds = VecDeque::new();
        let mut buf = [0u8; 64];
        let mut got = Vec::new();
        while got.len() < 9 {
            let n = recv(&b, &mut buf, &mut fds).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got, b"hellomode");
        assert_eq!(fds.len(), 1);
        let mut received = std::fs::File::from(fds.pop_front().unwrap());
        received.rewind().unwrap();
        let mut s = String::new();
        received.read_to_string(&mut s).unwrap();
        assert_eq!(s, "frame");
        drop(a);
        assert_eq!(recv(&b, &mut buf, &mut fds).unwrap(), 0);
    }

    fn tempfile() -> std::fs::File {
        let path = std::env::temp_dir().join(format!("burrow-display-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file
    }
}
