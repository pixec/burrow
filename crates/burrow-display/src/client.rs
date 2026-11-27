//! The host's end of the display socket.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::gpu::Mode;
use crate::wire::{self, Decoder, DeviceMessage, HostMessage};

/// A connection to one VM's display device.
pub struct Client {
    stream: UnixStream,
    decoder: Decoder,
    fds: VecDeque<OwnedFd>,
    preferred: (u32, u32),
}

/// What [`Client::recv`] returns: a device message, and for a mode the frame
/// it describes.
pub enum Received {
    Mode(Frame),
    Other(DeviceMessage),
}

impl Client {
    /// Connects and reads the device's greeting.
    pub fn connect(path: &Path) -> io::Result<Self> {
        Self::from_stream(UnixStream::connect(path)?)
    }

    pub fn from_stream(stream: UnixStream) -> io::Result<Self> {
        let mut client = Self {
            stream,
            decoder: Decoder::default(),
            fds: VecDeque::new(),
            preferred: (0, 0),
        };
        match client.next_message()? {
            DeviceMessage::Hello {
                version: wire::VERSION,
                width,
                height,
            } => client.preferred = (width, height),
            DeviceMessage::Hello { version, .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "the display device speaks protocol version {version}, not {}",
                        wire::VERSION
                    ),
                ));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the display device opened with {other:?}"),
                ));
            }
        }
        Ok(client)
    }

    /// The display's preferred mode when the connection was made.
    pub fn preferred_mode(&self) -> (u32, u32) {
        self.preferred
    }

    pub fn send(&self, message: &HostMessage) -> io::Result<()> {
        crate::fdpass::send(&self.stream, &wire::encode(message), None)
    }

    /// A second handle on the socket for sending from another thread.
    pub fn sender(&self) -> io::Result<Sender> {
        Ok(Sender(self.stream.try_clone()?))
    }

    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    pub fn recv(&mut self) -> io::Result<Received> {
        match self.next_message()? {
            DeviceMessage::Mode(mode) => {
                let fd = self.fds.pop_front().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a display mode came without its frame",
                    )
                })?;
                Ok(Received::Mode(Frame::map(fd, mode)?))
            }
            other => Ok(Received::Other(other)),
        }
    }

    fn next_message(&mut self) -> io::Result<DeviceMessage> {
        loop {
            if let Some(message) = self
                .decoder
                .decode::<DeviceMessage>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            {
                return Ok(message);
            }
            let mut buf = [0u8; 16 * 1024];
            let n = crate::fdpass::recv(&self.stream, &mut buf, &mut self.fds)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.decoder.feed(&buf[..n]);
        }
    }
}

pub struct Sender(UnixStream);

impl Sender {
    pub fn send(&self, message: &HostMessage) -> io::Result<()> {
        crate::fdpass::send(&self.0, &wire::encode(message), None)
    }

    /// Closes the connection for both handles, ending a [`Client::recv`]
    /// blocked on another thread.
    pub fn shutdown(&self) -> io::Result<()> {
        self.0.shutdown(std::net::Shutdown::Both)
    }
}

/// The device's frame, mapped read-only. The device writes it as the guest
/// draws, so a read can see a frame partway through an update.
pub struct Frame {
    ptr: *const u8,
    len: usize,
    mode: Mode,
}

// SAFETY: the mapping is read-only and owned by this value alone.
unsafe impl Send for Frame {}
// SAFETY: as above; reads go through raw copies, never shared references.
unsafe impl Sync for Frame {}

impl Frame {
    fn map(fd: OwnedFd, mode: Mode) -> io::Result<Self> {
        // SAFETY: fstat fills a plain struct.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fd is a live descriptor and stat a valid out-pointer.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = usize::try_from(stat.st_size).unwrap_or(0);
        let needed = u64::from(mode.offset)
            + u64::from(mode.stride) * u64::from(mode.height.saturating_sub(1))
            + u64::from(mode.width) * 4;
        if mode.width == 0
            || mode.height == 0
            || u64::from(mode.width) * 4 > u64::from(mode.stride)
            || needed > len as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a {len}-byte frame cannot hold {mode:?}"),
            ));
        }
        // SAFETY: mapping a descriptor read-only and shared; the result is
        // checked before use.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr.cast(),
            len,
            mode,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The visible frame as packed 8-bit RGB, row by row.
    pub fn to_rgb(&self) -> Vec<u8> {
        let Mode {
            width,
            height,
            stride,
            offset,
            format,
        } = self.mode;
        let [r, g, b] = format.rgb_offsets();
        let mut row = vec![0u8; width as usize * 4];
        let mut out = Vec::with_capacity(width as usize * height as usize * 3);
        for y in 0..height as usize {
            let start = offset as usize + y * stride as usize;
            // SAFETY: `map` checked that every visible row lies inside the
            // mapping.
            unsafe {
                std::ptr::copy_nonoverlapping(self.ptr.add(start), row.as_mut_ptr(), row.len())
            };
            for px in row.as_chunks::<4>().0 {
                out.extend_from_slice(&[px[r], px[g], px[b]]);
            }
        }
        out
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        // SAFETY: unmapping exactly the mapping `map` made.
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}
