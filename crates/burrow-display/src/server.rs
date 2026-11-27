//! The VMM's end of the display socket.
//!
//! [`Display`] is shared by the VMM's GPU and input device workers and one
//! socket thread running [`Display::serve`]. The workers own guest memory and
//! the queues; the socket thread owns the client. They meet in the
//! [`Gpu`] and [`Input`] locks, and wake each other through the hooks the
//! VMM supplies and the notice pipe.

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::gpu::{Gpu, Notice, Surface};
use crate::input::{Input, Kind};
use crate::wire::{self, Decoder, DeviceMessage, HostMessage};

/// How long a client may leave the device's messages unread before it is
/// dropped.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// A frame surface in a sealed memfd, which is what reaches the client.
pub struct Memfd {
    fd: OwnedFd,
    ptr: *mut u8,
    len: usize,
}

// SAFETY: the mapping belongs to this value alone.
unsafe impl Send for Memfd {}

impl Memfd {
    pub fn share(&self) -> io::Result<OwnedFd> {
        self.fd.try_clone()
    }
}

impl Surface for Memfd {
    fn alloc(len: usize) -> io::Result<Self> {
        // SAFETY: the name is NUL-terminated and the flags are memfd_create's.
        let raw = unsafe {
            libc::memfd_create(
                c"burrow-frame".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: memfd_create returned a descriptor this process owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: plain syscalls on a descriptor we own.
        unsafe {
            if libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) < 0 {
                return Err(io::Error::last_os_error());
            }
            // The client maps it: it must not shrink under that mapping.
            let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
            if libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: mapping the whole memfd shared; the result is checked.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len.max(1),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            ptr: ptr.cast(),
            len,
        })
    }

    fn pixels(&mut self) -> &mut [u8] {
        // SAFETY: the mapping is `len` bytes and lives as long as self.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for Memfd {
    fn drop(&mut self) {
        // SAFETY: unmapping exactly what `alloc` mapped.
        unsafe { libc::munmap(self.ptr.cast(), self.len.max(1)) };
    }
}

/// How the socket thread wakes the VMM's device workers.
pub struct Hooks {
    /// The GPU has a host request to service.
    pub gpu: Box<dyn Fn() + Send + Sync>,
    /// An input device has events, by [`Kind::index`].
    pub input: [Box<dyn Fn() + Send + Sync>; 2],
}

pub struct Display {
    pub gpu: Mutex<Gpu<Memfd>>,
    pub inputs: [Mutex<Input>; 2],
    hooks: Hooks,
    is_gpu_active: AtomicBool,
    wake_read: OwnedFd,
    wake_write: OwnedFd,
}

impl Display {
    pub fn new(gpu: Gpu<Memfd>, inputs: [Input; 2], hooks: Hooks) -> io::Result<Self> {
        let mut fds = [0; 2];
        // SAFETY: pipe2 fills two descriptors on success.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let [keyboard, tablet] = inputs;
        Ok(Self {
            gpu: Mutex::new(gpu),
            inputs: [Mutex::new(keyboard), Mutex::new(tablet)],
            hooks,
            is_gpu_active: AtomicBool::new(false),
            // SAFETY: pipe2 returned these and nothing else owns them.
            wake_read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            // SAFETY: as above.
            wake_write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        })
    }

    /// The GPU worker runs: host requests will be serviced. Until then a
    /// subscriber is told nothing is scanned out.
    pub fn set_gpu_active(&self, is_active: bool) {
        self.is_gpu_active.store(is_active, Ordering::SeqCst);
    }

    /// Wakes the socket thread to send what the GPU has queued.
    pub fn notify(&self) {
        // SAFETY: a one-byte write to our own non-blocking pipe. A full pipe
        // already holds a wakeup.
        unsafe { libc::write(self.wake_write.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
    }

    /// Serves one client at a time on `listener`, for the life of the VMM. A
    /// new connection replaces the old one.
    pub fn serve(&self, listener: &UnixListener) -> io::Result<()> {
        let mut client: Option<(UnixStream, Decoder)> = None;
        loop {
            let mut fds = vec![
                libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake_read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            if let Some((stream, _)) = &client {
                fds.push(libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            // SAFETY: fds is a live array of pollfd.
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if fds[1].revents != 0 {
                self.drain_wakeups();
                if let Some((stream, _)) = &client
                    && self.send_notices(stream).is_err()
                {
                    self.drop_client(&mut client);
                }
            }
            if fds[0].revents != 0 {
                let (stream, _) = listener.accept()?;
                self.drop_client(&mut client);
                if self.greet(&stream).is_ok() {
                    client = Some((stream, Decoder::default()));
                }
            }
            if fds.get(2).is_some_and(|fd| fd.revents != 0)
                && let Some((stream, decoder)) = &mut client
                && self.read_client(stream, decoder).is_err()
            {
                self.drop_client(&mut client);
            }
        }
    }

    fn greet(&self, stream: &UnixStream) -> io::Result<()> {
        stream.set_write_timeout(Some(SEND_TIMEOUT))?;
        let (width, height) = self.gpu.lock().unwrap().mode();
        let hello = DeviceMessage::Hello {
            version: wire::VERSION,
            width,
            height,
        };
        crate::fdpass::send(stream, &wire::encode(&hello), None)
    }

    fn drop_client(&self, client: &mut Option<(UnixStream, Decoder)>) {
        if client.take().is_some() {
            self.gpu.lock().unwrap().unsubscribe();
        }
    }

    fn drain_wakeups(&self) {
        let mut buf = [0u8; 64];
        // SAFETY: reading our own non-blocking pipe into a local buffer.
        while unsafe {
            libc::read(
                self.wake_read.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        } > 0
        {}
    }

    fn send_notices(&self, stream: &UnixStream) -> io::Result<()> {
        // The surface is taken with the notices, under one lock, so a mode
        // goes out with the memfd it describes.
        let (notices, fd) = {
            let mut gpu = self.gpu.lock().unwrap();
            let notices = gpu.take_notices();
            let fd = match notices.iter().any(|n| matches!(n, Notice::Mode(_))) {
                true => gpu.surface().map(|(s, _)| s.share()).transpose()?,
                false => None,
            };
            (notices, fd)
        };
        for notice in notices {
            let (message, fd) = match notice {
                Notice::Mode(mode) => match &fd {
                    Some(fd) => (DeviceMessage::Mode(mode), Some(fd.as_fd())),
                    None => continue,
                },
                Notice::Damage(rects) => (DeviceMessage::Damage(rects), None),
                Notice::Disabled => (DeviceMessage::Disabled, None),
                Notice::Cursor(c) => (DeviceMessage::Cursor(c), None),
                Notice::CursorImage(c) => (DeviceMessage::CursorImage(c), None),
            };
            crate::fdpass::send(stream, &wire::encode(&message), fd)?;
        }
        Ok(())
    }

    fn read_client(&self, stream: &UnixStream, decoder: &mut Decoder) -> io::Result<()> {
        let mut buf = [0u8; 8 * 1024];
        let mut fds = std::collections::VecDeque::new();
        let n = crate::fdpass::recv(stream, &mut buf, &mut fds)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        decoder.feed(&buf[..n]);
        while let Some(message) = decoder
            .decode::<HostMessage>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        {
            self.handle(stream, message)?;
        }
        Ok(())
    }

    fn handle(&self, stream: &UnixStream, message: HostMessage) -> io::Result<()> {
        match message {
            HostMessage::Subscribe => {
                let is_active = self.is_gpu_active.load(Ordering::SeqCst);
                self.gpu.lock().unwrap().request_subscribe();
                if is_active {
                    (self.hooks.gpu)();
                } else {
                    crate::fdpass::send(stream, &wire::encode(&DeviceMessage::Disabled), None)?;
                }
            }
            HostMessage::Unsubscribe => self.gpu.lock().unwrap().unsubscribe(),
            HostMessage::Resize { width, height } => {
                if crate::is_valid_mode(width, height) {
                    self.gpu.lock().unwrap().resize(width, height);
                    (self.hooks.gpu)();
                }
            }
            HostMessage::Input(events) => {
                for kind in Kind::ALL {
                    let mine: Vec<_> = events
                        .iter()
                        .filter(|e| Kind::of(e) == Some(kind))
                        .copied()
                        .collect();
                    if !mine.is_empty() && self.inputs[kind.index()].lock().unwrap().push(&mine) {
                        (self.hooks.input[kind.index()])();
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Client, Received};
    use crate::input::{EV_ABS, EV_KEY, InputEvent};
    use crate::{GuestMemory, MemoryError};
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    struct Zero;

    impl GuestMemory for Zero {
        fn read(&self, _addr: u64, buf: &mut [u8]) -> Result<(), MemoryError> {
            buf.fill(0x40);
            Ok(())
        }
    }

    fn request(kind: u32, words: &[u32]) -> Vec<u8> {
        let mut r = kind.to_le_bytes().to_vec();
        r.extend_from_slice(&[0; 20]);
        for w in words {
            r.extend_from_slice(&w.to_le_bytes());
        }
        r
    }

    #[test]
    fn a_client_subscribes_resizes_and_sends_input() {
        let dir = std::env::temp_dir().join(format!("burrow-display-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::SOCKET);
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();

        let gpu_wakes = Arc::new(AtomicUsize::new(0));
        let tablet_wakes = Arc::new(AtomicUsize::new(0));
        let (g, t) = (gpu_wakes.clone(), tablet_wakes.clone());
        let display = Arc::new(
            Display::new(
                Gpu::new(1024, 768),
                [Input::new(Kind::Keyboard), Input::new(Kind::Tablet)],
                Hooks {
                    gpu: Box::new(move || {
                        g.fetch_add(1, Ordering::SeqCst);
                    }),
                    input: [
                        Box::new(|| {}),
                        Box::new(move || {
                            t.fetch_add(1, Ordering::SeqCst);
                        }),
                    ],
                },
            )
            .unwrap(),
        );
        {
            let mut gpu = display.gpu.lock().unwrap();
            let mut out = Vec::new();
            gpu.process(&Zero, &request(0x0101, &[1, 2, 16, 8]), &mut out);
            let mut attach = request(0x0106, &[1, 1]);
            attach.extend_from_slice(&0x1000u64.to_le_bytes());
            attach.extend_from_slice(&512u32.to_le_bytes());
            attach.extend_from_slice(&[0; 4]);
            gpu.process(&Zero, &attach, &mut out);
            gpu.process(&Zero, &request(0x0103, &[0, 0, 16, 8, 0, 1]), &mut out);
        }
        let server = display.clone();
        std::thread::spawn(move || server.serve(&listener));

        let mut client = Client::connect(&path).unwrap();
        assert_eq!(client.preferred_mode(), (1024, 768));

        // Before the GPU worker runs, a subscriber hears nothing is shown.
        client.send(&HostMessage::Subscribe).unwrap();
        assert!(matches!(
            client.recv().unwrap(),
            Received::Other(DeviceMessage::Disabled)
        ));

        display.set_gpu_active(true);
        client.send(&HostMessage::Subscribe).unwrap();
        client
            .send(&HostMessage::Resize {
                width: 1280,
                height: 800,
            })
            .unwrap();
        client
            .send(&HostMessage::Resize {
                width: 10,
                height: 10,
            })
            .unwrap();
        client
            .send(&HostMessage::Input(vec![
                InputEvent::new(EV_ABS, 0, 100),
                InputEvent::new(EV_KEY, 30, 1),
            ]))
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while tablet_wakes.load(Ordering::SeqCst) == 0 || gpu_wakes.load(Ordering::SeqCst) < 2 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        // What the GPU worker does when woken.
        assert!(display.gpu.lock().unwrap().service(&Zero));
        display.notify();

        let Received::Mode(frame) = client.recv().unwrap() else {
            panic!("expected a mode");
        };
        assert_eq!((frame.mode().width, frame.mode().height), (16, 8));
        assert!(frame.to_rgb().iter().all(|b| *b == 0x40));
        assert!(matches!(
            client.recv().unwrap(),
            Received::Other(DeviceMessage::Damage(_))
        ));
        assert_eq!(display.gpu.lock().unwrap().mode(), (1280, 800));
        let keyboard = display.inputs[0].lock().unwrap();
        assert_eq!(keyboard.peek(), Some(InputEvent::new(EV_KEY, 30, 1)));
        drop(keyboard);
        assert_eq!(
            display.inputs[1].lock().unwrap().peek(),
            Some(InputEvent::new(EV_ABS, 0, 100))
        );

        drop(client);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while display.gpu.lock().unwrap().is_subscribed() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
