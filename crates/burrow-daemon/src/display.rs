//! A sandbox's display, read the same way whatever VMM runs it.
//!
//! A VM given a display serves it on [`burrow_vmm::DISPLAY_UDS`] in its
//! working directory: frames as a memfd and damage notices, input and
//! resolution changes the other way ([`burrow_display::wire`]).
//! [`FrameSource`] is what the rest of the node reads a display through.

use std::path::{Path, PathBuf};
use std::time::Duration;

use burrow_display::Rect;
use burrow_display::client::{Client, Frame, Received, Sender};
use burrow_display::gpu::Mode;
use burrow_display::input::InputEvent;
use burrow_display::wire::{DeviceMessage, HostMessage};
use tokio::sync::mpsc;

/// What a display's frames and input go through.
pub trait FrameSource {
    /// How the frame is laid out, once the guest scans one out.
    fn mode(&self) -> Option<Mode>;
    /// The parts of the frame that changed since the last call, coalesced.
    /// Empty when the display was switched off or the mode changed.
    async fn next_damage(&mut self) -> std::io::Result<Vec<Rect>>;
    /// The visible frame as packed 8-bit RGB.
    fn rgb(&self) -> Option<Vec<u8>>;
    async fn input(&self, events: Vec<InputEvent>) -> std::io::Result<()>;
    async fn resize(&self, width: u32, height: u32) -> std::io::Result<()>;
}

/// A display read through its VM's socket.
pub struct SocketSource {
    sender: Sender,
    received: mpsc::UnboundedReceiver<std::io::Result<Received>>,
    frame: Option<Frame>,
}

impl SocketSource {
    /// Connects to the display at `socket`.
    pub async fn connect(socket: &Path) -> std::io::Result<Self> {
        let socket = socket.to_path_buf();
        let mut client = tokio::task::spawn_blocking(move || Client::connect(&socket))
            .await
            .map_err(std::io::Error::other)??;
        let sender = client.sender()?;
        let (tx, received) = mpsc::unbounded_channel();
        std::thread::Builder::new()
            .name("display-reader".into())
            .spawn(move || {
                loop {
                    let message = client.recv();
                    let is_end = message.is_err();
                    if tx.send(message).is_err() || is_end {
                        return;
                    }
                }
            })?;
        Ok(Self {
            sender,
            received,
            frame: None,
        })
    }

    /// Asks for the display's frames, which arrive as damage.
    pub fn subscribe(&self) -> std::io::Result<()> {
        self.sender.send(&HostMessage::Subscribe)
    }

    /// Waits for the frame, then for the guest to stop drawing for `quiet`,
    /// at most `timeout` in all.
    pub async fn settle(&mut self, quiet: Duration, timeout: Duration) -> std::io::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        while self.frame.is_none() {
            tokio::time::timeout_at(deadline, self.next_damage())
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "the guest shows no frame")
                })??;
        }
        loop {
            let wait = quiet.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            match tokio::time::timeout(wait, self.next_damage()).await {
                Ok(damage) => damage?,
                Err(_) => return Ok(()),
            };
        }
    }
}

impl Drop for SocketSource {
    fn drop(&mut self) {
        let _ = self.sender.shutdown();
    }
}

impl FrameSource for SocketSource {
    fn mode(&self) -> Option<Mode> {
        self.frame.as_ref().map(Frame::mode)
    }

    async fn next_damage(&mut self) -> std::io::Result<Vec<Rect>> {
        let mut damage: Vec<Rect> = Vec::new();
        loop {
            let message = match damage.is_empty() {
                true => self.received.recv().await,
                false => match self.received.try_recv() {
                    Ok(message) => Some(message),
                    Err(_) => return Ok(damage),
                },
            };
            let message =
                message.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            match message? {
                Received::Mode(frame) => {
                    self.frame = Some(frame);
                    return Ok(Vec::new());
                }
                Received::Other(DeviceMessage::Disabled) => {
                    self.frame = None;
                    return Ok(Vec::new());
                }
                Received::Other(DeviceMessage::Damage(rects)) => damage.extend(rects),
                Received::Other(_) => {}
            }
        }
    }

    fn rgb(&self) -> Option<Vec<u8>> {
        self.frame.as_ref().map(Frame::to_rgb)
    }

    async fn input(&self, events: Vec<InputEvent>) -> std::io::Result<()> {
        self.sender.send(&HostMessage::Input(events))
    }

    async fn resize(&self, width: u32, height: u32) -> std::io::Result<()> {
        self.sender.send(&HostMessage::Resize { width, height })
    }
}

/// `width` x `height` packed RGB as a PNG.
pub fn png(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
    use std::io::Write as _;

    let row = width as usize * 3;
    let mut raw = Vec::with_capacity((row + 1) * height as usize);
    for line in rgb.chunks(row) {
        raw.push(0);
        raw.extend_from_slice(line);
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    z.write_all(&raw).expect("writing to memory");
    let idat = z.finish().expect("writing to memory");
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    for (kind, data) in [
        (b"IHDR", &ihdr[..]),
        (b"IDAT", &idat[..]),
        (b"IEND", &[][..]),
    ] {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let start = out.len();
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let crc = crc32(&out[start..]);
        out.extend_from_slice(&crc.to_be_bytes());
    }
    out
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// `burrowd display`: the node's own look at a sandbox's display.
#[derive(clap::Subcommand)]
pub enum DisplayCommand {
    /// Write a sandbox's screen to a PNG.
    Screenshot {
        sandbox: String,
        /// Where the PNG goes.
        #[arg(short, long)]
        out: PathBuf,
        /// The node's data directory, as `burrowd serve --data-dir`.
        #[arg(long, default_value = "/var/lib/burrow")]
        data_dir: PathBuf,
        /// The jail's base, as `burrowd serve --chroot-base`.
        #[arg(long, default_value = "/var/lib/burrow/jail")]
        chroot_base: PathBuf,
    },
    /// Offer a sandbox's display a new resolution.
    Resize {
        sandbox: String,
        width: u32,
        height: u32,
        #[arg(long, default_value = "/var/lib/burrow")]
        data_dir: PathBuf,
        #[arg(long, default_value = "/var/lib/burrow/jail")]
        chroot_base: PathBuf,
    },
    /// Press keys together and release them, by Linux input code: `29 56 111`
    /// is Ctrl+Alt+Delete.
    Keys {
        sandbox: String,
        #[arg(required = true)]
        codes: Vec<u16>,
        #[arg(long, default_value = "/var/lib/burrow")]
        data_dir: PathBuf,
        #[arg(long, default_value = "/var/lib/burrow/jail")]
        chroot_base: PathBuf,
    },
}

pub async fn run(command: DisplayCommand) -> anyhow::Result<()> {
    match command {
        DisplayCommand::Screenshot {
            sandbox,
            out,
            data_dir,
            chroot_base,
        } => {
            let socket = find_socket(&sandbox, &data_dir, &chroot_base)?;
            let mut source = SocketSource::connect(&socket).await?;
            source.subscribe()?;
            source
                .settle(Duration::from_millis(500), Duration::from_secs(10))
                .await?;
            let (Some(mode), Some(rgb)) = (source.mode(), source.rgb()) else {
                anyhow::bail!("{sandbox} shows nothing");
            };
            std::fs::write(&out, png(mode.width, mode.height, &rgb))?;
            println!("{}x{} {}", mode.width, mode.height, out.display());
            Ok(())
        }
        DisplayCommand::Resize {
            sandbox,
            width,
            height,
            data_dir,
            chroot_base,
        } => {
            if !burrow_display::is_valid_mode(width, height) {
                anyhow::bail!("{width}x{height} is not a resolution a display may have");
            }
            let socket = find_socket(&sandbox, &data_dir, &chroot_base)?;
            SocketSource::connect(&socket)
                .await?
                .resize(width, height)
                .await?;
            Ok(())
        }
        DisplayCommand::Keys {
            sandbox,
            codes,
            data_dir,
            chroot_base,
        } => {
            let socket = find_socket(&sandbox, &data_dir, &chroot_base)?;
            let source = SocketSource::connect(&socket).await?;
            let key = |code, value| InputEvent::new(burrow_display::input::EV_KEY, code, value);
            for code in &codes {
                source.input(vec![key(*code, 1)]).await?;
            }
            for code in codes.iter().rev() {
                source.input(vec![key(*code, 0)]).await?;
            }
            Ok(())
        }
    }
}

/// The display socket of the sandbox `id`, jailed or not.
fn find_socket(id: &str, data_dir: &Path, chroot_base: &Path) -> anyhow::Result<PathBuf> {
    crate::nodeapi::validate_sandbox_id("sandbox", id)
        .map_err(|err| anyhow::anyhow!("{}", err.message()))?;
    let jail = burrow_vmm::JailLayout {
        uid: 0,
        gid: 0,
        chroot_base: chroot_base.to_path_buf(),
    };
    [
        jail.chroot_for(burrow_vmm::Hypervisor::CloudHypervisor, id),
        data_dir.join("sandboxes").join(id),
    ]
    .into_iter()
    .map(|dir| dir.join(burrow_vmm::DISPLAY_UDS))
    .find(|socket| socket.exists())
    .ok_or_else(|| anyhow::anyhow!("{id} has no display on this node"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_png_has_its_chunks_and_checksums() {
        assert_eq!(crc32(b"IEND"), 0xae42_6082);
        let png = png(2, 1, &[255, 0, 0, 0, 255, 0]);
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(&png[16..24], &[0, 0, 0, 2, 0, 0, 0, 1]);
        assert_eq!(&png[png.len() - 12..], b"\0\0\0\0IEND\xae\x42\x60\x82");
    }

    #[test]
    fn a_sandbox_id_is_never_a_path() {
        let base = Path::new("/nonexistent");
        assert!(find_socket("../etc", base, base).is_err());
        assert!(find_socket("sbx_1", base, base).is_err());
    }
}
