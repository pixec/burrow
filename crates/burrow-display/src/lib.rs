//! Burrow's display device: virtio-gpu 2D with one scanout, and virtio-input
//! keyboard and tablet devices, written once and run inside each VMM.
//!
//! The crate depends on no VMM. A VMM adapter hands [`gpu::Gpu`] the readable
//! bytes of each request and a view of guest memory, and writes back the
//! response it returns; it feeds [`input::Input`] descriptors the same way.
//! Frames leave over the display socket as a sealed memfd plus damage
//! notices, and input arrives on it ([`wire`]). [`server`] is the VMM's end of
//! that socket and [`client`] burrowd's.

pub mod edid;
pub mod gpu;
pub mod input;
pub mod wire;

#[cfg(unix)]
pub mod client;
#[cfg(unix)]
mod fdpass;
#[cfg(target_os = "linux")]
pub mod server;

/// The display socket's name in a VM's working directory.
pub const SOCKET: &str = "display.sock";

/// The smallest and largest mode a display may be given, in pixels. The upper
/// bound keeps every mode expressible in an EDID detailed timing.
pub const MIN_WIDTH: u32 = 640;
pub const MIN_HEIGHT: u32 = 480;
pub const MAX_WIDTH: u32 = 3840;
pub const MAX_HEIGHT: u32 = 2160;

/// Whether `width` x `height` is a mode a display may be given.
pub fn is_valid_mode(width: u32, height: u32) -> bool {
    (MIN_WIDTH..=MAX_WIDTH).contains(&width) && (MIN_HEIGHT..=MAX_HEIGHT).contains(&height)
}

/// Read access to guest physical memory, which the VMM provides.
pub trait GuestMemory {
    /// Fills `buf` from guest physical address `addr`, failing if any part of
    /// the range is not guest memory.
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryError;

/// A rectangle in pixels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// Whether the rectangle lies inside a `width` x `height` area, without
    /// overflow.
    pub fn fits(&self, width: u32, height: u32) -> bool {
        self.x
            .checked_add(self.width)
            .is_some_and(|right| right <= width)
            && self
                .y
                .checked_add(self.height)
                .is_some_and(|bottom| bottom <= height)
    }

    pub fn intersect(&self, other: &Rect) -> Option<Rect> {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let right = (u64::from(self.x) + u64::from(self.width))
            .min(u64::from(other.x) + u64::from(other.width));
        let bottom = (u64::from(self.y) + u64::from(self.height))
            .min(u64::from(other.y) + u64::from(other.height));
        let rect = Rect::new(
            x,
            y,
            u32::try_from(right.saturating_sub(u64::from(x))).ok()?,
            u32::try_from(bottom.saturating_sub(u64::from(y))).ok()?,
        );
        (!rect.is_empty()).then_some(rect)
    }

    pub fn union(&self, other: &Rect) -> Rect {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = (self.x + self.width).max(other.x + other.width);
        let bottom = (self.y + self.height).max(other.y + other.height);
        Rect::new(x, y, right - x, bottom - y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rectangles_clip_and_merge() {
        let a = Rect::new(0, 0, 100, 50);
        let b = Rect::new(50, 25, 100, 100);
        assert_eq!(a.intersect(&b), Some(Rect::new(50, 25, 50, 25)));
        assert_eq!(a.intersect(&Rect::new(100, 0, 10, 10)), None);
        assert_eq!(a.union(&b), Rect::new(0, 0, 150, 125));
        assert!(a.fits(100, 50));
        assert!(!a.fits(99, 50));
        assert!(!Rect::new(u32::MAX, 0, 2, 1).fits(u32::MAX, 1));
    }

    #[test]
    fn modes_are_bounded() {
        assert!(is_valid_mode(1280, 800));
        assert!(is_valid_mode(MAX_WIDTH, MAX_HEIGHT));
        assert!(!is_valid_mode(639, 480));
        assert!(!is_valid_mode(4096, 2160));
    }
}
