//! virtio-gpu 2D with one scanout.
//!
//! [`Gpu`] holds the device's state and answers the control and cursor
//! queues' requests. It keeps no copy of a resource's pixels: they are in the
//! guest's backing pages, which a snapshot of guest memory already holds.
//! Only while a host client is subscribed does it keep a shadow of the
//! scanned-out frame, a [`Surface`], which transfers update and flushes
//! report as damage.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{GuestMemory, Rect, edid};

/// The device feature bits it offers beyond the transport's own.
pub const F_EDID: u64 = 1;
/// `events_read`: the display configuration changed.
pub const EVENT_DISPLAY: u32 = 1;
/// The device configuration space: `events_read`, `events_clear`,
/// `num_scanouts` and `num_capsets`.
pub const CONFIG_SIZE: usize = 16;

/// The control queue, then the cursor queue.
pub const QUEUES: usize = 2;

/// The most a guest may declare: per resource, in all, and in backing entries.
pub const MAX_RESOURCE_DIM: u32 = 8192;
pub const MAX_RESOURCES: usize = 64;
pub const MAX_RESOURCE_BYTES: u64 = 256 << 20;
pub const MAX_BACKING_ENTRIES: usize = 1 << 18;
/// The longest request read off the control queue. An attach of the most
/// entries one request may carry fits.
pub const MAX_REQUEST: usize = HDR + 8 + (1 << 16) * 16;

const BPP: u32 = 4;
const CURSOR_DIM: u32 = 64;
const HDR: usize = 24;
const FLAG_FENCE: u32 = 1;
const STATE_VERSION: u32 = 1;

mod cmd {
    pub const GET_DISPLAY_INFO: u32 = 0x0100;
    pub const RESOURCE_CREATE_2D: u32 = 0x0101;
    pub const RESOURCE_UNREF: u32 = 0x0102;
    pub const SET_SCANOUT: u32 = 0x0103;
    pub const RESOURCE_FLUSH: u32 = 0x0104;
    pub const TRANSFER_TO_HOST_2D: u32 = 0x0105;
    pub const RESOURCE_ATTACH_BACKING: u32 = 0x0106;
    pub const RESOURCE_DETACH_BACKING: u32 = 0x0107;
    pub const GET_EDID: u32 = 0x010a;
    pub const UPDATE_CURSOR: u32 = 0x0300;
    pub const MOVE_CURSOR: u32 = 0x0301;
}

mod resp {
    pub const OK_NODATA: u32 = 0x1100;
    pub const OK_DISPLAY_INFO: u32 = 0x1101;
    pub const OK_EDID: u32 = 0x1104;
    pub const ERR_UNSPEC: u32 = 0x1200;
    pub const ERR_OUT_OF_MEMORY: u32 = 0x1201;
    pub const ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
    pub const ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
    pub const ERR_INVALID_PARAMETER: u32 = 0x1205;
}

/// The pixel formats a 2D resource may have, all four bytes a pixel, named
/// by byte order in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum Format {
    B8G8R8A8 = 1,
    B8G8R8X8 = 2,
    A8R8G8B8 = 3,
    X8R8G8B8 = 4,
    R8G8B8A8 = 67,
    X8B8G8R8 = 68,
    A8B8G8R8 = 121,
    R8G8B8X8 = 134,
}

impl Format {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::B8G8R8A8,
            2 => Self::B8G8R8X8,
            3 => Self::A8R8G8B8,
            4 => Self::X8R8G8B8,
            67 => Self::R8G8B8A8,
            68 => Self::X8B8G8R8,
            121 => Self::A8B8G8R8,
            134 => Self::R8G8B8X8,
            _ => return None,
        })
    }

    /// Where red, green and blue sit within a pixel's four bytes.
    pub fn rgb_offsets(self) -> [usize; 3] {
        match self {
            Self::B8G8R8A8 | Self::B8G8R8X8 => [2, 1, 0],
            Self::A8R8G8B8 | Self::X8R8G8B8 => [1, 2, 3],
            Self::R8G8B8A8 | Self::R8G8B8X8 => [0, 1, 2],
            Self::X8B8G8R8 | Self::A8B8G8R8 => [3, 2, 1],
        }
    }
}

/// Host memory a subscribed client reads the frame from.
pub trait Surface: Send + Sized {
    /// A zeroed surface of `len` bytes.
    fn alloc(len: usize) -> std::io::Result<Self>;
    fn pixels(&mut self) -> &mut [u8];
}

/// A surface in ordinary memory, for tests and in-process consumers.
pub struct HeapSurface(pub Vec<u8>);

impl Surface for HeapSurface {
    fn alloc(len: usize) -> std::io::Result<Self> {
        Ok(Self(vec![0; len]))
    }

    fn pixels(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// How the shadow surface is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    /// Bytes from one row of the surface to the next.
    pub stride: u32,
    /// Bytes from the start of the surface to the visible frame's first pixel.
    pub offset: u32,
    pub format: Format,
}

/// What the device tells a subscribed client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// The surface was replaced; read it as this from now on.
    Mode(Mode),
    /// These parts of the frame changed, in frame coordinates.
    Damage(Vec<Rect>),
    /// Nothing is scanned out.
    Disabled,
    Cursor(CursorPosition),
    CursorImage(CursorImage),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorPosition {
    pub x: u32,
    pub y: u32,
    pub is_visible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorImage {
    pub hot_x: u32,
    pub hot_y: u32,
    /// 64 x 64 pixels in the cursor resource's format.
    pub pixels: Vec<u8>,
    pub format: Format,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Scanout {
    resource_id: u32,
    rect: Rect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Resource {
    format: Format,
    width: u32,
    height: u32,
    /// Guest physical address and length of each backing chunk, in order.
    backing: Vec<(u64, u32)>,
}

impl Resource {
    fn stride(&self) -> u32 {
        self.width * BPP
    }

    fn backing_len(&self) -> u64 {
        self.backing.iter().map(|(_, len)| u64::from(*len)).sum()
    }

    /// Reads `buf.len()` bytes at `offset` into the backing.
    fn read(&self, mem: &impl GuestMemory, mut offset: u64, buf: &mut [u8]) -> bool {
        let mut done = 0;
        for &(addr, len) in &self.backing {
            let len = u64::from(len);
            if offset >= len {
                offset -= len;
                continue;
            }
            let n = usize::try_from((len - offset).min((buf.len() - done) as u64)).unwrap_or(0);
            if mem.read(addr + offset, &mut buf[done..done + n]).is_err() {
                return false;
            }
            done += n;
            offset = 0;
            if done == buf.len() {
                return true;
            }
        }
        done == buf.len()
    }
}

/// The device metadata a snapshot carries: no pixels, which live in guest
/// memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuState {
    version: u32,
    width: u32,
    height: u32,
    events_read: u32,
    resources: BTreeMap<u32, Resource>,
    scanout: Option<Scanout>,
    cursor: CursorPosition,
    cursor_resource: u32,
    cursor_hot: (u32, u32),
}

#[derive(Debug, PartialEq, Eq)]
pub enum StateError {
    Version(u32),
    Invalid,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version(v) => write!(f, "unsupported display state format {v}"),
            Self::Invalid => write!(f, "the display state is inconsistent"),
        }
    }
}

impl std::error::Error for StateError {}

pub struct Gpu<S: Surface = HeapSurface> {
    width: u32,
    height: u32,
    events_read: u32,
    resources: BTreeMap<u32, Resource>,
    resource_bytes: u64,
    backing_entries: usize,
    scanout: Option<Scanout>,
    cursor: CursorPosition,
    cursor_resource: u32,
    cursor_hot: (u32, u32),
    is_subscribed: bool,
    shadow: Option<(S, Mode)>,
    /// Asked for by the host since the device last serviced it.
    pending: Pending,
    notices: VecDeque<Notice>,
}

#[derive(Default)]
struct Pending {
    subscribe: bool,
    config_changed: bool,
}

impl<S: Surface> Gpu<S> {
    /// A device whose display prefers `width` x `height`.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            events_read: 0,
            resources: BTreeMap::new(),
            resource_bytes: 0,
            backing_entries: 0,
            scanout: None,
            cursor: CursorPosition::default(),
            cursor_resource: 0,
            cursor_hot: (0, 0),
            is_subscribed: false,
            shadow: None,
            pending: Pending::default(),
            notices: VecDeque::new(),
        }
    }

    pub fn restore(state: GpuState) -> Result<Self, StateError> {
        if state.version != STATE_VERSION {
            return Err(StateError::Version(state.version));
        }
        let mut gpu = Self::new(state.width, state.height);
        for resource in state.resources.values() {
            gpu.resource_bytes += resource_bytes(resource.width, resource.height);
            gpu.backing_entries += resource.backing.len();
        }
        if gpu.resource_bytes > MAX_RESOURCE_BYTES
            || gpu.backing_entries > MAX_BACKING_ENTRIES
            || state.resources.len() > MAX_RESOURCES
        {
            return Err(StateError::Invalid);
        }
        if let Some(scanout) = &state.scanout {
            let fits = state
                .resources
                .get(&scanout.resource_id)
                .is_some_and(|r| scanout.rect.fits(r.width, r.height));
            if !fits {
                return Err(StateError::Invalid);
            }
        }
        gpu.events_read = state.events_read;
        gpu.resources = state.resources;
        gpu.scanout = state.scanout;
        gpu.cursor = state.cursor;
        gpu.cursor_resource = state.cursor_resource;
        gpu.cursor_hot = state.cursor_hot;
        Ok(gpu)
    }

    pub fn state(&self) -> GpuState {
        GpuState {
            version: STATE_VERSION,
            width: self.width,
            height: self.height,
            events_read: self.events_read,
            resources: self.resources.clone(),
            scanout: self.scanout,
            cursor: self.cursor,
            cursor_resource: self.cursor_resource,
            cursor_hot: self.cursor_hot,
        }
    }

    /// The device as a driver reset leaves it: the preferred mode and the
    /// subscription survive, everything the guest created does not.
    pub fn reset(&mut self) {
        let had_scanout = self.scanout.is_some();
        *self = Self {
            is_subscribed: self.is_subscribed,
            notices: std::mem::take(&mut self.notices),
            ..Self::new(self.width, self.height)
        };
        if had_scanout && self.is_subscribed {
            self.notify(Notice::Disabled);
        }
    }

    pub fn mode(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config = [0u8; CONFIG_SIZE];
        config[0..4].copy_from_slice(&self.events_read.to_le_bytes());
        config[8..12].copy_from_slice(&1u32.to_le_bytes());
        copy_from(&config, offset, data);
    }

    /// Only `events_clear` is writable.
    pub fn write_config(&mut self, offset: u64, data: &[u8]) {
        if offset == 4 && data.len() == 4 {
            let clear = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            self.events_read &= !clear;
        }
    }

    /// The host asks for a new preferred mode. The guest hears of it through
    /// a configuration change, raised the next time the device is serviced.
    pub fn resize(&mut self, width: u32, height: u32) {
        if (width, height) != (self.width, self.height) {
            self.width = width;
            self.height = height;
            self.events_read |= EVENT_DISPLAY;
            self.pending.config_changed = true;
        }
    }

    /// The host wants frames. Takes effect when the device is next serviced,
    /// which is where guest memory is at hand.
    pub fn request_subscribe(&mut self) {
        self.pending.subscribe = true;
    }

    pub fn unsubscribe(&mut self) {
        self.is_subscribed = false;
        self.pending.subscribe = false;
        self.shadow = None;
        self.notices.clear();
    }

    pub fn is_subscribed(&self) -> bool {
        self.is_subscribed
    }

    /// Does what the host asked for since the last call. Returns whether the
    /// guest must be sent a configuration change interrupt.
    pub fn service(&mut self, mem: &impl GuestMemory) -> bool {
        if std::mem::take(&mut self.pending.subscribe) {
            self.is_subscribed = true;
            self.shadow = None;
            self.present(mem);
            self.notify(Notice::Cursor(self.cursor));
        }
        std::mem::take(&mut self.pending.config_changed)
    }

    /// Whether a host request is waiting for [`Self::service`].
    pub fn is_service_pending(&self) -> bool {
        self.pending.subscribe || self.pending.config_changed
    }

    pub fn take_notices(&mut self) -> Vec<Notice> {
        self.notices.drain(..).collect()
    }

    pub fn has_notices(&self) -> bool {
        !self.notices.is_empty()
    }

    /// The shadow surface and how it is laid out, while subscribed and
    /// something is scanned out.
    pub fn surface(&self) -> Option<(&S, Mode)> {
        self.shadow.as_ref().map(|(s, m)| (s, *m))
    }

    /// Answers one control queue request, appending the response to
    /// `response`.
    pub fn process(&mut self, mem: &impl GuestMemory, request: &[u8], response: &mut Vec<u8>) {
        let Some(hdr) = Header::parse(request) else {
            Header::default().respond(resp::ERR_UNSPEC, response);
            return;
        };
        let body = &request[HDR..];
        match hdr.kind {
            cmd::GET_DISPLAY_INFO => {
                hdr.respond(resp::OK_DISPLAY_INFO, response);
                let mut modes = [0u8; 16 * 24];
                modes[8..12].copy_from_slice(&self.width.to_le_bytes());
                modes[12..16].copy_from_slice(&self.height.to_le_bytes());
                modes[16..20].copy_from_slice(&1u32.to_le_bytes());
                response.extend_from_slice(&modes);
            }
            cmd::GET_EDID => match words::<2>(body) {
                Some([0, _]) => {
                    hdr.respond(resp::OK_EDID, response);
                    response.extend_from_slice(&(edid::LEN as u32).to_le_bytes());
                    response.extend_from_slice(&[0; 4]);
                    let mut block = [0u8; 1024];
                    block[..edid::LEN].copy_from_slice(&edid::generate(self.width, self.height));
                    response.extend_from_slice(&block);
                }
                Some(_) => hdr.respond(resp::ERR_INVALID_SCANOUT_ID, response),
                None => hdr.respond(resp::ERR_INVALID_PARAMETER, response),
            },
            kind => {
                let code = self.command(mem, kind, body);
                hdr.respond(code, response);
            }
        }
    }

    fn command(&mut self, mem: &impl GuestMemory, kind: u32, body: &[u8]) -> u32 {
        match kind {
            cmd::RESOURCE_CREATE_2D => match words::<4>(body) {
                Some([id, format, width, height]) => self.create(id, format, width, height),
                None => resp::ERR_INVALID_PARAMETER,
            },
            cmd::RESOURCE_UNREF => match words::<1>(body) {
                Some([id]) => self.unref(id),
                None => resp::ERR_INVALID_PARAMETER,
            },
            cmd::RESOURCE_ATTACH_BACKING => match words::<2>(body) {
                Some([id, count]) => self.attach(id, count, &body[8..]),
                None => resp::ERR_INVALID_PARAMETER,
            },
            cmd::RESOURCE_DETACH_BACKING => match words::<1>(body) {
                Some([id]) => self.detach(id),
                None => resp::ERR_INVALID_PARAMETER,
            },
            cmd::SET_SCANOUT => match words::<6>(body) {
                Some([x, y, w, h, scanout, id]) => {
                    self.set_scanout(mem, Rect::new(x, y, w, h), scanout, id)
                }
                None => resp::ERR_INVALID_PARAMETER,
            },
            cmd::TRANSFER_TO_HOST_2D => match words::<8>(body) {
                Some([x, y, w, h, lo, hi, id, _]) => self.transfer(
                    mem,
                    Rect::new(x, y, w, h),
                    u64::from(lo) | (u64::from(hi) << 32),
                    id,
                ),
                None => resp::ERR_INVALID_PARAMETER,
            },
            cmd::RESOURCE_FLUSH => match words::<5>(body) {
                Some([x, y, w, h, id]) => self.flush(Rect::new(x, y, w, h), id),
                None => resp::ERR_INVALID_PARAMETER,
            },
            _ => resp::ERR_UNSPEC,
        }
    }

    /// Answers one cursor queue request, which has no response.
    pub fn process_cursor(&mut self, mem: &impl GuestMemory, request: &[u8]) {
        let Some(hdr) = Header::parse(request) else {
            return;
        };
        // scanout, x, y, padding, resource, hot_x, hot_y.
        let Some([scanout, x, y, _, id, hot_x, hot_y]) = words::<7>(&request[HDR..]) else {
            return;
        };
        if scanout != 0 {
            return;
        }
        if hdr.kind == cmd::UPDATE_CURSOR {
            self.cursor_resource = id;
            self.cursor_hot = (hot_x, hot_y);
            if self.is_subscribed
                && let Some(image) = self.cursor_image(mem)
            {
                self.notify(Notice::CursorImage(image));
            }
        } else if hdr.kind != cmd::MOVE_CURSOR {
            return;
        }
        self.cursor = CursorPosition {
            x,
            y,
            is_visible: self.cursor_resource != 0,
        };
        if self.is_subscribed {
            self.notify(Notice::Cursor(self.cursor));
        }
    }

    fn cursor_image(&self, mem: &impl GuestMemory) -> Option<CursorImage> {
        let resource = self.resources.get(&self.cursor_resource)?;
        if resource.width != CURSOR_DIM || resource.height != CURSOR_DIM {
            return None;
        }
        let mut pixels = vec![0u8; (CURSOR_DIM * CURSOR_DIM * BPP) as usize];
        resource.read(mem, 0, &mut pixels).then_some(CursorImage {
            hot_x: self.cursor_hot.0,
            hot_y: self.cursor_hot.1,
            pixels,
            format: resource.format,
        })
    }

    fn create(&mut self, id: u32, format: u32, width: u32, height: u32) -> u32 {
        let Some(format) = Format::from_u32(format) else {
            return resp::ERR_INVALID_PARAMETER;
        };
        if id == 0 || self.resources.contains_key(&id) {
            return resp::ERR_INVALID_RESOURCE_ID;
        }
        if width == 0 || height == 0 || width > MAX_RESOURCE_DIM || height > MAX_RESOURCE_DIM {
            return resp::ERR_INVALID_PARAMETER;
        }
        let bytes = resource_bytes(width, height);
        if self.resources.len() >= MAX_RESOURCES || self.resource_bytes + bytes > MAX_RESOURCE_BYTES
        {
            return resp::ERR_OUT_OF_MEMORY;
        }
        self.resource_bytes += bytes;
        self.resources.insert(
            id,
            Resource {
                format,
                width,
                height,
                backing: Vec::new(),
            },
        );
        resp::OK_NODATA
    }

    /// Freeing the scanned-out resource turns the scanout off first, as QEMU
    /// does: Windows' driver frees it before setting the next one.
    fn unref(&mut self, id: u32) -> u32 {
        let Some(resource) = self.resources.remove(&id) else {
            return resp::ERR_INVALID_RESOURCE_ID;
        };
        self.resource_bytes -= resource_bytes(resource.width, resource.height);
        self.backing_entries -= resource.backing.len();
        if self.scanout.is_some_and(|s| s.resource_id == id) {
            self.disable_scanout();
        }
        if self.cursor_resource == id {
            self.cursor_resource = 0;
        }
        resp::OK_NODATA
    }

    fn attach(&mut self, id: u32, count: u32, entries: &[u8]) -> u32 {
        let Some(resource) = self.resources.get_mut(&id) else {
            return resp::ERR_INVALID_RESOURCE_ID;
        };
        if !resource.backing.is_empty() {
            return resp::ERR_UNSPEC;
        }
        let count = count as usize;
        if count == 0 || entries.len() < count * 16 {
            return resp::ERR_INVALID_PARAMETER;
        }
        if self.backing_entries + count > MAX_BACKING_ENTRIES {
            return resp::ERR_OUT_OF_MEMORY;
        }
        let mut backing: Vec<(u64, u32)> = Vec::with_capacity(count);
        for entry in entries[..count * 16].as_chunks::<16>().0 {
            let addr = u64::from_le_bytes(entry[0..8].try_into().unwrap());
            let len = u32::from_le_bytes(entry[8..12].try_into().unwrap());
            if len == 0 || addr.checked_add(u64::from(len)).is_none() {
                return resp::ERR_INVALID_PARAMETER;
            }
            match backing.last_mut() {
                Some((last, last_len))
                    if *last + u64::from(*last_len) == addr
                        && last_len.checked_add(len).is_some() =>
                {
                    *last_len += len;
                }
                _ => backing.push((addr, len)),
            }
        }
        self.backing_entries += backing.len();
        resource.backing = backing;
        resp::OK_NODATA
    }

    fn detach(&mut self, id: u32) -> u32 {
        let Some(resource) = self.resources.get_mut(&id) else {
            return resp::ERR_INVALID_RESOURCE_ID;
        };
        if resource.backing.is_empty() {
            return resp::ERR_UNSPEC;
        }
        self.backing_entries -= resource.backing.len();
        resource.backing = Vec::new();
        resp::OK_NODATA
    }

    fn set_scanout(&mut self, mem: &impl GuestMemory, rect: Rect, scanout: u32, id: u32) -> u32 {
        if scanout != 0 {
            return resp::ERR_INVALID_SCANOUT_ID;
        }
        if id == 0 {
            self.disable_scanout();
            return resp::OK_NODATA;
        }
        let Some(resource) = self.resources.get(&id) else {
            return resp::ERR_INVALID_RESOURCE_ID;
        };
        if rect.is_empty() || !rect.fits(resource.width, resource.height) {
            return resp::ERR_INVALID_PARAMETER;
        }
        self.scanout = Some(Scanout {
            resource_id: id,
            rect,
        });
        if self.is_subscribed {
            self.present(mem);
        }
        resp::OK_NODATA
    }

    fn disable_scanout(&mut self) {
        if self.scanout.take().is_some() && self.is_subscribed {
            self.shadow = None;
            self.notify(Notice::Disabled);
        }
    }

    fn transfer(&mut self, mem: &impl GuestMemory, rect: Rect, offset: u64, id: u32) -> u32 {
        let Some(resource) = self.resources.get(&id) else {
            return resp::ERR_INVALID_RESOURCE_ID;
        };
        if !rect.fits(resource.width, resource.height) {
            return resp::ERR_INVALID_PARAMETER;
        }
        if rect.is_empty() {
            return resp::OK_NODATA;
        }
        let stride = u64::from(resource.stride());
        let row = u64::from(rect.width * BPP);
        let end = offset
            .checked_add(stride * u64::from(rect.height - 1))
            .and_then(|last| last.checked_add(row));
        if resource.backing.is_empty() || end.is_none_or(|end| end > resource.backing_len()) {
            return resp::ERR_INVALID_PARAMETER;
        }
        if self.scanout.is_none_or(|s| s.resource_id != id) {
            return resp::OK_NODATA;
        }
        let Some((surface, _)) = self.shadow.as_mut() else {
            return resp::OK_NODATA;
        };
        // The shadow mirrors the whole resource, so rows land where they are
        // in it.
        let pixels = surface.pixels();
        for h in 0..rect.height {
            let src = offset + stride * u64::from(h);
            let dst = (u64::from(rect.y + h) * stride + u64::from(rect.x * BPP)) as usize;
            if !resource.read(mem, src, &mut pixels[dst..dst + row as usize]) {
                return resp::ERR_UNSPEC;
            }
        }
        resp::OK_NODATA
    }

    fn flush(&mut self, rect: Rect, id: u32) -> u32 {
        let Some(resource) = self.resources.get(&id) else {
            return resp::ERR_INVALID_RESOURCE_ID;
        };
        if !rect.fits(resource.width, resource.height) {
            return resp::ERR_INVALID_PARAMETER;
        }
        if let Some(scanout) = self.scanout.filter(|s| s.resource_id == id)
            && self.shadow.is_some()
            && let Some(damage) = rect.intersect(&scanout.rect)
        {
            self.notify(Notice::Damage(vec![Rect::new(
                damage.x - scanout.rect.x,
                damage.y - scanout.rect.y,
                damage.width,
                damage.height,
            )]));
        }
        resp::OK_NODATA
    }

    /// Points the shadow at the scanout as it now is and gathers the whole
    /// frame into it from the guest's backing.
    fn present(&mut self, mem: &impl GuestMemory) {
        let Some(scanout) = self.scanout else {
            self.shadow = None;
            self.notify(Notice::Disabled);
            return;
        };
        let resource = &self.resources[&scanout.resource_id];
        let stride = resource.stride();
        let mode = Mode {
            width: scanout.rect.width,
            height: scanout.rect.height,
            stride,
            offset: scanout.rect.y * stride + scanout.rect.x * BPP,
            format: resource.format,
        };
        let len = (u64::from(stride) * u64::from(resource.height)) as usize;
        let is_reusable = self
            .shadow
            .as_mut()
            .is_some_and(|(s, m)| *m == mode && s.pixels().len() == len);
        if !is_reusable {
            self.shadow = S::alloc(len).ok().map(|surface| (surface, mode));
        }
        if let Some((surface, _)) = self.shadow.as_mut() {
            // Backing too short for the frame shows as black where it runs
            // out.
            let pixels = surface.pixels();
            let backing = resource.backing_len().min(len as u64) as usize;
            if !resource.read(mem, 0, &mut pixels[..backing]) {
                pixels.fill(0);
            }
        }
        match (&self.shadow, is_reusable) {
            (None, _) => self.notify(Notice::Disabled),
            (Some(_), false) => self.notify(Notice::Mode(mode)),
            (Some(_), true) => {}
        }
        if self.shadow.is_some() {
            self.notify(Notice::Damage(vec![Rect::new(
                0,
                0,
                mode.width,
                mode.height,
            )]));
        }
    }

    /// Queues a notice for the client. A new mode makes everything queued
    /// before it moot, and damage folds into the damage before it.
    fn notify(&mut self, notice: Notice) {
        match notice {
            Notice::Mode(_) | Notice::Disabled => self
                .notices
                .retain(|n| !matches!(n, Notice::Mode(_) | Notice::Damage(_) | Notice::Disabled)),
            Notice::Damage(ref rects) => {
                if let Some(Notice::Damage(queued)) = self.notices.back_mut() {
                    let merged = rects.iter().fold(queued[0], |acc, r| acc.union(r));
                    *queued = vec![merged];
                    return;
                }
            }
            Notice::Cursor(_) => self.notices.retain(|n| !matches!(n, Notice::Cursor(_))),
            Notice::CursorImage(_) => self
                .notices
                .retain(|n| !matches!(n, Notice::CursorImage(_))),
        }
        self.notices.push_back(notice);
    }
}

fn resource_bytes(width: u32, height: u32) -> u64 {
    u64::from(width) * u64::from(height) * u64::from(BPP)
}

fn copy_from(config: &[u8], offset: u64, data: &mut [u8]) {
    let Ok(offset) = usize::try_from(offset) else {
        return;
    };
    if let Some(src) = config.get(offset..offset.saturating_add(data.len())) {
        data.copy_from_slice(src);
    }
}

/// The first `N` little-endian words of `body`.
fn words<const N: usize>(body: &[u8]) -> Option<[u32; N]> {
    let bytes = body.get(..N * 4)?;
    let mut out = [0u32; N];
    for (word, chunk) in out.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    Some(out)
}

/// `virtio_gpu_ctrl_hdr`, which every request opens with and every response
/// echoes.
#[derive(Debug, Default, Clone, Copy)]
struct Header {
    kind: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    ring_idx: u8,
}

impl Header {
    fn parse(request: &[u8]) -> Option<Self> {
        let hdr = request.get(..HDR)?;
        Some(Self {
            kind: u32::from_le_bytes(hdr[0..4].try_into().unwrap()),
            flags: u32::from_le_bytes(hdr[4..8].try_into().unwrap()),
            fence_id: u64::from_le_bytes(hdr[8..16].try_into().unwrap()),
            ctx_id: u32::from_le_bytes(hdr[16..20].try_into().unwrap()),
            ring_idx: hdr[20],
        })
    }

    /// Every command completes before its response is written, so a fenced
    /// request's fence is signalled by the response itself.
    fn respond(&self, kind: u32, response: &mut Vec<u8>) {
        response.extend_from_slice(&kind.to_le_bytes());
        response.extend_from_slice(&(self.flags & FLAG_FENCE).to_le_bytes());
        response.extend_from_slice(&self.fence_id.to_le_bytes());
        response.extend_from_slice(&self.ctx_id.to_le_bytes());
        response.extend_from_slice(&[self.ring_idx, 0, 0, 0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryError;

    /// Guest memory as one flat buffer at guest address 0x1000.
    struct Flat(Vec<u8>);

    const BASE: u64 = 0x1000;

    impl GuestMemory for Flat {
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryError> {
            let start = addr.checked_sub(BASE).ok_or(MemoryError)? as usize;
            let src = self.0.get(start..start + buf.len()).ok_or(MemoryError)?;
            buf.copy_from_slice(src);
            Ok(())
        }
    }

    fn req(kind: u32, words: &[u32]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&kind.to_le_bytes());
        r.extend_from_slice(&[0; 20]);
        for w in words {
            r.extend_from_slice(&w.to_le_bytes());
        }
        r
    }

    fn attach_req(id: u32, entries: &[(u64, u32)]) -> Vec<u8> {
        let mut r = req(cmd::RESOURCE_ATTACH_BACKING, &[id, entries.len() as u32]);
        for (addr, len) in entries {
            r.extend_from_slice(&addr.to_le_bytes());
            r.extend_from_slice(&len.to_le_bytes());
            r.extend_from_slice(&[0; 4]);
        }
        r
    }

    fn run(gpu: &mut Gpu, mem: &Flat, request: &[u8]) -> (u32, Vec<u8>) {
        let mut out = Vec::new();
        gpu.process(mem, request, &mut out);
        (u32::from_le_bytes(out[0..4].try_into().unwrap()), out)
    }

    fn code(gpu: &mut Gpu, mem: &Flat, request: &[u8]) -> u32 {
        run(gpu, mem, request).0
    }

    /// A 4x2 resource 1, backed in two chunks, scanned out.
    fn scanned_out(mem: &Flat) -> Gpu {
        let mut gpu = Gpu::new(1024, 768);
        assert_eq!(
            code(&mut gpu, mem, &req(cmd::RESOURCE_CREATE_2D, &[1, 2, 4, 2])),
            resp::OK_NODATA
        );
        assert_eq!(
            code(
                &mut gpu,
                mem,
                &attach_req(1, &[(BASE, 16), (BASE + 0x100, 16)])
            ),
            resp::OK_NODATA
        );
        assert_eq!(
            code(&mut gpu, mem, &req(cmd::SET_SCANOUT, &[0, 0, 4, 2, 0, 1])),
            resp::OK_NODATA
        );
        gpu
    }

    fn memory() -> Flat {
        let mut bytes = vec![0u8; 0x200];
        for (i, b) in bytes[..16].iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in bytes[0x100..0x110].iter_mut().enumerate() {
            *b = 0x80 + i as u8;
        }
        Flat(bytes)
    }

    #[test]
    fn display_info_reports_one_enabled_scanout_at_the_mode() {
        let mem = memory();
        let mut gpu = Gpu::new(1280, 800);
        let (kind, out) = run(&mut gpu, &mem, &req(cmd::GET_DISPLAY_INFO, &[]));
        assert_eq!(kind, resp::OK_DISPLAY_INFO);
        assert_eq!(out.len(), HDR + 16 * 24);
        assert_eq!(words::<6>(&out[HDR..]).unwrap(), [0, 0, 1280, 800, 1, 0]);
        assert_eq!(words::<6>(&out[HDR + 24..]).unwrap(), [0; 6]);
    }

    #[test]
    fn edid_is_returned_for_scanout_zero_only() {
        let mem = memory();
        let mut gpu = Gpu::new(1920, 1080);
        let (kind, out) = run(&mut gpu, &mem, &req(cmd::GET_EDID, &[0, 0]));
        assert_eq!(kind, resp::OK_EDID);
        assert_eq!(out.len(), HDR + 8 + 1024);
        assert_eq!(words::<1>(&out[HDR..]).unwrap(), [128]);
        assert_eq!(&out[HDR + 8..HDR + 8 + 128], &edid::generate(1920, 1080));
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::GET_EDID, &[1, 0])),
            resp::ERR_INVALID_SCANOUT_ID
        );
    }

    #[test]
    fn a_fenced_request_is_answered_with_its_fence() {
        let mem = memory();
        let mut gpu = Gpu::new(800, 600);
        let mut r = req(cmd::RESOURCE_CREATE_2D, &[7, 2, 8, 8]);
        r[4..8].copy_from_slice(&FLAG_FENCE.to_le_bytes());
        r[8..16].copy_from_slice(&0xdead_beef_u64.to_le_bytes());
        let (kind, out) = run(&mut gpu, &mem, &r);
        assert_eq!(kind, resp::OK_NODATA);
        assert_eq!(out.len(), HDR);
        assert_eq!(
            u32::from_le_bytes(out[4..8].try_into().unwrap()),
            FLAG_FENCE
        );
        assert_eq!(
            u64::from_le_bytes(out[8..16].try_into().unwrap()),
            0xdead_beef
        );
    }

    #[test]
    fn malformed_and_unknown_requests_are_refused() {
        let mem = memory();
        let mut gpu = Gpu::new(800, 600);
        let mut out = Vec::new();
        gpu.process(&mem, &[0; 10], &mut out);
        assert_eq!(words::<1>(&out).unwrap(), [resp::ERR_UNSPEC]);
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_CREATE_2D, &[1, 2])),
            resp::ERR_INVALID_PARAMETER
        );
        assert_eq!(code(&mut gpu, &mem, &req(0x0108, &[])), resp::ERR_UNSPEC);
        assert_eq!(code(&mut gpu, &mem, &req(0x010c, &[])), resp::ERR_UNSPEC);
        assert_eq!(
            code(&mut gpu, &mem, &attach_req(1, &[(BASE, 16)])),
            resp::ERR_INVALID_RESOURCE_ID
        );
    }

    #[test]
    fn resources_are_capped_and_checked() {
        let mem = memory();
        let mut gpu = Gpu::new(800, 600);
        let create = |gpu: &mut Gpu, id, w, h| {
            code(gpu, &mem, &req(cmd::RESOURCE_CREATE_2D, &[id, 2, w, h]))
        };
        assert_eq!(create(&mut gpu, 0, 8, 8), resp::ERR_INVALID_RESOURCE_ID);
        assert_eq!(
            code(
                &mut gpu,
                &mem,
                &req(cmd::RESOURCE_CREATE_2D, &[1, 99, 8, 8])
            ),
            resp::ERR_INVALID_PARAMETER
        );
        assert_eq!(create(&mut gpu, 1, 8193, 1), resp::ERR_INVALID_PARAMETER);
        assert_eq!(create(&mut gpu, 1, 0, 1), resp::ERR_INVALID_PARAMETER);
        assert_eq!(create(&mut gpu, 1, 8192, 8192), resp::OK_NODATA);
        assert_eq!(create(&mut gpu, 2, 1, 1), resp::ERR_OUT_OF_MEMORY);
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_UNREF, &[1])),
            resp::OK_NODATA
        );
        assert_eq!(create(&mut gpu, 1, 4096, 4096), resp::OK_NODATA);
        assert_eq!(create(&mut gpu, 1, 8, 8), resp::ERR_INVALID_RESOURCE_ID);
        for id in 2..=4 {
            assert_eq!(create(&mut gpu, id, 4096, 4096), resp::OK_NODATA);
        }
        assert_eq!(create(&mut gpu, 5, 1, 1), resp::ERR_OUT_OF_MEMORY);
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_UNREF, &[4])),
            resp::OK_NODATA
        );
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_UNREF, &[4])),
            resp::ERR_INVALID_RESOURCE_ID
        );
        for id in 5..5 + MAX_RESOURCES as u32 - 3 {
            assert_eq!(create(&mut gpu, id, 1, 1), resp::OK_NODATA);
        }
        assert_eq!(create(&mut gpu, 1000, 1, 1), resp::ERR_OUT_OF_MEMORY);
    }

    #[test]
    fn backing_is_validated_and_coalesced() {
        let mem = memory();
        let mut gpu = Gpu::new(800, 600);
        code(&mut gpu, &mem, &req(cmd::RESOURCE_CREATE_2D, &[1, 2, 4, 2]));
        assert_eq!(
            code(&mut gpu, &mem, &attach_req(1, &[])),
            resp::ERR_INVALID_PARAMETER
        );
        assert_eq!(
            code(&mut gpu, &mem, &attach_req(1, &[(u64::MAX, 2)])),
            resp::ERR_INVALID_PARAMETER
        );
        let mut short = attach_req(1, &[(BASE, 16)]);
        short[HDR + 4..HDR + 8].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(code(&mut gpu, &mem, &short), resp::ERR_INVALID_PARAMETER);
        assert_eq!(
            code(
                &mut gpu,
                &mem,
                &attach_req(1, &[(BASE, 8), (BASE + 8, 8), (BASE + 0x100, 16)])
            ),
            resp::OK_NODATA
        );
        assert_eq!(
            gpu.resources[&1].backing,
            vec![(BASE, 16), (BASE + 0x100, 16)]
        );
        assert_eq!(
            code(&mut gpu, &mem, &attach_req(1, &[(BASE, 16)])),
            resp::ERR_UNSPEC
        );
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_DETACH_BACKING, &[1])),
            resp::OK_NODATA
        );
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_DETACH_BACKING, &[1])),
            resp::ERR_UNSPEC
        );
        assert_eq!(gpu.backing_entries, 0);
    }

    #[test]
    fn scanouts_and_transfers_are_bounds_checked() {
        let mem = memory();
        let mut gpu = scanned_out(&mem);
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::SET_SCANOUT, &[0, 0, 4, 2, 1, 1])),
            resp::ERR_INVALID_SCANOUT_ID
        );
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::SET_SCANOUT, &[0, 0, 5, 2, 0, 1])),
            resp::ERR_INVALID_PARAMETER
        );
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::SET_SCANOUT, &[0, 0, 4, 2, 0, 9])),
            resp::ERR_INVALID_RESOURCE_ID
        );
        let transfer =
            |x, y, w, h, offset: u32| req(cmd::TRANSFER_TO_HOST_2D, &[x, y, w, h, offset, 0, 1, 0]);
        assert_eq!(
            code(&mut gpu, &mem, &transfer(0, 0, 4, 2, 0)),
            resp::OK_NODATA
        );
        assert_eq!(
            code(&mut gpu, &mem, &transfer(0, 0, 4, 3, 0)),
            resp::ERR_INVALID_PARAMETER
        );
        assert_eq!(
            code(&mut gpu, &mem, &transfer(0, 1, 4, 1, 17)),
            resp::ERR_INVALID_PARAMETER
        );
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_FLUSH, &[0, 0, 4, 2, 2])),
            resp::ERR_INVALID_RESOURCE_ID
        );
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_FLUSH, &[3, 0, 4, 2, 1])),
            resp::ERR_INVALID_PARAMETER
        );
    }

    #[test]
    fn without_a_subscriber_frames_cost_nothing() {
        let mem = memory();
        let mut gpu = scanned_out(&mem);
        code(
            &mut gpu,
            &mem,
            &req(cmd::TRANSFER_TO_HOST_2D, &[0, 0, 4, 2, 0, 0, 1, 0]),
        );
        code(&mut gpu, &mem, &req(cmd::RESOURCE_FLUSH, &[0, 0, 4, 2, 1]));
        assert!(gpu.surface().is_none());
        assert!(!gpu.has_notices());
    }

    #[test]
    fn a_subscriber_gets_the_whole_frame_then_damage() {
        let mut mem = memory();
        let mut gpu = scanned_out(&mem);
        gpu.request_subscribe();
        assert!(gpu.is_service_pending());
        assert!(!gpu.service(&mem));
        let mode = Mode {
            width: 4,
            height: 2,
            stride: 16,
            offset: 0,
            format: Format::B8G8R8X8,
        };
        assert_eq!(
            gpu.take_notices(),
            vec![
                Notice::Mode(mode),
                Notice::Damage(vec![Rect::new(0, 0, 4, 2)]),
                Notice::Cursor(CursorPosition::default()),
            ]
        );
        let (surface, _) = gpu.surface().unwrap();
        assert_eq!(&surface.0[..16], &(0..16).collect::<Vec<u8>>()[..]);
        assert_eq!(&surface.0[16..], &(0x80..0x90).collect::<Vec<u8>>()[..]);

        // Pixel (1, 1) changes in guest memory; only a transfer brings it in.
        mem.0[0x104..0x108].copy_from_slice(&[9, 9, 9, 9]);
        code(&mut gpu, &mem, &req(cmd::RESOURCE_FLUSH, &[1, 1, 1, 1, 1]));
        assert_eq!(
            &gpu.surface().unwrap().0.0[20..24],
            &[0x84, 0x85, 0x86, 0x87]
        );
        gpu.take_notices();
        code(
            &mut gpu,
            &mem,
            &req(cmd::TRANSFER_TO_HOST_2D, &[1, 1, 1, 1, 20, 0, 1, 0]),
        );
        code(&mut gpu, &mem, &req(cmd::RESOURCE_FLUSH, &[1, 1, 1, 1, 1]));
        code(&mut gpu, &mem, &req(cmd::RESOURCE_FLUSH, &[3, 0, 1, 1, 1]));
        assert_eq!(&gpu.surface().unwrap().0.0[20..24], &[9, 9, 9, 9]);
        assert_eq!(
            gpu.take_notices(),
            vec![Notice::Damage(vec![Rect::new(1, 0, 3, 2)])]
        );

        gpu.unsubscribe();
        assert!(gpu.surface().is_none());
    }

    #[test]
    fn freeing_the_scanned_out_resource_disables_the_scanout() {
        let mem = memory();
        let mut gpu = scanned_out(&mem);
        gpu.request_subscribe();
        gpu.service(&mem);
        gpu.take_notices();
        assert_eq!(
            code(&mut gpu, &mem, &req(cmd::RESOURCE_UNREF, &[1])),
            resp::OK_NODATA
        );
        assert_eq!(gpu.take_notices(), vec![Notice::Disabled]);
        assert!(gpu.surface().is_none());
        assert_eq!(gpu.resource_bytes, 0);
        assert_eq!(gpu.backing_entries, 0);
    }

    #[test]
    fn a_resize_changes_the_mode_and_raises_a_display_event() {
        let mem = memory();
        let mut gpu = Gpu::new(1024, 768);
        gpu.resize(1024, 768);
        assert!(!gpu.service(&mem));
        gpu.resize(1920, 1080);
        assert!(gpu.service(&mem));
        let mut config = [0u8; CONFIG_SIZE];
        gpu.read_config(0, &mut config);
        assert_eq!(words::<4>(&config).unwrap(), [EVENT_DISPLAY, 0, 1, 0]);
        gpu.write_config(4, &EVENT_DISPLAY.to_le_bytes());
        gpu.read_config(0, &mut config[..4]);
        assert_eq!(words::<1>(&config).unwrap(), [0]);
        let (_, out) = run(&mut gpu, &mem, &req(cmd::GET_DISPLAY_INFO, &[]));
        assert_eq!(words::<4>(&out[HDR..]).unwrap(), [0, 0, 1920, 1080]);
    }

    #[test]
    fn the_cursor_is_reported_to_a_subscriber() {
        let mut mem = Flat(vec![0x55; 64 * 64 * 4 + 0x100]);
        mem.0[0] = 1;
        let mut gpu = Gpu::new(800, 600);
        gpu.request_subscribe();
        gpu.service(&mem);
        assert_eq!(gpu.take_notices()[0], Notice::Disabled);
        code(
            &mut gpu,
            &mem,
            &req(cmd::RESOURCE_CREATE_2D, &[5, 1, 64, 64]),
        );
        code(&mut gpu, &mem, &attach_req(5, &[(BASE, 64 * 64 * 4)]));
        gpu.process_cursor(&mem, &req(cmd::UPDATE_CURSOR, &[0, 10, 20, 0, 5, 3, 4]));
        let notices = gpu.take_notices();
        let Notice::CursorImage(image) = &notices[0] else {
            panic!("{notices:?}");
        };
        assert_eq!(
            (image.hot_x, image.hot_y, image.pixels.len()),
            (3, 4, 16384)
        );
        assert_eq!(image.pixels[0], 1);
        assert_eq!(
            notices[1],
            Notice::Cursor(CursorPosition {
                x: 10,
                y: 20,
                is_visible: true
            })
        );
        gpu.process_cursor(&mem, &req(cmd::MOVE_CURSOR, &[0, 11, 21, 0, 0, 0, 0]));
        gpu.process_cursor(&mem, &req(cmd::MOVE_CURSOR, &[0, 12, 22, 0, 0, 0, 0]));
        assert_eq!(
            gpu.take_notices(),
            vec![Notice::Cursor(CursorPosition {
                x: 12,
                y: 22,
                is_visible: true
            })]
        );
    }

    #[test]
    fn state_round_trips_and_a_restored_device_renders() {
        let mem = memory();
        let gpu = scanned_out(&mem);
        let json = serde_json::to_string(&gpu.state()).unwrap();
        assert!(json.len() < 1024, "{json}");
        let mut restored: Gpu = Gpu::restore(serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(restored.state(), gpu.state());
        assert_eq!(restored.resource_bytes, 32);
        restored.request_subscribe();
        restored.service(&mem);
        assert_eq!(&restored.surface().unwrap().0.0[..4], &[0, 1, 2, 3]);
    }

    #[test]
    fn a_state_of_another_format_or_inconsistent_is_refused() {
        let mem = memory();
        let mut state = scanned_out(&mem).state();
        state.version = 2;
        assert_eq!(
            Gpu::<HeapSurface>::restore(state.clone()).err(),
            Some(StateError::Version(2))
        );
        state.version = STATE_VERSION;
        state.scanout = Some(Scanout {
            resource_id: 9,
            rect: Rect::new(0, 0, 1, 1),
        });
        assert_eq!(
            Gpu::<HeapSurface>::restore(state).err(),
            Some(StateError::Invalid)
        );
    }

    #[test]
    fn a_reset_forgets_the_guest_but_keeps_the_mode() {
        let mem = memory();
        let mut gpu = scanned_out(&mem);
        gpu.resize(1280, 720);
        gpu.reset();
        assert_eq!(gpu.mode(), (1280, 720));
        assert!(gpu.resources.is_empty());
        assert_eq!(gpu.scanout, None);
    }
}
