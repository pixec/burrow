//! The display socket protocol between a VMM's display device and burrowd.
//!
//! The device listens on [`crate::SOCKET`] in the VM's working directory and
//! burrowd connects. Each message is a little-endian `u32` length, then a tag
//! byte and the message body. The device opens with [`DeviceMessage::Hello`].
//! A [`DeviceMessage::Mode`] carries the frame's memfd as `SCM_RIGHTS` on the
//! same `sendmsg`: a sealed memfd holding the whole scanned-out resource,
//! which the host maps read-only and reads again after each
//! [`DeviceMessage::Damage`].
//!
//! Nothing is sent but `Hello` until the host subscribes. Input needs no
//! subscription. Tablet coordinates run from 0 to [`crate::input::TABLET_MAX`]
//! across the frame.

use crate::Rect;
use crate::gpu::{CursorImage, CursorPosition, Format, Mode};
use crate::input::InputEvent;

pub const VERSION: u16 = 1;
/// The longest message either side sends: a cursor image and its header.
pub const MAX_MESSAGE: usize = 32 * 1024;
const MAX_RECTS: usize = 256;
const MAX_EVENTS: usize = 512;
const CURSOR_BYTES: usize = 64 * 64 * 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceMessage {
    /// The protocol version, and the display's preferred mode.
    Hello {
        version: u16,
        width: u32,
        height: u32,
    },
    /// The frame's layout. Its memfd rides with this message.
    Mode(Mode),
    Damage(Vec<Rect>),
    Disabled,
    Cursor(CursorPosition),
    CursorImage(CursorImage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMessage {
    Subscribe,
    Unsubscribe,
    /// A new preferred mode, which the guest is told of and may adopt.
    Resize {
        width: u32,
        height: u32,
    },
    Input(Vec<InputEvent>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    TooLong(usize),
    UnknownTag(u8),
    Malformed(u8),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong(len) => write!(f, "a display message of {len} bytes is too long"),
            Self::UnknownTag(tag) => write!(f, "unknown display message {tag:#x}"),
            Self::Malformed(tag) => write!(f, "malformed display message {tag:#x}"),
        }
    }
}

impl std::error::Error for WireError {}

pub trait Message: Sized {
    fn tag(&self) -> u8;
    fn write_body(&self, out: &mut Vec<u8>);
    fn read(tag: u8, body: &mut Reader<'_>) -> Result<Self, WireError>;
}

/// One message as it goes on the wire, length first.
pub fn encode<M: Message>(message: &M) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, message.tag()];
    message.write_body(&mut out);
    let len = (out.len() - 4) as u32;
    out[..4].copy_from_slice(&len.to_le_bytes());
    out
}

/// Splits a byte stream back into messages.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole message, if one has arrived.
    pub fn decode<M: Message>(&mut self) -> Result<Option<M>, WireError> {
        let Some(len) = self.buf.get(..4) else {
            return Ok(None);
        };
        let len = u32::from_le_bytes(len.try_into().unwrap()) as usize;
        if len == 0 || len > MAX_MESSAGE {
            return Err(WireError::TooLong(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let tag = self.buf[4];
        let mut reader = Reader(&self.buf[5..4 + len]);
        let message = M::read(tag, &mut reader)?;
        if !reader.0.is_empty() {
            return Err(WireError::Malformed(tag));
        }
        self.buf.drain(..4 + len);
        Ok(Some(message))
    }
}

pub struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self, tag: u8) -> Result<[u8; N], WireError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(WireError::Malformed(tag))?;
        self.0 = rest;
        Ok(*head)
    }

    fn u8(&mut self, tag: u8) -> Result<u8, WireError> {
        Ok(self.take::<1>(tag)?[0])
    }

    fn u16(&mut self, tag: u8) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take(tag)?))
    }

    fn u32(&mut self, tag: u8) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take(tag)?))
    }

    fn bytes(&mut self, tag: u8, len: usize) -> Result<Vec<u8>, WireError> {
        if self.0.len() < len {
            return Err(WireError::Malformed(tag));
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head.to_vec())
    }

    fn format(&mut self, tag: u8) -> Result<Format, WireError> {
        Format::from_u32(self.u32(tag)?).ok_or(WireError::Malformed(tag))
    }
}

fn put(out: &mut Vec<u8>, words: &[u32]) {
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
}

mod tag {
    pub const HELLO: u8 = 0x01;
    pub const MODE: u8 = 0x02;
    pub const DAMAGE: u8 = 0x03;
    pub const DISABLED: u8 = 0x04;
    pub const CURSOR: u8 = 0x05;
    pub const CURSOR_IMAGE: u8 = 0x06;
    pub const SUBSCRIBE: u8 = 0x81;
    pub const UNSUBSCRIBE: u8 = 0x82;
    pub const RESIZE: u8 = 0x83;
    pub const INPUT: u8 = 0x84;
}

impl Message for DeviceMessage {
    fn tag(&self) -> u8 {
        match self {
            Self::Hello { .. } => tag::HELLO,
            Self::Mode(_) => tag::MODE,
            Self::Damage(_) => tag::DAMAGE,
            Self::Disabled => tag::DISABLED,
            Self::Cursor(_) => tag::CURSOR,
            Self::CursorImage(_) => tag::CURSOR_IMAGE,
        }
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::Hello {
                version,
                width,
                height,
            } => {
                out.extend_from_slice(&version.to_le_bytes());
                put(out, &[*width, *height]);
            }
            Self::Mode(m) => put(
                out,
                &[m.width, m.height, m.stride, m.offset, m.format as u32],
            ),
            Self::Damage(rects) => {
                let rects = &rects[..rects.len().min(MAX_RECTS)];
                out.extend_from_slice(&(rects.len() as u16).to_le_bytes());
                for r in rects {
                    put(out, &[r.x, r.y, r.width, r.height]);
                }
            }
            Self::Disabled => {}
            Self::Cursor(c) => {
                put(out, &[c.x, c.y]);
                out.push(u8::from(c.is_visible));
            }
            Self::CursorImage(c) => {
                put(out, &[c.hot_x, c.hot_y, c.format as u32]);
                out.extend_from_slice(&c.pixels);
            }
        }
    }

    fn read(tag: u8, r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(match tag {
            tag::HELLO => Self::Hello {
                version: r.u16(tag)?,
                width: r.u32(tag)?,
                height: r.u32(tag)?,
            },
            tag::MODE => Self::Mode(Mode {
                width: r.u32(tag)?,
                height: r.u32(tag)?,
                stride: r.u32(tag)?,
                offset: r.u32(tag)?,
                format: r.format(tag)?,
            }),
            tag::DAMAGE => {
                let n = usize::from(r.u16(tag)?);
                if n > MAX_RECTS {
                    return Err(WireError::Malformed(tag));
                }
                let mut rects = Vec::with_capacity(n);
                for _ in 0..n {
                    rects.push(Rect::new(
                        r.u32(tag)?,
                        r.u32(tag)?,
                        r.u32(tag)?,
                        r.u32(tag)?,
                    ));
                }
                Self::Damage(rects)
            }
            tag::DISABLED => Self::Disabled,
            tag::CURSOR => Self::Cursor(CursorPosition {
                x: r.u32(tag)?,
                y: r.u32(tag)?,
                is_visible: r.u8(tag)? != 0,
            }),
            tag::CURSOR_IMAGE => Self::CursorImage(CursorImage {
                hot_x: r.u32(tag)?,
                hot_y: r.u32(tag)?,
                format: r.format(tag)?,
                pixels: r.bytes(tag, CURSOR_BYTES)?,
            }),
            _ => return Err(WireError::UnknownTag(tag)),
        })
    }
}

impl Message for HostMessage {
    fn tag(&self) -> u8 {
        match self {
            Self::Subscribe => tag::SUBSCRIBE,
            Self::Unsubscribe => tag::UNSUBSCRIBE,
            Self::Resize { .. } => tag::RESIZE,
            Self::Input(_) => tag::INPUT,
        }
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::Subscribe | Self::Unsubscribe => {}
            Self::Resize { width, height } => put(out, &[*width, *height]),
            Self::Input(events) => {
                let events = &events[..events.len().min(MAX_EVENTS)];
                out.extend_from_slice(&(events.len() as u16).to_le_bytes());
                for e in events {
                    out.extend_from_slice(&e.to_bytes());
                }
            }
        }
    }

    fn read(tag: u8, r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(match tag {
            tag::SUBSCRIBE => Self::Subscribe,
            tag::UNSUBSCRIBE => Self::Unsubscribe,
            tag::RESIZE => Self::Resize {
                width: r.u32(tag)?,
                height: r.u32(tag)?,
            },
            tag::INPUT => {
                let n = usize::from(r.u16(tag)?);
                if n > MAX_EVENTS {
                    return Err(WireError::Malformed(tag));
                }
                let mut events = Vec::with_capacity(n);
                for _ in 0..n {
                    events.push(InputEvent::new(
                        r.u16(tag)?,
                        r.u16(tag)?,
                        r.u32(tag)? as i32,
                    ));
                }
                Self::Input(events)
            }
            _ => return Err(WireError::UnknownTag(tag)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{ABS_X, EV_ABS, EV_KEY};

    fn round_trip<M: Message + PartialEq + std::fmt::Debug>(message: M) {
        let mut d = Decoder::default();
        d.feed(&encode(&message));
        assert_eq!(d.decode::<M>().unwrap(), Some(message));
        assert_eq!(d.decode::<M>().unwrap(), None);
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(DeviceMessage::Hello {
            version: VERSION,
            width: 1280,
            height: 800,
        });
        round_trip(DeviceMessage::Mode(Mode {
            width: 1024,
            height: 768,
            stride: 4096,
            offset: 0,
            format: Format::B8G8R8X8,
        }));
        round_trip(DeviceMessage::Damage(vec![
            Rect::new(1, 2, 3, 4),
            Rect::new(5, 6, 7, 8),
        ]));
        round_trip(DeviceMessage::Disabled);
        round_trip(DeviceMessage::Cursor(CursorPosition {
            x: 3,
            y: 4,
            is_visible: true,
        }));
        round_trip(DeviceMessage::CursorImage(CursorImage {
            hot_x: 1,
            hot_y: 2,
            pixels: vec![7; CURSOR_BYTES],
            format: Format::B8G8R8A8,
        }));
        round_trip(HostMessage::Subscribe);
        round_trip(HostMessage::Unsubscribe);
        round_trip(HostMessage::Resize {
            width: 1920,
            height: 1080,
        });
        round_trip(HostMessage::Input(vec![
            InputEvent::new(EV_KEY, 30, 1),
            InputEvent::new(EV_ABS, ABS_X, -5),
        ]));
    }

    #[test]
    fn messages_arrive_in_pieces_and_back_to_back() {
        let mut bytes = encode(&HostMessage::Subscribe);
        bytes.extend(encode(&HostMessage::Resize {
            width: 800,
            height: 600,
        }));
        let mut d = Decoder::default();
        for chunk in bytes.chunks(3) {
            d.feed(chunk);
        }
        assert_eq!(
            d.decode::<HostMessage>().unwrap(),
            Some(HostMessage::Subscribe)
        );
        assert_eq!(
            d.decode::<HostMessage>().unwrap(),
            Some(HostMessage::Resize {
                width: 800,
                height: 600
            })
        );
        let mut d = Decoder::default();
        d.feed(&bytes[..6]);
        assert_eq!(
            d.decode::<HostMessage>().unwrap(),
            Some(HostMessage::Subscribe)
        );
        assert_eq!(d.decode::<HostMessage>().unwrap(), None);
    }

    #[test]
    fn bad_messages_are_refused() {
        let mut d = Decoder::default();
        d.feed(&(MAX_MESSAGE as u32 + 1).to_le_bytes());
        assert!(matches!(
            d.decode::<HostMessage>(),
            Err(WireError::TooLong(_))
        ));

        let mut d = Decoder::default();
        d.feed(&[1, 0, 0, 0, 0x7f]);
        assert_eq!(d.decode::<HostMessage>(), Err(WireError::UnknownTag(0x7f)));

        let mut d = Decoder::default();
        d.feed(&[3, 0, 0, 0, tag::RESIZE, 1, 2]);
        assert_eq!(
            d.decode::<HostMessage>(),
            Err(WireError::Malformed(tag::RESIZE))
        );

        let mut d = Decoder::default();
        d.feed(&[2, 0, 0, 0, tag::SUBSCRIBE, 0]);
        assert_eq!(
            d.decode::<HostMessage>(),
            Err(WireError::Malformed(tag::SUBSCRIBE))
        );

        let mut bad_format = encode(&DeviceMessage::Mode(Mode {
            width: 1,
            height: 1,
            stride: 4,
            offset: 0,
            format: Format::B8G8R8X8,
        }));
        let n = bad_format.len();
        bad_format[n - 4..].copy_from_slice(&9u32.to_le_bytes());
        let mut d = Decoder::default();
        d.feed(&bad_format);
        assert_eq!(
            d.decode::<DeviceMessage>(),
            Err(WireError::Malformed(tag::MODE))
        );

        let mut too_many = vec![0, 0, 0, 0, tag::INPUT];
        too_many.extend_from_slice(&(MAX_EVENTS as u16 + 1).to_le_bytes());
        too_many.extend(vec![0; (MAX_EVENTS + 1) * 8]);
        let len = (too_many.len() - 4) as u32;
        too_many[..4].copy_from_slice(&len.to_le_bytes());
        let mut d = Decoder::default();
        d.feed(&too_many);
        assert_eq!(
            d.decode::<HostMessage>(),
            Err(WireError::Malformed(tag::INPUT))
        );
    }
}
