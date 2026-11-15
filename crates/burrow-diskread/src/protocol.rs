//! What a reader is asked and answers, as frames on its pipes.
//!
//! A frame is a tag byte, a little-endian `u32` length and that many bytes.
//! A request is one [`Tag::Request`] frame of JSON. A listing or a stat is
//! answered with one [`Tag::Reply`]; a read or a tar with [`Tag::Data`]
//! frames and then [`Tag::End`]. Any request can instead end in
//! [`Tag::Error`], data already sent included.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// The largest frame either side accepts.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    Request = 0,
    Reply = 1,
    Data = 2,
    End = 3,
    Error = 4,
}

impl Tag {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Request,
            1 => Self::Reply,
            2 => Self::Data,
            3 => Self::End,
            4 => Self::Error,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    ListDir {
        path: String,
    },
    Stat {
        path: String,
    },
    Read {
        path: String,
        offset: u64,
        len: u64,
    },
    /// The tree at `path` as a tar archive whose entries are named from
    /// `path`'s last component, so it unpacks into `path`'s parent.
    Tar {
        path: String,
        max_bytes: u64,
        max_entries: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Dir,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: Vec<u8>,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Time {
    pub secs: i64,
    pub nanos: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stat {
    pub kind: Kind,
    /// Permission bits, setuid, setgid and sticky included.
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub inode: u32,
    pub links: u16,
    pub atime: Time,
    pub mtime: Time,
    /// A symlink's target.
    pub target: Option<Vec<u8>>,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// What a tar held, sent with its [`Tag::End`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TarSummary {
    pub entries: u64,
    pub bytes: u64,
    /// Devices, fifos and sockets, which a tar of a tree leaves out.
    pub skipped: u64,
}

pub fn write_frame(out: &mut impl Write, tag: Tag, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(io::Error::other)?;
    out.write_all(&[tag as u8])?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(payload)
}

/// The next frame, or `None` at a clean end of input.
pub fn read_frame(input: &mut impl Read) -> io::Result<Option<(Tag, Vec<u8>)>> {
    let mut header = [0; 5];
    match input.read_exact(&mut header) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let tag = Tag::from_byte(header[0])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown frame"))?;
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame is too large",
        ));
    }
    let mut payload = vec![0; len];
    input.read_exact(&mut payload)?;
    Ok(Some((tag, payload)))
}

/// Writes whatever is written to it as [`Tag::Data`] frames.
pub struct DataFrames<W: Write> {
    out: W,
    buffer: Vec<u8>,
}

impl<W: Write> DataFrames<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            buffer: Vec::with_capacity(64 << 10),
        }
    }

    pub fn into_inner(mut self) -> io::Result<W> {
        self.flush_buffer()?;
        Ok(self.out)
    }

    fn flush_buffer(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            write_frame(&mut self.out, Tag::Data, &self.buffer)?;
            self.buffer.clear();
        }
        Ok(())
    }
}

impl<W: Write> Write for DataFrames<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let room = self.buffer.capacity() - self.buffer.len();
        let taken = bytes.len().min(room.max(1));
        self.buffer.extend_from_slice(&bytes[..taken]);
        if self.buffer.len() >= self.buffer.capacity() {
            self.flush_buffer()?;
        }
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer()?;
        self.out.flush()
    }
}
