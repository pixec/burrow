// Extended attributes, read from an inode's spare space and its attribute
// block. Added for Burrow; not part of the upstream crate.

use crate::Ext4;
use crate::checksum::Checksum;
use crate::error::{CorruptKind, Ext4Error};
use crate::features::ReadOnlyCompatibleFeatures;
use crate::inode::{Inode, InodeIndex};
use crate::path::Path;
use crate::resolve::FollowSymlinks;
use crate::util::{read_u16le, read_u32le, usize_from_u32};
use alloc::vec;
use alloc::vec::Vec;

const MAGIC: u32 = 0xEA02_0000;
const ENTRY_HEADER: usize = 16;
const BLOCK_HEADER: usize = 32;

/// One extended attribute: its full name, prefix included, and value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Xattr {
    /// The name, with its namespace prefix such as `security.`.
    pub name: Vec<u8>,
    /// The value, as stored.
    pub value: Vec<u8>,
}

fn prefix(index: u8) -> Option<&'static [u8]> {
    Some(match index {
        1 => b"user.",
        2 => b"system.posix_acl_access",
        3 => b"system.posix_acl_default",
        4 => b"trusted.",
        6 => b"security.",
        7 => b"system.",
        8 => b"system.richacl",
        _ => return None,
    })
}

/// Parses the entries in `entries`, whose values are found at offsets
/// from the start of `values`.
fn parse(
    inode: InodeIndex,
    entries: &[u8],
    values: &[u8],
    out: &mut Vec<Xattr>,
) -> Result<(), Ext4Error> {
    let corrupt = || Ext4Error::from(CorruptKind::Xattr(inode));
    let mut at = 0;
    loop {
        let Some(header) = entries.get(at..at + ENTRY_HEADER) else {
            // A full region may end without the terminating zeroes.
            return match entries.len().saturating_sub(at) < 4 {
                true => Ok(()),
                false => Err(corrupt()),
            };
        };
        if read_u32le(header, 0) == 0 {
            return Ok(());
        }
        let name_len = usize::from(header[0]);
        let index = header[1];
        let value_offset = usize::from(read_u16le(header, 2));
        let value_inode = read_u32le(header, 4);
        let value_size = usize_from_u32(read_u32le(header, 8));
        if value_inode != 0 {
            return Err(corrupt());
        }
        let name = entries
            .get(at + ENTRY_HEADER..at + ENTRY_HEADER + name_len)
            .ok_or_else(corrupt)?;
        let value = values
            .get(
                value_offset
                    ..value_offset
                        .checked_add(value_size)
                        .ok_or_else(corrupt)?,
            )
            .ok_or_else(corrupt)?;
        if let Some(prefix) = prefix(index) {
            let mut full = Vec::with_capacity(prefix.len() + name.len());
            full.extend_from_slice(prefix);
            full.extend_from_slice(name);
            out.push(Xattr {
                name: full,
                value: value.to_vec(),
            });
        }
        at += (ENTRY_HEADER + name_len).next_multiple_of(4);
    }
}

impl Ext4 {
    /// Get the extended attributes of `path`, not following a symlink in
    /// its final component.
    pub fn xattrs<'p, P>(&self, path: P) -> Result<Vec<Xattr>, Ext4Error>
    where
        P: TryInto<Path<'p>>,
    {
        let path = path.try_into().map_err(|_| Ext4Error::MalformedPath)?;
        let (inode, _) = crate::resolve::resolve_path(
            self,
            path,
            FollowSymlinks::ExcludeFinalComponent,
        )?;
        self.inode_xattrs(&inode)
    }

    fn inode_xattrs(&self, inode: &Inode) -> Result<Vec<Xattr>, Ext4Error> {
        let mut out = Vec::new();
        let space = &inode.xattr_space;
        if space.len() >= 4 && read_u32le(space, 0) == MAGIC {
            parse(inode.index, &space[4..], &space[4..], &mut out)?;
        }
        if inode.xattr_block == 0 {
            return Ok(out);
        }
        let corrupt = || Ext4Error::from(CorruptKind::Xattr(inode.index));
        let mut block = vec![0; self.0.superblock.block_size.to_usize()];
        self.read_from_block(inode.xattr_block, 0, &mut block)?;
        if read_u32le(&block, 0) != MAGIC || read_u32le(&block, 8) != 1 {
            return Err(corrupt());
        }
        if self
            .0
            .superblock
            .read_only_compatible_features
            .contains(ReadOnlyCompatibleFeatures::METADATA_CHECKSUMS)
        {
            let expected = read_u32le(&block, 0x10);
            let mut checksum =
                Checksum::with_seed(self.0.superblock.checksum_seed);
            checksum.update(&inode.xattr_block.to_le_bytes());
            checksum.update(&block[..0x10]);
            checksum.update_u32_le(0);
            checksum.update(&block[0x14..]);
            if checksum.finalize() != expected {
                return Err(corrupt());
            }
        }
        parse(inode.index, &block[BLOCK_HEADER..], &block, &mut out)?;
        Ok(out)
    }
}
