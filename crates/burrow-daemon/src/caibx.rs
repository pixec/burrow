//! casync's blob index format (`.caibx`), which Burrow stores every image's
//! index in, so `casync extract` or `desync extract --digest sha256` can
//! rebuild an image from the object store without Burrow.
//!
//! An index is a header naming the feature flags and the chunk sizes, then a
//! table of the end offset and id of every chunk, then a tail pointing back at
//! the header. Burrow cuts at fixed boundaries, so the minimum, average and
//! maximum chunk sizes are all [`crate::chunks::CHUNK_SIZE`], and ids are
//! SHA-256, which casync and desync read from the absence of the
//! SHA-512/256 flag. A zero chunk is listed like any other, under the id of
//! that many zero bytes, and read back as a hole.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use sha2::{Digest as _, Sha256};

use crate::chunks::{CHUNK_SIZE, ImageIndex};

const CA_FORMAT_INDEX: u64 = 0x96824d9c7b129ff9;
const CA_FORMAT_TABLE: u64 = 0xe75b9e112f17417d;
const CA_FORMAT_TABLE_TAIL_MARKER: u64 = 0x4b4f050e5549ecd1;
const CA_FORMAT_SHA512_256: u64 = 0x2000000000000000;
/// The index object's size, and so the table's offset from the start.
const INDEX_SIZE: u64 = 48;
const ITEM_SIZE: usize = 40;

/// The id of `len` zero bytes, at most a chunk. Only a file's last chunk is
/// ever shorter than a whole one.
pub fn zero_id(len: u64) -> String {
    static WHOLE: OnceLock<String> = OnceLock::new();
    let hash = |len: u64| hex::encode(Sha256::digest(vec![0u8; len as usize]));
    if len == CHUNK_SIZE {
        return WHOLE.get_or_init(|| hash(len)).clone();
    }
    hash(len)
}

/// Refused for an index Burrow could not have written: chunks of another
/// size, or a digest that is not one.
pub fn encode(index: &ImageIndex) -> Result<Vec<u8>, String> {
    if index.chunk_size != CHUNK_SIZE {
        return Err(format!(
            "its chunk size is {}, not {CHUNK_SIZE}",
            index.chunk_size
        ));
    }
    let count = index.size.div_ceil(CHUNK_SIZE);
    if index.chunks.keys().next_back().is_some_and(|&n| n >= count) {
        return Err("it names a chunk past its end".into());
    }
    let mut out = Vec::with_capacity(INDEX_SIZE as usize + 16 + (count as usize + 1) * ITEM_SIZE);
    for word in [
        INDEX_SIZE,
        CA_FORMAT_INDEX,
        0,
        index.chunk_size,
        index.chunk_size,
        index.chunk_size,
        u64::MAX,
        CA_FORMAT_TABLE,
    ] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for n in 0..count {
        let (start, end) = index.range(n);
        let id = match index.chunks.get(&n) {
            Some(digest) => hex::decode(digest)
                .ok()
                .filter(|id| id.len() == 32)
                .ok_or_else(|| format!("{digest:?} is not a SHA-256 digest"))?,
            None => hex::decode(zero_id(end - start)).expect("a digest is hex"),
        };
        out.extend_from_slice(&end.to_le_bytes());
        out.extend_from_slice(&id);
    }
    let table = 16 + (count + 1) * ITEM_SIZE as u64;
    for word in [0, 0, INDEX_SIZE, table, CA_FORMAT_TABLE_TAIL_MARKER] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<ImageIndex, String> {
    let word = |at: usize| -> Result<u64, String> {
        bytes
            .get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
            .ok_or_else(|| "it ends early".to_string())
    };
    if word(0)? != INDEX_SIZE || word(8)? != CA_FORMAT_INDEX {
        return Err("it is not a casync index".into());
    }
    if word(16)? & CA_FORMAT_SHA512_256 != 0 {
        return Err("its chunk ids are SHA-512/256, not SHA-256".into());
    }
    let chunk_size = word(24)?;
    if word(32)? != chunk_size || word(40)? != chunk_size {
        return Err("its chunks are not cut at fixed boundaries".into());
    }
    if chunk_size != CHUNK_SIZE {
        return Err(format!("its chunk size is {chunk_size}, not {CHUNK_SIZE}"));
    }
    if word(48)? != u64::MAX || word(56)? != CA_FORMAT_TABLE {
        return Err("it has no chunk table".into());
    }
    let items = &bytes[64..];
    if items.len() < ITEM_SIZE || !items.len().is_multiple_of(ITEM_SIZE) {
        return Err("its table is cut short".into());
    }
    let count = items.len() / ITEM_SIZE - 1;
    let tail = &items[count * ITEM_SIZE..];
    let tail_word = |n: usize| u64::from_le_bytes(tail[n * 8..n * 8 + 8].try_into().expect("8"));
    if tail_word(0) != 0
        || tail_word(1) != 0
        || tail_word(2) != INDEX_SIZE
        || tail_word(3) != 16 + items.len() as u64
        || tail_word(4) != CA_FORMAT_TABLE_TAIL_MARKER
    {
        return Err("its table has no tail".into());
    }
    let mut chunks = BTreeMap::new();
    let mut size = 0;
    for (n, item) in items[..count * ITEM_SIZE]
        .as_chunks::<ITEM_SIZE>()
        .0
        .iter()
        .enumerate()
    {
        let n = n as u64;
        let end = u64::from_le_bytes(item[..8].try_into().expect("8 bytes"));
        let start = n * chunk_size;
        let is_last = n + 1 == count as u64;
        if end <= start || end > start + chunk_size || (!is_last && end != start + chunk_size) {
            return Err(format!("chunk {n} does not end on a fixed boundary"));
        }
        let id = hex::encode(&item[8..]);
        if id != zero_id(end - start) {
            chunks.insert(n, id);
        }
        size = end;
    }
    Ok(ImageIndex {
        size,
        chunk_size,
        chunks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> ImageIndex {
        ImageIndex {
            size: 3 * CHUNK_SIZE + 5,
            chunk_size: CHUNK_SIZE,
            chunks: [(0, "aa".repeat(32)), (2, "bb".repeat(32))].into(),
        }
    }

    /// Laid out as casync writes one: header, table header, an item per
    /// chunk with zero chunks under the zero id, and the tail.
    #[test]
    fn an_index_is_laid_out_as_casync_writes_it() {
        let bytes = encode(&index()).unwrap();
        assert_eq!(bytes.len(), 48 + 16 + 5 * 40);
        let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        assert_eq!(word(0), 48);
        assert_eq!(word(8), CA_FORMAT_INDEX);
        assert_eq!(word(16), 0, "SHA-256 ids, no SHA-512/256 flag");
        assert_eq!([word(24), word(32), word(40)], [CHUNK_SIZE; 3]);
        assert_eq!(word(48), u64::MAX);
        assert_eq!(word(64), CHUNK_SIZE);
        assert_eq!(hex::encode(&bytes[72..104]), "aa".repeat(32));
        assert_eq!(word(104), 2 * CHUNK_SIZE);
        assert_eq!(hex::encode(&bytes[112..144]), zero_id(CHUNK_SIZE));
        assert_eq!(word(184), 3 * CHUNK_SIZE + 5);
        assert_eq!(hex::encode(&bytes[192..224]), zero_id(5));
        assert_eq!(word(240), 48);
        assert_eq!(word(248), 16 + 5 * 40);
        assert_eq!(word(256), CA_FORMAT_TABLE_TAIL_MARKER);
        assert_eq!(
            zero_id(CHUNK_SIZE),
            hex::encode(Sha256::digest(vec![0u8; CHUNK_SIZE as usize]))
        );
    }

    #[test]
    fn an_index_round_trips_with_its_zero_chunks_as_holes() {
        let decoded = decode(&encode(&index()).unwrap()).unwrap();
        assert_eq!(decoded.size, 3 * CHUNK_SIZE + 5);
        assert_eq!(decoded.chunk_size, CHUNK_SIZE);
        assert_eq!(decoded.chunks, index().chunks);

        let empty = ImageIndex {
            size: 0,
            chunk_size: CHUNK_SIZE,
            chunks: BTreeMap::new(),
        };
        assert_eq!(decode(&encode(&empty).unwrap()).unwrap().size, 0);
    }

    #[test]
    fn an_index_burrow_cannot_read_is_refused() {
        let bytes = encode(&index()).unwrap();
        let mut sha512 = bytes.clone();
        sha512[16..24].copy_from_slice(&CA_FORMAT_SHA512_256.to_le_bytes());
        assert!(decode(&sha512).unwrap_err().contains("SHA-512/256"));
        let mut content_defined = bytes.clone();
        content_defined[24..32].copy_from_slice(&(CHUNK_SIZE / 4).to_le_bytes());
        assert!(decode(&content_defined).unwrap_err().contains("fixed"));
        assert!(decode(&bytes[..bytes.len() - 8]).is_err());
        assert!(decode(br#"{"size":0,"chunk_size":1048576,"chunks":{}}"#).is_err());
        let mut huge = bytes.clone();
        for at in [24, 32, 40] {
            huge[at..at + 8].copy_from_slice(&(1u64 << 62).to_le_bytes());
        }
        assert!(decode(&huge).unwrap_err().contains("chunk size"));
    }

    /// What Burrow could not have written is refused rather than encoded,
    /// so an old index naming garbage stops its migration, not the node.
    #[test]
    fn an_index_burrow_could_not_have_written_is_not_encoded() {
        let sized = |chunk_size| ImageIndex {
            chunk_size,
            ..index()
        };
        assert!(encode(&sized(0)).unwrap_err().contains("chunk size"));
        assert!(encode(&sized(1 << 40)).unwrap_err().contains("chunk size"));
        let mut bad = index();
        bad.chunks.insert(1, "not hex".into());
        assert!(encode(&bad).unwrap_err().contains("SHA-256"));
        let mut past = index();
        past.chunks.insert(9, "cc".repeat(32));
        assert!(encode(&past).unwrap_err().contains("past its end"));
    }
}
