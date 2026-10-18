//! Puffin patches: binary diffs of files holding deflate streams, computed
//! between their puffed forms.
//!
//! A patch is the magic `PUF1`, a 32-bit big-endian header length, a
//! [`PatchHeader`], and the raw patch. The header gives, for the source and
//! the destination, the bit extents of their deflate streams, the matching
//! byte extents in the puffed file (stored in bits) and the puffed size. The
//! raw patch turns the puffed source into the puffed destination; it is a
//! bsdiff patch, or a brotli-compressed zucchini patch.

mod bits;
mod huff;
mod huffman;
mod puff;
mod stream;

use prost::{Enumeration, Message};

use crate::error::{Error, Result, ensure};
use crate::operation::brotli_decode;
use crate::sink::Sink;
use crate::{bsdiff, zucchini};
use stream::Extent;

#[derive(Clone, Copy, PartialEq, Message)]
struct BitExtent {
    #[prost(uint64, tag = "1")]
    offset: u64,
    #[prost(uint64, tag = "2")]
    length: u64,
}

#[derive(Clone, PartialEq, Message)]
struct StreamInfo {
    #[prost(message, repeated, tag = "1")]
    deflates: Vec<BitExtent>,
    #[prost(message, repeated, tag = "2")]
    puffs: Vec<BitExtent>,
    #[prost(uint64, tag = "3")]
    puff_length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
enum PatchType {
    Bsdiff = 0,
    Zucchini = 1,
}

#[derive(Clone, PartialEq, Message)]
struct PatchHeader {
    #[prost(int32, tag = "1")]
    version: i32,
    #[prost(message, optional, tag = "2")]
    src: Option<StreamInfo>,
    #[prost(message, optional, tag = "3")]
    dst: Option<StreamInfo>,
    #[prost(enumeration = "PatchType", tag = "4")]
    r#type: i32,
}

const MAGIC: &[u8; 4] = b"PUF1";

fn corrupt(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::patch("puffin", message)
}

struct Layout {
    deflates: Vec<Extent>,
    puffs: Vec<Extent>,
    size: u64,
}

impl Layout {
    fn new(info: Option<StreamInfo>) -> Self {
        let info = info.unwrap_or_default();
        let extents = |extents: &[BitExtent], scale: u64| {
            extents
                .iter()
                .map(|e| Extent {
                    offset: e.offset / scale,
                    length: e.length / scale,
                })
                .collect()
        };
        Self {
            deflates: extents(&info.deflates, 1),
            puffs: extents(&info.puffs, 8),
            size: info.puff_length,
        }
    }
}

/// Applies a puffin `patch` to `src`, sending the new file to `out`.
pub(crate) fn apply(src: &[u8], patch: &[u8], out: &mut impl Sink) -> Result<()> {
    ensure!(patch.len() >= 8 && patch[..4] == *MAGIC, corrupt("missing PUF1 magic"));
    let header_len = u32::from_be_bytes(patch[4..8].try_into().unwrap()) as usize;
    ensure!(header_len <= patch.len() - 8, corrupt("header runs past the patch"));
    let header = PatchHeader::decode(&patch[8..8 + header_len]).map_err(|e| corrupt(format!("header: {e}")))?;
    let raw = &patch[8 + header_len..];
    let kind = PatchType::try_from(header.r#type)
        .map_err(|_| corrupt(format!("unknown inner patch type {}", header.r#type)))?;
    let src_layout = Layout::new(header.src);
    let dst_layout = Layout::new(header.dst);

    let puffed_src = stream::puff(src, &src_layout.deflates, &src_layout.puffs, src_layout.size)?;
    let puffed_dst = match kind {
        PatchType::Bsdiff => {
            let mut puffed = Vec::with_capacity(bsdiff::new_size(raw)?.min(1 << 30) as usize);
            bsdiff::apply(&puffed_src, raw, &mut puffed)?;
            puffed
        }
        PatchType::Zucchini => zucchini::apply(&puffed_src, &brotli_decode(raw)?)?,
    };
    drop(puffed_src);
    stream::huff(
        &puffed_dst,
        &dst_layout.deflates,
        &dst_layout.puffs,
        dst_layout.size,
        &mut |bytes| out.put(bytes),
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use zip::CompressionMethod::{Deflated, Stored};
    use zip::write::SimpleFileOptions;

    use super::bits::{BitReader, BitWriter};
    use super::huff::{Huffer, PuffReader};
    use super::puff::{PuffWriter, Puffer};
    use super::stream::{self, Extent};

    /// Literals, incompressible stretches, runs, and copies at distances up
    /// to the 32 KiB window and lengths past the longest match.
    fn sample(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed.max(1);
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            match next() % 4 {
                0 => data.extend((0..next() % 64).map(|_| next() as u8)),
                1 => data.extend_from_slice(b"the quick brown fox jumps over the lazy dog "),
                2 if data.len() > 300 => {
                    let back = (next() as usize % data.len().min(32768)).max(1);
                    for _ in 0..next() % 600 {
                        data.push(data[data.len() - back]);
                    }
                }
                _ => data.extend(std::iter::repeat_n(next() as u8, (next() % 600) as usize)),
            }
        }
        data.truncate(len);
        data
    }

    fn deflate(data: &[u8], level: u32) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Puffs the deflate stream filling `deflate`, which decompresses to at
    /// most `len` bytes.
    fn puff_stream(deflate: &[u8], len: usize) -> Vec<u8> {
        let mut puffed = vec![0u8; len * 2 + 4096];
        let mut writer = PuffWriter::new(&mut puffed);
        assert!(Puffer::default().puff_deflate(&mut BitReader::new(deflate), &mut writer));
        assert!(writer.flush());
        let size = writer.size();
        puffed.truncate(size);
        puffed
    }

    #[test]
    fn deflate_streams_survive_puffing() {
        for (len, seed) in [(0, 1), (10, 2), (5000, 3), (300_000, 4)] {
            let data = sample(len, seed);
            // Level 0 writes stored blocks, small inputs fixed codes, and the
            // rest dynamic codes.
            for level in [0, 1, 6, 9] {
                let deflate = deflate(&data, level);
                let puffed = puff_stream(&deflate, len);
                let mut out = vec![0u8; deflate.len()];
                let mut writer = BitWriter::new(&mut out);
                assert!(Huffer::default().huff_deflate(&mut PuffReader::new(&puffed), &mut writer));
                assert!(writer.flush());
                assert!(
                    writer.size() == deflate.len() && out == deflate,
                    "{len} bytes at level {level}"
                );
            }
        }
    }

    /// A zip archive: deflate streams of several sizes, among raw headers
    /// and a stored entry.
    #[test]
    fn files_with_deflate_streams_survive_puffing() {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let entries = [
            (20_000, Deflated),
            (3000, Stored),
            (100_000, Deflated),
            (0, Deflated),
            (777, Deflated),
        ];
        for (index, &(len, method)) in entries.iter().enumerate() {
            zip.start_file(
                format!("entry{index}"),
                SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
            zip.write_all(&sample(len, index as u32 + 7)).unwrap();
        }
        let file = zip.finish().unwrap().into_inner();

        let mut archive = zip::ZipArchive::new(Cursor::new(&file)).unwrap();
        let (mut deflates, mut puffs) = (Vec::new(), Vec::new());
        // Puffing changes the length of each stream, shifting what follows.
        let mut shift = 0i64;
        for index in 0..archive.len() {
            let entry = archive.by_index_raw(index).unwrap();
            if entry.compression() != Deflated {
                continue;
            }
            let start = entry.data_start().unwrap();
            let bytes = &file[start as usize..][..entry.compressed_size() as usize];
            let puffed = puff_stream(bytes, entry.size() as usize);
            deflates.push(Extent {
                offset: start * 8,
                length: bytes.len() as u64 * 8,
            });
            puffs.push(Extent {
                offset: (start as i64 + shift) as u64,
                length: puffed.len() as u64,
            });
            shift += puffed.len() as i64 - bytes.len() as i64;
        }
        assert_eq!(deflates.len(), 4);

        let puff_size = (file.len() as i64 + shift) as u64;
        let puffed = stream::puff(&file, &deflates, &puffs, puff_size).unwrap();
        let mut out = Vec::new();
        stream::huff(&puffed, &deflates, &puffs, puff_size, &mut |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
        assert!(out == file);
    }
}
