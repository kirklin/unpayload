//! Mapping between a file holding deflate streams and its puffed form.
//!
//! Each deflate stream, given as a bit extent of the file, corresponds to a
//! puff, a byte extent of the puffed file. Bytes outside deflate streams are
//! kept as they are. A byte shared by the end of a deflate stream and the
//! following raw data appears in the puffed file shifted down so that only
//! the raw bits remain; a byte shared with the start of a deflate stream keeps
//! only its raw low bits.

use super::bits::{BitReader, BitWriter};
use super::huff::{Huffer, PuffReader};
use super::puff::{PuffWriter, Puffer};
use crate::error::{Error, Result, ensure};

#[derive(Clone, Copy)]
pub(super) struct Extent {
    pub offset: u64,
    pub length: u64,
}

impl Extent {
    fn end(self) -> u64 {
        self.offset.wrapping_add(self.length)
    }
}

fn corrupt(message: &'static str) -> Error {
    Error::patch("puffin", message)
}

fn check_layout(puff_size: u64, deflates: &[Extent], puffs: &[Extent]) -> Result<()> {
    ensure!(
        deflates.len() == puffs.len(),
        corrupt("deflate and puff lists differ in length")
    );
    if let Some(last) = puffs.last() {
        ensure!(puff_size >= last.end(), corrupt("puffs run past the puffed size"));
    }
    let ordered = |extents: &[Extent]| extents.windows(2).all(|w| w[0].end() <= w[1].offset);
    ensure!(
        ordered(deflates) && ordered(puffs),
        corrupt("deflates or puffs overlap")
    );
    Ok(())
}

/// Positions of a puffed stream, both appended with a zero-length sentinel at
/// its end.
struct Layout {
    deflates: Vec<Extent>,
    puffs: Vec<Extent>,
    /// First puff whose end lies after the start of the stream.
    first: usize,
    puff_pos: u64,
    deflate_bit_pos: u64,
    max_puff: u64,
}

impl Layout {
    fn new(puff_size: u64, deflates: &[Extent], puffs: &[Extent]) -> Result<Self> {
        check_layout(puff_size, deflates, puffs)?;
        let deflate_size = match (deflates.last(), puffs.last()) {
            (Some(deflate), Some(puff)) => (deflate.end() / 8).wrapping_add(puff_size).wrapping_sub(puff.end()),
            _ => puff_size,
        };
        let max_puff = puffs.iter().map(|p| p.length).max().unwrap_or(0);
        let mut deflates = deflates.to_vec();
        let mut puffs = puffs.to_vec();
        deflates.push(Extent {
            offset: deflate_size.wrapping_mul(8),
            length: 0,
        });
        puffs.push(Extent {
            offset: puff_size,
            length: 0,
        });
        let first = puffs[..puffs.len() - 1]
            .iter()
            .position(|p| p.end() > 0)
            .unwrap_or(puffs.len() - 1);
        let (puff_pos, mut deflate_bit_pos) = if puffs[first].offset > 0 {
            let back_track = puffs[first].offset;
            (
                0,
                deflates[first]
                    .offset
                    .div_ceil(8)
                    .wrapping_sub(back_track)
                    .wrapping_mul(8),
            )
        } else {
            (puffs[first].offset, deflates[first].offset)
        };
        if puffs[first].offset > 0 && first > 0 {
            deflate_bit_pos = deflate_bit_pos.max(deflates[first - 1].end());
        }
        Ok(Self {
            deflates,
            puffs,
            first,
            puff_pos,
            deflate_bit_pos,
            max_puff,
        })
    }
}

fn slice(data: &[u8], start: u64, len: u64) -> Result<&[u8]> {
    let start = usize::try_from(start).map_err(|_| corrupt("offset out of range"))?;
    let len = usize::try_from(len).map_err(|_| corrupt("length out of range"))?;
    start
        .checked_add(len)
        .and_then(|end| data.get(start..end))
        .ok_or(corrupt("reads past the end of the source"))
}

/// Produces the `puff_size` bytes of the puffed form of `src`.
pub(super) fn puff(src: &[u8], deflates: &[Extent], puffs: &[Extent], puff_size: u64) -> Result<Vec<u8>> {
    let Layout {
        deflates,
        puffs,
        first,
        mut puff_pos,
        mut deflate_bit_pos,
        max_puff,
    } = Layout::new(puff_size, deflates, puffs)?;
    let length = usize::try_from(puff_size).map_err(|_| corrupt("puffed size out of range"))?;
    let mut out = vec![0u8; length];
    let mut puff_buffer = vec![0u8; max_puff as usize + 1];
    let mut puffer = Puffer::default();
    let mut current = first;
    let mut skip = 0u64;
    let mut done = 0usize;
    while done < length {
        let deflate = deflates[current];
        let puff = puffs[current];
        if puff_pos < puff.offset {
            let start_byte = deflate_bit_pos / 8;
            let end_byte = deflate.offset.div_ceil(8);
            let count = ((length - done) as u64).min(end_byte.wrapping_sub(start_byte));
            ensure!(count >= 1, corrupt("raw bytes between deflates are inconsistent"));
            let chunk = &mut out[done..done + count as usize];
            chunk.copy_from_slice(slice(src, start_byte, count)?);
            if (start_byte + count) * 8 > deflate.offset {
                chunk[count as usize - 1] &= ((1u32 << (deflate.offset & 7)) - 1) as u8;
            }
            if start_byte * 8 < deflate_bit_pos {
                chunk[0] >>= deflate_bit_pos & 7;
            }
            deflate_bit_pos -= deflate_bit_pos & 7;
            deflate_bit_pos += count * 8;
            deflate_bit_pos = deflate_bit_pos.min(deflate.offset);
            done += count as usize;
            puff_pos += count;
            ensure!(puff_pos <= puff.offset, corrupt("raw bytes run into a puff"));
        } else {
            let start_byte = deflate.offset / 8;
            let end_byte = (deflate.offset + deflate.length).div_ceil(8);
            let bytes = slice(src, start_byte, end_byte - start_byte)?;
            let mut reader = BitReader::new(bytes);
            let skipped = (deflate.offset & 7) as usize;
            ensure!(reader.cache_bits(skipped), corrupt("deflate starts past the end"));
            reader.drop_bits(skipped);
            let target = &mut puff_buffer[..puff.length as usize];
            let mut writer = PuffWriter::new(target);
            ensure!(
                puffer.puff_deflate(&mut reader, &mut writer),
                corrupt("cannot puff a source deflate stream")
            );
            ensure!(
                reader.offset() == bytes.len() && writer.size() as u64 == puff.length,
                corrupt("source deflate stream does not match its recorded extents")
            );
            let count = ((length - done) as u64).min(puff.length - skip);
            out[done..done + count as usize].copy_from_slice(&puff_buffer[skip as usize..(skip + count) as usize]);
            skip += count;
            done += count as usize;
            if puff_pos + skip == puff.end() {
                puff_pos += skip;
                skip = 0;
                deflate_bit_pos = deflate.end();
                current += 1;
                if current == puffs.len() {
                    break;
                }
            }
        }
    }
    ensure!(done == length, corrupt("puffed stream is shorter than recorded"));
    Ok(out)
}

/// Converts `puffed` back into deflate form, sending the bytes to `out`.
pub(super) fn huff(
    puffed: &[u8],
    deflates: &[Extent],
    puffs: &[Extent],
    puff_size: u64,
    out: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let Layout {
        deflates,
        puffs,
        first,
        mut puff_pos,
        mut deflate_bit_pos,
        max_puff,
    } = Layout::new(puff_size, deflates, puffs)?;
    let extra_byte = |current: usize| -> usize {
        if current + 1 == deflates.len() {
            return 0;
        }
        let end_bit = deflates[current].end();
        usize::from(end_bit & 7 != 0 && (end_bit + 7) & !7 <= deflates[current + 1].offset)
    };
    let mut puff_buffer = vec![0u8; max_puff as usize + 1];
    let mut deflate_buffer = Vec::new();
    let mut huffer = Huffer::default();
    let mut current = first;
    let mut extra = extra_byte(current);
    let mut skip = 0usize;
    let mut last_byte = 0u8;
    let mut done = 0usize;
    let length = puffed.len();
    while done < length {
        let deflate = deflates[current];
        let puff = puffs[current];
        if deflate_bit_pos < deflate.offset & !7 {
            ensure!(deflate_bit_pos & 7 == 0, corrupt("raw bytes start inside a byte"));
            let count = (deflate.offset / 8 - deflate_bit_pos / 8).min((length - done) as u64) as usize;
            out(&puffed[done..done + count])?;
            done += count;
            puff_pos += count as u64;
            deflate_bit_pos += count as u64 * 8;
            continue;
        }
        if deflate_bit_pos < deflate.offset {
            last_byte |= puffed[done] << (deflate_bit_pos & 7);
            done += 1;
            skip = 0;
            deflate_bit_pos = deflate.offset;
            puff_pos += 1;
            ensure!(
                puff_pos == puff.offset,
                corrupt("raw bits before a deflate are inconsistent")
            );
        }
        let wanted = puff.length as usize + extra;
        let count = (length - done).min(wanted - skip);
        ensure!(
            puff_buffer.len() >= skip + count,
            corrupt("puff is larger than recorded")
        );
        puff_buffer[skip..skip + count].copy_from_slice(&puffed[done..done + count]);
        skip += count;
        done += count;
        if skip != wanted {
            continue;
        }
        let start_byte = deflate.offset / 8;
        let end_byte = (deflate.offset + deflate.length).div_ceil(8);
        let mut size = (end_byte - start_byte) as usize;
        deflate_buffer.clear();
        deflate_buffer.resize(size, 0);
        let mut writer = BitWriter::new(&mut deflate_buffer);
        ensure!(
            writer.write_bits((deflate.offset & 7) as usize, u32::from(last_byte)),
            corrupt("deflate stream is larger than recorded")
        );
        last_byte = 0;
        let mut reader = PuffReader::new(&puff_buffer[..puff.length as usize]);
        ensure!(
            huffer.huff_deflate(&mut reader, &mut writer),
            corrupt("cannot rebuild a deflate stream")
        );
        ensure!(
            writer.size() == size && reader.bytes_left() == 0,
            corrupt("rebuilt deflate stream does not match its recorded extents")
        );
        deflate_bit_pos = deflate.end();
        if extra == 1 {
            ensure!(size > 0, corrupt("empty deflate stream"));
            deflate_buffer[size - 1] |= puff_buffer[puff.length as usize] << (deflate_bit_pos & 7);
            deflate_bit_pos = (deflate_bit_pos + 7) & !7;
        } else if deflate_bit_pos & 7 != 0 {
            ensure!(size > 0, corrupt("empty deflate stream"));
            last_byte = deflate_buffer[size - 1];
            size -= 1;
        }
        out(&deflate_buffer[..size])?;
        puff_pos += skip as u64;
        skip = 0;
        current += 1;
        if current == puffs.len() {
            break;
        }
        extra = extra_byte(current);
    }
    ensure!(done == length, corrupt("puffed stream continues past the last puff"));
    Ok(())
}
