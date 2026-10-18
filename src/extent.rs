//! Block extents as byte ranges, and writing data across them.

use std::ops::Range;

use crate::error::{Error, Result, ensure};
use crate::fsio::NamedFile;
use crate::metadata::Extent;

/// Byte ranges covered by `extents`, in order.
pub(crate) fn byte_ranges(extents: &[Extent], block_size: u64) -> Result<Vec<Range<u64>>> {
    extents
        .iter()
        .map(|extent| {
            let start = extent.start_block().checked_mul(block_size);
            let len = extent.num_blocks().checked_mul(block_size);
            start
                .zip(len)
                .and_then(|(start, len)| Some(start..start.checked_add(len)?))
                .ok_or(Error::invalid("extent out of the addressable range"))
        })
        .collect()
}

pub(crate) fn total_len(ranges: &[Range<u64>]) -> u64 {
    ranges.iter().map(|r| r.end - r.start).sum()
}

/// Writes a stream of bytes across destination ranges of a file, in order.
pub(crate) struct ExtentWriter<'a> {
    file: NamedFile<'a>,
    ranges: &'a [Range<u64>],
    index: usize,
    position: u64,
}

impl<'a> ExtentWriter<'a> {
    pub fn new(file: NamedFile<'a>, ranges: &'a [Range<u64>]) -> Self {
        Self {
            file,
            ranges,
            index: 0,
            position: ranges.first().map_or(0, |r| r.start),
        }
    }

    pub fn write(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let range = self.ranges.get(self.index).ok_or(Error::invalid(
                "operation produced more data than its destination extents hold",
            ))?;
            if self.position == range.end {
                self.index += 1;
                if let Some(next) = self.ranges.get(self.index) {
                    self.position = next.start;
                }
                continue;
            }
            let n = (range.end - self.position).min(data.len() as u64) as usize;
            self.file.write_all_at(&data[..n], self.position)?;
            self.position += n as u64;
            data = &data[n..];
        }
        Ok(())
    }

    /// Copies everything `reader` produces into the destination ranges.
    pub fn copy_from(&mut self, mut reader: impl std::io::Read) -> Result<()> {
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::invalid(format!("decompressing operation data: {e}"))),
            };
            self.write(&buf[..n])?;
        }
    }
}

/// Sorts `ranges` and checks that none overlaps another.
pub(crate) fn ensure_disjoint(ranges: &mut [Range<u64>]) -> Result<()> {
    ranges.sort_unstable_by_key(|r| r.start);
    for pair in ranges.windows(2) {
        ensure!(
            pair[0].end <= pair[1].start,
            Error::invalid(format!("destination extents overlap at byte {}", pair[1].start))
        );
    }
    Ok(())
}

/// Parts of `0..limit` not covered by the sorted, disjoint `covered` ranges.
pub(crate) fn gaps(covered: &[Range<u64>], limit: u64) -> Vec<Range<u64>> {
    let mut gaps = Vec::new();
    let mut cursor = 0;
    for range in covered {
        if range.start >= limit {
            break;
        }
        if range.start > cursor {
            gaps.push(cursor..range.start);
        }
        cursor = cursor.max(range.end);
    }
    if cursor < limit {
        gaps.push(cursor..limit);
    }
    gaps
}
