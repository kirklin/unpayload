//! Reading zucchini ensemble patches.
//!
//! All integers are little-endian. A patch is a 24-byte header (magic `Zucc`,
//! major and minor version, old size and CRC-32, new size and CRC-32), an
//! element count, and the elements. Each element starts with a 22-byte header
//! (old offset and length, new offset and length, executable type, version),
//! followed by length-prefixed buffers: equivalences (source skips as signed
//! varints, destination skips and lengths as varints), extra data, raw deltas
//! (varint skips and signed bytes), reference deltas (signed varints) and,
//! per target pool, extra targets (varint skips).

use std::collections::BTreeMap;

use super::{Equivalence, ExeType, corrupt};
use crate::error::{Result, ensure};

const MAGIC: u32 = u32::from_le_bytes(*b"Zucc");
const MAJOR_VERSION: u16 = 1;
const NO_POOL: u8 = 0xFF;

/// A cursor over a byte buffer.
#[derive(Clone, Copy, Default)]
pub(super) struct Source<'a> {
    bytes: &'a [u8],
}

impl<'a> Source<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(n)?;
        self.bytes = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).map(|bytes| bytes.try_into().unwrap())
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// A buffer prefixed by its 32-bit length.
    fn buffer(&mut self) -> Option<Source<'a>> {
        let len = self.u32()? as usize;
        self.take(len).map(Source::new)
    }

    pub fn varuint(&mut self) -> Option<u32> {
        let mut value = 0u32;
        let mut shift = 0;
        for (i, &byte) in self.bytes.iter().enumerate() {
            value |= u32::from(byte & 0x7F).wrapping_shl(shift);
            if byte < 0x80 {
                self.bytes = &self.bytes[i + 1..];
                return Some(value);
            }
            shift += 7;
            if shift >= 32 {
                return None;
            }
        }
        None
    }

    pub fn varint(&mut self) -> Option<i32> {
        let raw = self.varuint()?;
        Some(if raw & 1 != 0 {
            !((raw >> 1) as i32)
        } else {
            (raw >> 1) as i32
        })
    }
}

pub(super) struct Header {
    pub old_size: u32,
    pub old_crc: u32,
    pub new_size: u32,
    pub new_crc: u32,
}

/// A region of the old and the new file patched as a unit.
#[derive(Clone, Copy)]
pub(super) struct ElementMatch {
    pub old_offset: u32,
    pub old_length: u32,
    pub new_offset: u32,
    pub new_length: u32,
    pub exe_type: ExeType,
}

#[derive(Clone, Default)]
pub(super) struct EquivalenceSource<'a> {
    src_skip: Source<'a>,
    dst_skip: Source<'a>,
    copy_count: Source<'a>,
    previous_src: u32,
    previous_dst: u32,
}

impl<'a> EquivalenceSource<'a> {
    fn parse(source: &mut Source<'a>) -> Option<Self> {
        Some(Self {
            src_skip: source.buffer()?,
            dst_skip: source.buffer()?,
            copy_count: source.buffer()?,
            ..Self::default()
        })
    }

    pub fn done(&self) -> bool {
        self.src_skip.is_empty() && self.dst_skip.is_empty() && self.copy_count.is_empty()
    }
}

impl Iterator for EquivalenceSource<'_> {
    type Item = Equivalence;

    fn next(&mut self) -> Option<Equivalence> {
        if self.src_skip.is_empty() || self.dst_skip.is_empty() || self.copy_count.is_empty() {
            return None;
        }
        let length = self.copy_count.varuint()?;
        let src_diff = self.src_skip.varint()?;
        let src_offset = u32::try_from(i64::from(self.previous_src) + i64::from(src_diff)).ok()?;
        self.previous_src = src_offset.checked_add(length)?;
        let dst_diff = self.dst_skip.varuint()?;
        let dst_offset = self.previous_dst.checked_add(dst_diff)?;
        self.previous_dst = dst_offset.checked_add(length)?;
        Some(Equivalence {
            src_offset,
            dst_offset,
            length,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RawDelta {
    pub copy_offset: u32,
    pub diff: i8,
}

#[derive(Clone, Default)]
pub(super) struct RawDeltaSource<'a> {
    skip: Source<'a>,
    diff: Source<'a>,
    compensation: u32,
}

impl RawDeltaSource<'_> {
    pub fn done(&self) -> bool {
        self.skip.is_empty() && self.diff.is_empty()
    }
}

impl Iterator for RawDeltaSource<'_> {
    type Item = RawDelta;

    fn next(&mut self) -> Option<RawDelta> {
        if self.skip.is_empty() || self.diff.is_empty() {
            return None;
        }
        let copy_offset = self.skip.varuint()?.checked_add(self.compensation)?;
        let diff = self.diff.u8()? as i8;
        if diff == 0 {
            return None;
        }
        self.compensation = copy_offset.checked_add(1)?;
        Some(RawDelta { copy_offset, diff })
    }
}

#[derive(Clone, Default)]
pub(super) struct ReferenceDeltaSource<'a> {
    source: Source<'a>,
}

impl ReferenceDeltaSource<'_> {
    pub fn done(&self) -> bool {
        self.source.is_empty()
    }
}

impl Iterator for ReferenceDeltaSource<'_> {
    type Item = i32;

    fn next(&mut self) -> Option<i32> {
        if self.source.is_empty() {
            return None;
        }
        self.source.varint()
    }
}

#[derive(Clone, Default)]
pub(super) struct TargetSource<'a> {
    source: Source<'a>,
    compensation: u32,
}

impl TargetSource<'_> {
    pub fn done(&self) -> bool {
        self.source.is_empty()
    }
}

impl Iterator for TargetSource<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.source.is_empty() {
            return None;
        }
        let target = self.source.varuint()?.checked_add(self.compensation)?;
        self.compensation = target.checked_add(1)?;
        Some(target)
    }
}

pub(super) struct ElementPatch<'a> {
    pub matched: ElementMatch,
    pub equivalences: EquivalenceSource<'a>,
    pub extra_data: Source<'a>,
    pub raw_deltas: RawDeltaSource<'a>,
    pub reference_deltas: ReferenceDeltaSource<'a>,
    pub extra_targets: BTreeMap<u8, TargetSource<'a>>,
}

impl<'a> ElementPatch<'a> {
    fn parse(source: &mut Source<'a>) -> Result<Self> {
        let truncated = || corrupt("element is truncated");
        let old_offset = source.u32().ok_or_else(truncated)?;
        let old_length = source.u32().ok_or_else(truncated)?;
        let new_offset = source.u32().ok_or_else(truncated)?;
        let new_length = source.u32().ok_or_else(truncated)?;
        let tag = source.u32().ok_or_else(truncated)?;
        let version = source.u16().ok_or_else(truncated)?;
        let exe_type = ExeType::from_tag(tag).ok_or_else(|| corrupt(format!("unknown executable type {tag:#x}")))?;
        ensure!(
            version == exe_type.version(),
            corrupt(format!("{exe_type:?} element version {version} is not supported"))
        );
        ensure!(old_length != 0 && new_length != 0, corrupt("empty element"));
        let matched = ElementMatch {
            old_offset,
            old_length,
            new_offset,
            new_length,
            exe_type,
        };
        let equivalences = EquivalenceSource::parse(source).ok_or_else(truncated)?;
        let extra_data = source.buffer().ok_or_else(truncated)?;
        validate_equivalences(&matched, &equivalences, &extra_data)?;
        let raw_deltas = RawDeltaSource {
            skip: source.buffer().ok_or_else(truncated)?,
            diff: source.buffer().ok_or_else(truncated)?,
            compensation: 0,
        };
        let reference_deltas = ReferenceDeltaSource {
            source: source.buffer().ok_or_else(truncated)?,
        };
        let pools = source.u32().ok_or_else(truncated)?;
        let mut extra_targets = BTreeMap::new();
        for _ in 0..pools {
            let pool = source.u8().ok_or_else(truncated)?;
            ensure!(pool != NO_POOL, corrupt("invalid target pool"));
            let targets = TargetSource {
                source: source.buffer().ok_or_else(truncated)?,
                compensation: 0,
            };
            ensure!(
                extra_targets.insert(pool, targets).is_none(),
                corrupt("target pool listed twice")
            );
        }
        Ok(Self {
            matched,
            equivalences,
            extra_data,
            raw_deltas,
            reference_deltas,
            extra_targets,
        })
    }
}

/// Every equivalence lies within the element and ends no earlier than the
/// previous one, and the extra data fills exactly what they leave uncovered.
fn validate_equivalences(matched: &ElementMatch, equivalences: &EquivalenceSource, extra_data: &Source) -> Result<()> {
    let bounded = |begin: u32, size: u32, bound: u32| begin < bound && size <= bound - begin;
    let mut total = 0u32;
    let mut previous_end = 0u32;
    for equivalence in equivalences.clone() {
        ensure!(
            bounded(equivalence.src_offset, equivalence.length, matched.old_length)
                && bounded(equivalence.dst_offset, equivalence.length, matched.new_length),
            corrupt("equivalence out of bounds")
        );
        ensure!(
            previous_end <= equivalence.dst_end(),
            corrupt("equivalences out of order")
        );
        previous_end = equivalence.dst_end();
        total = total
            .checked_add(equivalence.length)
            .ok_or(corrupt("equivalence lengths overflow"))?;
    }
    ensure!(
        total <= matched.new_length && extra_data.len() as u64 == u64::from(matched.new_length - total),
        corrupt("extra data does not fill the gaps between equivalences")
    );
    Ok(())
}

pub(super) struct EnsemblePatch<'a> {
    pub header: Header,
    pub elements: Vec<ElementPatch<'a>>,
}

impl<'a> EnsemblePatch<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut source = Source::new(bytes);
        let truncated = || corrupt("header is truncated");
        let magic = source.u32().ok_or_else(truncated)?;
        ensure!(magic == MAGIC, corrupt("missing Zucc magic"));
        let major = source.u16().ok_or_else(truncated)?;
        let _minor = source.u16().ok_or_else(truncated)?;
        ensure!(
            major == MAJOR_VERSION,
            corrupt(format!("unsupported major version {major}"))
        );
        let header = Header {
            old_size: source.u32().ok_or_else(truncated)?,
            old_crc: source.u32().ok_or_else(truncated)?,
            new_size: source.u32().ok_or_else(truncated)?,
            new_crc: source.u32().ok_or_else(truncated)?,
        };
        let count = source.u32().ok_or_else(truncated)?;
        let fits = |offset: u32, size: u32, container: u32| offset <= container && container - offset >= size;
        let mut elements = Vec::new();
        let mut next_dst = 0u32;
        for _ in 0..count {
            let element = ElementPatch::parse(&mut source)?;
            let m = element.matched;
            ensure!(
                fits(m.old_offset, m.old_length, header.old_size)
                    && fits(m.new_offset, m.new_length, header.new_size)
                    && m.new_offset == next_dst,
                corrupt("element out of place")
            );
            next_dst = m.new_offset + m.new_length;
            elements.push(element);
        }
        ensure!(
            next_dst == header.new_size,
            corrupt("elements do not cover the new file")
        );
        ensure!(source.is_empty(), corrupt("trailing bytes after the last element"));
        Ok(Self { header, elements })
    }
}
