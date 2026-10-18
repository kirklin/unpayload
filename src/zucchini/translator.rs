//! Translation between file offsets and relative virtual addresses (RVAs).
//!
//! An executable maps ranges of the file to ranges of addresses. A range may
//! cover more addresses than file bytes (zero-filled memory such as `.bss`);
//! such dangling addresses translate to fake offsets placed past every real
//! offset.

use super::{INVALID_OFFSET, OFFSET_BOUND, Offset};
use crate::introsort;

pub(super) type Rva = u32;
pub(super) const INVALID_RVA: Rva = u32::MAX - 1;
pub(super) const RVA_BOUND: Rva = u32::MAX / 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Unit {
    pub offset_begin: Offset,
    pub offset_size: u32,
    pub rva_begin: Rva,
    pub rva_size: u32,
}

impl Unit {
    fn offset_end(&self) -> Offset {
        self.offset_begin.wrapping_add(self.offset_size)
    }

    fn rva_end(&self) -> Rva {
        self.rva_begin.wrapping_add(self.rva_size)
    }

    fn covers_offset(&self, offset: Offset) -> bool {
        self.offset_begin <= offset && offset - self.offset_begin < self.offset_size
    }

    fn covers_rva(&self, rva: Rva) -> bool {
        self.rva_begin <= rva && rva - self.rva_begin < self.rva_size
    }

    fn has_dangling_rva(&self) -> bool {
        self.rva_size > self.offset_size
    }

    fn covers_dangling_rva(&self, rva: Rva) -> bool {
        self.covers_rva(rva) && rva - self.rva_begin >= self.offset_size
    }
}

#[derive(Default)]
pub(super) struct AddressTranslator {
    by_offset: Vec<Unit>,
    by_rva: Vec<Unit>,
    fake_offset_begin: Offset,
}

fn bounded(begin: u32, size: u32, bound: u32) -> bool {
    begin < bound && size <= bound - begin
}

impl AddressTranslator {
    /// Builds a translator from `units`; `None` when they contradict each
    /// other.
    pub fn new(mut units: Vec<Unit>) -> Option<Self> {
        for unit in &mut units {
            if !bounded(unit.offset_begin, unit.offset_size, OFFSET_BOUND)
                || !bounded(unit.rva_begin, unit.rva_size, RVA_BOUND)
            {
                return None;
            }
            unit.offset_size = unit.offset_size.min(unit.rva_size);
        }
        units.retain(|unit| unit.rva_size != 0);
        introsort::sort_by(&mut units, |a, b| (a.rva_begin, a.rva_size) < (b.rva_begin, b.rva_size));
        units.dedup();

        // Merge units whose address ranges overlap or touch, when their
        // offsets agree.
        if units.len() > 1 {
            let mut slow = 0;
            for fast in 1..units.len() {
                let (s, f) = (units[slow], units[fast]);
                if s.rva_end() < f.rva_begin {
                    slow += 1;
                    units[slow] = f;
                    continue;
                }
                let merge_is_optional = s.rva_end() == f.rva_begin;
                if f.offset_begin < s.offset_begin || f.offset_begin - s.offset_begin != f.rva_begin - s.rva_begin {
                    if merge_is_optional {
                        slow += 1;
                        units[slow] = f;
                        continue;
                    }
                    return None;
                }
                if (f.has_dangling_rva() && f.offset_end() < s.offset_end())
                    || (s.has_dangling_rva() && s.offset_end() < f.offset_end())
                {
                    if merge_is_optional {
                        slow += 1;
                        units[slow] = f;
                        continue;
                    }
                    return None;
                }
                let merged = &mut units[slow];
                merged.rva_size = merged.rva_size.max(f.rva_end() - merged.rva_begin);
                merged.offset_size = merged.offset_size.max(f.offset_end() - merged.offset_begin);
            }
            units.truncate(slow + 1);
        }

        introsort::sort_by(&mut units, |a, b| a.offset_begin < b.offset_begin);
        if units.windows(2).any(|w| w[0].offset_end() > w[1].offset_begin) {
            return None;
        }
        let offset_bound = units.iter().map(Unit::offset_end).max().unwrap_or(0);
        let rva_bound = units.iter().map(Unit::rva_end).max().unwrap_or(0);
        if !bounded(offset_bound, rva_bound, OFFSET_BOUND) {
            return None;
        }
        let by_offset = units.clone();
        introsort::sort_by(&mut units, |a, b| a.rva_begin < b.rva_begin);
        Some(Self {
            by_offset,
            by_rva: units,
            fake_offset_begin: offset_bound,
        })
    }

    fn unit_for_offset(&self, offset: Offset) -> Option<&Unit> {
        let pos = self.by_offset.partition_point(|u| u.offset_begin <= offset);
        let unit = self.by_offset.get(pos.checked_sub(1)?)?;
        unit.covers_offset(offset).then_some(unit)
    }

    fn unit_for_rva(&self, rva: Rva) -> Option<&Unit> {
        let pos = self.by_rva.partition_point(|u| u.rva_begin <= rva);
        let unit = self.by_rva.get(pos.checked_sub(1)?)?;
        unit.covers_rva(rva).then_some(unit)
    }

    pub fn offset_to_rva(&self, offset: Offset) -> Rva {
        if offset >= self.fake_offset_begin {
            let rva = offset - self.fake_offset_begin;
            return match self.unit_for_rva(rva) {
                Some(unit) if unit.has_dangling_rva() && unit.covers_dangling_rva(rva) => rva,
                _ => INVALID_RVA,
            };
        }
        match self.unit_for_offset(offset) {
            Some(unit) => offset - unit.offset_begin + unit.rva_begin,
            None => INVALID_RVA,
        }
    }

    pub fn rva_to_offset(&self, rva: Rva) -> Offset {
        match self.unit_for_rva(rva) {
            Some(unit) => {
                let delta = rva - unit.rva_begin;
                if delta < unit.offset_size {
                    delta + unit.offset_begin
                } else {
                    self.fake_offset_begin.wrapping_add(rva)
                }
            }
            None => INVALID_OFFSET,
        }
    }

    /// Whether `rva` lies in some unit.
    pub fn is_valid_rva(&self, rva: Rva) -> bool {
        rva != INVALID_RVA && self.unit_for_rva(rva).is_some()
    }
}
