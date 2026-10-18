//! Projecting offsets of the old element into the new one, and the sorted
//! target pools that reference deltas index into.

use super::{Equivalence, INVALID_OFFSET, OFFSET_BOUND, Offset};
use crate::introsort;

pub(super) struct OffsetMapper {
    /// Disjoint in the old element, sorted by their old offsets.
    equivalences: Vec<Equivalence>,
    old_size: Offset,
    new_size: Offset,
}

impl OffsetMapper {
    pub fn new(equivalences: impl Iterator<Item = Equivalence>, old_size: Offset, new_size: Offset) -> Self {
        let mut equivalences: Vec<_> = equivalences.collect();
        prune(&mut equivalences);
        Self {
            equivalences,
            old_size,
            new_size,
        }
    }

    /// Maps `offset` through `unit`, clamped into the new element.
    fn naive_project(&self, unit: &Equivalence, offset: Offset) -> Offset {
        let projected = i64::from(offset) - i64::from(unit.src_offset) + i64::from(unit.dst_offset);
        projected.clamp(0, i64::from(self.new_size) - 1) as Offset
    }

    /// Maps any old offset to a new one through the nearest equivalence;
    /// offsets past the old element keep their distance past its end.
    pub fn extended_forward_project(&self, offset: Offset) -> Offset {
        if offset < self.old_size {
            let mut pos = self.equivalences.partition_point(|e| e.src_offset <= offset);
            if pos != 0
                && (pos == self.equivalences.len()
                    || offset < self.equivalences[pos - 1].src_end()
                    || offset - self.equivalences[pos - 1].src_end() < self.equivalences[pos].src_offset - offset)
            {
                pos -= 1;
            }
            return self.naive_project(&self.equivalences[pos], offset);
        }
        let delta = offset - self.old_size;
        if delta < OFFSET_BOUND - self.new_size {
            self.new_size + delta
        } else {
            OFFSET_BOUND - 1
        }
    }

    /// Maps sorted `offsets` that fall inside an equivalence and drops the
    /// rest.
    pub fn forward_project_all(&self, offsets: &mut Vec<Offset>) {
        let mut current = 0;
        for offset in offsets.iter_mut() {
            while current < self.equivalences.len() && self.equivalences[current].src_end() <= *offset {
                current += 1;
            }
            *offset = match self.equivalences.get(current) {
                Some(e) if e.src_offset <= *offset => offset.wrapping_sub(e.src_offset).wrapping_add(e.dst_offset),
                _ => INVALID_OFFSET,
            };
        }
        offsets.retain(|&offset| offset != INVALID_OFFSET);
    }
}

/// Sorts equivalences by old offset and trims overlaps in the old element,
/// keeping the longer of two overlapping equivalences intact.
fn prune(equivalences: &mut Vec<Equivalence>) {
    introsort::sort_by(equivalences, |a, b| a.src_offset < b.src_offset);
    let n = equivalences.len();
    let mut current = 0;
    while current < n {
        let mut next = current + 1;
        let mut reaper = false;
        while next < n {
            if equivalences[next].src_offset >= equivalences[current].src_end() {
                break;
            }
            if equivalences[current].length < equivalences[next].length {
                let delta = equivalences[current].src_end() - equivalences[next].src_offset;
                equivalences[current].length -= delta;
                reaper = true;
                break;
            }
            next += 1;
        }
        if reaper {
            for reduced in &mut equivalences[current + 1..next] {
                reduced.length = 0;
            }
            current = next;
        } else {
            let end = equivalences[current].src_end();
            for reduced in &mut equivalences[current + 1..next] {
                let delta = end.wrapping_sub(reduced.src_offset);
                reduced.length -= reduced.length.min(delta);
                reduced.src_offset = reduced.src_offset.wrapping_add(delta);
                reduced.dst_offset = reduced.dst_offset.wrapping_add(delta);
            }
            current += 1;
        }
    }
    equivalences.retain(|e| e.length != 0);
}

/// Targets of one pool of references, sorted and unique.
#[derive(Default)]
pub(super) struct TargetPool {
    targets: Vec<Offset>,
}

impl TargetPool {
    pub fn insert(&mut self, targets: impl Iterator<Item = Offset>) {
        self.targets.extend(targets);
        self.targets.sort_unstable();
        self.targets.dedup();
    }

    pub fn filter_and_project(&mut self, mapper: &OffsetMapper) {
        mapper.forward_project_all(&mut self.targets);
        self.targets.sort_unstable();
    }

    /// Key of the target nearest to `offset`, preferring the lower on a tie.
    pub fn key_for_nearest_offset(&self, offset: Offset) -> u32 {
        let mut pos = self.targets.partition_point(|&t| t < offset);
        if pos != 0 && (pos == self.targets.len() || self.targets[pos] - offset >= offset - self.targets[pos - 1]) {
            pos -= 1;
        }
        pos as u32
    }

    pub fn offset_for_key(&self, key: u32) -> Option<Offset> {
        self.targets.get(key as usize).copied()
    }
}
