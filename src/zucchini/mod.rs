//! Zucchini patches: binary diffs that understand executables.
//!
//! Each element of a patch maps a region of the old file to a region of the
//! new file. Applying an element copies the old bytes named by its
//! equivalences, fills the gaps with extra data, adds byte-wise raw deltas,
//! and finally rewrites every reference (branch targets, relocations, string
//! and method indices and the like) of the copied code: references are read
//! from the old element, their targets projected into the new element and
//! adjusted by per-reference deltas expressed as distances in a sorted pool
//! of targets.

mod arm;
mod dex;
mod disasm;
mod elf;
mod mapper;
mod patch;
mod translator;

use std::collections::BTreeMap;

use crate::error::{Error, Result, ensure};
use disasm::Disassembler;
use mapper::{OffsetMapper, TargetPool};
use patch::{ElementPatch, EnsemblePatch, Source};

/// An offset into an element.
type Offset = u32;
const INVALID_OFFSET: Offset = u32::MAX - 1;
/// Upper bound of real offsets; offsets from here up stand for addresses with
/// no file data.
const OFFSET_BOUND: Offset = u32::MAX / 2;

fn corrupt(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::patch("zucchini", message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExeType {
    NoOp,
    Win32X86,
    Win32X64,
    ElfX86,
    ElfX64,
    ElfArm32,
    ElfArm64,
    Dex,
    Ztf,
}

impl ExeType {
    fn from_tag(tag: u32) -> Option<Self> {
        Some(match &tag.to_le_bytes() {
            b"NoOp" => Self::NoOp,
            b"Px86" => Self::Win32X86,
            b"Px64" => Self::Win32X64,
            b"Ex86" => Self::ElfX86,
            b"Ex64" => Self::ElfX64,
            b"EA32" => Self::ElfArm32,
            b"EA64" => Self::ElfArm64,
            b"DEX " => Self::Dex,
            b"ZTF " => Self::Ztf,
            _ => return None,
        })
    }

    /// Element format version; types this program cannot disassemble report
    /// the invalid version, which only elements without a disassembler match.
    fn version(self) -> u16 {
        match self {
            Self::Win32X86 | Self::Win32X64 | Self::Ztf => 0xFFFF,
            _ => 1,
        }
    }
}

/// A region of the old file that reappears in the new file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Equivalence {
    pub src_offset: Offset,
    pub dst_offset: Offset,
    pub length: u32,
}

impl Equivalence {
    pub fn src_end(&self) -> Offset {
        self.src_offset.wrapping_add(self.length)
    }

    pub fn dst_end(&self) -> Offset {
        self.dst_offset.wrapping_add(self.length)
    }
}

/// Bytes at `location` that encode a link to `target`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Reference {
    pub location: Offset,
    pub target: Offset,
}

/// Applies a zucchini `patch` to `old`, returning the new file.
pub(crate) fn apply(old: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    let patch = EnsemblePatch::parse(patch)?;
    let header = &patch.header;
    ensure!(
        old.len() as u64 == u64::from(header.old_size) && crc32fast::hash(old) == header.old_crc,
        corrupt("the source differs from the one the patch was made for")
    );
    let mut new = vec![0u8; header.new_size as usize];
    for element in &patch.elements {
        let m = element.matched;
        let old = &old[m.old_offset as usize..][..m.old_length as usize];
        let new = &mut new[m.new_offset as usize..][..m.new_length as usize];
        apply_element(element, old, new)?;
    }
    ensure!(
        crc32fast::hash(&new) == header.new_crc,
        corrupt("the patched file fails its checksum")
    );
    Ok(new)
}

fn apply_element(element: &ElementPatch, old: &[u8], new: &mut [u8]) -> Result<()> {
    copy_equivalences(element, old, new)?;
    add_raw_deltas(element, new)?;
    correct_references(element, old, new)
}

fn copy_equivalences(element: &ElementPatch, old: &[u8], new: &mut [u8]) -> Result<()> {
    let mut equivalences = element.equivalences.clone();
    let mut extra = element.extra_data;
    let mut position = 0usize;
    for equivalence in equivalences.by_ref() {
        fill_gap(new, &mut extra, &mut position, equivalence.dst_offset as usize)?;
        let src = &old[equivalence.src_offset as usize..][..equivalence.length as usize];
        new[position..position + src.len()].copy_from_slice(src);
        position += src.len();
    }
    let end = new.len();
    fill_gap(new, &mut extra, &mut position, end)?;
    ensure!(
        equivalences.done() && extra.is_empty(),
        corrupt("trailing equivalences or extra data")
    );
    Ok(())
}

/// Fills `new` from `position` up to `until` with extra data.
fn fill_gap(new: &mut [u8], extra: &mut Source, position: &mut usize, until: usize) -> Result<()> {
    ensure!(until >= *position, corrupt("equivalences overlap in the new element"));
    let bytes = extra.take(until - *position).ok_or(corrupt("not enough extra data"))?;
    new[*position..until].copy_from_slice(bytes);
    *position = until;
    Ok(())
}

fn add_raw_deltas(element: &ElementPatch, new: &mut [u8]) -> Result<()> {
    // Raw deltas count positions within the bytes equivalences copy.
    let mut equivalences = element.equivalences.clone();
    let mut deltas = element.raw_deltas.clone();
    let mut equivalence = equivalences.next();
    let mut base = 0u32;
    for delta in deltas.by_ref() {
        while let Some(e) = equivalence
            && base.wrapping_add(e.length) <= delta.copy_offset
        {
            base = base.wrapping_add(e.length);
            equivalence = equivalences.next();
        }
        let e = equivalence.ok_or(corrupt("raw delta past the last equivalence"))?;
        ensure!(
            delta.copy_offset >= base && delta.copy_offset < base.wrapping_add(e.length),
            corrupt("raw delta outside its equivalence")
        );
        let index = e.dst_offset.wrapping_sub(base).wrapping_add(delta.copy_offset) as usize;
        let byte = new.get_mut(index).ok_or(corrupt("raw delta out of bounds"))?;
        *byte = byte.wrapping_add(delta.diff as u8);
    }
    ensure!(deltas.done(), corrupt("trailing raw deltas"));
    Ok(())
}

fn correct_references(element: &ElementPatch, old: &[u8], new: &mut [u8]) -> Result<()> {
    let exe_type = element.matched.exe_type;
    let old_disasm = Disassembler::parse(old, exe_type)?;
    let new_disasm = Disassembler::parse(new, exe_type)?;
    ensure!(
        old_disasm.size() == old.len() && new_disasm.size() == new.len(),
        corrupt("element size differs from the executable it holds")
    );
    let mut pools: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    for group in old_disasm.groups() {
        pools.entry(group.pool).or_default().push(group.tag);
    }
    let mapper = OffsetMapper::new(element.equivalences.clone(), old.len() as u32, new.len() as u32);
    let mut deltas = element.reference_deltas.clone();
    let old_size = old.len() as Offset;
    let mut references = Vec::new();

    for (pool, tags) in &pools {
        let mut targets = TargetPool::default();
        for &tag in tags {
            references.clear();
            old_disasm.read(old, tag, 0, old_size, &mut references)?;
            targets.insert(references.iter().map(|r| r.target));
        }
        targets.filter_and_project(&mapper);
        let mut extra = element.extra_targets.get(pool).cloned().unwrap_or_default();
        targets.insert(extra.by_ref());
        ensure!(extra.done(), corrupt("trailing extra targets"));

        for &tag in tags {
            for equivalence in element.equivalences.clone() {
                references.clear();
                old_disasm.read(old, tag, equivalence.src_offset, equivalence.src_end(), &mut references)?;
                for reference in &references {
                    let projected = mapper.extended_forward_project(reference.target);
                    let expected = targets.key_for_nearest_offset(projected);
                    let delta = deltas.next().ok_or(corrupt("missing reference delta"))?;
                    let key = expected.wrapping_add(delta as u32);
                    let target = targets.offset_for_key(key).ok_or(corrupt("invalid reference delta"))?;
                    let location = reference
                        .location
                        .wrapping_sub(equivalence.src_offset)
                        .wrapping_add(equivalence.dst_offset);
                    new_disasm.write(new, tag, Reference { location, target })?;
                }
            }
        }
    }
    ensure!(deltas.done(), corrupt("trailing reference deltas"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// A file from tests/data/zucchini, which holds two builds of each test
    /// executable and the patch zucchini makes between them.
    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/zucchini")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// Number of references of each type in `image`, by tag.
    fn census(image: &[u8], exe_type: ExeType) -> Vec<usize> {
        let disasm = Disassembler::parse(image, exe_type).unwrap();
        assert_eq!(disasm.size(), image.len());
        disasm
            .groups()
            .iter()
            .map(|group| {
                let mut references = Vec::new();
                disasm
                    .read(image, group.tag, 0, image.len() as Offset, &mut references)
                    .unwrap();
                references.len()
            })
            .collect()
    }

    /// Applies the fixture patch for `name`, after checking that it holds an
    /// element of `exe_type`.
    fn patch(name: &str, exe_type: ExeType) {
        let (older, newer, patch) = (
            fixture(&format!("{name}.older")),
            fixture(&format!("{name}.newer")),
            fixture(&format!("{name}.zuc")),
        );
        let elements = EnsemblePatch::parse(&patch).unwrap().elements;
        assert!(
            elements.iter().any(|element| element.matched.exe_type == exe_type),
            "{name}: no {exe_type:?} element"
        );
        assert!(apply(&older, &patch).unwrap() == newer, "{name}: wrong result");
    }

    #[test]
    fn x86() {
        let counts = census(&fixture("libx86.older"), ExeType::ElfX86);
        assert!(counts.iter().all(|&n| n > 0), "{counts:?}");
        patch("libx86", ExeType::ElfX86);
    }

    #[test]
    fn x64() {
        let counts = census(&fixture("libx64.older"), ExeType::ElfX64);
        assert!(counts.iter().all(|&n| n > 0), "{counts:?}");
        patch("libx64", ExeType::ElfX64);
    }

    /// ARM code holds 24-bit ARM branches, and no THUMB2 branches.
    #[test]
    fn arm() {
        let counts = census(&fixture("libarm.older"), ExeType::ElfArm32);
        assert!(
            counts[..3].iter().all(|&n| n > 0) && counts[3..].iter().all(|&n| n == 0),
            "{counts:?}"
        );
        patch("libarm", ExeType::ElfArm32);
    }

    /// THUMB2 code holds THUMB2 branches of every width, and no ARM branches.
    #[test]
    fn thumb2() {
        let counts = census(&fixture("libthumb.older"), ExeType::ElfArm32);
        assert!(
            counts[2] == 0 && counts.iter().enumerate().all(|(tag, &n)| tag == 2 || n > 0),
            "{counts:?}"
        );
        patch("libthumb", ExeType::ElfArm32);
    }

    #[test]
    fn arm64() {
        let counts = census(&fixture("libarm64.older"), ExeType::ElfArm64);
        assert!(counts.iter().all(|&n| n > 0), "{counts:?}");
        patch("libarm64", ExeType::ElfArm64);
    }

    #[test]
    fn dex() {
        let counts = census(&fixture("classes.older"), ExeType::Dex);
        assert_eq!(counts.len(), 42);
        assert!(counts.iter().filter(|&&n| n > 0).count() >= 30, "{counts:?}");
        patch("classes", ExeType::Dex);
    }

    #[test]
    fn raw() {
        patch("raw", ExeType::NoOp);
    }

    #[test]
    fn wrong_source() {
        let mut older = fixture("libx64.older");
        older[100] ^= 1;
        assert!(apply(&older, &fixture("libx64.zuc")).is_err());
    }
}
