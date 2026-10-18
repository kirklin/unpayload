//! ELF executables for x86, x64, ARM and AArch64.
//!
//! References come from three places: `R_*_RELATIVE` relocation entries,
//! which lead to the absolute addresses they adjust (abs32, as wide as an
//! address); those addresses; and displacements of branches and
//! PC-relative operands found by scanning code sections (rel32). Sections
//! map file offsets to virtual addresses.

use std::fmt;
use std::ops::Range;

use object::elf;
use object::endian::LittleEndian as LE;
use object::pod::{self, Pod};
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};

use super::arm::{Arm32, Arm64, thumb2_instruction_size};
use super::disasm::{Group, put, u32_at};
use super::translator::{AddressTranslator, INVALID_RVA, RVA_BOUND, Rva, Unit};
use super::{INVALID_OFFSET, Offset, Reference, corrupt};
use crate::error::{Result, ensure};
use crate::introsort;

/// Bound on section addresses and on the offsets of sections without file
/// data.
const SIZE_BOUND: u64 = 0x7FFF_0000;

const RELOC: u8 = 0;
const ABS32: u8 = 1;
/// Tag of the first rel32 address type.
const REL32: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Arch {
    X86,
    X64,
    Arm32,
    Arm64,
}

impl Arch {
    fn is_64(self) -> bool {
        matches!(self, Self::X64 | Self::Arm64)
    }

    fn machine(self) -> elf::Machine {
        match self {
            Self::X86 => elf::EM_386,
            Self::X64 => elf::EM_X86_64,
            Self::Arm32 => elf::EM_ARM,
            Self::Arm64 => elf::EM_AARCH64,
        }
    }

    fn relative(self) -> elf::RelocationType {
        match self {
            Self::X86 => elf::R_386_RELATIVE,
            Self::X64 => elf::R_X86_64_RELATIVE,
            Self::Arm32 => elf::R_ARM_RELATIVE,
            Self::Arm64 => elf::R_AARCH64_RELATIVE,
        }
    }

    /// Width of an absolute address.
    fn width(self) -> u32 {
        if self.is_64() { 8 } else { 4 }
    }

    /// Number of rel32 address types.
    fn rel32_types(self) -> usize {
        match self {
            Self::X86 | Self::X64 => 1,
            Self::Arm32 => Arm32::ALL.len(),
            Self::Arm64 => Arm64::ALL.len(),
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
            Self::Arm32 => "ARM",
            Self::Arm64 => "ARM64",
        })
    }
}

#[derive(Clone, Copy)]
struct RelocSection {
    offset: u64,
    size: u64,
    entry_size: u64,
}

#[derive(Clone, Copy)]
struct CodeSection {
    offset: u32,
    size: u32,
    addr: Rva,
}

/// What a section contributes to the image.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// It invalidates the image.
    Malformed,
    Ignored,
    /// Addresses without file data, such as `.bss`.
    Unbacked,
    /// Addresses backed by file data, which may hold pointers or code.
    Backed,
}

impl Role {
    fn of<S: SectionHeader<Endian = LE>>(section: &S, image_size: usize) -> Self {
        let (offset, size, addr) = dims(section);
        let unbacked = section.sh_type(LE) == elf::SHT_NOBITS;
        let bound = if unbacked { SIZE_BOUND } else { image_size as u64 };
        if !fits(addr, size, SIZE_BOUND) || !fits(offset, size, bound) {
            return Self::Malformed;
        }
        // Empty and unaddressed sections, and thread-local `.tbss` whose
        // addresses overlap other sections, would only confuse translation.
        if size == 0 || addr == 0 || (unbacked && section.sh_flags(LE).intersects(elf::SHF_TLS)) {
            return Self::Ignored;
        }
        if unbacked { Self::Unbacked } else { Self::Backed }
    }
}

pub(super) struct Elf {
    arch: Arch,
    size: usize,
    translator: AddressTranslator,
    /// Sorted by offset.
    relocs: Vec<RelocSection>,
    /// Sorted locations of absolute addresses.
    abs32: Vec<Offset>,
    /// Sorted locations of displacements, per address type.
    rel32: Vec<Vec<Offset>>,
}

impl Elf {
    pub fn parse(image: &[u8], arch: Arch) -> Result<Self> {
        let elf = if arch.is_64() {
            Self::parse_as::<elf::FileHeader64<LE>>(image, arch)
        } else {
            Self::parse_as::<elf::FileHeader32<LE>>(image, arch)
        };
        elf.ok_or_else(|| corrupt(format!("element is not a valid ELF {arch} image")))
    }

    fn parse_as<H: FileHeader<Endian = LE>>(image: &[u8], arch: Arch) -> Option<Self> {
        u32::try_from(image.len()).ok()?;
        let header = detect::<H>(image, arch)?;
        let (sections, sections_end) =
            table::<H::SectionHeader>(image, header.e_shoff(LE).into(), header.e_shnum(LE).into())?;
        let (segments, segments_end) =
            table::<H::ProgramHeader>(image, header.e_phoff(LE).into(), header.e_phnum(LE).into())?;

        // The section name table must exist, and end with a terminator.
        let names = sections.get(usize::from(header.e_shstrndx(LE).0))?;
        let (names_offset, names_size, _) = dims(names);
        if names_size > 0 {
            let names = image[clamp(names_offset, image.len())..].get(..usize::try_from(names_size).ok()?)?;
            if names.last() != Some(&0) {
                return None;
            }
        }

        let mut size = sections_end.max(segments_end) as u64;
        for segment in segments {
            let (offset, filesz): (u64, u64) = (segment.p_offset(LE).into(), segment.p_filesz(LE).into());
            let end = offset.checked_add(filesz).filter(|&end| end <= u64::from(u32::MAX))?;
            if !fits(offset, filesz, image.len() as u64) {
                return None;
            }
            size = size.max(end);
        }

        let mut units = Vec::with_capacity(sections.len());
        let mut roles = Vec::with_capacity(sections.len());
        for section in sections {
            let role = Role::of(section, image.len());
            let (offset, length, addr) = dims(section);
            let unit = Unit {
                offset_begin: offset as Offset,
                offset_size: length as u32,
                rva_begin: addr as Rva,
                rva_size: length as u32,
            };
            match role {
                Role::Malformed => return None,
                Role::Ignored => {}
                Role::Unbacked => units.push(unit),
                Role::Backed => {
                    units.push(unit);
                    size = size.max(offset + length);
                }
            }
            roles.push(role);
        }
        let translator = AddressTranslator::new(units)?;
        let size = size as usize;
        let image = &image[..size];

        let mut relocs = Vec::new();
        let mut code = Vec::new();
        for (section, role) in sections.iter().zip(&roles) {
            if *role != Role::Backed {
                continue;
            }
            let (offset, length, addr) = dims(section);
            let entry_size: u64 = section.sh_entsize(LE).into();
            let kind = section.sh_type(LE);
            if kind == elf::SHT_REL || kind == elf::SHT_RELA {
                let entry = if kind == elf::SHT_REL {
                    size_of::<H::Rel>()
                } else {
                    size_of::<H::Rela>()
                };
                if entry_size == entry as u64 {
                    relocs.push(RelocSection {
                        offset,
                        size: length,
                        entry_size,
                    });
                }
            } else if kind == elf::SHT_PROGBITS && section.sh_flags(LE).intersects(elf::SHF_EXECINSTR) {
                code.push(CodeSection {
                    offset: offset as u32,
                    size: length as u32,
                    addr: addr as Rva,
                });
            }
        }
        introsort::sort_by(&mut relocs, |a, b| a.offset < b.offset);
        introsort::sort_by(&mut code, |a, b| a.offset < b.offset);

        let mut elf = Self {
            arch,
            size,
            translator,
            relocs,
            abs32: Vec::new(),
            rel32: vec![Vec::new(); arch.rel32_types()],
        };

        // Relocations lead to the absolute addresses; keep those that
        // translate, and drop any whose body overlaps an earlier one.
        let mut references = Vec::new();
        elf.read_relocs(image, 0, size as Offset, &mut references).ok()?;
        let mut abs32: Vec<Offset> = references.iter().map(|r| r.target).collect();
        abs32.sort_unstable();
        abs32.retain(|&location| elf.abs32_target(image, location).is_some());
        let mut last: Option<Offset> = None;
        abs32.retain(|&location| {
            let keep = last.is_none_or(|last| location - last >= arch.width());
            if keep {
                last = Some(location);
            }
            keep
        });
        elf.abs32 = abs32;

        for section in &code {
            elf.scan(image, section, &code);
        }
        for locations in &mut elf.rel32 {
            locations.sort_unstable();
        }
        Some(elf)
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn groups(&self) -> Vec<Group> {
        let rel32 = (0..self.rel32.len()).map(|kind| Group {
            tag: REL32 + kind as u8,
            pool: 2,
        });
        [Group { tag: RELOC, pool: 0 }, Group { tag: ABS32, pool: 1 }]
            .into_iter()
            .chain(rel32)
            .collect()
    }

    /// Collects the displacements in `section` that lie between absolute
    /// addresses.
    fn scan(&mut self, image: &[u8], section: &CodeSection, code: &[CodeSection]) {
        let scanner = Scanner {
            arch: self.arch,
            translator: &self.translator,
            image,
            thumb2: self.arch == Arch::Arm32 && is_thumb2(image, section),
        };
        let addresses = section.addr..section.addr + section.size;
        let region = section.offset as usize..(section.offset + section.size) as usize;
        for gap in Gaps::new(&self.abs32, self.arch.width(), region) {
            let mut cursor = gap.start;
            while let Some(candidate) = scanner.find(cursor..gap.end) {
                let accepted = match self.arch {
                    Arch::X86 | Arch::X64 => {
                        self.translator.is_valid_rva(candidate.target)
                            && (candidate.anywhere || addresses.contains(&candidate.target))
                    }
                    // Misjudged ARM or THUMB2 mode, or data taken for code,
                    // yields targets outside code.
                    Arch::Arm32 | Arch::Arm64 => {
                        let target = self.translator.rva_to_offset(candidate.target);
                        target != INVALID_OFFSET && in_code(code, target)
                    }
                };
                if accepted {
                    self.rel32[candidate.kind].push(candidate.location as Offset);
                    cursor = candidate.accept;
                } else {
                    cursor = candidate.reject;
                }
            }
        }
    }

    /// Appends the references of type `tag` located in `[lo, hi)`.
    pub fn read(&self, image: &[u8], tag: u8, lo: Offset, hi: Offset, out: &mut Vec<Reference>) -> Result<()> {
        let image = &image[..self.size];
        match tag {
            RELOC => self.read_relocs(image, lo, hi, out),
            ABS32 => self.read_abs32(image, lo, hi, out),
            _ => {
                self.read_rel32(image, usize::from(tag - REL32), lo, hi, out);
                Ok(())
            }
        }
    }

    /// Relocation entries in `[lo, hi)`, leading to the addresses they adjust.
    fn read_relocs(&self, image: &[u8], lo: Offset, hi: Offset, out: &mut Vec<Reference>) -> Result<()> {
        let sections = &self.relocs;
        if sections.is_empty() {
            return Ok(());
        }
        let (lo, mut hi) = (u64::from(lo), u64::from(hi));
        // Begin at the first entry at or after `lo`, and extend `hi` over the
        // entry it cuts.
        let mut index = sections.partition_point(|s| s.offset <= lo).saturating_sub(1);
        let mut section = sections[index];
        let mut cursor = section.offset;
        if cursor < lo {
            cursor += (lo - cursor).div_ceil(section.entry_size) * section.entry_size;
        }
        if let Some(last) = sections[..sections.partition_point(|s| s.offset <= hi)].last()
            && hi - last.offset < last.size
        {
            hi = last.offset + (hi - last.offset).div_ceil(last.entry_size) * last.entry_size;
        }
        while cursor + section.entry_size <= hi {
            while cursor >= section.offset + section.size {
                index += 1;
                let Some(&next) = sections.get(index) else {
                    return Ok(());
                };
                section = next;
                cursor = section.offset;
                if cursor + section.entry_size > hi {
                    return Ok(());
                }
            }
            if let Some(rva) = self.reloc_target(image, cursor)? {
                let target = self.translator.rva_to_offset(rva);
                if target != INVALID_OFFSET && fits(target.into(), self.arch.width().into(), image.len() as u64) {
                    out.push(Reference {
                        location: cursor as Offset,
                        target,
                    });
                }
            }
            cursor += section.entry_size;
        }
        Ok(())
    }

    /// The address adjusted by the relocation entry at `at`, if it is a
    /// relative relocation.
    fn reloc_target(&self, image: &[u8], at: u64) -> Result<Option<Rva>> {
        let bytes = image.get(at as usize..).unwrap_or_default();
        let truncated = |()| corrupt("relocation entry runs past the image");
        let relative = self.arch.relative();
        Ok(if self.arch.is_64() {
            let (rel, _) = pod::from_bytes::<elf::Rel64<LE>>(bytes).map_err(truncated)?;
            let offset = rel.r_offset.get(LE);
            (rel.r_type(LE) == relative && offset <= u64::from(u32::MAX)).then_some(offset as Rva)
        } else {
            let (rel, _) = pod::from_bytes::<elf::Rel32<LE>>(bytes).map_err(truncated)?;
            (rel.r_type(LE) == relative).then(|| rel.r_offset.get(LE))
        })
    }

    fn read_abs32(&self, image: &[u8], lo: Offset, hi: Offset, out: &mut Vec<Reference>) -> Result<()> {
        let range = self.abs32_index(lo)?..self.abs32_index(hi)?;
        for &location in &self.abs32[range] {
            if let Some(target) = self.abs32_target(image, location) {
                out.push(Reference { location, target });
            }
        }
        Ok(())
    }

    /// Index of the first absolute address at or after `offset`, which must
    /// not cut one.
    fn abs32_index(&self, offset: Offset) -> Result<usize> {
        let index = self.abs32.partition_point(|&location| location < offset);
        ensure!(
            index == 0 || offset - self.abs32[index - 1] >= self.arch.width(),
            corrupt("equivalence cuts an absolute address")
        );
        Ok(index)
    }

    /// Target of the absolute address stored at `location`.
    fn abs32_target(&self, image: &[u8], location: Offset) -> Option<Offset> {
        let bytes = image.get(location as usize..)?.get(..self.arch.width() as usize)?;
        let value = if self.arch.is_64() {
            u64::from_le_bytes(bytes.try_into().unwrap())
        } else {
            u32::from_le_bytes(bytes.try_into().unwrap()).into()
        };
        if value >= u64::from(RVA_BOUND) {
            return None;
        }
        let target = self.translator.rva_to_offset(value as Rva);
        (target != INVALID_OFFSET).then_some(target)
    }

    fn read_rel32(&self, image: &[u8], kind: usize, lo: Offset, hi: Offset, out: &mut Vec<Reference>) {
        let locations = &self.rel32[kind];
        let first = locations.partition_point(|&location| location < lo);
        for &location in locations[first..].iter().take_while(|&&location| location < hi) {
            let at = location as usize;
            let rva = self.translator.offset_to_rva(location);
            let target_rva = match self.arch {
                Arch::X86 | Arch::X64 => Some(rva.wrapping_add(4).wrapping_add(u32_at(image, at))),
                Arch::Arm32 => Arm32::ALL[kind].read(rva, Arm32::ALL[kind].fetch(image, at)),
                Arch::Arm64 => Arm64::ALL[kind].read(rva, Arm64::fetch(image, at)),
            };
            if let Some(target_rva) = target_rva {
                let target = self.translator.rva_to_offset(target_rva);
                if target != INVALID_OFFSET {
                    out.push(Reference { location, target });
                }
            }
        }
    }

    /// Stores `reference` of type `tag`.
    pub fn write(&self, image: &mut [u8], tag: u8, reference: Reference) -> Result<()> {
        let Reference { location, target } = reference;
        let at = location as usize;
        let target_rva = self.translator.offset_to_rva(target);
        match tag {
            // Only the address an entry adjusts changes, never its type.
            RELOC => {
                let bytes = image.get_mut(at..).unwrap_or_default();
                let truncated = |()| corrupt("reference out of bounds");
                if self.arch.is_64() {
                    let (rel, _) = pod::from_bytes_mut::<elf::Rel64<LE>>(bytes).map_err(truncated)?;
                    rel.r_offset.set(LE, target_rva.into());
                } else {
                    let (rel, _) = pod::from_bytes_mut::<elf::Rel32<LE>>(bytes).map_err(truncated)?;
                    rel.r_offset.set(LE, target_rva);
                }
            }
            // Addresses that do not fit are left alone.
            ABS32 => {
                let width = self.arch.width() as usize;
                if target_rva != INVALID_RVA
                    && let Some(bytes) = image.get_mut(at..).and_then(|rest| rest.get_mut(..width))
                {
                    bytes.copy_from_slice(&u64::from(target_rva).to_le_bytes()[..width]);
                }
            }
            _ => {
                let kind = usize::from(tag - REL32);
                let rva = self.translator.offset_to_rva(location);
                match self.arch {
                    Arch::X86 | Arch::X64 => {
                        put(image, at, &target_rva.wrapping_sub(rva.wrapping_add(4)).to_le_bytes())?;
                    }
                    // Branches that cannot reach the target keep their code.
                    Arch::Arm32 => {
                        let arm = Arm32::ALL[kind];
                        ensure!(at + arm.width() <= image.len(), corrupt("reference out of bounds"));
                        let mut code = arm.fetch(image, at);
                        if arm.write(rva, target_rva, &mut code) {
                            arm.store(image, at, code);
                        }
                    }
                    Arch::Arm64 => {
                        let arm = Arm64::ALL[kind];
                        ensure!(at + 4 <= image.len(), corrupt("reference out of bounds"));
                        let mut code = Arm64::fetch(image, at);
                        if arm.write(rva, target_rva, &mut code) {
                            Arm64::store(image, at, code);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// The file header, when `image` starts with one for `arch`.
fn detect<H: FileHeader<Endian = LE>>(image: &[u8], arch: Arch) -> Option<&H> {
    let (header, _) = pod::from_bytes::<H>(image).ok()?;
    let ident = header.e_ident();
    let class = if arch.is_64() { elf::ELFCLASS64 } else { elf::ELFCLASS32 };
    (ident.magic == elf::ELFMAG
        && ident.class == class
        && ident.data == elf::ELFDATA2LSB
        && (header.e_type(LE) == elf::ET_EXEC || header.e_type(LE) == elf::ET_DYN)
        && header.e_version(LE) == 1
        && ident.version == elf::EV_CURRENT
        && header.e_machine(LE) == arch.machine()
        && usize::from(header.e_shentsize(LE)) == size_of::<H::SectionHeader>())
    .then_some(header)
}

/// `count` records at `offset`, which is clamped to the image end; also
/// returns where they end.
fn table<T: Pod>(image: &[u8], offset: u64, count: usize) -> Option<(&[T], usize)> {
    let start = clamp(offset, image.len());
    let (records, _) = pod::slice_from_bytes::<T>(&image[start..], count).ok()?;
    Some((records, start + size_of_val(records)))
}

fn clamp(offset: u64, len: usize) -> usize {
    offset.min(len as u64) as usize
}

/// File offset, size and address of a section.
fn dims<S: SectionHeader<Endian = LE>>(section: &S) -> (u64, u64, u64) {
    (
        section.sh_offset(LE).into(),
        section.sh_size(LE).into(),
        section.sh_addr(LE).into(),
    )
}

/// Whether `size` bytes at `offset` fit in a container of `container` bytes.
fn fits(offset: u64, size: u64, container: u64) -> bool {
    offset <= container && container - offset >= size
}

/// Whether `offset` lies in one of the sorted code sections.
fn in_code(code: &[CodeSection], offset: Offset) -> bool {
    let index = code.partition_point(|section| section.offset <= offset);
    index > 0 && offset - code[index - 1].offset < code[index - 1].size
}

/// Guesses whether ARM code is THUMB2. ARM instructions are 4-byte aligned
/// and mostly carry the "always" condition in their top nibble.
fn is_thumb2(image: &[u8], section: &CodeSection) -> bool {
    if !section.addr.is_multiple_of(4) || !section.size.is_multiple_of(4) {
        return true;
    }
    let code = &image[section.offset as usize..][..section.size as usize];
    let always = code
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|word| word[3] & 0xF0 == 0xE0)
        .count();
    (always as f64) < (code.len() / 4) as f64 * 0.4
}

/// Non-empty stretches of a region that no absolute address covers.
struct Gaps<'a> {
    abs32: &'a [Offset],
    width: usize,
    low: usize,
    end: usize,
}

impl<'a> Gaps<'a> {
    fn new(abs32: &'a [Offset], width: u32, region: Range<usize>) -> Self {
        let first = abs32.partition_point(|&location| (location as usize) < region.start);
        let width = width as usize;
        let mut low = region.start;
        if let Some(&previous) = first.checked_sub(1).map(|index| &abs32[index]) {
            low = low.max(previous as usize + width);
        }
        Self {
            abs32: &abs32[first..],
            width,
            low,
            end: region.end,
        }
    }
}

impl Iterator for Gaps<'_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Range<usize>> {
        while let Some((&location, rest)) = self.abs32.split_first()
            && (location as usize) < self.end
        {
            self.abs32 = rest;
            let gap = self.low..location as usize;
            self.low = location as usize + self.width;
            if !gap.is_empty() {
                return Some(gap);
            }
        }
        if self.low < self.end {
            let gap = self.low..self.end;
            self.low = self.end;
            return Some(gap);
        }
        None
    }
}

/// A displacement that scanning code turned up.
struct Candidate {
    location: usize,
    target: Rva,
    /// Address type, indexing the rel32 tables.
    kind: usize,
    /// Whether the target may lie outside the scanned section.
    anywhere: bool,
    /// Where scanning resumes when the candidate is rejected or accepted.
    reject: usize,
    accept: usize,
}

impl Candidate {
    /// ARM scanning resumes after the instruction either way.
    fn arm(location: usize, target: Rva, kind: usize, width: usize) -> Self {
        Self {
            location,
            target,
            kind,
            anywhere: false,
            reject: location + width,
            accept: location + width,
        }
    }
}

struct Scanner<'a> {
    arch: Arch,
    translator: &'a AddressTranslator,
    image: &'a [u8],
    thumb2: bool,
}

impl Scanner<'_> {
    fn find(&self, region: Range<usize>) -> Option<Candidate> {
        match self.arch {
            Arch::X86 | Arch::X64 => self.find_x86(region),
            Arch::Arm32 if self.thumb2 => self.find_thumb2(region),
            Arch::Arm32 => self.find_arm(region),
            Arch::Arm64 => self.find_arm64(region),
        }
    }

    fn rva(&self, at: usize) -> Rva {
        self.translator.offset_to_rva(at as Offset)
    }

    /// Opcodes followed by a 32-bit displacement, regardless of instruction
    /// boundaries.
    fn find_x86(&self, region: Range<usize>) -> Option<Candidate> {
        let image = self.image;
        let x64 = self.arch == Arch::X64;
        for at in region.clone() {
            let left = region.end - at;
            let found = if left >= 5 && matches!(image[at], 0xE8 | 0xE9) {
                // CALL and JMP.
                Some((1, false))
            } else if left >= 6 && image[at] == 0x0F && image[at + 1] & 0xF0 == 0x80 {
                // Conditional jumps.
                Some((2, false))
            } else if left >= 6
                && x64
                && ((image[at] == 0xFF && matches!(image[at + 1], 0x15 | 0x25))
                    || (matches!(image[at], 0x89 | 0x8B | 0x8D) && image[at + 1] & 0xC7 == 0x05))
            {
                // Indirect CALL and JMP, MOV and LEA, relative to RIP.
                Some((2, true))
            } else {
                None
            };
            if let Some((opcode, anywhere)) = found {
                let location = at + opcode;
                let target = self.rva(location).wrapping_add(4).wrapping_add(u32_at(image, location));
                return Some(Candidate {
                    location,
                    target,
                    kind: 0,
                    anywhere,
                    reject: at + 1,
                    accept: location + 4,
                });
            }
        }
        None
    }

    fn find_arm(&self, region: Range<usize>) -> Option<Candidate> {
        if region.len() < 4 {
            return None;
        }
        let mut at = region.start + (region.start.wrapping_neg() & 3);
        while at + 4 <= region.end {
            let arm = Arm32::A24;
            if let Some(target) = arm.read(self.rva(at), arm.fetch(self.image, at)) {
                return Some(Candidate::arm(at, target, arm as usize, 4));
            }
            at += 4;
        }
        None
    }

    fn find_thumb2(&self, region: Range<usize>) -> Option<Candidate> {
        if region.len() < 2 {
            return None;
        }
        let mut at = region.start + (region.start & 1);
        while at + 2 <= region.end {
            let rva = self.rva(at);
            let code16 = Arm32::T8.fetch(self.image, at);
            let width = thumb2_instruction_size(code16 as u16);
            let kinds: &[Arm32] = match width {
                2 => &[Arm32::T8, Arm32::T11],
                _ if at + 4 <= region.end => &[Arm32::T20, Arm32::T24],
                _ => &[],
            };
            let found = kinds
                .iter()
                .find_map(|&arm| Some((arm, arm.read(rva, arm.fetch(self.image, at))?)));
            if let Some((arm, target)) = found {
                return Some(Candidate::arm(at, target, arm as usize, width));
            }
            at += width;
        }
        None
    }

    fn find_arm64(&self, region: Range<usize>) -> Option<Candidate> {
        if region.len() < 4 {
            return None;
        }
        let mut at = region.start + (region.start.wrapping_neg() & 3);
        while at + 4 <= region.end {
            let (rva, code) = (self.rva(at), Arm64::fetch(self.image, at));
            if let Some((arm, target)) = Arm64::ALL.into_iter().find_map(|arm| Some((arm, arm.read(rva, code)?))) {
                return Some(Candidate::arm(at, target, arm as usize, 4));
            }
            at += 4;
        }
        None
    }
}
