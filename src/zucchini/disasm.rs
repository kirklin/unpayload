//! Disassemblers find the references an executable holds, and rewrite them.

use super::dex::Dex;
use super::elf::{Arch, Elf};
use super::{ExeType, Offset, Reference, corrupt};
use crate::error::Result;

/// A type of reference, and the pool of targets it shares with other types.
#[derive(Clone, Copy)]
pub(super) struct Group {
    pub tag: u8,
    pub pool: u8,
}

pub(super) enum Disassembler {
    /// Data without references.
    NoOp(usize),
    Elf(Elf),
    Dex(Dex),
}

impl Disassembler {
    pub fn parse(image: &[u8], exe_type: ExeType) -> Result<Self> {
        let elf = |arch| Elf::parse(image, arch).map(Self::Elf);
        match exe_type {
            ExeType::NoOp => Ok(Self::NoOp(image.len())),
            ExeType::ElfX86 => elf(Arch::X86),
            ExeType::ElfX64 => elf(Arch::X64),
            ExeType::ElfArm32 => elf(Arch::Arm32),
            ExeType::ElfArm64 => elf(Arch::Arm64),
            ExeType::Dex => Dex::parse(image).map(Self::Dex),
            ExeType::Win32X86 | ExeType::Win32X64 | ExeType::Ztf => {
                Err(corrupt(format!("{exe_type:?} elements are not supported")))
            }
        }
    }

    /// Length of the executable, which may end before its image does.
    pub fn size(&self) -> usize {
        match self {
            Self::NoOp(size) => *size,
            Self::Elf(elf) => elf.size(),
            Self::Dex(dex) => dex.size(),
        }
    }

    pub fn groups(&self) -> Vec<Group> {
        match self {
            Self::NoOp(_) => Vec::new(),
            Self::Elf(elf) => elf.groups(),
            Self::Dex(dex) => dex.groups(),
        }
    }

    /// Appends the references of type `tag` located in `[lo, hi)`.
    pub fn read(&self, image: &[u8], tag: u8, lo: Offset, hi: Offset, out: &mut Vec<Reference>) -> Result<()> {
        match self {
            Self::NoOp(_) => Ok(()),
            Self::Elf(elf) => elf.read(image, tag, lo, hi, out),
            Self::Dex(dex) => {
                dex.read(image, tag, lo, hi, out);
                Ok(())
            }
        }
    }

    /// Stores `reference` of type `tag` in `image`.
    pub fn write(&self, image: &mut [u8], tag: u8, reference: Reference) -> Result<()> {
        match self {
            Self::NoOp(_) => Ok(()),
            Self::Elf(elf) => elf.write(image, tag, reference),
            Self::Dex(dex) => dex.write(image, tag, reference),
        }
    }
}

/// The integer at `at`, which callers know lies in the image.
pub(super) fn u16_at(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([image[at], image[at + 1]])
}

/// The integer at `at`, which callers know lies in the image.
pub(super) fn u32_at(image: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(image[at..at + 4].try_into().unwrap())
}

/// Writes `bytes` at `at`, which a corrupt patch may place out of bounds.
pub(super) fn put(image: &mut [u8], at: usize, bytes: &[u8]) -> Result<()> {
    image
        .get_mut(at..)
        .and_then(|rest| rest.get_mut(..bytes.len()))
        .ok_or_else(|| corrupt("reference out of bounds"))?
        .copy_from_slice(bytes);
    Ok(())
}
