//! Branch displacements of 32-bit ARM, THUMB2 and AArch64 instructions.
//!
//! Each address type can decode an instruction's displacement, encode a new
//! one, and convert between displacements and target addresses. Bit layouts
//! follow the ARM architecture reference manuals.

use super::translator::Rva;

/// Alignment a decoded target must be rounded down to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Align {
    Two = 2,
    Four = 4,
}

fn misaligned(rva: Rva, align: Align) -> bool {
    rva & (align as u32 - 1) != 0
}

/// Sign-extends the bits `lo..=hi` of `value`.
fn signed_bits(value: u32, lo: u32, hi: u32) -> i32 {
    ((value << (31 - hi)) as i32) >> (31 - hi + lo)
}

fn unsigned_bits(value: u32, lo: u32, hi: u32) -> u32 {
    (value << (31 - hi)) >> (31 - hi + lo)
}

fn bit(value: u32, pos: u32) -> u32 {
    (value >> pos) & 1
}

fn sign_extend(pos: u32, value: u32) -> i32 {
    ((value << (31 - pos)) as i32) >> (31 - pos)
}

/// Whether `disp` survives truncation to `digits` bits.
fn signed_fit(disp: i32, digits: u32) -> bool {
    disp == sign_extend(digits - 1, disp as u32)
}

fn arm_target(instr: Rva, disp: i32, align: Align) -> Rva {
    let ret = instr.wrapping_add(8).wrapping_add(disp as u32);
    ret - (ret & (align as u32 - 1))
}

fn thumb2_target(instr: Rva, disp: i32, align: Align) -> Rva {
    let ret = instr.wrapping_add(4).wrapping_add(disp as u32);
    ret - (ret & (align as u32 - 1))
}

fn arm_disp(instr: Rva, target: Rva, align: Align) -> i32 {
    let ret = (target as i32).wrapping_sub(instr.wrapping_add(8) as i32);
    ret.wrapping_add(ret.wrapping_neg() & (align as i32 - 1))
}

fn thumb2_disp(instr: Rva, target: Rva, align: Align) -> i32 {
    let ret = (target as i32).wrapping_sub(instr.wrapping_add(4) as i32);
    ret.wrapping_add(ret.wrapping_neg() & (align as i32 - 1))
}

/// Address types of 32-bit ARM and THUMB2 branches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Arm32 {
    /// B, BL, BLX (A1/A2) with a 24-bit immediate.
    A24,
    /// B (T1) with an 8-bit immediate.
    T8,
    /// B (T2) with an 11-bit immediate.
    T11,
    /// Conditional B (T3) with a 20-bit immediate.
    T20,
    /// B (T4), BL (T1), BLX (T2) with a 24-bit immediate.
    T24,
}

impl Arm32 {
    pub const ALL: [Self; 5] = [Self::A24, Self::T8, Self::T11, Self::T20, Self::T24];

    /// Width of the instruction in bytes.
    pub fn width(self) -> usize {
        match self {
            Self::T8 | Self::T11 => 2,
            _ => 4,
        }
    }

    pub fn fetch(self, image: &[u8], at: usize) -> u32 {
        match self {
            Self::A24 => u32::from_le_bytes(image[at..at + 4].try_into().unwrap()),
            Self::T8 | Self::T11 => u32::from(u16::from_le_bytes([image[at], image[at + 1]])),
            Self::T20 | Self::T24 => thumb2_code32(image, at),
        }
    }

    pub fn store(self, image: &mut [u8], at: usize, code: u32) {
        match self {
            Self::A24 => image[at..at + 4].copy_from_slice(&code.to_le_bytes()),
            Self::T8 | Self::T11 => image[at..at + 2].copy_from_slice(&(code as u16).to_le_bytes()),
            Self::T20 | Self::T24 => {
                image[at..at + 2].copy_from_slice(&((code >> 16) as u16).to_le_bytes());
                image[at + 2..at + 4].copy_from_slice(&(code as u16).to_le_bytes());
            }
        }
    }

    fn decode(self, code: u32) -> Option<(i32, Align)> {
        match self {
            Self::A24 => {
                let bits = unsigned_bits(code, 24, 27);
                if bits != 0xA && bits != 0xB {
                    return None;
                }
                let mut disp = signed_bits(code, 0, 23).wrapping_shl(2);
                if unsigned_bits(code, 28, 31) == 0xF {
                    disp |= (bit(code, 24) << 1) as i32;
                    return Some((disp, Align::Two));
                }
                Some((disp, Align::Four))
            }
            Self::T8 => {
                let code = code as u16;
                ((code & 0xF000) == 0xD000 && (code & 0x0F00) != 0x0F00)
                    .then(|| (signed_bits(u32::from(code), 0, 7).wrapping_shl(1), Align::Two))
            }
            Self::T11 => {
                let code = code as u16;
                ((code & 0xF800) == 0xE000).then(|| (signed_bits(u32::from(code), 0, 10).wrapping_shl(1), Align::Two))
            }
            Self::T20 => {
                if (code & 0xF800_D000) != 0xF000_8000 || (code & 0x03C0_0000) == 0x03C0_0000 {
                    return None;
                }
                let imm11 = unsigned_bits(code, 0, 10);
                let j2 = bit(code, 11);
                let j1 = bit(code, 13);
                let imm6 = unsigned_bits(code, 16, 21);
                let s = bit(code, 26);
                let t = (imm6 << 12) | (imm11 << 1) | (s << 20) | (j2 << 19) | (j1 << 18);
                Some((sign_extend(20, t), Align::Two))
            }
            Self::T24 => {
                let bits = code & 0xF800_D000;
                if bits != 0xF000_9000 && bits != 0xF000_D000 && bits != 0xF000_C000 {
                    return None;
                }
                let imm11 = unsigned_bits(code, 0, 10);
                let j2 = bit(code, 11);
                let j1 = bit(code, 13);
                let imm10 = unsigned_bits(code, 16, 25);
                let s = bit(code, 26);
                let t = (imm10 << 12) | (imm11 << 1) | (s << 24) | ((j1 ^ s ^ 1) << 23) | ((j2 ^ s ^ 1) << 22);
                let disp = sign_extend(24, t);
                if bits == 0xF000_C000 {
                    if bit(code, 0) != 0 {
                        return None;
                    }
                    return Some((disp, Align::Four));
                }
                Some((disp, Align::Two))
            }
        }
    }

    fn encode(self, disp: i32, code: &mut u32) -> bool {
        let t = *code;
        let d = disp as u32;
        match self {
            Self::A24 => {
                let bits = unsigned_bits(t, 24, 27);
                if (bits != 0xA && bits != 0xB) || !signed_fit(disp, 26) {
                    return false;
                }
                let mut t = t;
                if unsigned_bits(t, 28, 31) == 0xF {
                    if disp % 2 != 0 {
                        return false;
                    }
                    t = (t & 0xFEFF_FFFF) | (bit(d, 1) << 24);
                } else if disp % 4 != 0 {
                    return false;
                }
                *code = (t & 0xFF00_0000) | ((disp >> 2) as u32 & 0x00FF_FFFF);
                true
            }
            Self::T8 => {
                let t = t as u16;
                if (t & 0xF000) != 0xD000 || (t & 0x0F00) == 0x0F00 || disp % 2 != 0 || !signed_fit(disp, 9) {
                    return false;
                }
                *code = u32::from((t & 0xFF00) | ((disp >> 1) as u16 & 0x00FF));
                true
            }
            Self::T11 => {
                let t = t as u16;
                if (t & 0xF800) != 0xE000 || disp % 2 != 0 || !signed_fit(disp, 12) {
                    return false;
                }
                *code = u32::from((t & 0xF800) | ((disp >> 1) as u16 & 0x07FF));
                true
            }
            Self::T20 => {
                if (t & 0xF800_D000) != 0xF000_8000
                    || (t & 0x03C0_0000) == 0x03C0_0000
                    || disp % 2 != 0
                    || !signed_fit(disp, 21)
                {
                    return false;
                }
                let s = bit(d, 20);
                let j2 = bit(d, 19);
                let j1 = bit(d, 18);
                let imm6 = unsigned_bits(d, 12, 17);
                let imm11 = unsigned_bits(d, 1, 11);
                *code = (t & 0xFBC0_D000) | (s << 26) | (imm6 << 16) | (j1 << 13) | (j2 << 11) | imm11;
                true
            }
            Self::T24 => {
                let bits = t & 0xF800_D000;
                if (bits != 0xF000_9000 && bits != 0xF000_D000 && bits != 0xF000_C000) || disp % 2 != 0 {
                    return false;
                }
                if bits == 0xF000_C000 && bit(d, 1) != 0 {
                    return false;
                }
                if !signed_fit(disp, 25) {
                    return false;
                }
                let imm11 = unsigned_bits(d, 1, 11);
                let imm10 = unsigned_bits(d, 12, 21);
                let i2 = bit(d, 22);
                let i1 = bit(d, 23);
                let s = bit(d, 24);
                *code =
                    (t & 0xF800_D000) | (s << 26) | (imm10 << 16) | ((i1 ^ s ^ 1) << 13) | ((i2 ^ s ^ 1) << 11) | imm11;
                true
            }
        }
    }

    /// Target address of the branch at `instr`.
    pub fn read(self, instr: Rva, code: u32) -> Option<Rva> {
        let instr_align = if self == Self::A24 { Align::Four } else { Align::Two };
        if misaligned(instr, instr_align) {
            return None;
        }
        let (disp, align) = self.decode(code)?;
        Some(match self {
            Self::A24 => arm_target(instr, disp, align),
            _ => thumb2_target(instr, disp, align),
        })
    }

    /// Points the branch at `instr` to `target`.
    pub fn write(self, instr: Rva, target: Rva, code: &mut u32) -> bool {
        match self {
            Self::A24 | Self::T24 => {
                let instr_align = if self == Self::A24 { Align::Four } else { Align::Two };
                if misaligned(instr, instr_align) {
                    return false;
                }
                let Some((_, align)) = self.decode(*code) else {
                    return false;
                };
                if misaligned(target, align) {
                    return false;
                }
                let disp = match self {
                    Self::A24 => arm_disp(instr, target, align),
                    _ => thumb2_disp(instr, target, align),
                };
                self.encode(disp, code)
            }
            _ => {
                if misaligned(instr, Align::Two) || misaligned(target, Align::Two) {
                    return false;
                }
                self.encode(thumb2_disp(instr, target, Align::Two), code)
            }
        }
    }
}

pub(super) fn thumb2_code32(image: &[u8], at: usize) -> u32 {
    (u32::from(u16::from_le_bytes([image[at], image[at + 1]])) << 16)
        | u32::from(u16::from_le_bytes([image[at + 2], image[at + 3]]))
}

/// Size of the THUMB2 instruction starting with `code16`.
pub(super) fn thumb2_instruction_size(code16: u16) -> usize {
    if (code16 & 0xF000) == 0xF000 || (code16 & 0xF800) == 0xE800 {
        4
    } else {
        2
    }
}

/// Address types of AArch64 branches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Arm64 {
    /// TBZ, TBNZ with a 14-bit immediate.
    Immd14,
    /// B.cond, CBZ, CBNZ with a 19-bit immediate.
    Immd19,
    /// B, BL with a 26-bit immediate.
    Immd26,
}

impl Arm64 {
    pub const ALL: [Self; 3] = [Self::Immd14, Self::Immd19, Self::Immd26];

    pub fn fetch(image: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(image[at..at + 4].try_into().unwrap())
    }

    pub fn store(image: &mut [u8], at: usize, code: u32) {
        image[at..at + 4].copy_from_slice(&code.to_le_bytes());
    }

    fn decode(self, code: u32) -> Option<i32> {
        match self {
            Self::Immd14 => {
                let bits = code & 0x7F00_0000;
                (bits == 0x3600_0000 || bits == 0x3700_0000).then(|| signed_bits(code, 5, 18).wrapping_shl(2))
            }
            Self::Immd19 => {
                let bits1 = code & 0xFF00_0010;
                let bits2 = code & 0x7F00_0000;
                (bits1 == 0x5400_0000 || bits2 == 0x3400_0000 || bits2 == 0x3500_0000)
                    .then(|| signed_bits(code, 5, 23).wrapping_shl(2))
            }
            Self::Immd26 => {
                let bits = code & 0xFC00_0000;
                (bits == 0x1400_0000 || bits == 0x9400_0000).then(|| signed_bits(code, 0, 25).wrapping_shl(2))
            }
        }
    }

    fn encode(self, disp: i32, code: &mut u32) -> bool {
        let t = *code;
        let d = disp as u32;
        match self {
            Self::Immd14 => {
                let bits = t & 0x7F00_0000;
                if (bits != 0x3600_0000 && bits != 0x3700_0000) || disp % 4 != 0 || !signed_fit(disp, 16) {
                    return false;
                }
                *code = (t & 0xFFF8_001F) | (unsigned_bits(d, 2, 15) << 5);
            }
            Self::Immd19 => {
                let bits1 = t & 0xFF00_0010;
                let bits2 = t & 0x7F00_0000;
                if (bits1 != 0x5400_0000 && bits2 != 0x3400_0000 && bits2 != 0x3500_0000)
                    || disp % 4 != 0
                    || !signed_fit(disp, 21)
                {
                    return false;
                }
                *code = (t & 0xFF00_001F) | (unsigned_bits(d, 2, 20) << 5);
            }
            Self::Immd26 => {
                let bits = t & 0xFC00_0000;
                if (bits != 0x1400_0000 && bits != 0x9400_0000) || disp % 4 != 0 || !signed_fit(disp, 28) {
                    return false;
                }
                *code = (t & 0xFC00_0000) | unsigned_bits(d, 2, 27);
            }
        }
        true
    }

    pub fn read(self, instr: Rva, code: u32) -> Option<Rva> {
        if misaligned(instr, Align::Four) {
            return None;
        }
        self.decode(code).map(|disp| instr.wrapping_add(disp as u32))
    }

    pub fn write(self, instr: Rva, target: Rva, code: &mut u32) -> bool {
        if misaligned(instr, Align::Four) || misaligned(target, Align::Four) {
            return false;
        }
        self.encode(target.wrapping_sub(instr) as i32, code)
    }
}
