//! Canonical Huffman tables of deflate blocks.

use super::bits::{BitReader, BitWriter};
use crate::introsort;

/// Order in which code length code lengths are stored.
pub(super) const PERMUTATIONS: [u8; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Base length of each length code; the last entry is a guard.
pub(super) const LENGTH_BASES: [u16; 30] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
    0xFFFF,
];

pub(super) const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Base distance of each distance code; the last entry is a guard.
pub(super) const DISTANCE_BASES: [u16; 31] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577, 0xFFFF,
];

pub(super) const DISTANCE_EXTRA_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

const MAX_BITS: usize = 15;

#[derive(Clone, Copy)]
struct Code {
    /// The code with its bits reversed, as it appears in the bit stream.
    code: u16,
    alphabet: u16,
}

/// One table set per block type. Decoding uses lookup tables indexed by the
/// next `max_bits` input bits, whose entries hold `alphabet | 0x8000`;
/// encoding uses the bit-reversed code of each alphabet.
#[derive(Default)]
pub(super) struct HuffmanTable {
    codes: Vec<Code>,
    lit_len_lens: Vec<u8>,
    lit_len_lookup: Vec<u16>,
    lit_len_reversed: Vec<u16>,
    lit_len_max_bits: usize,
    distance_lens: Vec<u8>,
    distance_lookup: Vec<u16>,
    distance_reversed: Vec<u16>,
    distance_max_bits: usize,
    code_lens: Vec<u8>,
    code_lookup: Vec<u16>,
    code_reversed: Vec<u16>,
    code_max_bits: usize,
    lens: Vec<u8>,
    initialized: bool,
}

/// Assigns canonical codes to `lens`, returning the longest code length.
/// Fails when some length has more codes than it can hold.
fn assign_codes(codes: &mut Vec<Code>, lens: &[u8]) -> Option<usize> {
    let mut count = [0u16; MAX_BITS + 1];
    for &len in lens {
        count[len as usize] += 1;
    }
    let mut max_bits = MAX_BITS;
    while max_bits >= 1 && count[max_bits] == 0 {
        max_bits -= 1;
    }
    if (1..=max_bits).any(|bits| u32::from(count[bits]) > 1 << bits) {
        return None;
    }
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code = 0u16;
    count[0] = 0;
    for bits in 1..=MAX_BITS {
        code = ((u32::from(code) + u32::from(count[bits - 1])) << 1) as u16;
        next_code[bits] = code;
    }
    codes.clear();
    for (alphabet, &len) in lens.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let mut forward = next_code[len as usize];
        let mut reversed = 0u16;
        for _ in 0..len {
            reversed = (reversed << 1) | (forward & 1);
            forward >>= 1;
        }
        codes.push(Code {
            code: reversed,
            alphabet: alphabet as u16,
        });
        next_code[len as usize] = next_code[len as usize].wrapping_add(1);
    }
    Some(max_bits)
}

fn build_lookup(codes: &mut Vec<Code>, lens: &[u8], lookup: &mut [u16]) -> Option<usize> {
    let max_bits = assign_codes(codes, lens)?;
    introsort::sort_by(codes, |a, b| lens[a.alphabet as usize] > lens[b.alphabet as usize]);
    lookup[..1 << max_bits].fill(0);
    for code in codes.iter() {
        let len = lens[code.alphabet as usize] as usize;
        let entry = code.alphabet | 0x8000;
        lookup[code.code as usize] = entry;
        for fill in 1..1usize << (max_bits - len) {
            let location = (fill << len) | code.code as usize;
            if lookup[location] & 0x8000 == 0 {
                lookup[location] = entry;
            }
        }
    }
    Some(max_bits)
}

fn build_reversed(codes: &mut Vec<Code>, lens: &[u8], reversed: &mut [u16]) -> Option<usize> {
    let max_bits = assign_codes(codes, lens)?;
    introsort::sort_by(codes, |a, b| a.alphabet < b.alphabet);
    let mut next = 0;
    for (alphabet, slot) in reversed.iter_mut().enumerate() {
        if next < codes.len() && alphabet == codes[next].alphabet as usize {
            *slot = codes[next].code;
            next += 1;
        } else {
            *slot = 0;
        }
    }
    Some(max_bits)
}

fn check_counts(num_lit_len: usize, num_distance: usize, num_codes: usize) -> bool {
    num_lit_len <= 286 && num_distance <= 30 && num_codes <= 19
}

impl HuffmanTable {
    pub fn build_fixed(&mut self) -> bool {
        if self.initialized {
            return true;
        }
        self.lit_len_lens = (0..288)
            .map(|i| match i {
                0..144 => 8,
                144..256 => 9,
                256..280 => 7,
                _ => 8,
            })
            .collect();
        self.lit_len_reversed = vec![0; 288];
        self.lit_len_lookup = vec![0; 1 << 9];
        self.distance_lens = vec![5; 30];
        self.distance_reversed = vec![0; 30];
        self.distance_lookup = vec![0; 1 << 5];
        let built = (|| {
            self.lit_len_max_bits = build_lookup(&mut self.codes, &self.lit_len_lens, &mut self.lit_len_lookup)?;
            self.distance_max_bits = build_lookup(&mut self.codes, &self.distance_lens, &mut self.distance_lookup)?;
            self.lit_len_max_bits = build_reversed(&mut self.codes, &self.lit_len_lens, &mut self.lit_len_reversed)?;
            self.distance_max_bits = build_reversed(&mut self.codes, &self.distance_lens, &mut self.distance_reversed)?;
            Some(())
        })();
        self.initialized = built.is_some();
        self.initialized
    }

    /// Reads a dynamic block's table from `reader`, storing its compact puff
    /// form in `buffer`. On success `length` holds the bytes stored.
    pub fn build_dynamic_from_bits(&mut self, reader: &mut BitReader, buffer: &mut [u8], length: &mut usize) -> bool {
        if !self.initialized {
            self.code_lens = vec![0; 19];
            self.code_lookup = vec![0; 1 << 7];
            self.lit_len_lens = vec![0; 286];
            self.lit_len_lookup = vec![0; 1 << 15];
            self.distance_lens = vec![0; 30];
            self.distance_lookup = vec![0; 1 << 15];
            self.initialized = true;
        }
        if *length < 3 || !reader.cache_bits(14) {
            return false;
        }
        let mut index = 0;
        buffer[index] = reader.read_bits(5) as u8;
        index += 1;
        let num_lit_len = reader.read_bits(5) as usize + 257;
        reader.drop_bits(5);
        buffer[index] = reader.read_bits(5) as u8;
        index += 1;
        let num_distance = reader.read_bits(5) as usize + 1;
        reader.drop_bits(5);
        buffer[index] = reader.read_bits(4) as u8;
        index += 1;
        let num_codes = reader.read_bits(4) as usize + 4;
        reader.drop_bits(4);
        if !check_counts(num_lit_len, num_distance, num_codes) || *length - index < num_codes.div_ceil(2) {
            return false;
        }

        let mut odd = false;
        for &position in &PERMUTATIONS[..num_codes] {
            if !reader.cache_bits(3) {
                return false;
            }
            let len = reader.read_bits(3) as u8;
            self.code_lens[position as usize] = len;
            if odd {
                buffer[index] |= len;
                index += 1;
            } else {
                buffer[index] = len << 4;
            }
            odd = !odd;
            reader.drop_bits(3);
        }
        if odd {
            index += 1;
        }
        for &position in &PERMUTATIONS[num_codes..] {
            self.code_lens[position as usize] = 0;
        }
        let Some(code_max_bits) = build_lookup(&mut self.codes, &self.code_lens, &mut self.code_lookup) else {
            return false;
        };
        self.code_max_bits = code_max_bits;

        let mut available = *length - index;
        let mut lens = std::mem::take(&mut self.lens);
        let read = self.read_code_lengths(
            reader,
            &mut buffer[index..],
            &mut available,
            num_lit_len + num_distance,
            &mut lens,
        );
        self.lens = lens;
        if !read {
            return false;
        }
        index += available;
        self.lit_len_lens.clear();
        self.lit_len_lens.extend_from_slice(&self.lens[..num_lit_len]);
        self.distance_lens.clear();
        self.distance_lens.extend_from_slice(&self.lens[num_lit_len..]);
        let Some(lit_len_max_bits) = build_lookup(&mut self.codes, &self.lit_len_lens, &mut self.lit_len_lookup) else {
            return false;
        };
        self.lit_len_max_bits = lit_len_max_bits;
        let Some(distance_max_bits) = build_lookup(&mut self.codes, &self.distance_lens, &mut self.distance_lookup)
        else {
            return false;
        };
        self.distance_max_bits = distance_max_bits;
        *length = index;
        true
    }

    fn read_code_lengths(
        &self,
        reader: &mut BitReader,
        buffer: &mut [u8],
        length: &mut usize,
        num_codes: usize,
        lens: &mut Vec<u8>,
    ) -> bool {
        let mut index = 0;
        lens.clear();
        let mut count = 0;
        while count < num_codes {
            if !reader.cache_bits(self.code_max_bits) {
                return false;
            }
            let bits = reader.read_bits(self.code_max_bits);
            let Some((code, nbits)) = self.code_alphabet(bits) else {
                return false;
            };
            if index >= *length {
                return false;
            }
            reader.drop_bits(nbits);
            if code < 16 {
                buffer[index] = code as u8;
                index += 1;
                lens.push(code as u8);
                count += 1;
                continue;
            }
            let (copies, value) = match code {
                16 => {
                    if count == 0 || !reader.cache_bits(2) {
                        return false;
                    }
                    let extra = reader.read_bits(2);
                    buffer[index] = 16 + extra as u8;
                    reader.drop_bits(2);
                    (3 + extra as usize, lens[count - 1])
                }
                17 => {
                    if !reader.cache_bits(3) {
                        return false;
                    }
                    let extra = reader.read_bits(3);
                    buffer[index] = 20 + extra as u8;
                    reader.drop_bits(3);
                    (3 + extra as usize, 0)
                }
                18 => {
                    if !reader.cache_bits(7) {
                        return false;
                    }
                    let extra = reader.read_bits(7);
                    buffer[index] = 28 + extra as u8;
                    reader.drop_bits(7);
                    (11 + extra as usize, 0)
                }
                _ => return false,
            };
            index += 1;
            count += copies;
            lens.resize(lens.len() + copies, value);
        }
        if lens.len() != num_codes {
            return false;
        }
        *length = index;
        true
    }

    /// Writes the dynamic block table stored in compact puff form in `buffer`.
    pub fn build_dynamic_to_bits(&mut self, buffer: &[u8], writer: &mut BitWriter) -> bool {
        if !self.initialized {
            self.code_lens = vec![0; 19];
            self.code_reversed = vec![0; 19];
            self.lit_len_lens = vec![0; 286];
            self.lit_len_reversed = vec![0; 286];
            self.distance_lens = vec![0; 30];
            self.distance_reversed = vec![0; 30];
            self.initialized = true;
        }
        let length = buffer.len();
        if length < 3 {
            return false;
        }
        let num_lit_len = buffer[0] as usize + 257;
        let num_distance = buffer[1] as usize + 1;
        let num_codes = buffer[2] as usize + 4;
        if !writer.write_bits(5, u32::from(buffer[0]))
            || !writer.write_bits(5, u32::from(buffer[1]))
            || !writer.write_bits(4, u32::from(buffer[2]))
            || !check_counts(num_lit_len, num_distance, num_codes)
            || length - 3 < num_codes.div_ceil(2)
        {
            return false;
        }
        let mut index = 3;
        let mut odd = false;
        for &position in &PERMUTATIONS[..num_codes] {
            let len = if odd {
                let len = buffer[index] & 0x0F;
                index += 1;
                len
            } else {
                buffer[index] >> 4
            };
            odd = !odd;
            self.code_lens[position as usize] = len;
            if !writer.write_bits(3, u32::from(len)) {
                return false;
            }
        }
        if odd {
            index += 1;
        }
        for &position in &PERMUTATIONS[num_codes..] {
            self.code_lens[position as usize] = 0;
        }
        let Some(code_max_bits) = build_reversed(&mut self.codes, &self.code_lens, &mut self.code_reversed) else {
            return false;
        };
        self.code_max_bits = code_max_bits;

        let mut lens = std::mem::take(&mut self.lens);
        let written = self.write_code_lengths(&buffer[index..], writer, num_lit_len + num_distance, &mut lens);
        self.lens = lens;
        let Some(used) = written else {
            return false;
        };
        index += used;
        self.lit_len_lens.clear();
        self.lit_len_lens.extend_from_slice(&self.lens[..num_lit_len]);
        self.distance_lens.clear();
        self.distance_lens.extend_from_slice(&self.lens[num_lit_len..]);
        let Some(lit_len_max_bits) = build_reversed(&mut self.codes, &self.lit_len_lens, &mut self.lit_len_reversed)
        else {
            return false;
        };
        self.lit_len_max_bits = lit_len_max_bits;
        let Some(distance_max_bits) = build_reversed(&mut self.codes, &self.distance_lens, &mut self.distance_reversed)
        else {
            return false;
        };
        self.distance_max_bits = distance_max_bits;
        length == index
    }

    /// Writes code lengths from their compact puff form; returns the bytes used.
    fn write_code_lengths(
        &self,
        buffer: &[u8],
        writer: &mut BitWriter,
        num_codes: usize,
        lens: &mut Vec<u8>,
    ) -> Option<usize> {
        lens.clear();
        let mut index = 0;
        let mut count = 0;
        while count < num_codes {
            let pcode = *buffer.get(index)?;
            index += 1;
            if pcode > 155 {
                return None;
            }
            let code = match pcode {
                0..16 => pcode,
                16..20 => 16,
                20..28 => 17,
                _ => 18,
            };
            let (huffman, nbits) = self.code_huffman(code)?;
            if !writer.write_bits(nbits, u32::from(huffman)) {
                return None;
            }
            if code < 16 {
                lens.push(code);
                count += 1;
                continue;
            }
            let (copies, value) = match code {
                16 => {
                    if count == 0 || !writer.write_bits(2, u32::from(pcode - 16)) {
                        return None;
                    }
                    (3 + (pcode - 16) as usize, lens[count - 1])
                }
                17 => {
                    if !writer.write_bits(3, u32::from(pcode - 20)) {
                        return None;
                    }
                    (3 + (pcode - 20) as usize, 0)
                }
                _ => {
                    if !writer.write_bits(7, u32::from(pcode - 28)) {
                        return None;
                    }
                    (11 + (pcode - 28) as usize, 0)
                }
            };
            count += copies;
            lens.resize(lens.len() + copies, value);
        }
        (lens.len() == num_codes).then_some(index)
    }

    pub fn lit_len_max_bits(&self) -> usize {
        self.lit_len_max_bits
    }

    pub fn distance_max_bits(&self) -> usize {
        self.distance_max_bits
    }

    fn code_alphabet(&self, bits: u32) -> Option<(u16, usize)> {
        let entry = self.code_lookup[bits as usize];
        (entry & 0x8000 != 0).then(|| {
            let alphabet = entry & 0x7FFF;
            (alphabet, self.code_lens[alphabet as usize] as usize)
        })
    }

    /// Decodes a literal/length alphabet from the next input bits.
    pub fn lit_len_alphabet(&self, bits: u32) -> Option<(u16, usize)> {
        let entry = self.lit_len_lookup[bits as usize];
        (entry & 0x8000 != 0).then(|| {
            let alphabet = entry & 0x7FFF;
            (alphabet, self.lit_len_lens[alphabet as usize] as usize)
        })
    }

    pub fn distance_alphabet(&self, bits: u32) -> Option<(u16, usize)> {
        let entry = self.distance_lookup[bits as usize];
        (entry & 0x8000 != 0).then(|| {
            let alphabet = entry & 0x7FFF;
            (alphabet, self.distance_lens[alphabet as usize] as usize)
        })
    }

    pub fn end_of_block_bit_length(&self) -> Option<usize> {
        self.lit_len_lens.get(256).map(|&len| len as usize)
    }

    fn code_huffman(&self, alphabet: u8) -> Option<(u16, usize)> {
        let alphabet = alphabet as usize;
        (alphabet < self.code_lens.len()).then(|| (self.code_reversed[alphabet], self.code_lens[alphabet] as usize))
    }

    pub fn lit_len_huffman(&self, alphabet: u16) -> Option<(u16, usize)> {
        let alphabet = alphabet as usize;
        (alphabet < self.lit_len_lens.len())
            .then(|| (self.lit_len_reversed[alphabet], self.lit_len_lens[alphabet] as usize))
    }

    pub fn distance_huffman(&self, alphabet: u16) -> Option<(u16, usize)> {
        let alphabet = alphabet as usize;
        (alphabet < self.distance_lens.len())
            .then(|| (self.distance_reversed[alphabet], self.distance_lens[alphabet] as usize))
    }
}
