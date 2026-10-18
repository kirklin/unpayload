//! Converting deflate streams into puff form.
//!
//! A puff stream keeps the LZ77 structure of a deflate stream but stores it
//! byte-aligned:
//!
//! - block metadata: a 16-bit big-endian length minus one, then a header byte
//!   (final bit at 0x80, block type at 0x60, and for stored blocks the five
//!   padding bits deflate skips), followed for dynamic blocks by the Huffman
//!   table in compact form;
//! - a literal run: one byte `length - 1` for up to 127 literals, otherwise
//!   0x7F and a 16-bit big-endian `length - 128`; then the literals;
//! - a copy: `0x80 | (length - 3)` for lengths up to 129, otherwise 0xFF and
//!   `length - 130`; then the distance minus one as 16-bit big-endian;
//! - end of block: 0xFF 0x81.

use super::bits::BitReader;
use super::huffman::{DISTANCE_BASES, DISTANCE_EXTRA_BITS, HuffmanTable, LENGTH_BASES, LENGTH_EXTRA_BITS};

/// Largest block metadata: header byte, three counts and every code length.
pub(super) const MAX_METADATA: usize = 1 + 3 + 286 + 30 + 19;
const MAX_LITERAL_RUN: usize = (1 << 16) + 127;

pub(super) enum PuffData<'a> {
    Literal(u8),
    Literals(&'a [u8]),
    LenDist { length: usize, distance: usize },
    BlockMetadata(&'a [u8]),
    EndOfBlock,
}

#[derive(PartialEq, Eq)]
enum State {
    NonLiteral,
    SmallLiterals,
    LargeLiterals,
}

pub(super) struct PuffWriter<'a> {
    out: &'a mut [u8],
    index: usize,
    run_start: usize,
    run_length: usize,
    state: State,
}

impl<'a> PuffWriter<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self {
            out,
            index: 0,
            run_start: 0,
            run_length: 0,
            state: State::NonLiteral,
        }
    }

    pub fn insert(&mut self, data: PuffData) -> bool {
        match data {
            PuffData::Literals([]) => true,
            PuffData::Literal(_) | PuffData::Literals(_) => {
                let length = match data {
                    PuffData::Literals(bytes) => bytes.len(),
                    _ => 1,
                };
                if self.state == State::NonLiteral {
                    self.run_start = self.index;
                    self.index += 1;
                    self.state = State::SmallLiterals;
                }
                if self.state == State::SmallLiterals && self.run_length + length > 127 {
                    if self.index + 2 > self.out.len() {
                        return false;
                    }
                    let from = self.run_start + 1;
                    self.out.copy_within(from..from + self.run_length, from + 2);
                    self.index += 2;
                    self.state = State::LargeLiterals;
                }
                if self.index + length > self.out.len() {
                    return false;
                }
                match data {
                    PuffData::Literal(byte) => self.out[self.index] = byte,
                    PuffData::Literals(bytes) => self.out[self.index..self.index + length].copy_from_slice(bytes),
                    _ => unreachable!(),
                }
                self.index += length;
                self.run_length += length;
                self.run_length != MAX_LITERAL_RUN || self.flush_literals()
            }
            PuffData::LenDist { length, distance } => {
                if !self.flush_literals() || !(3..=258).contains(&length) || !(1..=32768).contains(&distance) {
                    return false;
                }
                if length < 130 {
                    if self.index + 3 > self.out.len() {
                        return false;
                    }
                    self.out[self.index] = 0x80 | (length - 3) as u8;
                    self.index += 1;
                } else {
                    if self.index + 4 > self.out.len() {
                        return false;
                    }
                    self.out[self.index] = 0xFF;
                    self.out[self.index + 1] = (length - 3 - 127) as u8;
                    self.index += 2;
                }
                self.out[self.index..self.index + 2].copy_from_slice(&((distance - 1) as u16).to_be_bytes());
                self.index += 2;
                self.run_start = self.index;
                self.state = State::NonLiteral;
                true
            }
            PuffData::BlockMetadata(metadata) => {
                if !self.flush_literals()
                    || metadata.is_empty()
                    || metadata.len() > MAX_METADATA
                    || self.index + metadata.len() + 2 > self.out.len()
                {
                    return false;
                }
                self.out[self.index..self.index + 2].copy_from_slice(&((metadata.len() - 1) as u16).to_be_bytes());
                self.index += 2;
                self.out[self.index..self.index + metadata.len()].copy_from_slice(metadata);
                self.index += metadata.len();
                self.run_start = self.index;
                self.state = State::NonLiteral;
                true
            }
            PuffData::EndOfBlock => {
                if !self.flush_literals() || self.index + 2 > self.out.len() {
                    return false;
                }
                self.out[self.index] = 0xFF;
                self.out[self.index + 1] = (259 - 3 - 127) as u8;
                self.index += 2;
                self.run_start = self.index;
                self.state = State::NonLiteral;
                true
            }
        }
    }

    fn flush_literals(&mut self) -> bool {
        if self.run_length == 0 {
            return true;
        }
        match self.state {
            State::SmallLiterals => {
                if self.run_length != self.index - self.run_start - 1 {
                    return false;
                }
                self.out[self.run_start] = (self.run_length - 1) as u8;
            }
            State::LargeLiterals => {
                if self.run_length != self.index - self.run_start - 3 {
                    return false;
                }
                self.out[self.run_start] = 127;
                self.out[self.run_start + 1..self.run_start + 3]
                    .copy_from_slice(&((self.run_length - 127 - 1) as u16).to_be_bytes());
            }
            State::NonLiteral => {}
        }
        if self.state != State::NonLiteral {
            self.run_start = self.index;
            self.state = State::NonLiteral;
        }
        self.run_length = 0;
        true
    }

    pub fn flush(&mut self) -> bool {
        self.flush_literals()
    }

    pub fn size(&self) -> usize {
        self.index
    }
}

/// Converts every deflate block that starts within `reader` into puff form,
/// stopping once fewer than eight bits remain.
#[derive(Default)]
pub(super) struct Puffer {
    dynamic: HuffmanTable,
    fixed: HuffmanTable,
}

impl Puffer {
    pub fn puff_deflate(&mut self, reader: &mut BitReader, writer: &mut PuffWriter) -> bool {
        let mut metadata = [0u8; MAX_METADATA];
        while reader.cache_bits(8) {
            if !reader.cache_bits(3) {
                return false;
            }
            let final_bit = reader.read_bits(1) as u8;
            reader.drop_bits(1);
            let kind = reader.read_bits(2) as u8;
            reader.drop_bits(2);
            let header = (final_bit << 7) | (kind << 5);
            let table = match kind {
                0 => {
                    let skipped = reader.read_boundary_bits();
                    reader.skip_boundary_bits();
                    if !reader.cache_bits(32) {
                        return false;
                    }
                    let len = reader.read_bits(16);
                    reader.drop_bits(16);
                    let nlen = reader.read_bits(16);
                    reader.drop_bits(16);
                    if len ^ nlen != 0xFFFF {
                        return false;
                    }
                    if !writer.insert(PuffData::BlockMetadata(&[header | skipped])) {
                        return false;
                    }
                    let Some(bytes) = reader.take_bytes(len as usize) else {
                        return false;
                    };
                    if !writer.insert(PuffData::Literals(bytes)) || !writer.insert(PuffData::EndOfBlock) {
                        return false;
                    }
                    continue;
                }
                1 => {
                    self.fixed.build_fixed();
                    if !writer.insert(PuffData::BlockMetadata(&[header])) {
                        return false;
                    }
                    &self.fixed
                }
                2 => {
                    metadata[0] = header;
                    let mut length = MAX_METADATA - 1;
                    if !self
                        .dynamic
                        .build_dynamic_from_bits(reader, &mut metadata[1..], &mut length)
                        || !writer.insert(PuffData::BlockMetadata(&metadata[..length + 1]))
                    {
                        return false;
                    }
                    &self.dynamic
                }
                _ => return false,
            };
            if !puff_block(table, reader, writer) {
                return false;
            }
        }
        writer.flush()
    }
}

/// Converts the compressed symbols of one block, up to and including its end
/// of block symbol.
fn puff_block(table: &HuffmanTable, reader: &mut BitReader, writer: &mut PuffWriter) -> bool {
    loop {
        let mut max_bits = table.lit_len_max_bits();
        if !reader.cache_bits(max_bits) {
            match table.end_of_block_bit_length() {
                Some(bits) => max_bits = bits,
                None => return false,
            }
        }
        if !reader.cache_bits(max_bits) {
            return false;
        }
        let Some((alphabet, nbits)) = table.lit_len_alphabet(reader.read_bits(max_bits)) else {
            return false;
        };
        reader.drop_bits(nbits);
        match alphabet {
            0..256 => {
                if !writer.insert(PuffData::Literal(alphabet as u8)) {
                    return false;
                }
            }
            256 => return writer.insert(PuffData::EndOfBlock),
            257..=285 => {
                let code = (alphabet - 257) as usize;
                let Some(extra) = read_extra(reader, LENGTH_EXTRA_BITS[code]) else {
                    return false;
                };
                let length = usize::from(LENGTH_BASES[code]) + extra;

                let mut bits = table.distance_max_bits();
                if !reader.cache_bits(bits) {
                    bits = reader.bits_remaining();
                    if !reader.cache_bits(bits) {
                        return false;
                    }
                }
                let Some((distance_code, nbits)) = table.distance_alphabet(reader.read_bits(bits)) else {
                    return false;
                };
                reader.drop_bits(nbits);
                let code = distance_code as usize;
                let Some(extra) = read_extra(reader, DISTANCE_EXTRA_BITS[code]) else {
                    return false;
                };
                let distance = usize::from(DISTANCE_BASES[code]) + extra;
                if !writer.insert(PuffData::LenDist { length, distance }) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn read_extra(reader: &mut BitReader, nbits: u8) -> Option<usize> {
    if nbits == 0 {
        return Some(0);
    }
    let nbits = nbits as usize;
    if !reader.cache_bits(nbits) {
        return None;
    }
    let value = reader.read_bits(nbits) as usize;
    reader.drop_bits(nbits);
    Some(value)
}
