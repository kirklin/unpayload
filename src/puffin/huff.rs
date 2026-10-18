//! Converting puff streams back into deflate streams.

use super::bits::BitWriter;
use super::huffman::{DISTANCE_BASES, DISTANCE_EXTRA_BITS, HuffmanTable, LENGTH_BASES, LENGTH_EXTRA_BITS};
use super::puff::{MAX_METADATA, PuffData};

#[derive(PartialEq, Eq)]
enum State {
    BlockMetadata,
    LenDist,
}

pub(super) struct PuffReader<'a> {
    input: &'a [u8],
    index: usize,
    state: State,
}

impl<'a> PuffReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            index: 0,
            state: State::BlockMetadata,
        }
    }

    pub fn bytes_left(&self) -> usize {
        self.input.len() - self.index
    }

    fn u16_at(&self, index: usize) -> usize {
        usize::from(u16::from_be_bytes([self.input[index], self.input[index + 1]]))
    }

    pub fn next(&mut self) -> Option<PuffData<'a>> {
        let len = self.input.len();
        if self.state == State::BlockMetadata {
            if self.index + 2 >= len {
                return None;
            }
            let length = self.u16_at(self.index) + 1;
            self.index += 2;
            if self.index + length > len || length > MAX_METADATA {
                return None;
            }
            let metadata = &self.input[self.index..self.index + length];
            self.index += length;
            self.state = State::LenDist;
            return Some(PuffData::BlockMetadata(metadata));
        }
        let tag = *self.input.get(self.index)?;
        if tag & 0x80 != 0 {
            let mut length = usize::from(tag & 0x7F);
            if length == 127 {
                self.index += 1;
                length = usize::from(*self.input.get(self.index)?) + 127;
            }
            length += 3;
            if length > 259 {
                return None;
            }
            self.index += 1;
            if length == 259 {
                self.state = State::BlockMetadata;
                return Some(PuffData::EndOfBlock);
            }
            if self.index + 1 >= len {
                return None;
            }
            let distance = self.u16_at(self.index);
            if distance >= 1 << 15 {
                return None;
            }
            self.index += 2;
            return Some(PuffData::LenDist {
                length,
                distance: distance + 1,
            });
        }
        let mut length = usize::from(tag & 0x7F);
        if length < 127 {
            self.index += 1;
        } else {
            self.index += 1;
            if self.index + 1 >= len {
                return None;
            }
            length = self.u16_at(self.index) + 127;
            self.index += 2;
        }
        length += 1;
        if self.index + length > len {
            return None;
        }
        let literals = &self.input[self.index..self.index + length];
        self.index += length;
        Some(PuffData::Literals(literals))
    }
}

/// Encodes puff blocks back into deflate blocks with their recorded tables.
#[derive(Default)]
pub(super) struct Huffer {
    dynamic: HuffmanTable,
    fixed: HuffmanTable,
}

impl Huffer {
    pub fn huff_deflate(&mut self, reader: &mut PuffReader, writer: &mut BitWriter) -> bool {
        while reader.bytes_left() != 0 {
            let Some(PuffData::BlockMetadata(metadata)) = reader.next() else {
                return false;
            };
            let header = metadata[0];
            let final_bit = (header & 0x80) >> 7;
            let kind = (header & 0x60) >> 5;
            let skipped = header & 0x1F;
            if !writer.write_bits(1, u32::from(final_bit)) || !writer.write_bits(2, u32::from(kind)) {
                return false;
            }
            let table = match kind {
                0 => {
                    writer.write_boundary_bits(skipped);
                    match reader.next() {
                        Some(PuffData::Literals(bytes)) => {
                            let length = bytes.len() as u32;
                            if !writer.write_bits(16, length)
                                || !writer.write_bits(16, !length)
                                || !writer.write_bytes(bytes)
                                || !matches!(reader.next(), Some(PuffData::EndOfBlock))
                            {
                                return false;
                            }
                        }
                        Some(PuffData::EndOfBlock) => {
                            if !writer.write_bits(16, 0) || !writer.write_bits(16, !0) {
                                return false;
                            }
                        }
                        _ => return false,
                    }
                    continue;
                }
                1 => {
                    self.fixed.build_fixed();
                    &self.fixed
                }
                2 => {
                    if !self.dynamic.build_dynamic_to_bits(&metadata[1..], writer) {
                        return false;
                    }
                    &self.dynamic
                }
                _ => return false,
            };
            if !huff_block(table, reader, writer) {
                return false;
            }
        }
        writer.flush()
    }
}

fn huff_block(table: &HuffmanTable, reader: &mut PuffReader, writer: &mut BitWriter) -> bool {
    let write_literal = |writer: &mut BitWriter, literal: u8| {
        table
            .lit_len_huffman(u16::from(literal))
            .is_some_and(|(code, nbits)| writer.write_bits(nbits, u32::from(code)))
    };
    loop {
        match reader.next() {
            Some(PuffData::Literal(literal)) => {
                if !write_literal(writer, literal) {
                    return false;
                }
            }
            Some(PuffData::Literals(literals)) => {
                for &literal in literals {
                    if !write_literal(writer, literal) {
                        return false;
                    }
                }
            }
            Some(PuffData::LenDist { length, distance }) => {
                if !(3..=258).contains(&length) {
                    return false;
                }
                let code = base_index(&LENGTH_BASES, length);
                let Some((huffman, nbits)) = table.lit_len_huffman(code as u16 + 257) else {
                    return false;
                };
                if !writer.write_bits(nbits, u32::from(huffman)) {
                    return false;
                }
                let extra = LENGTH_EXTRA_BITS[code];
                if extra > 0 && !writer.write_bits(extra as usize, (length - usize::from(LENGTH_BASES[code])) as u32) {
                    return false;
                }
                let code = base_index(&DISTANCE_BASES, distance);
                let Some((huffman, nbits)) = table.distance_huffman(code as u16) else {
                    return false;
                };
                if !writer.write_bits(nbits, u32::from(huffman)) {
                    return false;
                }
                let extra = DISTANCE_EXTRA_BITS[code];
                if extra > 0
                    && !writer.write_bits(extra as usize, (distance - usize::from(DISTANCE_BASES[code])) as u32)
                {
                    return false;
                }
            }
            Some(PuffData::EndOfBlock) => {
                return table
                    .lit_len_huffman(256)
                    .is_some_and(|(code, nbits)| writer.write_bits(nbits, u32::from(code)));
            }
            Some(PuffData::BlockMetadata(_)) | None => return false,
        }
    }
}

/// Index of the last base not greater than `value`.
fn base_index(bases: &[u16], value: usize) -> usize {
    let mut index = 0;
    while value > usize::from(bases[index]) {
        index += 1;
    }
    if value < usize::from(bases[index]) {
        index -= 1;
    }
    index
}
