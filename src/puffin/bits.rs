//! Bit-level reading and writing of deflate streams, least significant bit
//! first.

/// Reads bits from a byte buffer through a 32-bit cache.
pub(super) struct BitReader<'a> {
    input: &'a [u8],
    index: usize,
    cache: u32,
    cached: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            index: 0,
            cache: 0,
            cached: 0,
        }
    }

    /// Ensures at least `nbits` bits are cached; false when the input does
    /// not hold that many.
    pub fn cache_bits(&mut self, nbits: usize) -> bool {
        if (self.input.len() - self.index) * 8 + self.cached < nbits || nbits > 32 {
            return false;
        }
        while self.cached < nbits {
            self.cache |= u32::from(self.input[self.index]) << self.cached;
            self.index += 1;
            self.cached += 8;
        }
        true
    }

    /// The next `nbits` cached bits, without consuming them.
    pub fn read_bits(&self, nbits: usize) -> u32 {
        if nbits >= 32 {
            self.cache
        } else {
            self.cache & ((1 << nbits) - 1)
        }
    }

    pub fn drop_bits(&mut self, nbits: usize) {
        self.cache = if nbits >= 32 { 0 } else { self.cache >> nbits };
        self.cached -= nbits;
    }

    /// The cached bits that precede the next byte boundary.
    pub fn read_boundary_bits(&self) -> u8 {
        (self.cache & ((1 << (self.cached & 7)) - 1)) as u8
    }

    pub fn skip_boundary_bits(&mut self) {
        let nbits = self.cached & 7;
        self.cache >>= nbits;
        self.cached -= nbits;
    }

    /// Takes `length` whole bytes, starting at the first byte not fully
    /// consumed, and empties the cache.
    pub fn take_bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        self.index -= self.cached.div_ceil(8);
        self.cache = 0;
        self.cached = 0;
        let bytes = self.input.get(self.index..self.index.checked_add(length)?)?;
        self.index += length;
        Some(bytes)
    }

    /// Index of the first byte holding unconsumed bits.
    pub fn offset(&self) -> usize {
        self.index - self.cached / 8
    }

    pub fn bits_remaining(&self) -> usize {
        (self.input.len() - self.index) * 8 + self.cached
    }
}

/// Writes bits into a byte buffer through a 32-bit holder.
pub(super) struct BitWriter<'a> {
    output: &'a mut [u8],
    index: usize,
    holder: u32,
    held: usize,
}

impl<'a> BitWriter<'a> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            index: 0,
            holder: 0,
            held: 0,
        }
    }

    /// Appends the low `nbits` of `bits`. Bits of `bits` above `nbits` in its
    /// last byte are merged into the holder as well, so callers pass values
    /// that fit.
    pub fn write_bits(&mut self, mut nbits: usize, mut bits: u32) -> bool {
        if (self.output.len() - self.index) * 8 < self.held + nbits || nbits > 32 {
            return false;
        }
        while nbits > 0 {
            while self.held >= 8 {
                self.output[self.index] = self.holder as u8;
                self.index += 1;
                self.holder >>= 8;
                self.held -= 8;
            }
            while self.held < 24 && nbits > 0 {
                self.holder |= (bits & 0xFF) << self.held;
                let n = nbits.min(8);
                self.held += n;
                bits >>= n;
                nbits -= n;
            }
        }
        true
    }

    /// Appends whole bytes; the writer must be at a byte boundary.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> bool {
        if (self.output.len() - self.index) * 8 < self.held + bytes.len() * 8
            || !self.held.is_multiple_of(8)
            || !self.flush()
        {
            return false;
        }
        self.output[self.index..self.index + bytes.len()].copy_from_slice(bytes);
        self.index += bytes.len();
        true
    }

    /// Pads to the next byte boundary with the low bits of `bits`.
    pub fn write_boundary_bits(&mut self, bits: u8) -> bool {
        self.write_bits((8 - (self.held & 7)) & 7, u32::from(bits))
    }

    pub fn flush(&mut self) -> bool {
        if !self.write_boundary_bits(0) {
            return false;
        }
        while self.held > 0 {
            self.output[self.index] = self.holder as u8;
            self.index += 1;
            self.holder >>= 8;
            self.held -= 8;
        }
        true
    }

    pub fn size(&self) -> usize {
        self.index
    }
}
