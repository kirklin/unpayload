//! dm-verity metadata that incremental payloads leave for the device to
//! compute after installing a partition: the hash tree and the
//! Reed-Solomon FEC parity.

use std::ops::Range;

use rayon::prelude::*;
use sha2::Digest;

use crate::error::{Error, Result, ensure};
use crate::extent::byte_range;
use crate::fsio::NamedFile;
use crate::metadata::PartitionUpdate;
use crate::partition;

/// Recomputes the hash tree and then the FEC parity, when the manifest asks
/// for them. The FEC covers the hash tree, so the order matters.
pub(crate) fn rebuild(
    update: &PartitionUpdate,
    image: NamedFile,
    block_size: u64,
    progress: &(dyn Fn(u64) + Sync),
) -> Result<()> {
    if partition::has_hash_tree(update) {
        let data = byte_range(update.hash_tree_data_extent, block_size)?;
        let tree = byte_range(update.hash_tree_extent, block_size)?;
        let algorithm = update.hash_tree_algorithm.as_deref().unwrap_or_default();
        let salt = update.hash_tree_salt.as_deref().unwrap_or_default();
        write_hash_tree(image, block_size, data, tree.clone(), algorithm, salt)?;
        progress(tree.end - tree.start);
    }
    if partition::has_fec(update) {
        let data = byte_range(update.fec_data_extent, block_size)?;
        let fec = byte_range(update.fec_extent, block_size)?;
        write_fec(image, block_size, data, fec.clone(), update.fec_roots())?;
        progress(fec.end - fec.start);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Blake2b256,
}

impl Algorithm {
    fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            "sha384" => Self::Sha384,
            "sha512" => Self::Sha512,
            "blake2b-256" => Self::Blake2b256,
            _ => return None,
        })
    }

    fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 | Self::Blake2b256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Writes `hash(salt || block)` to the front of `out`.
    fn hash(self, salt: &[u8], block: &[u8], out: &mut [u8]) {
        fn run<D: Digest>(salt: &[u8], block: &[u8], out: &mut [u8]) {
            let digest = D::new().chain_update(salt).chain_update(block).finalize();
            out[..digest.len()].copy_from_slice(&digest);
        }
        match self {
            Self::Sha1 => run::<sha1::Sha1>(salt, block, out),
            Self::Sha256 => run::<sha2::Sha256>(salt, block, out),
            Self::Sha384 => run::<sha2::Sha384>(salt, block, out),
            Self::Sha512 => run::<sha2::Sha512>(salt, block, out),
            Self::Blake2b256 => run::<blake2::Blake2b256>(salt, block, out),
        }
    }
}

/// Blocks hashed per task when hashing the data.
const HASH_BATCH: u64 = 2048;

/// Builds the hash tree over `data` and writes it, top level first, to `tree`.
///
/// Each block is hashed together with the salt prefix, and every digest is
/// zero-padded to the next power of two. Level 0 holds the digests of the
/// data blocks; each further level holds the digests of the blocks of the
/// level below, until a level fits in one block. Levels are zero-padded to
/// whole blocks.
fn write_hash_tree(
    image: NamedFile,
    block_size: u64,
    data: Range<u64>,
    tree: Range<u64>,
    algorithm: &str,
    salt: &[u8],
) -> Result<()> {
    let algorithm = Algorithm::parse(algorithm)
        .ok_or_else(|| Error::invalid(format!("unsupported hash tree algorithm {algorithm:?}")))?;
    let hash_size = algorithm.digest_len().next_power_of_two();
    let bs = block_size as usize;
    ensure!(
        hash_size * 2 < bs,
        Error::invalid("hash tree block size is too small for its digests")
    );
    ensure!(
        tree.start >= data.end,
        Error::invalid("hash tree starts before the end of the data it covers")
    );
    let data_blocks = (data.end - data.start) / block_size;
    ensure!(data_blocks > 0, Error::invalid("hash tree covers no data"));

    let mut level = vec![0u8; (data_blocks as usize * hash_size).next_multiple_of(bs)];
    level[..data_blocks as usize * hash_size]
        .par_chunks_mut(HASH_BATCH as usize * hash_size)
        .enumerate()
        .try_for_each(|(batch, digests)| {
            let blocks = digests.len() / hash_size;
            let mut buf = vec![0u8; blocks * bs];
            let offset = data.start + batch as u64 * HASH_BATCH * block_size;
            image.read_exact_at(&mut buf, offset)?;
            for (block, digest) in buf.chunks_exact(bs).zip(digests.chunks_exact_mut(hash_size)) {
                algorithm.hash(salt, block, digest);
            }
            Ok::<_, Error>(())
        })?;

    let mut levels = vec![level];
    while levels.last().unwrap().len() > bs {
        let below = levels.last().unwrap();
        let blocks = below.len() / bs;
        let mut next = vec![0u8; (blocks * hash_size).next_multiple_of(bs)];
        next[..blocks * hash_size]
            .par_chunks_mut(hash_size)
            .zip(below.par_chunks_exact(bs))
            .for_each(|(digest, block)| algorithm.hash(salt, block, digest));
        levels.push(next);
    }

    let size: usize = levels.iter().map(Vec::len).sum();
    ensure!(
        size as u64 == tree.end - tree.start,
        Error::invalid(format!(
            "hash tree takes {size} bytes, the manifest reserves {}",
            tree.end - tree.start
        ))
    );
    let mut offset = tree.start;
    for level in levels.iter().rev() {
        image.write_all_at(level, offset)?;
        offset += level.len() as u64;
    }
    Ok(())
}

/// FEC data is interleaved in 4096-byte blocks.
const FEC_BLOCK: u64 = 4096;
/// Rounds encoded per task.
const FEC_BATCH: u64 = 64;

/// Computes Reed-Solomon parity over `data` and writes it to `fec`.
///
/// The code is RS(255, 255 - roots) over GF(2^8) with field polynomial 0x11d
/// and generator roots α^0 … α^(roots-1), α = 2. Data blocks are interleaved:
/// with `rounds = ⌈blocks / (255 - roots)⌉`, round `r` encodes, for every byte
/// position `k`, the codeword made of byte `k` of blocks `r`, `r + rounds`,
/// `r + 2·rounds`, …; blocks past the end of the data read as zeros. The parity
/// of round `r` takes `roots` bytes per position, stored in position order.
fn write_fec(image: NamedFile, block_size: u64, data: Range<u64>, fec: Range<u64>, roots: u32) -> Result<()> {
    ensure!(
        block_size == FEC_BLOCK,
        Error::invalid(format!(
            "FEC needs {FEC_BLOCK}-byte blocks, the payload uses {block_size}"
        ))
    );
    ensure!(
        (1..255).contains(&roots),
        Error::invalid(format!("unsupported FEC root count {roots}"))
    );
    ensure!(
        fec.start >= data.end,
        Error::invalid("FEC starts before the end of the data it covers")
    );
    let roots = roots as usize;
    let data_len = 255 - roots as u64;
    let blocks = (data.end - data.start) / FEC_BLOCK;
    let rounds = blocks.div_ceil(data_len);
    ensure!(
        rounds * roots as u64 * FEC_BLOCK == fec.end - fec.start,
        Error::invalid(format!(
            "FEC takes {} bytes, the manifest reserves {}",
            rounds * roots as u64 * FEC_BLOCK,
            fec.end - fec.start
        ))
    );

    let encoder = Encoder::new(roots);
    let bs = FEC_BLOCK as usize;
    (0..rounds.div_ceil(FEC_BATCH)).into_par_iter().try_for_each(|batch| {
        let first = batch * FEC_BATCH;
        let width = FEC_BATCH.min(rounds - first);
        let mut symbols = vec![0u8; width as usize * bs];
        let mut parity = vec![0u8; width as usize * bs * roots];
        for j in 0..data_len {
            let start = j * rounds + first;
            let present = width.min(blocks.saturating_sub(start)) as usize;
            if present > 0 {
                let offset = data.start + start * FEC_BLOCK;
                image.read_exact_at(&mut symbols[..present * bs], offset)?;
            }
            symbols[present * bs..].fill(0);
            encoder.update(&mut parity, &symbols);
        }
        let offset = fec.start + first * roots as u64 * FEC_BLOCK;
        image.write_all_at(&parity, offset)
    })
}

/// Systematic Reed-Solomon encoder that feeds codewords symbol by symbol.
struct Encoder {
    roots: usize,
    /// `products[j][f]` is `f` times the coefficient of `x^(roots-1-j)` of the
    /// generator polynomial.
    products: Vec<[u8; 256]>,
}

impl Encoder {
    fn new(roots: usize) -> Self {
        let mut generator = vec![0u8; roots + 1];
        generator[0] = 1;
        let mut root = 1u8;
        for i in 0..roots {
            for k in (1..=i + 1).rev() {
                generator[k] = generator[k - 1] ^ gf_mul(generator[k], root);
            }
            generator[0] = gf_mul(generator[0], root);
            root = gf_mul(root, 2);
        }
        let products = (0..roots)
            .map(|j| std::array::from_fn(|f| gf_mul(generator[roots - 1 - j], f as u8)))
            .collect();
        Self { roots, products }
    }

    /// Shifts the next symbol of many codewords into their parity registers:
    /// `symbols[i]` belongs to the codeword whose register is
    /// `parity[i * roots..(i + 1) * roots]`.
    fn update(&self, parity: &mut [u8], symbols: &[u8]) {
        if self.roots == 2 {
            let (low, high) = (&self.products[0], &self.products[1]);
            for (register, &symbol) in parity.as_chunks_mut::<2>().0.iter_mut().zip(symbols) {
                let feedback = (symbol ^ register[0]) as usize;
                register[0] = register[1] ^ low[feedback];
                register[1] = high[feedback];
            }
            return;
        }
        for (register, &symbol) in parity.chunks_exact_mut(self.roots).zip(symbols) {
            let feedback = (symbol ^ register[0]) as usize;
            for j in 0..self.roots - 1 {
                register[j] = register[j + 1] ^ self.products[j][feedback];
            }
            register[self.roots - 1] = self.products[self.roots - 1][feedback];
        }
    }
}

/// Multiplication in GF(2^8) with field polynomial x^8 + x^4 + x^3 + x^2 + 1.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evaluates a polynomial given highest coefficient first.
    fn evaluate(coefficients: &[u8], x: u8) -> u8 {
        coefficients.iter().fold(0, |acc, &c| gf_mul(acc, x) ^ c)
    }

    #[test]
    fn codewords_vanish_at_generator_roots() {
        for roots in [2, 3, 8, 24] {
            let encoder = Encoder::new(roots);
            let message: Vec<u8> = (0..255 - roots).map(|i| (i * 37 + roots) as u8).collect();
            let mut parity = vec![0u8; roots];
            for &symbol in &message {
                encoder.update(&mut parity, &[symbol]);
            }
            let codeword: Vec<u8> = message.iter().chain(&parity).copied().collect();
            let mut root = 1u8;
            for _ in 0..roots {
                assert_eq!(evaluate(&codeword, root), 0, "roots = {roots}");
                root = gf_mul(root, 2);
            }
        }
    }
}
