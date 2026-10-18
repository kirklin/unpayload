//! LZ4DIFF patches: diffs of LZ4-compressed filesystem data (EROFS clusters)
//! computed between the decompressed forms.
//!
//! A patch is the magic `LZ4DIFF`, a 32-bit big-endian version (1), a 32-bit
//! big-endian header length, one padding byte, the [`Header`] and an inner
//! bsdiff or puffin patch. The header lists the compressed blocks of the
//! source and the destination. Applying decompresses the source blocks,
//! patches the result, and compresses the destination blocks again with the
//! recorded algorithm, filling each block's recorded compressed length. Blocks
//! whose recompression differs from the original carry a bsdiff patch that
//! fixes them up.

use std::ffi::{c_char, c_int, c_void};

use prost::{Enumeration, Message};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result, ensure, hex};
use crate::sink::Sink;
use crate::{bsdiff, puffin};

use lz4_sys as _;

unsafe extern "C" {
    fn LZ4_decompress_safe_partial(
        src: *const c_char,
        dst: *mut c_char,
        src_size: c_int,
        target_output_size: c_int,
        dst_capacity: c_int,
    ) -> c_int;
    fn LZ4_compress_destSize(
        src: *const c_char,
        dst: *mut c_char,
        src_size: *mut c_int,
        target_dst_size: c_int,
    ) -> c_int;
    fn LZ4_createStreamHC() -> *mut c_void;
    fn LZ4_freeStreamHC(stream: *mut c_void) -> c_int;
    fn LZ4_compress_HC_destSize(
        state: *mut c_void,
        src: *const c_char,
        dst: *mut c_char,
        src_size: *mut c_int,
        target_dst_size: c_int,
        level: c_int,
    ) -> c_int;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
enum Algorithm {
    Uncompressed = 0,
    Lz4 = 1,
    Lz4hc = 2,
}

#[derive(Clone, Copy, PartialEq, Message)]
struct CompressionAlgorithm {
    #[prost(enumeration = "Algorithm", tag = "1")]
    r#type: i32,
    #[prost(int32, tag = "2")]
    level: i32,
}

#[derive(Clone, PartialEq, Message)]
struct BlockInfo {
    #[prost(uint64, tag = "1")]
    uncompressed_offset: u64,
    #[prost(uint64, tag = "2")]
    uncompressed_length: u64,
    #[prost(uint64, tag = "3")]
    compressed_length: u64,
    #[prost(bytes = "vec", tag = "4")]
    sha256_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    postfix_bspatch: Vec<u8>,
}

impl BlockInfo {
    fn is_compressed(&self) -> bool {
        self.compressed_length < self.uncompressed_length
    }
}

#[derive(Clone, PartialEq, Message)]
struct CompressionInfo {
    #[prost(message, optional, tag = "1")]
    algo: Option<CompressionAlgorithm>,
    #[prost(message, repeated, tag = "2")]
    block_info: Vec<BlockInfo>,
    #[prost(bool, tag = "3")]
    zero_padding_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
enum InnerPatchType {
    Bsdiff = 0,
    Puffdiff = 1,
}

#[derive(Clone, PartialEq, Message)]
struct Header {
    #[prost(message, optional, tag = "1")]
    src_info: Option<CompressionInfo>,
    #[prost(message, optional, tag = "2")]
    dst_info: Option<CompressionInfo>,
    #[prost(enumeration = "InnerPatchType", tag = "3")]
    inner_type: i32,
}

const MAGIC: &[u8; 7] = b"LZ4DIFF";
const HEADER_LEN: usize = 16;
const VERSION: u32 = 1;
const BLOCK_SIZE: usize = 4096;

fn corrupt(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::patch("lz4diff", message)
}

/// Applies an LZ4DIFF `patch` to `src`, sending the new data to `out`.
pub(crate) fn apply(src: &[u8], patch: &[u8], out: &mut impl Sink) -> Result<()> {
    ensure!(
        patch.len() >= HEADER_LEN && patch[..7] == *MAGIC,
        corrupt("missing LZ4DIFF magic")
    );
    let version = u32::from_be_bytes(patch[7..11].try_into().unwrap());
    ensure!(version == VERSION, corrupt(format!("unsupported version {version}")));
    let header_len = u32::from_be_bytes(patch[11..15].try_into().unwrap()) as usize;
    ensure!(
        header_len <= patch.len() - HEADER_LEN,
        corrupt("header runs past the patch")
    );
    let header =
        Header::decode(&patch[HEADER_LEN..HEADER_LEN + header_len]).map_err(|e| corrupt(format!("header: {e}")))?;
    let inner = &patch[HEADER_LEN + header_len..];
    let src_info = header.src_info.unwrap_or_default();
    let dst_info = header.dst_info.unwrap_or_default();

    let decompressed_src = decompress(src, &src_info)?;
    let mut decompressed_dst = Vec::new();
    match InnerPatchType::try_from(header.inner_type) {
        Ok(InnerPatchType::Bsdiff) => bsdiff::apply(&decompressed_src, inner, &mut decompressed_dst)?,
        Ok(InnerPatchType::Puffdiff) => puffin::apply(&decompressed_src, inner, &mut decompressed_dst)?,
        Err(_) => return Err(corrupt(format!("unknown inner patch type {}", header.inner_type))),
    }
    drop(decompressed_src);
    compress(&decompressed_dst, &dst_info, out)
}

fn check_layout(blocks: &[BlockInfo]) -> Result<(u64, u64)> {
    let mut uncompressed = 0u64;
    let mut compressed = 0u64;
    for block in blocks {
        ensure!(
            block.uncompressed_offset == uncompressed,
            corrupt("compressed blocks are not contiguous")
        );
        uncompressed = uncompressed
            .checked_add(block.uncompressed_length)
            .ok_or(corrupt("block sizes overflow"))?;
        compressed = compressed
            .checked_add(block.compressed_length)
            .ok_or(corrupt("block sizes overflow"))?;
    }
    Ok((uncompressed, compressed))
}

fn int(value: u64) -> Result<c_int> {
    c_int::try_from(value).map_err(|_| corrupt("block too large"))
}

/// Decompresses the blocks of `data`, which must consist of exactly them.
fn decompress(data: &[u8], info: &CompressionInfo) -> Result<Vec<u8>> {
    ensure!(
        !info.block_info.is_empty(),
        corrupt("source lists no compressed blocks")
    );
    let (uncompressed, compressed) = check_layout(&info.block_info)?;
    ensure!(
        data.len() as u64 == compressed,
        corrupt("source size differs from its compressed blocks")
    );
    let mut output = Vec::with_capacity(uncompressed as usize);
    let mut offset = 0usize;
    for block in &info.block_info {
        let cluster = &data[offset..offset + block.compressed_length as usize];
        offset += cluster.len();
        let length = block.uncompressed_length as usize;
        if !block.is_compressed() {
            ensure!(
                !cluster.is_empty() && length <= cluster.len(),
                corrupt("stored block is shorter than its contents")
            );
            output.extend_from_slice(&cluster[..length]);
            continue;
        }
        let margin = if info.zero_padding_enabled {
            cluster.iter().take(BLOCK_SIZE).take_while(|&&b| b == 0).count()
        } else {
            0
        };
        let input = &cluster[margin..];
        let start = output.len();
        output.resize(start + length, 0);
        let target = int(length as u64)?;
        // SAFETY: `input` and the `length` bytes after `start` are valid for
        // the sizes passed.
        let produced = unsafe {
            LZ4_decompress_safe_partial(
                input.as_ptr().cast(),
                output[start..].as_mut_ptr().cast(),
                int(input.len() as u64)?,
                target,
                target,
            )
        };
        ensure!(produced == target, corrupt("cannot decompress a source block"));
    }
    Ok(output)
}

/// Compresses `data` into the destination blocks and writes them, followed by
/// any bytes past the last block.
fn compress(data: &[u8], info: &CompressionInfo, out: &mut impl Sink) -> Result<()> {
    let (uncompressed, _) = check_layout(&info.block_info)?;
    ensure!(
        data.len() as u64 >= uncompressed,
        corrupt("patched data is shorter than its compressed blocks")
    );
    let algorithm = info.algo.unwrap_or_default();
    let hc = HcStream::new()?;
    let mut buffer = Vec::new();
    for block in &info.block_info {
        let start = block.uncompressed_offset as usize;
        let contents = &data[start..start + block.uncompressed_length as usize];
        buffer.clear();
        buffer.resize(block.compressed_length as usize, 0);
        if block.is_compressed() {
            let mut source_len = int(uncompressed - block.uncompressed_offset)?;
            let target = int(block.compressed_length)?;
            let source = data[start..].as_ptr().cast();
            let destination = buffer.as_mut_ptr().cast();
            // SAFETY: the compressor reads at most `source_len` bytes from
            // `source`, all within `data`, and writes at most `target` bytes
            // into `buffer`.
            let written = unsafe {
                match Algorithm::try_from(algorithm.r#type) {
                    Ok(Algorithm::Lz4hc) => {
                        LZ4_compress_HC_destSize(hc.0, source, destination, &mut source_len, target, algorithm.level)
                    }
                    Ok(Algorithm::Lz4) => LZ4_compress_destSize(source, destination, &mut source_len, target),
                    _ => return Err(corrupt(format!("unsupported compression {}", algorithm.r#type))),
                }
            };
            ensure!(
                written > 0 && written <= target,
                corrupt("cannot compress a destination block")
            );
            let written = written as usize;
            if written < buffer.len() && info.zero_padding_enabled {
                let padding = buffer.len() - written;
                buffer.copy_within(..written, padding);
                buffer[..padding].fill(0);
            }
        } else {
            buffer[..contents.len()].copy_from_slice(contents);
        }
        if block.postfix_bspatch.is_empty() && block.sha256_hash.is_empty() {
            out.put(&buffer)?;
            continue;
        }
        if !block.sha256_hash.is_empty() {
            let digest = Sha256::digest(&buffer);
            ensure!(
                digest.as_slice() == block.sha256_hash,
                corrupt(format!(
                    "recompressed block at {} hashes to {}, the patch expects {}",
                    block.uncompressed_offset,
                    hex(&digest),
                    hex(&block.sha256_hash)
                ))
            );
        }
        if block.postfix_bspatch.is_empty() {
            out.put(&buffer)?;
            continue;
        }
        let mut fixed = Vec::with_capacity(buffer.len());
        bsdiff::apply(&buffer, &block.postfix_bspatch, &mut fixed)?;
        ensure!(fixed.len() == buffer.len(), corrupt("fixed-up block changed size"));
        out.put(&fixed)?;
    }
    out.put(&data[uncompressed as usize..])
}

struct HcStream(*mut c_void);

impl HcStream {
    fn new() -> Result<Self> {
        // SAFETY: plain allocation, freed in `drop`.
        let stream = unsafe { LZ4_createStreamHC() };
        ensure!(!stream.is_null(), corrupt("cannot allocate the compressor"));
        Ok(Self(stream))
    }
}

impl Drop for HcStream {
    fn drop(&mut self) {
        // SAFETY: the stream came from `LZ4_createStreamHC`.
        unsafe { LZ4_freeStreamHC(self.0) };
    }
}
