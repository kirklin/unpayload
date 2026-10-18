//! bsdiff patches, in the classic `BSDIFF40` format and the `BSDF2` variant.
//!
//! A patch starts with a 32-byte header: an 8-byte magic, then the control
//! stream length, the diff stream length and the size of the new file, each an
//! 8-byte little-endian sign-magnitude integer. The three compressed streams
//! follow. `BSDIFF40` compresses all of them with bzip2; in `BSDF2` the bytes
//! after the 5-byte magic select bzip2 (1) or brotli (2) for each stream.
//!
//! The control stream is a sequence of triples `(diff, extra, seek)`: add
//! `diff` bytes of the diff stream to as many old bytes, copy `extra` bytes of
//! the extra stream, then move the old position by `seek`. Old bytes outside
//! the old file count as zero.

use std::io::Read;

use crate::error::{Error, Result, ensure};
use crate::sink::Sink;

const HEADER_LEN: usize = 32;

fn corrupt(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::patch("bsdiff", message)
}

fn sign_magnitude(bytes: &[u8]) -> i64 {
    let raw = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let magnitude = (raw & i64::MAX as u64) as i64;
    if raw >> 63 == 1 { -magnitude } else { magnitude }
}

fn decoder<'a>(kind: u8, data: &'a [u8]) -> Result<Box<dyn Read + 'a>> {
    Ok(match kind {
        1 => Box::new(bzip2::read::BzDecoder::new(data)),
        2 => Box::new(brotli_decompressor::Decompressor::new(data, 1 << 16)),
        _ => return Err(corrupt(format!("unknown stream compressor {kind}"))),
    })
}

/// Size of the file `patch` produces.
pub(crate) fn new_size(patch: &[u8]) -> Result<u64> {
    ensure!(patch.len() >= HEADER_LEN, corrupt("patch is shorter than its header"));
    let size = sign_magnitude(&patch[24..32]);
    ensure!(size >= 0, corrupt("negative new file size"));
    Ok(size as u64)
}

/// Applies `patch` to `old`, sending the new file to `out`.
pub(crate) fn apply(old: &[u8], patch: &[u8], out: &mut impl Sink) -> Result<()> {
    ensure!(patch.len() >= HEADER_LEN, corrupt("patch is shorter than its header"));
    let kinds = if &patch[..8] == b"BSDIFF40" {
        [1, 1, 1]
    } else if &patch[..5] == b"BSDF2" {
        [patch[5], patch[6], patch[7]]
    } else {
        return Err(corrupt("unknown patch magic"));
    };
    let ctrl_len = sign_magnitude(&patch[8..16]);
    let diff_len = sign_magnitude(&patch[16..24]);
    let new_size = new_size(patch)?;
    let body = &patch[HEADER_LEN..];
    ensure!(
        ctrl_len >= 0 && diff_len >= 0 && ctrl_len as u64 <= body.len() as u64,
        corrupt("stream lengths exceed the patch")
    );
    let (ctrl, rest) = body.split_at(ctrl_len as usize);
    ensure!(
        diff_len as u64 <= rest.len() as u64,
        corrupt("stream lengths exceed the patch")
    );
    let (diff, extra) = rest.split_at(diff_len as usize);
    let mut ctrl = decoder(kinds[0], ctrl)?;
    let mut diff = decoder(kinds[1], diff)?;
    let mut extra = decoder(kinds[2], extra)?;

    let read = |stream: &mut Box<dyn Read + '_>, buf: &mut [u8], what: &'static str| {
        stream
            .read_exact(buf)
            .map_err(|e| corrupt(format!("reading {what} stream: {e}")))
    };

    let mut buf = vec![0u8; 1 << 20];
    let mut new_pos = 0u64;
    let mut old_pos = 0i64;
    while new_pos < new_size {
        let mut triple = [0u8; 24];
        read(&mut ctrl, &mut triple, "control")?;
        let diff_size = sign_magnitude(&triple[0..8]);
        let extra_size = sign_magnitude(&triple[8..16]);
        let seek = sign_magnitude(&triple[16..24]);
        ensure!(diff_size >= 0 && extra_size >= 0, corrupt("negative block length"));
        let (diff_size, extra_size) = (diff_size as u64, extra_size as u64);
        ensure!(
            diff_size <= new_size - new_pos,
            corrupt("diff block runs past the new file")
        );

        let mut remaining = diff_size;
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            let chunk = &mut buf[..n];
            read(&mut diff, chunk, "diff")?;
            add_old(chunk, old, old_pos);
            out.put(chunk)?;
            old_pos = old_pos.checked_add(n as i64).ok_or(corrupt("old position overflows"))?;
            remaining -= n as u64;
        }
        new_pos += diff_size;

        ensure!(
            extra_size <= new_size - new_pos,
            corrupt("extra block runs past the new file")
        );
        let mut remaining = extra_size;
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            read(&mut extra, &mut buf[..n], "extra")?;
            out.put(&buf[..n])?;
            remaining -= n as u64;
        }
        new_pos += extra_size;
        old_pos = old_pos.checked_add(seek).ok_or(corrupt("old position overflows"))?;
    }
    Ok(())
}

/// Adds the old bytes at `old_pos..` to `chunk`, treating bytes outside `old`
/// as zero.
fn add_old(chunk: &mut [u8], old: &[u8], old_pos: i64) {
    let len = chunk.len() as i64;
    let start = old_pos.clamp(0, old.len() as i64);
    let end = old_pos.saturating_add(len).clamp(0, old.len() as i64);
    if start >= end {
        return;
    }
    let skip = (start - old_pos) as usize;
    let old = &old[start as usize..end as usize];
    for (byte, old) in chunk[skip..skip + old.len()].iter_mut().zip(old) {
        *byte = byte.wrapping_add(*old);
    }
}
