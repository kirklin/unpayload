//! Executes a single install operation against the target image.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result, ensure, hex};
use crate::extent::{ExtentWriter, byte_ranges, total_len};
use crate::fsio::NamedFile;
use crate::metadata::{InstallOperation, OperationType};
use crate::source::SourceImage;
use crate::{bsdiff, puffin, zucchini};

pub(crate) struct Target<'a> {
    pub image: NamedFile<'a>,
    pub block_size: u64,
    pub source: Option<&'a SourceImage>,
}

/// Runs `op` with its operation `data`, writing into the target image.
pub(crate) fn execute(op: &InstallOperation, kind: OperationType, data: &[u8], target: &Target) -> Result<()> {
    let dst = byte_ranges(&op.dst_extents, target.block_size)?;
    let mut out = ExtentWriter::new(target.image, &dst);
    match kind {
        OperationType::Replace => out.write(data),
        OperationType::ReplaceBz => {
            let mut decoder = bzip2::bufread::BzDecoder::new(data);
            out.copy_from(&mut decoder)?;
            ensure_consumed(decoder.into_inner())
        }
        OperationType::ReplaceXz => {
            let mut decoder = liblzma::bufread::XzDecoder::new(data);
            out.copy_from(&mut decoder)?;
            ensure_consumed(decoder.into_inner())
        }
        OperationType::ReplaceZstd => {
            let decoder =
                zstd::stream::read::Decoder::with_buffer(data).map_err(|e| Error::invalid(format!("zstd: {e}")))?;
            out.copy_from(decoder)
        }
        // The target image starts out zero-filled.
        OperationType::Zero | OperationType::Discard => Ok(()),
        OperationType::SourceCopy => out.write(&source_data(op, target)?),
        OperationType::SourceBsdiff | OperationType::BrotliBsdiff | OperationType::Bsdiff => {
            bsdiff::apply(&source_data(op, target)?, data, &mut out)
        }
        OperationType::Puffdiff => puffin::apply(&source_data(op, target)?, data, &mut out),
        OperationType::Zucchini => {
            let src = source_data(op, target)?;
            let patch = brotli_decode(data)?;
            let new = zucchini::apply(&src, &patch)?;
            ensure!(
                new.len() as u64 == total_len(&dst),
                Error::patch("zucchini", "new file size differs from the destination extents")
            );
            out.write(&new)
        }
        OperationType::Move => Err(Error::invalid(
            "MOVE operations update a partition in place and cannot be extracted",
        )),
        kind => Err(Error::invalid(format!("{} operations are not supported", kind.name()))),
    }
}

/// Upper bound of the memory an operation holds while it runs.
pub(crate) fn memory(op: &InstallOperation, kind: OperationType, block_size: u64) -> u64 {
    let blocks =
        |extents: &[crate::metadata::Extent]| extents.iter().map(|e| e.num_blocks()).fold(0u64, u64::saturating_add);
    let src = blocks(&op.src_extents).saturating_mul(block_size);
    let dst = blocks(&op.dst_extents).saturating_mul(block_size);
    let data = op.data_length();
    match kind {
        OperationType::Puffdiff => src.saturating_add(dst).saturating_mul(4).saturating_add(data),
        OperationType::Zucchini => src.saturating_add(dst).saturating_mul(2).saturating_add(data),
        _ => src.saturating_add(data),
    }
}

fn ensure_consumed(rest: &[u8]) -> Result<()> {
    ensure!(
        rest.is_empty(),
        Error::invalid("trailing bytes after the compressed operation data")
    );
    Ok(())
}

fn source_data(op: &InstallOperation, target: &Target) -> Result<Vec<u8>> {
    let source = target.source.ok_or(Error::invalid(
        "operation reads a source image the partition does not use",
    ))?;
    let data = source.read(&byte_ranges(&op.src_extents, target.block_size)?)?;
    if let Some(expected) = op.src_sha256_hash.as_deref().filter(|h| !h.is_empty()) {
        let actual = Sha256::digest(&data);
        ensure!(
            actual.as_slice() == expected,
            Error::Source(format!(
                "{} is not the image this payload updates: the blocks this operation reads hash to {}, expected {}",
                source.path().display(),
                hex(&actual),
                hex(expected),
            ))
        );
    }
    Ok(data)
}

pub(crate) fn brotli_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut brotli_decompressor::Decompressor::new(data, 1 << 16), &mut out)
        .map_err(|e| Error::invalid(format!("brotli: {e}")))?;
    Ok(out)
}
