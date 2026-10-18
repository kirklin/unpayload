//! Executes a single install operation against the target image.

use crate::error::{Error, Result, ensure};
use crate::extent::{ExtentWriter, byte_ranges};
use crate::fsio::NamedFile;
use crate::metadata::{InstallOperation, OperationType};

pub(crate) struct Target<'a> {
    pub image: NamedFile<'a>,
    pub block_size: u64,
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
        kind => Err(Error::invalid(format!(
            "{} operations patch a source image, which is not supported",
            kind.name()
        ))),
    }
}

/// Upper bound of the memory an operation holds while it runs.
pub(crate) fn memory(op: &InstallOperation) -> u64 {
    op.data_length()
}

fn ensure_consumed(rest: &[u8]) -> Result<()> {
    ensure!(
        rest.is_empty(),
        Error::invalid("trailing bytes after the compressed operation data")
    );
    Ok(())
}
