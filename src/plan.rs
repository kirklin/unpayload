//! What building one partition's image takes, checked before anything is
//! written or read.

use std::ops::Range;
use std::path::Path;

use crate::error::{Error, Result, ensure};
use crate::extent::{byte_range, byte_ranges, ensure_disjoint, gaps};
use crate::metadata::{OperationType, PartitionUpdate};
use crate::partition::{self, operation_type};
use crate::payload::Payload;
use crate::source::SourceImage;

pub(crate) struct Plan<'p> {
    pub update: &'p PartitionUpdate,
    pub name: &'p str,
    /// Size of the image in bytes.
    pub size: u64,
    pub block_size: u64,
    /// Type of every operation, in the order of the operations.
    pub kinds: Vec<OperationType>,
    /// Byte ranges the operations write, sorted and disjoint.
    pub written: Vec<Range<u64>>,
}

impl<'p> Plan<'p> {
    /// Validates a partition update: its name, its size and every operation.
    pub fn new(payload: &Payload, update: &'p PartitionUpdate) -> Result<Self> {
        let name = update.partition_name.as_str();
        let in_partition = |error: Error| Error::Partition {
            partition: name.to_owned(),
            source: Box::new(error),
        };
        ensure!(
            !name.is_empty() && !name.contains(['/', '\\']) && name != "." && name != "..",
            Error::invalid(format!("unusable partition name {name:?}"))
        );
        let block_size = u64::from(payload.block_size());
        let size = partition::new_size(update)
            .ok_or_else(|| in_partition(Error::invalid("the manifest gives no image size")))?;
        let image_end = size.div_ceil(block_size) * block_size;
        let data_size = payload.size() - payload.data_offset();

        let mut kinds = Vec::with_capacity(update.operations.len());
        let mut written = Vec::new();
        for (index, op) in update.operations.iter().enumerate() {
            let in_operation = |error: Error| Error::Operation {
                partition: name.to_owned(),
                index,
                kind: operation_type(op).map_or("unknown", OperationType::name),
                source: Box::new(error),
            };
            let kind = operation_type(op)
                .ok_or_else(|| in_operation(Error::invalid(format!("unsupported operation type {}", op.r#type))))?;
            ensure!(
                kind != OperationType::Move,
                in_operation(Error::invalid(
                    "MOVE operations update a partition in place and cannot be extracted"
                ))
            );
            let dst = byte_ranges(&op.dst_extents, block_size).map_err(in_operation)?;
            ensure!(
                dst.iter().all(|range| range.end <= image_end),
                in_operation(Error::invalid("destination extents run past the end of the image"))
            );
            ensure!(
                op.data_offset()
                    .checked_add(op.data_length())
                    .is_some_and(|end| end <= data_size),
                in_operation(Error::invalid("operation data runs past the end of the payload"))
            );
            written.extend(dst);
            kinds.push(kind);
        }
        ensure_disjoint(&mut written).map_err(in_partition)?;

        Ok(Self {
            update,
            name,
            size,
            block_size,
            kinds,
            written,
        })
    }

    pub fn in_partition(&self, error: Error) -> Error {
        Error::Partition {
            partition: self.name.to_owned(),
            source: Box::new(error),
        }
    }

    /// Opens the source image in `source_dir` when the partition is built
    /// from one.
    pub fn source(&self, source_dir: Option<&Path>) -> Result<Option<SourceImage>> {
        if !partition::reads_source(self.update) {
            return Ok(None);
        }
        let dir = source_dir.ok_or_else(|| Error::MissingSource(self.name.to_owned()))?;
        let path = dir.join(format!("{}.img", self.name));
        let image = SourceImage::open(&path)?;
        if let Some(expected) = self.update.old_partition_info.as_ref().and_then(|info| info.size) {
            ensure!(
                image.size() >= expected,
                Error::Source(format!(
                    "{} is {} bytes, the payload updates an image of {expected} bytes",
                    path.display(),
                    image.size()
                ))
            );
        }
        Ok(Some(image))
    }

    /// Byte ranges of the dm-verity hash tree and of the FEC parity, each
    /// empty when the payload leaves none to compute.
    pub fn verity(&self) -> Result<(Range<u64>, Range<u64>)> {
        let tree = byte_range(self.update.hash_tree_extent, self.block_size).map_err(|e| self.in_partition(e))?;
        let fec = byte_range(self.update.fec_extent, self.block_size).map_err(|e| self.in_partition(e))?;
        Ok((tree, fec))
    }

    /// Byte ranges no operation writes and no verity data fills, which an
    /// incremental payload leaves as they are in the source image.
    pub fn fallthrough(&self, source: Option<&SourceImage>, tree: &Range<u64>, fec: &Range<u64>) -> Vec<Range<u64>> {
        let Some(image) = source else {
            return Vec::new();
        };
        let mut covered = self.written.clone();
        covered.extend([tree.clone(), fec.clone()]);
        covered.sort_unstable_by_key(|range| range.start);
        gaps(&covered, self.size.min(image.size()))
    }
}
