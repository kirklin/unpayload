//! Reading a partition's image at arbitrary offsets without extracting it.
//!
//! A read runs only the operations that write the blocks it touches and keeps
//! what they produce, so every operation runs at most once and a remote
//! payload is fetched only where the image is read. The dm-verity hash tree
//! and FEC parity are computed from the whole image, so they can only be read
//! from an extracted one.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result, ensure};
use crate::extent::byte_ranges;
use crate::fsio::{self, NamedFile};
use crate::input::ReadAt;
use crate::metadata::{OperationType, PartitionUpdate};
use crate::operation::{self, Target};
use crate::payload::Payload;
use crate::plan::Plan;
use crate::source::SourceImage;

/// Most operation data fetched from the payload in one read.
const MAX_FETCH: u64 = 32 << 20;

#[derive(Clone, Debug)]
pub struct ImageOptions {
    /// Directory holding `<partition>.img`, the source image a partition of
    /// an incremental payload is built from.
    pub source_dir: Option<PathBuf>,
    /// Check the source data operations read against the SHA-256 hashes in
    /// the manifest. Operation data is checked either way. The image as a
    /// whole is not: only the blocks that are read are ever produced.
    pub verify: bool,
}

impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            source_dir: None,
            verify: true,
        }
    }
}

/// The image of one partition, read through [`ReadAt`]. It shares the
/// payload it was opened from and outlives it.
pub struct PartitionImage {
    payload: Payload,
    /// Index of the partition in the manifest.
    partition: usize,
    size: u64,
    block_size: u64,
    /// Type of every operation, in the order of the operations.
    kinds: Vec<OperationType>,
    /// Byte range of every destination extent with the index of the operation
    /// that writes it, sorted by start.
    writes: Vec<(Range<u64>, usize)>,
    source: Option<SourceImage>,
    /// Byte ranges read from the source image as they are.
    fallthrough: Vec<Range<u64>>,
    /// Byte ranges of the hash tree and of the FEC parity.
    verity: [Range<u64>; 2],
    /// What the operations run so far produced, each block at its place in
    /// the image; zeros everywhere else.
    produced: File,
    /// Name the errors of `produced` carry.
    label: PathBuf,
    /// Whether each operation has run.
    ran: Mutex<Vec<bool>>,
    verify: bool,
}

impl Payload {
    /// Opens the image of partition `name` for reads at arbitrary offsets.
    /// Nothing of it is produced until it is read.
    pub fn open_image(&self, name: &str, options: &ImageOptions) -> Result<PartitionImage> {
        let partition = self
            .partitions()
            .iter()
            .position(|update| update.partition_name == name)
            .ok_or_else(|| Error::UnknownPartitions(vec![name.to_owned()]))?;
        let update = &self.partitions()[partition];
        let plan = Plan::new(self, update)?;
        let source = plan.source(options.source_dir.as_deref())?;
        let (tree, fec) = plan.verity()?;
        let fallthrough = plan.fallthrough(source.as_ref(), &tree, &fec);

        let mut writes = Vec::new();
        for (index, op) in update.operations.iter().enumerate() {
            let dst = byte_ranges(&op.dst_extents, plan.block_size)?;
            writes.extend(dst.into_iter().map(|range| (range, index)));
        }
        writes.sort_unstable_by_key(|(range, _)| range.start);

        let produced = tempfile::tempfile().map_err(Error::Temporary)?;
        produced
            .set_len(plan.size.div_ceil(plan.block_size) * plan.block_size)
            .map_err(Error::Temporary)?;
        Ok(PartitionImage {
            payload: self.clone(),
            partition,
            size: plan.size,
            block_size: plan.block_size,
            kinds: plan.kinds,
            writes,
            source,
            fallthrough,
            verity: [tree, fec],
            produced,
            label: PathBuf::from(format!("{name}.img")),
            ran: Mutex::new(vec![false; update.operations.len()]),
            verify: options.verify,
        })
    }
}

impl PartitionImage {
    /// Name of the partition.
    pub fn name(&self) -> &str {
        &self.update().partition_name
    }

    fn update(&self) -> &PartitionUpdate {
        &self.payload.partitions()[self.partition]
    }

    /// Fills `buf` with the bytes of `range`, which lies within the image and
    /// outside the verity data.
    fn fill(&self, buf: &mut [u8], range: Range<u64>) -> Result<()> {
        self.run_operations(&range)?;
        fsio::read_exact_at(&self.produced, buf, range.start).map_err(Error::file(&self.label))?;
        let Some(source) = &self.source else {
            return Ok(());
        };
        for gap in overlapping(&self.fallthrough, &range) {
            let part = gap.start.max(range.start)..gap.end.min(range.end);
            let data = source.read(std::slice::from_ref(&part))?;
            buf[(part.start - range.start) as usize..(part.end - range.start) as usize].copy_from_slice(&data);
        }
        Ok(())
    }

    /// Runs the operations that write into `range` and have not run yet.
    fn run_operations(&self, range: &Range<u64>) -> Result<()> {
        let operations = &self.update().operations;
        let mut ran = self.ran.lock().unwrap();
        let first = self.writes.partition_point(|(written, _)| written.end <= range.start);
        let mut needed: Vec<usize> = self.writes[first..]
            .iter()
            .take_while(|(written, _)| written.start < range.end)
            .map(|&(_, index)| index)
            .filter(|&index| !ran[index])
            .collect();
        // Operations whose data lies together in the payload are fetched
        // together.
        needed.sort_unstable_by_key(|&index| (operations[index].data_offset(), index));
        needed.dedup();

        let mut rest = needed.as_slice();
        while let Some(&index) = rest.first() {
            let start = operations[index].data_offset();
            let mut end = start;
            let mut count = 0;
            for &index in rest {
                let op = &operations[index];
                if op.data_length() > 0 && (op.data_offset() != end || (count > 0 && end - start >= MAX_FETCH)) {
                    break;
                }
                end += op.data_length();
                count += 1;
            }
            let (group, after) = rest.split_at(count);
            let mut data = vec![0u8; (end - start) as usize];
            if !data.is_empty() {
                self.payload.read_data(start, &mut data)?;
            }
            for &index in group {
                let op = &operations[index];
                let blob = match op.data_length() {
                    0 => &[][..],
                    len => &data[(op.data_offset() - start) as usize..][..len as usize],
                };
                self.run(index, blob)?;
                ran[index] = true;
            }
            rest = after;
        }
        Ok(())
    }

    /// Runs operation `index` with its operation data `blob`.
    fn run(&self, index: usize, blob: &[u8]) -> Result<()> {
        let op = &self.update().operations[index];
        let kind = self.kinds[index];
        let target = Target {
            image: NamedFile {
                file: &self.produced,
                path: &self.label,
            },
            block_size: self.block_size,
            source: self.source.as_ref(),
            verify: self.verify,
        };
        let result = (|| {
            if let Some(expected) = op.data_sha256_hash.as_deref().filter(|h| !h.is_empty()) {
                let actual = Sha256::digest(blob);
                ensure!(
                    actual.as_slice() == expected,
                    Error::hash_mismatch("operation data", expected, &actual)
                );
            }
            operation::execute(op, kind, blob, &target)
        })();
        result.map_err(|error| Error::Operation {
            partition: self.name().to_owned(),
            index,
            kind: kind.name(),
            source: Box::new(error),
        })
    }
}

impl ReadAt for PartitionImage {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.size)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let range = offset..end;
        if range.is_empty() {
            return Ok(());
        }
        for (verity, what) in self.verity.iter().zip(["hash tree", "FEC parity"]) {
            if verity.start < range.end && range.start < verity.end {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "the dm-verity {what} of {} is computed from the whole image, extract the partition to read it",
                        self.name()
                    ),
                ));
            }
        }
        self.fill(buf, range).map_err(io::Error::other)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn read_granularity(&self) -> u64 {
        self.payload.read_granularity()
    }
}

/// The ranges of the sorted, disjoint `ranges` that overlap `range`.
fn overlapping<'a>(ranges: &'a [Range<u64>], range: &'a Range<u64>) -> impl Iterator<Item = &'a Range<u64>> {
    let first = ranges.partition_point(|r| r.end <= range.start);
    ranges[first..].iter().take_while(|r| r.start < range.end)
}
