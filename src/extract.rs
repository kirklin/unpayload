//! Extracting partition images from a payload.
//!
//! Every selected partition is validated before anything is written. The
//! operations of all partitions then run in parallel: they write disjoint
//! block ranges of their images, so their order does not matter. Images are
//! written under a `.part` name and renamed once complete and, unless
//! verification is off, once their SHA-256 matches the manifest.

use std::fs::{self, OpenOptions};
use std::num::NonZeroUsize;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::budget::Budget;
use crate::error::{Error, Result, ensure, hex};
use crate::extent::{byte_range, byte_ranges, ensure_disjoint, gaps, total_len};
use crate::fsio::NamedFile;
use crate::metadata::{OperationType, PartitionInfo, PartitionUpdate};
use crate::operation::{self, Target};
use crate::partition::{self, operation_type};
use crate::payload::Payload;
use crate::source::SourceImage;
use crate::verity;

const COPY_PIECE: u64 = 8 << 20;
const MAX_CHUNK_OPERATIONS: usize = 256;

#[derive(Clone, Debug)]
pub struct ExtractOptions {
    /// Directory the images are written to.
    pub output_dir: PathBuf,
    /// Partitions to extract; all of them when empty.
    pub partitions: Vec<String>,
    /// Directory holding `<partition>.img` source images, needed by
    /// partitions an incremental payload patches.
    pub source_dir: Option<PathBuf>,
    /// Replace images that already exist in `output_dir`.
    pub overwrite: bool,
    /// Check the source data operations read and every finished image
    /// against the SHA-256 hashes in the manifest. Operation data is checked
    /// either way.
    pub verify: bool,
    /// Worker threads; the number of CPUs when `None`.
    pub threads: Option<NonZeroUsize>,
    /// Memory that operations running at the same time may hold, in bytes.
    pub memory_limit: u64,
    /// Once set, extraction stops between operations with
    /// [`Error::Cancelled`], removing the images it has not finished.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("."),
            partitions: Vec::new(),
            source_dir: None,
            overwrite: false,
            verify: true,
            threads: None,
            memory_limit: 4 << 30,
            cancel: None,
        }
    }
}

/// Progress of an extraction.
#[derive(Debug)]
pub enum Event<'a> {
    /// Extraction begins; `total` is the number of bytes that will be written.
    Started { partitions: &'a [&'a str], total: u64 },
    /// `bytes` more bytes of `partition` were written.
    Progress { partition: &'a str, bytes: u64 },
    /// An image was finished and moved into place.
    Extracted(&'a Extracted),
}

#[derive(Clone, Debug)]
pub struct Extracted {
    pub partition: String,
    pub path: PathBuf,
    pub size: u64,
    /// SHA-256 of the image; `None` when verification is off.
    pub sha256: Option<Vec<u8>>,
}

impl Payload {
    /// Writes the selected partition images into `options.output_dir`.
    pub fn extract(&self, options: &ExtractOptions, events: &(dyn Fn(Event<'_>) + Sync)) -> Result<Vec<Extracted>> {
        let updates = select(self, &options.partitions)?;
        let jobs = updates
            .into_iter()
            .map(|update| Job::plan(self, update, options))
            .collect::<Result<Vec<_>>>()?;
        fs::create_dir_all(&options.output_dir).map_err(Error::file(&options.output_dir))?;

        let names: Vec<&str> = jobs.iter().map(|job| job.name).collect();
        let total = jobs.iter().map(|job| job.work).sum();
        events(Event::Started {
            partitions: &names,
            total,
        });

        let threads = options
            .threads
            .or_else(|| std::thread::available_parallelism().ok())
            .map_or(1, NonZeroUsize::get);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(Error::Threads)?;
        let run = Run {
            payload: self,
            budget: Budget::new(options.memory_limit),
            verify: options.verify,
            aborted: AtomicBool::new(false),
            cancel: options.cancel.as_deref(),
            failure: Mutex::new(None),
            events,
        };
        let extracted = pool.install(|| {
            jobs.par_iter()
                .filter_map(|job| run.guard(job.name, || job.run(&run)))
                .collect::<Vec<_>>()
        });
        match run.failure.into_inner().unwrap() {
            Some(error) => Err(error),
            None => Ok(extracted),
        }
    }
}

fn select<'p>(payload: &'p Payload, names: &[String]) -> Result<Vec<&'p PartitionUpdate>> {
    if names.is_empty() {
        return Ok(payload.partitions().iter().collect());
    }
    let mut selected: Vec<&PartitionUpdate> = Vec::new();
    let mut unknown = Vec::new();
    for name in names {
        match payload.partition(name) {
            Some(update) if !selected.iter().any(|u| u.partition_name == *name) => selected.push(update),
            Some(_) => {}
            None => unknown.push(name.clone()),
        }
    }
    ensure!(unknown.is_empty(), Error::UnknownPartitions(unknown));
    Ok(selected)
}

struct Run<'a> {
    payload: &'a Payload,
    budget: Budget,
    verify: bool,
    aborted: AtomicBool,
    cancel: Option<&'a AtomicBool>,
    failure: Mutex<Option<Error>>,
    events: &'a (dyn Fn(Event<'_>) + Sync),
}

impl Run<'_> {
    fn check(&self) -> Result<()> {
        ensure!(
            !self.cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)),
            Error::Cancelled
        );
        ensure!(!self.aborted.load(Ordering::Relaxed), Error::Stopped);
        Ok(())
    }

    /// Runs `work`, recording the first real failure and stopping the rest.
    fn guard<T>(&self, partition: &str, work: impl FnOnce() -> Result<T>) -> Option<T> {
        match work() {
            Ok(value) => Some(value),
            Err(error) => {
                self.aborted.store(true, Ordering::Relaxed);
                if !matches!(error, Error::Stopped) {
                    let error = match error {
                        Error::Operation { .. } | Error::Partition { .. } | Error::Cancelled => error,
                        error => Error::Partition {
                            partition: partition.to_owned(),
                            source: Box::new(error),
                        },
                    };
                    self.failure.lock().unwrap().get_or_insert(error);
                }
                None
            }
        }
    }

    fn progress(&self, partition: &str, bytes: u64) {
        (self.events)(Event::Progress { partition, bytes });
    }
}

struct Job<'p> {
    update: &'p PartitionUpdate,
    name: &'p str,
    size: u64,
    block_size: u64,
    kinds: Vec<OperationType>,
    chunks: Vec<Range<usize>>,
    source: Option<SourceImage>,
    fallthrough: Vec<Range<u64>>,
    output: PathBuf,
    partial: PathBuf,
    work: u64,
}

impl<'p> Job<'p> {
    /// Validates a partition update and works out what extracting it takes.
    fn plan(payload: &Payload, update: &'p PartitionUpdate, options: &ExtractOptions) -> Result<Self> {
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

        let output = options.output_dir.join(format!("{name}.img"));
        let partial = options.output_dir.join(format!("{name}.img.part"));
        let source = if partition::reads_source(update) {
            let dir = options
                .source_dir
                .as_ref()
                .ok_or_else(|| Error::MissingSource(name.to_owned()))?;
            let path = dir.join(format!("{name}.img"));
            let image = SourceImage::open(&path)?;
            if let Some(expected) = update.old_partition_info.as_ref().and_then(|info| info.size) {
                ensure!(
                    image.size() >= expected,
                    Error::Source(format!(
                        "{} is {} bytes, the payload updates an image of {expected} bytes",
                        path.display(),
                        image.size()
                    ))
                );
            }
            if same_file(&path, &output) {
                return Err(Error::Source(format!(
                    "{} is both the source image and the output, choose another output directory",
                    path.display()
                )));
            }
            Some(image)
        } else {
            None
        };
        ensure!(options.overwrite || !output.exists(), Error::OutputExists(output));

        let tree = byte_range(update.hash_tree_extent, block_size).map_err(in_partition)?;
        let fec = byte_range(update.fec_extent, block_size).map_err(in_partition)?;
        let fallthrough = match &source {
            Some(image) => {
                let mut covered = written.clone();
                covered.extend([tree.clone(), fec.clone()]);
                covered.sort_unstable_by_key(|range| range.start);
                gaps(&covered, size.min(image.size()))
            }
            None => Vec::new(),
        };
        let work = total_len(&written) + total_len(&fallthrough) + (tree.end - tree.start) + (fec.end - fec.start);

        Ok(Self {
            update,
            name,
            size,
            block_size,
            kinds,
            chunks: chunks(update, payload.read_granularity()),
            source,
            fallthrough,
            output,
            partial,
            work,
        })
    }

    fn run(&self, run: &Run) -> Result<Extracted> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.partial)
            .map_err(Error::file(&self.partial))?;
        let partial = RemoveOnDrop(Some(&self.partial));
        file.set_len(self.size).map_err(Error::file(&self.partial))?;
        let image = NamedFile {
            file: &file,
            path: &self.partial,
        };

        if let Some(source) = &self.source {
            let pieces: Vec<Range<u64>> = self
                .fallthrough
                .iter()
                .flat_map(|range| {
                    (range.start..range.end)
                        .step_by(COPY_PIECE as usize)
                        .map(move |start| start..(start + COPY_PIECE).min(range.end))
                })
                .collect();
            pieces.par_iter().try_for_each(|piece| {
                run.check()?;
                let data = source.read(std::slice::from_ref(piece))?;
                image.write_all_at(&data, piece.start)?;
                run.progress(self.name, piece.end - piece.start);
                Ok::<_, Error>(())
            })?;
        }

        let target = Target {
            image,
            block_size: self.block_size,
            source: self.source.as_ref(),
            verify: run.verify,
        };
        self.chunks
            .par_iter()
            .try_for_each(|chunk| self.run_chunk(chunk.clone(), &target, run))?;

        run.check()?;
        verity::rebuild(self.update, image, self.block_size, &|bytes| {
            run.progress(self.name, bytes)
        })?;
        file.set_len(self.size).map_err(Error::file(&self.partial))?;

        let sha256 = run.verify.then(|| self.verify(image)).transpose()?;
        drop(file);
        fs::rename(&self.partial, &self.output).map_err(Error::file(&self.output))?;
        partial.disarm();
        let extracted = Extracted {
            partition: self.name.to_owned(),
            path: self.output.clone(),
            size: self.size,
            sha256,
        };
        (run.events)(Event::Extracted(&extracted));
        Ok(extracted)
    }

    /// Hashes the finished image and checks it against the manifest.
    fn verify(&self, image: NamedFile) -> Result<Vec<u8>> {
        let sha256 = digest(image, self.size)?;
        if let Some(expected) = hash(self.update.new_partition_info.as_ref())
            && sha256 != expected
        {
            // Blocks no operation reads are copied from the source unchecked,
            // so a wrong source image may only show here.
            if let Some(source) = &self.source {
                self.check_source(source)?;
            }
            return Err(Error::hash_mismatch(format!("{}.img", self.name), expected, &sha256));
        }
        Ok(sha256)
    }

    /// Fails when `source` is not the image the payload updates.
    fn check_source(&self, source: &SourceImage) -> Result<()> {
        let info = self.update.old_partition_info.as_ref();
        let (Some(size), Some(expected)) = (info.and_then(|info| info.size), hash(info)) else {
            return Ok(());
        };
        let actual = source.digest(size)?;
        ensure!(
            actual == expected,
            Error::Source(format!(
                "{} is not the image this payload updates: it hashes to {}, expected {}",
                source.path().display(),
                hex(&actual),
                hex(expected)
            ))
        );
        Ok(())
    }

    fn run_chunk(&self, chunk: Range<usize>, target: &Target, run: &Run) -> Result<()> {
        let ops = &self.update.operations[chunk.clone()];
        let with_data = || ops.iter().filter(|op| op.data_length() > 0);
        let start = with_data().map(|op| op.data_offset()).min().unwrap_or(0);
        let end = with_data()
            .map(|op| op.data_offset() + op.data_length())
            .max()
            .unwrap_or(0);
        let mut data = vec![0u8; (end - start) as usize];
        if !data.is_empty() {
            run.check()?;
            run.payload.read_data(start, &mut data)?;
        }
        for (index, op) in chunk.zip(ops) {
            run.check()?;
            let kind = self.kinds[index];
            let blob = match op.data_length() {
                0 => &[][..],
                len => &data[(op.data_offset() - start) as usize..][..len as usize],
            };
            let result = (|| {
                if let Some(expected) = op.data_sha256_hash.as_deref().filter(|h| !h.is_empty()) {
                    let actual = Sha256::digest(blob);
                    ensure!(
                        actual.as_slice() == expected,
                        Error::hash_mismatch("operation data", expected, &actual)
                    );
                }
                let _permit = run.budget.acquire(operation::memory(op, kind, self.block_size));
                operation::execute(op, kind, blob, target)
            })();
            result.map_err(|error| Error::Operation {
                partition: self.name.to_owned(),
                index,
                kind: kind.name(),
                source: Box::new(error),
            })?;
            let written = op.dst_extents.iter().map(|e| e.num_blocks()).sum::<u64>() * self.block_size;
            run.progress(self.name, written);
        }
        Ok(())
    }
}

/// Groups consecutive operations whose data is contiguous until a group holds
/// at least `granularity` bytes, so remote payloads are read in few requests.
fn chunks(update: &PartitionUpdate, granularity: u64) -> Vec<Range<usize>> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut data_end: Option<u64> = None;
    let mut size = 0u64;
    for (index, op) in update.operations.iter().enumerate() {
        let len = op.data_length();
        let breaks = len > 0 && data_end.is_some_and(|end| end != op.data_offset());
        if index > start && (size >= granularity || breaks || index - start >= MAX_CHUNK_OPERATIONS) {
            chunks.push(start..index);
            start = index;
            size = 0;
            data_end = None;
        }
        if len > 0 {
            data_end = Some(op.data_offset() + len);
            size += len;
        }
    }
    if start < update.operations.len() {
        chunks.push(start..update.operations.len());
    }
    chunks
}

/// The hash a partition image should have, when the manifest gives one.
fn hash(info: Option<&PartitionInfo>) -> Option<&[u8]> {
    info?.hash.as_deref().filter(|hash| !hash.is_empty())
}

fn digest(image: NamedFile, len: u64) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 4 << 20];
    let mut offset = 0;
    while offset < len {
        let n = (len - offset).min(buf.len() as u64) as usize;
        image.read_exact_at(&mut buf[..n], offset)?;
        hasher.update(&buf[..n]);
        offset += n as u64;
    }
    Ok(hasher.finalize().to_vec())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

struct RemoveOnDrop<'a>(Option<&'a Path>);

impl RemoveOnDrop<'_> {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.0 {
            let _ = fs::remove_file(path);
        }
    }
}
