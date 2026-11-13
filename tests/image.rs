//! Reads partition images at arbitrary offsets and compares every read with
//! the image extraction writes, which is checked against the SHA-256 the
//! payload records.

use std::fs;
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::TempDir;
use unpayload::metadata::OperationType;
use unpayload::{Error, ExtractOptions, ImageOptions, LocalFile, Payload, ReadAt, partition};

fn data(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(path)
}

fn payload(case: &str) -> Payload {
    Payload::open(data(case).join("payload.bin")).unwrap()
}

fn image_options(source: Option<&str>) -> ImageOptions {
    ImageOptions {
        source_dir: source.map(|case| data(case).join("old")),
        ..ImageOptions::default()
    }
}

/// Extracts every partition of `payload` into a fresh directory.
fn extracted(payload: &Payload, source: Option<&str>) -> TempDir {
    let out = tempfile::tempdir().unwrap();
    let options = ExtractOptions {
        output_dir: out.path().to_owned(),
        source_dir: source.map(|case| data(case).join("old")),
        ..ExtractOptions::default()
    };
    payload.extract(&options, &|_| {}).unwrap();
    out
}

/// The byte ranges of an image that can be read without extracting it: all
/// of it but the hash tree and the FEC parity.
fn readable(payload: &Payload, name: &str) -> Vec<Range<u64>> {
    let update = payload.partition(name).unwrap();
    let block_size = u64::from(payload.block_size());
    let mut verity: Vec<Range<u64>> = [update.hash_tree_extent, update.fec_extent]
        .into_iter()
        .flatten()
        .filter(|extent| extent.num_blocks() > 0)
        .map(|extent| extent.start_block() * block_size..(extent.start_block() + extent.num_blocks()) * block_size)
        .collect();
    verity.sort_unstable_by_key(|range| range.start);
    let mut readable = Vec::new();
    let mut cursor = 0;
    for range in verity {
        readable.push(cursor..range.start);
        cursor = range.end;
    }
    readable.push(cursor..partition::new_size(update).unwrap());
    readable.retain(|range| !range.is_empty());
    readable
}

/// The error an operation failed with, under the I/O error a read gives.
fn cause(error: &io::Error) -> &Error {
    let mut error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Error>())
        .expect("a read fails with an error of this crate");
    while let Error::Operation { source, .. } | Error::Partition { source, .. } = error {
        error = source;
    }
    error
}

/// Reads every partition of `case` in pieces, last to first and then whole,
/// each from an image opened afresh, and compares them with the extracted
/// images.
fn compare(case: &str, source: Option<&str>) {
    let payload = payload(case);
    let out = extracted(&payload, source);
    for update in payload.partitions() {
        let name = update.partition_name.as_str();
        let expected = fs::read(out.path().join(format!("{name}.img"))).unwrap();
        let readable = readable(&payload, name);
        assert_eq!(expected.len() as u64, partition::new_size(update).unwrap());

        let image = payload.open_image(name, &image_options(source)).unwrap();
        assert_eq!((image.name(), image.size()), (name, expected.len() as u64));
        for range in readable.iter().rev() {
            let mut offset = range.end;
            while offset > range.start {
                let start = offset.saturating_sub(5000).max(range.start);
                let mut piece = vec![0u8; (offset - start) as usize];
                image.read_exact_at(&mut piece, start).unwrap();
                assert_eq!(
                    piece,
                    expected[start as usize..offset as usize],
                    "{case}: {name} at {start}"
                );
                offset = start.saturating_sub(32_337);
            }
        }

        let image = payload.open_image(name, &image_options(source)).unwrap();
        for range in &readable {
            let mut whole = vec![0u8; (range.end - range.start) as usize];
            image.read_exact_at(&mut whole, range.start).unwrap();
            assert!(
                whole == expected[range.start as usize..range.end as usize],
                "{case}: {name} read whole from {}",
                range.start
            );
            // What was read once reads the same again.
            let mut again = vec![0u8; whole.len().min(4097)];
            image.read_exact_at(&mut again, range.start).unwrap();
            assert_eq!(again, whole[..again.len()], "{case}: {name} read again");
        }
    }
}

#[test]
fn full() {
    compare("full", None);
    compare("full-zstd", None);
}

#[test]
fn delta() {
    compare("delta", Some("delta"));
    compare("delta-bz2", Some("delta"));
    compare("delta-v3", Some("delta"));
}

#[test]
fn files() {
    compare("files", Some("files"));
}

#[test]
fn lz4() {
    compare("lz4", Some("lz4"));
    compare("lz4hc", Some("lz4hc"));
}

/// Everything before the verity data reads as extracted; the hash tree and
/// the FEC parity are computed from the whole image and are not read.
#[test]
fn verity() {
    compare("verity", Some("verity"));
    let payload = payload("verity");
    for update in payload.partitions() {
        let name = update.partition_name.as_str();
        let image = payload.open_image(name, &image_options(Some("verity"))).unwrap();
        let [before, after] = &readable(&payload, name)[..] else {
            panic!("{name} has verity data in its middle")
        };
        let mut buf = [0u8; 16];
        for offset in [before.end, before.end - 8, after.start - 16, after.start - 1] {
            let error = image.read_exact_at(&mut buf, offset).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{name} at {offset}: {error}");
        }
        image.read_exact_at(&mut buf, before.end - 16).unwrap();
        image.read_exact_at(&mut buf, after.start).unwrap();
    }
}

/// Counts the bytes read from a payload.
struct Counted {
    inner: LocalFile,
    bytes: Arc<AtomicU64>,
}

impl ReadAt for Counted {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
        self.inner.read_exact_at(buf, offset)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// A read fetches the data of the operations it touches and nothing else,
/// and fetches it once.
#[test]
fn only_what_is_read_is_fetched() {
    let bytes = Arc::new(AtomicU64::new(0));
    let reader = Counted {
        inner: LocalFile::open(&data("full/payload.bin")).unwrap(),
        bytes: bytes.clone(),
    };
    let payload = Payload::from_reader(Arc::new(reader)).unwrap();
    let data_length = |name: &str| -> u64 {
        let update = payload.partition(name).unwrap();
        update.operations.iter().map(|op| op.data_length()).sum()
    };

    let text = payload.open_image("text", &ImageOptions::default()).unwrap();
    let noise = payload.open_image("noise", &ImageOptions::default()).unwrap();
    let opened = bytes.load(Ordering::Relaxed);
    let mut buf = [0u8; 64];
    text.read_exact_at(&mut buf, 4096).unwrap();
    assert_eq!(bytes.load(Ordering::Relaxed) - opened, data_length("text"));
    text.read_exact_at(&mut buf, 500_000).unwrap();
    assert_eq!(
        bytes.load(Ordering::Relaxed) - opened,
        data_length("text"),
        "fetched once"
    );
    noise.read_exact_at(&mut buf, 0).unwrap();
    assert_eq!(
        bytes.load(Ordering::Relaxed) - opened,
        data_length("text") + data_length("noise")
    );
}

/// Corrupt operation data fails the reads of the blocks its operation writes
/// and no others.
#[test]
fn corrupt_operation_data() {
    let dir = tempfile::tempdir().unwrap();
    let original = payload("delta");
    let update = original.partition("raw").unwrap();
    let block_size = u64::from(original.block_size());
    let patched = update
        .operations
        .iter()
        .find(|op| partition::operation_type(op) == Some(OperationType::BrotliBsdiff))
        .unwrap();
    let copied = update
        .operations
        .iter()
        .find(|op| partition::operation_type(op) == Some(OperationType::SourceCopy))
        .unwrap();
    let mut bytes = fs::read(data("delta/payload.bin")).unwrap();
    bytes[(original.data_offset() + patched.data_offset()) as usize] ^= 0xFF;
    let path = dir.path().join("payload.bin");
    fs::write(&path, bytes).unwrap();

    let payload = Payload::open(&path).unwrap();
    let image = payload.open_image("raw", &image_options(Some("delta"))).unwrap();
    let mut buf = [0u8; 512];
    image
        .read_exact_at(&mut buf, copied.dst_extents[0].start_block() * block_size)
        .unwrap();
    let at = patched.dst_extents[0].start_block() * block_size;
    for _ in 0..2 {
        let error = image.read_exact_at(&mut buf, at).unwrap_err();
        assert!(
            matches!(cause(&error), Error::HashMismatch { what, .. } if what == "operation data"),
            "{error:?}"
        );
    }
}

#[test]
fn reads_past_the_end() {
    let payload = payload("full");
    let image = payload.open_image("text", &ImageOptions::default()).unwrap();
    let size = image.size();
    let mut buf = [0u8; 16];
    image.read_exact_at(&mut buf, size - 16).unwrap();
    image.read_exact_at(&mut [], size).unwrap();
    for offset in [size - 15, size, u64::MAX] {
        let error = image.read_exact_at(&mut buf, offset).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "at {offset}");
    }
}

#[test]
fn unknown_partition() {
    let error = payload("full")
        .open_image("boot", &ImageOptions::default())
        .err()
        .unwrap();
    assert!(matches!(&error, Error::UnknownPartitions(names) if names == &["boot"]));
}

#[test]
fn missing_source() {
    let error = payload("delta")
        .open_image("raw", &ImageOptions::default())
        .err()
        .unwrap();
    assert!(matches!(&error, Error::MissingSource(name) if name == "raw"));
}

/// A wrong source image fails the reads of the blocks built from the part of
/// it that changed, unless verification is off.
#[test]
fn wrong_source() {
    let source = tempfile::tempdir().unwrap();
    let mut old = fs::read(data("delta/old/raw.img")).unwrap();
    old[0] ^= 1;
    fs::write(source.path().join("raw.img"), old).unwrap();
    let payload = payload("delta");
    let mut options = ImageOptions {
        source_dir: Some(source.path().to_owned()),
        ..ImageOptions::default()
    };
    let read_all = |options: &ImageOptions| {
        let image = payload.open_image("raw", options).unwrap();
        let mut whole = vec![0u8; image.size() as usize];
        image.read_exact_at(&mut whole, 0)
    };
    let error = read_all(&options).unwrap_err();
    assert!(
        matches!(cause(&error), Error::Source(message) if message.contains("is not the image")),
        "{error:?}"
    );
    options.verify = false;
    read_all(&options).unwrap();
}
