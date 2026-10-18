//! Extracts the payloads in tests/data, which tests/fixtures/build.sh made
//! with the Android payload generator. Extraction checks every image against
//! the SHA-256 the payload records, so a successful extraction means the
//! images match the ones the payload was made from.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tempfile::TempDir;
use unpayload::{Error, Event, ExtractOptions, Extracted, Payload, partition};

fn data(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(path)
}

fn payload(case: &str) -> Payload {
    Payload::open(data(case).join("payload.bin")).unwrap()
}

/// Options that write into a fresh directory.
fn options() -> (ExtractOptions, TempDir) {
    let out = tempfile::tempdir().unwrap();
    let options = ExtractOptions {
        output_dir: out.path().to_owned(),
        ..ExtractOptions::default()
    };
    (options, out)
}

fn extract(payload: &Payload, options: &ExtractOptions) -> Result<Vec<Extracted>, Error> {
    payload.extract(options, &|_| {})
}

/// Extracts every partition of `case` and returns the operation types its
/// payload uses.
fn extract_all(case: &str) -> BTreeSet<String> {
    let payload = payload(case);
    let (options, out) = options();
    let extracted = extract(&payload, &options).unwrap();
    assert_eq!(extracted.len(), payload.partitions().len());
    for image in &extracted {
        assert_eq!(fs::metadata(&image.path).unwrap().len(), image.size);
    }
    assert_no_partial_files(out.path());
    payload
        .partitions()
        .iter()
        .flat_map(partition::operation_counts)
        .map(|(kind, _)| kind)
        .collect()
}

fn assert_uses(kinds: &BTreeSet<String>, expected: &[&str]) {
    for kind in expected {
        assert!(kinds.contains(*kind), "no {kind} operation among {kinds:?}");
    }
}

fn assert_no_partial_files(dir: &Path) {
    for entry in fs::read_dir(dir).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(!name.to_string_lossy().ends_with(".part"), "{name:?} left behind");
    }
}

/// The error under the partition and operation it happened in.
fn innermost(error: &Error) -> &Error {
    match error {
        Error::Operation { source, .. } | Error::Partition { source, .. } => innermost(source),
        error => error,
    }
}

#[test]
fn full() {
    assert_uses(&extract_all("full"), &["REPLACE", "REPLACE_XZ"]);
}

#[test]
fn full_zstd() {
    assert_uses(&extract_all("full-zstd"), &["REPLACE_ZSTD"]);
}

#[test]
fn selected_partitions() {
    let payload = payload("full");
    let (mut options, out) = options();
    options.partitions = vec!["noise".into(), "text".into(), "noise".into()];
    let extracted = extract(&payload, &options).unwrap();
    let names: Vec<_> = extracted.iter().map(|image| image.partition.as_str()).collect();
    assert_eq!(names, ["noise", "text"]);
    assert!(!out.path().join("mixed.img").exists());
}

#[test]
fn unknown_partitions() {
    let (mut options, _out) = options();
    options.partitions = vec!["text".into(), "boot".into(), "vendor".into()];
    let error = extract(&payload("full"), &options).unwrap_err();
    assert!(matches!(&error, Error::UnknownPartitions(names) if names == &["boot", "vendor"]));
}

#[test]
fn existing_images() {
    let payload = payload("full");
    let (mut options, out) = options();
    extract(&payload, &options).unwrap();
    let error = extract(&payload, &options).unwrap_err();
    assert!(matches!(error, Error::OutputExists(_)));
    options.overwrite = true;
    extract(&payload, &options).unwrap();
    assert_no_partial_files(out.path());
}

#[test]
fn cancelled() {
    let cancel = Arc::new(AtomicBool::new(false));
    let (mut options, out) = options();
    options.cancel = Some(cancel.clone());
    let error = payload("full")
        .extract(&options, &|event| {
            if matches!(event, Event::Progress { .. }) {
                cancel.store(true, Ordering::Relaxed);
            }
        })
        .unwrap_err();
    assert!(matches!(error, Error::Cancelled), "{error:?}");
    assert_no_partial_files(out.path());
}

#[test]
fn corrupt_operation_data() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = fs::read(data("full/payload.bin")).unwrap();
    let payload = payload("full");
    let update = payload.partition("text").unwrap();
    let at = payload.data_offset() + update.operations[0].data_offset() + 100;
    bytes[at as usize] ^= 0xFF;
    let path = dir.path().join("payload.bin");
    fs::write(&path, bytes).unwrap();

    let (mut options, out) = options();
    options.partitions = vec!["text".into()];
    let error = extract(&Payload::open(&path).unwrap(), &options).unwrap_err();
    assert!(
        matches!(innermost(&error), Error::HashMismatch { what, .. } if what == "operation data"),
        "{error:?}"
    );
    assert_no_partial_files(out.path());
}

#[test]
fn truncated_payload() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = fs::read(data("full/payload.bin")).unwrap();
    let path = dir.path().join("payload.bin");
    fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    let (options, _out) = options();
    let error = extract(&Payload::open(&path).unwrap(), &options).unwrap_err();
    assert!(matches!(innermost(&error), Error::InvalidPayload(_)), "{error:?}");
}
