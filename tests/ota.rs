//! Real OTA packages, named by environment variables: UNPAYLOAD_OLDER and
//! UNPAYLOAD_NEWER, full packages of two builds, and UNPAYLOAD_INCREMENTAL,
//! the incremental package between them. Run with `cargo test --release --
//! --ignored`.

use std::fs;
use std::path::{Path, PathBuf};

use unpayload::{ExtractOptions, Extracted, Payload};

fn package(variable: &str) -> PathBuf {
    std::env::var_os(variable)
        .unwrap_or_else(|| panic!("set {variable} to an OTA package"))
        .into()
}

fn extract(package: &Path, source: Option<PathBuf>, output: PathBuf) -> Vec<Extracted> {
    let options = ExtractOptions {
        output_dir: output,
        source_dir: source,
        ..ExtractOptions::default()
    };
    Payload::open(package).unwrap().extract(&options, &|_| {}).unwrap()
}

/// Updating the images of the older build with the incremental package gives
/// the images of the newer build.
#[test]
#[ignore = "needs real OTA packages"]
fn incremental_matches_full() {
    let (older, newer, incremental) = (
        package("UNPAYLOAD_OLDER"),
        package("UNPAYLOAD_NEWER"),
        package("UNPAYLOAD_INCREMENTAL"),
    );
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("older");
    extract(&older, None, source.clone());
    let updated = extract(&incremental, Some(source), dir.path().join("updated"));
    let expected = extract(&newer, None, dir.path().join("newer"));

    assert_eq!(updated.len(), expected.len());
    for image in &expected {
        let other = updated
            .iter()
            .find(|other| other.partition == image.partition)
            .unwrap_or_else(|| panic!("{} missing from the update", image.partition));
        assert_eq!(other.sha256, image.sha256, "{}", image.partition);
        assert!(fs::read(&other.path).unwrap() == fs::read(&image.path).unwrap());
    }
}
