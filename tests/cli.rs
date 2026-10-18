//! Runs the command-line program on the payloads in tests/data.

#![cfg(feature = "cli")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn data(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(path)
}

/// Extracts `payload` into `output` with `args`.
fn unpayload(payload: &str, output: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_unpayload"))
        .arg(data(payload))
        .arg("--output")
        .arg(output)
        .args(args)
        .output()
        .unwrap()
}

/// A wrong source image stops the extraction unless verification is off, in
/// which case no hash is reported for the image.
#[test]
fn no_verify() {
    let source = tempfile::tempdir().unwrap();
    let mut image = fs::read(data("delta/old/raw.img")).unwrap();
    image[0] ^= 1;
    fs::write(source.path().join("raw.img"), image).unwrap();
    let source = source.path().to_str().unwrap();
    let out = tempfile::tempdir().unwrap();

    let checked = unpayload("delta/payload.bin", out.path(), &["--source", source, "--json"]);
    assert!(!checked.status.success());
    let message = String::from_utf8(checked.stderr).unwrap();
    assert!(message.contains("is not the image"), "{message}");

    let unchecked = unpayload(
        "delta/payload.bin",
        out.path(),
        &["--source", source, "--json", "--no-verify"],
    );
    assert!(
        unchecked.status.success(),
        "{}",
        String::from_utf8_lossy(&unchecked.stderr)
    );
    let images: serde_json::Value = serde_json::from_slice(&unchecked.stdout).unwrap();
    assert_eq!(images[0]["partition"], "raw");
    assert!(images[0]["sha256"].is_null(), "{images}");
}
