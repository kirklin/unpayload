//! Runs the command-line program on the payloads in tests/data.

#![cfg(feature = "cli")]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

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

/// The lines of `--json` output, after checking that the program succeeded.
fn json_lines(output: &Output) -> Vec<Value> {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// While extracting, `--json` prints the progress of each partition in whole
/// percent whenever it grows, reaching 100 before the line of its image.
#[test]
fn progress_lines() {
    let out = tempfile::tempdir().unwrap();
    let lines = json_lines(&unpayload("full/payload.bin", out.path(), &["--json"]));
    let mut percents: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut images = Vec::new();
    for line in &lines {
        let partition = line["partition"].as_str().unwrap().to_owned();
        match line["event"].as_str().unwrap() {
            "progress" => percents
                .entry(partition)
                .or_default()
                .push(line["percent"].as_u64().unwrap()),
            "extracted" => {
                assert_eq!(percents[&partition].last(), Some(&100), "{line}");
                assert_eq!(line["sha256"].as_str().unwrap().len(), 64, "{line}");
                assert!(Path::new(line["path"].as_str().unwrap()).is_file(), "{line}");
                images.push(partition);
            }
            event => panic!("unexpected event {event}"),
        }
    }
    images.sort();
    assert_eq!(images, ["mixed", "noise", "text"]);
    for (partition, percents) in &percents {
        assert!(
            percents.windows(2).all(|pair| pair[0] < pair[1]),
            "{partition}: {percents:?}"
        );
    }
}

/// With `--quiet`, `--json` prints only the lines of the images.
#[test]
fn quiet_json() {
    let out = tempfile::tempdir().unwrap();
    let lines = json_lines(&unpayload("full/payload.bin", out.path(), &["--json", "--quiet"]));
    assert_eq!(lines.len(), 3);
    assert!(lines.iter().all(|line| line["event"] == "extracted"), "{lines:?}");
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
    let lines = json_lines(&unchecked);
    let image = lines.iter().find(|line| line["event"] == "extracted").unwrap();
    assert_eq!(image["partition"], "raw");
    assert!(image["sha256"].is_null(), "{image}");
}
