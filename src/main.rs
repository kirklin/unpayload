use std::collections::BTreeMap;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use indicatif::{HumanBytes, HumanDuration, ProgressBar, ProgressStyle};
use serde::Serialize;
use unpayload::{Error, Event, ExtractOptions, Payload, partition};

/// Extract partition images from Android OTA payloads, full or incremental.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// payload.bin, OTA zip archive, or http(s) URL of either
    input: String,

    /// List partitions instead of extracting them
    #[arg(short, long)]
    list: bool,

    /// Extract only these partitions
    #[arg(short, long, value_name = "NAMES", value_delimiter = ',')]
    partitions: Vec<String>,

    /// Directory holding the <partition>.img images an incremental payload updates
    #[arg(short, long, value_name = "DIR")]
    source: Option<PathBuf>,

    /// Directory to write images to
    #[arg(short, long, value_name = "DIR", default_value = ".")]
    output: PathBuf,

    /// Overwrite images that already exist
    #[arg(short, long)]
    force: bool,

    /// Skip checking source and extracted images against the SHA-256 hashes in the payload
    #[arg(long)]
    no_verify: bool,

    /// Number of worker threads [default: number of CPUs]
    #[arg(short, long, value_name = "N")]
    jobs: Option<NonZeroUsize>,

    /// Print JSON instead of text
    #[arg(long)]
    json: bool,

    /// Print nothing but errors
    #[arg(short, long)]
    quiet: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Err(error) = run(&cli) else {
        return ExitCode::SUCCESS;
    };
    // A reader that stops early, such as `head`, is not a failure.
    if error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
    {
        return ExitCode::SUCCESS;
    }
    let hint = match error.downcast_ref::<Error>() {
        Some(Error::Cancelled) => {
            eprintln!("unpayload: cancelled");
            return ExitCode::from(130);
        }
        Some(Error::OutputExists(_)) => "; pass --force to overwrite it",
        Some(Error::MissingSource(_)) => "; pass --source DIR holding the images of the build this payload updates",
        _ => "",
    };
    eprintln!("unpayload: {error:#}{hint}");
    ExitCode::FAILURE
}

fn run(cli: &Cli) -> Result<()> {
    let payload = if cli.input.starts_with("http://") || cli.input.starts_with("https://") {
        Payload::open_url(&cli.input)?
    } else {
        Payload::open(&cli.input)?
    };
    if cli.list {
        list(&payload, cli.json)
    } else {
        extract(&payload, cli)
    }
}

#[derive(Serialize)]
struct Image<'a> {
    partition: &'a str,
    path: &'a Path,
    size: u64,
    sha256: Option<String>,
}

fn extract(payload: &Payload, cli: &Cli) -> Result<()> {
    // An interrupt stops extraction and removes unfinished images; a second
    // one ends the program at once.
    let cancel = Arc::new(AtomicBool::new(false));
    let interrupted = cancel.clone();
    ctrlc::set_handler(move || {
        if interrupted.swap(true, Ordering::Relaxed) {
            std::process::exit(130);
        }
    })?;
    let options = ExtractOptions {
        output_dir: cli.output.clone(),
        partitions: cli.partitions.clone(),
        source_dir: cli.source.clone(),
        overwrite: cli.force,
        verify: !cli.no_verify,
        threads: cli.jobs,
        cancel: Some(cancel),
        ..ExtractOptions::default()
    };
    let report = !cli.quiet && !cli.json;
    let bar = if cli.quiet {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(0).with_style(
            ProgressStyle::with_template(
                "{wide_bar} {percent:>3}%  {bytes}/{total_bytes}  {binary_bytes_per_sec}  {msg}",
            )?
            .progress_chars("━╸─"),
        )
    };
    let count = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let width = AtomicUsize::new(0);
    let started = Instant::now();

    let extracted = payload.extract(&options, &|event| match event {
        Event::Started { partitions, total } => {
            count.store(partitions.len(), Ordering::Relaxed);
            let longest = partitions.iter().map(|name| name.len()).max().unwrap_or(0);
            width.store(longest + ".img".len(), Ordering::Relaxed);
            bar.set_length(total);
            bar.set_message(format!("0/{} images", partitions.len()));
        }
        Event::Progress { bytes, .. } => bar.inc(bytes),
        Event::Extracted(image) => {
            let done = done.fetch_add(1, Ordering::Relaxed) + 1;
            bar.set_message(format!("{done}/{} images", count.load(Ordering::Relaxed)));
            if report {
                let name = format!("{}.img", image.partition);
                let width = width.load(Ordering::Relaxed);
                bar.suspend(|| eprintln!("{name:<width$}  {:>11}", HumanBytes(image.size).to_string()));
            }
        }
    });
    bar.finish_and_clear();
    let extracted = extracted?;

    if cli.json {
        let images: Vec<Image> = extracted
            .iter()
            .map(|image| Image {
                partition: &image.partition,
                path: &image.path,
                size: image.size,
                sha256: image.sha256.as_deref().map(hex),
            })
            .collect();
        let mut out = io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &images)?;
        writeln!(out)?;
    } else if report {
        let total: u64 = extracted.iter().map(|image| image.size).sum();
        eprintln!(
            "extracted {} {}, {}, into {} in {}",
            extracted.len(),
            if extracted.len() == 1 { "image" } else { "images" },
            HumanBytes(total),
            cli.output.display(),
            HumanDuration(started.elapsed()),
        );
    }
    Ok(())
}

#[derive(Serialize)]
struct Listing<'a> {
    minor_version: u32,
    block_size: u32,
    incremental: bool,
    security_patch_level: Option<&'a str>,
    max_timestamp: Option<i64>,
    partitions: Vec<PartitionListing<'a>>,
}

#[derive(Serialize)]
struct PartitionListing<'a> {
    name: &'a str,
    size: Option<u64>,
    sha256: Option<String>,
    source_size: Option<u64>,
    source_sha256: Option<String>,
    reads_source: bool,
    hash_tree: bool,
    fec: bool,
    operations: BTreeMap<String, usize>,
}

fn list(payload: &Payload, json: bool) -> Result<()> {
    let manifest = payload.manifest();
    let partitions: Vec<_> = payload
        .partitions()
        .iter()
        .map(|update| PartitionListing {
            name: &update.partition_name,
            size: partition::new_size(update),
            sha256: update
                .new_partition_info
                .as_ref()
                .and_then(|i| i.hash.as_deref())
                .map(hex),
            source_size: update.old_partition_info.as_ref().and_then(|i| i.size),
            source_sha256: update
                .old_partition_info
                .as_ref()
                .and_then(|i| i.hash.as_deref())
                .map(hex),
            reads_source: partition::reads_source(update),
            hash_tree: partition::has_hash_tree(update),
            fec: partition::has_fec(update),
            operations: partition::operation_counts(update),
        })
        .collect();
    let listing = Listing {
        minor_version: payload.minor_version(),
        block_size: payload.block_size(),
        incremental: payload.is_incremental(),
        security_patch_level: manifest.security_patch_level.as_deref(),
        max_timestamp: manifest.max_timestamp,
        partitions,
    };
    let mut out = io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &listing)?;
        writeln!(out)?;
        return Ok(());
    }

    let total: u64 = listing.partitions.iter().filter_map(|p| p.size).sum();
    writeln!(
        out,
        "{} payload, minor version {}, block size {}, {} partitions, {}",
        if listing.incremental { "incremental" } else { "full" },
        listing.minor_version,
        listing.block_size,
        listing.partitions.len(),
        HumanBytes(total),
    )?;
    if let Some(level) = listing.security_patch_level {
        writeln!(out, "security patch level {level}")?;
    }
    writeln!(out)?;
    let width = listing
        .partitions
        .iter()
        .map(|p| p.name.len())
        .max()
        .unwrap_or(0)
        .max(9);
    writeln!(
        out,
        "{:width$}  {:>11}  {:6}  OPERATIONS",
        "PARTITION", "SIZE", "SOURCE"
    )?;
    for p in &listing.partitions {
        let mut operations: Vec<_> = p.operations.iter().collect();
        operations.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let operations: Vec<_> = operations.iter().map(|(name, n)| format!("{name} {n}")).collect();
        writeln!(
            out,
            "{:width$}  {:>11}  {:6}  {}",
            p.name,
            p.size.map(|s| HumanBytes(s).to_string()).unwrap_or_default(),
            if p.reads_source { "yes" } else { "" },
            operations.join(", "),
        )?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
