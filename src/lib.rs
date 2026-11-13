//! Extract partition images from Android OTA update payloads.
//!
//! A payload is either a raw `payload.bin` or an OTA zip archive holding one.
//! Full payloads rebuild every partition from their own data; incremental
//! payloads patch the source images of the build they update from.
//!
//! [`Payload::extract`] writes whole images. [`Payload::open_image`] reads
//! one at arbitrary offsets instead, producing only the blocks that are
//! read: a filesystem reader on top of it takes single files out of a
//! partition of a remote OTA package without downloading the partition.

mod bsdiff;
mod budget;
mod error;
mod extent;
mod extract;
mod fsio;
#[cfg(feature = "http")]
mod http;
mod image;
mod input;
mod introsort;
mod lz4diff;
pub mod metadata;
mod operation;
pub mod partition;
mod payload;
mod plan;
mod puffin;
mod sink;
mod source;
mod verity;
mod zucchini;

pub use error::{Error, Result};
pub use extract::{Event, ExtractOptions, Extracted};
pub use image::{ImageOptions, PartitionImage};
pub use input::{LocalFile, ReadAt, Slice};
pub use payload::Payload;
