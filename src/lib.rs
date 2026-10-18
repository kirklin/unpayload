//! Extract partition images from Android OTA update payloads.
//!
//! A payload is either a raw `payload.bin` or an OTA zip archive holding one.
//! Full payloads rebuild every partition from their own data; incremental
//! payloads patch the source images of the build they update from.

mod bsdiff;
mod budget;
mod error;
mod extent;
mod extract;
mod fsio;
mod input;
mod introsort;
mod lz4diff;
pub mod metadata;
mod operation;
pub mod partition;
mod payload;
mod puffin;
mod sink;
mod source;
mod zucchini;

pub use error::{Error, Result};
pub use extract::{Event, ExtractOptions, Extracted};
pub use input::{LocalFile, ReadAt, Slice};
pub use payload::Payload;
