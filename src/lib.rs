//! Extract partition images from Android OTA update payloads.
//!
//! Full payloads rebuild every partition from their own data; incremental
//! payloads patch the source images of the build they update from.

mod bsdiff;
mod budget;
mod error;
mod extent;
mod extract;
mod fsio;
mod input;
pub mod metadata;
mod operation;
pub mod partition;
mod payload;
mod sink;
mod source;

pub use error::{Error, Result};
pub use extract::{Event, ExtractOptions, Extracted};
pub use input::{LocalFile, ReadAt};
pub use payload::Payload;
