//! Extract partition images from Android OTA update payloads.
//!
//! Full payloads rebuild every partition from their own data.

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

pub use error::{Error, Result};
pub use extract::{Event, ExtractOptions, Extracted};
pub use input::{LocalFile, ReadAt};
pub use payload::Payload;
