//! The update payload container: header, manifest and operation data.
//!
//! Layout, all integers big-endian:
//!
//! | field                    | size                     |
//! |--------------------------|--------------------------|
//! | magic `CrAU`             | 4                        |
//! | major version (2)        | 8                        |
//! | manifest size            | 8                        |
//! | metadata signature size  | 4                        |
//! | manifest                 | manifest size            |
//! | metadata signature       | metadata signature size  |
//! | operation data           | rest                     |

use std::path::Path;
use std::sync::Arc;

use prost::Message;

use crate::error::{Error, Result, ensure};
use crate::input::{self, LocalFile, ReadAt};
use crate::metadata::{DeltaArchiveManifest, PartitionUpdate};

const MAGIC: [u8; 4] = *b"CrAU";
const ZIP_MAGIC: [u8; 4] = *b"PK\x03\x04";
const HEADER_LEN: u64 = 24;
const SUPPORTED_MAJOR_VERSION: u64 = 2;

pub struct Payload {
    reader: Arc<dyn ReadAt>,
    manifest: DeltaArchiveManifest,
    data_offset: u64,
}

impl Payload {
    /// Opens a `payload.bin` or an OTA zip archive that contains one.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_reader(Arc::new(LocalFile::open(path.as_ref())?))
    }

    /// Opens a `payload.bin` or OTA zip archive served over HTTP(S), fetching
    /// only the byte ranges that are needed.
    #[cfg(feature = "http")]
    pub fn open_url(url: &str) -> Result<Self> {
        Self::from_reader(Arc::new(crate::http::HttpFile::open(url)?))
    }

    /// Reads a payload from any random-access source holding either a raw
    /// payload or an OTA zip archive.
    pub fn from_reader(reader: Arc<dyn ReadAt>) -> Result<Self> {
        let mut magic = [0u8; 4];
        ensure!(
            reader.size() >= magic.len() as u64,
            Error::NotPayload("input is too small to be a payload".into())
        );
        reader.read_exact_at(&mut magic, 0).map_err(Error::Read)?;
        let payload = match magic {
            MAGIC => reader,
            ZIP_MAGIC => input::payload_in_zip(reader)?,
            _ => {
                return Err(Error::NotPayload(
                    "input is neither a payload.bin nor an OTA zip archive".into(),
                ));
            }
        };
        Self::parse(payload)
    }

    fn parse(reader: Arc<dyn ReadAt>) -> Result<Self> {
        let mut header = [0u8; HEADER_LEN as usize];
        ensure!(
            reader.size() >= HEADER_LEN,
            Error::invalid("payload header is truncated")
        );
        reader.read_exact_at(&mut header, 0).map_err(Error::Read)?;
        ensure!(header[..4] == MAGIC, Error::NotPayload("missing payload magic".into()));
        let version = u64::from_be_bytes(header[4..12].try_into().unwrap());
        ensure!(version == SUPPORTED_MAJOR_VERSION, Error::UnsupportedVersion(version));
        let manifest_size = u64::from_be_bytes(header[12..20].try_into().unwrap());
        let signature_size = u64::from(u32::from_be_bytes(header[20..24].try_into().unwrap()));
        let data_offset = HEADER_LEN
            .checked_add(manifest_size)
            .and_then(|end| end.checked_add(signature_size))
            .filter(|&end| end <= reader.size())
            .ok_or(Error::invalid("manifest extends past the end of the payload"))?;

        let mut bytes = vec![0u8; manifest_size as usize];
        reader.read_exact_at(&mut bytes, HEADER_LEN).map_err(Error::Read)?;
        let manifest = DeltaArchiveManifest::decode(bytes.as_slice())?;
        ensure!(
            manifest.block_size().is_power_of_two(),
            Error::invalid(format!("block size {} is not a power of two", manifest.block_size()))
        );
        ensure!(
            manifest.minor_version() != 1,
            Error::invalid("in-place delta payloads (minor version 1) are not supported")
        );
        Ok(Self {
            reader,
            manifest,
            data_offset,
        })
    }

    pub fn manifest(&self) -> &DeltaArchiveManifest {
        &self.manifest
    }

    pub fn partitions(&self) -> &[PartitionUpdate] {
        &self.manifest.partitions
    }

    pub fn partition(&self, name: &str) -> Option<&PartitionUpdate> {
        self.partitions().iter().find(|p| p.partition_name == name)
    }

    pub fn block_size(&self) -> u32 {
        self.manifest.block_size()
    }

    /// Payload minor version; 0 for full payloads.
    pub fn minor_version(&self) -> u32 {
        self.manifest.minor_version()
    }

    /// Whether some partition is built from a source image.
    pub fn is_incremental(&self) -> bool {
        self.partitions().iter().any(crate::partition::reads_source)
    }

    /// Size in bytes of the payload itself, excluding any surrounding archive.
    pub fn size(&self) -> u64 {
        self.reader.size()
    }

    /// Offset of the operation data within the payload.
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }

    pub(crate) fn read_granularity(&self) -> u64 {
        self.reader.read_granularity()
    }

    /// Reads `buf.len()` bytes of operation data starting at `offset`, which is
    /// relative to the start of the operation data.
    pub(crate) fn read_data(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = self
            .data_offset
            .checked_add(offset)
            .filter(|start| {
                start
                    .checked_add(buf.len() as u64)
                    .is_some_and(|end| end <= self.reader.size())
            })
            .ok_or(Error::invalid("operation data extends past the end of the payload"))?;
        self.reader.read_exact_at(buf, start).map_err(Error::Read)
    }
}
