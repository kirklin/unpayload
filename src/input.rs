//! Random-access byte sources: local files, slices of them, and payloads
//! stored inside OTA zip archives.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use zip::read::{ArchiveOffset, Config};
use zip::{CompressionMethod, ZipArchive};

use crate::error::{Error, Result, ensure};
use crate::fsio;

/// Bytes that can be read at arbitrary offsets from several threads at once.
pub trait ReadAt: Send + Sync {
    /// Fills `buf` with the bytes starting at `offset`.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;

    /// Total number of bytes.
    fn size(&self) -> u64;
}

pub struct LocalFile {
    file: File,
    size: u64,
}

impl LocalFile {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(Error::file(path))?;
        Self::from_file(file).map_err(Error::file(path))
    }

    pub fn from_file(file: File) -> io::Result<Self> {
        let size = file.metadata()?.len();
        Ok(Self { file, size })
    }
}

impl ReadAt for LocalFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        fsio::read_exact_at(&self.file, buf, offset)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// A window of `len` bytes starting at `start` within another source.
pub struct Slice {
    inner: Arc<dyn ReadAt>,
    start: u64,
    len: u64,
}

impl Slice {
    pub fn new(inner: Arc<dyn ReadAt>, start: u64, len: u64) -> io::Result<Self> {
        if start.checked_add(len).is_none_or(|end| end > inner.size()) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "slice extends past the end of its source",
            ));
        }
        Ok(Self { inner, start, len })
    }
}

impl ReadAt for Slice {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let in_bounds = offset.checked_add(buf.len() as u64).is_some_and(|end| end <= self.len);
        if !in_bounds {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.inner.read_exact_at(buf, self.start + offset)
    }

    fn size(&self) -> u64 {
        self.len
    }
}

/// Sequential reader with seeking over a [`ReadAt`], used to parse zip archives.
struct Cursor<'a> {
    inner: &'a dyn ReadAt,
    pos: u64,
}

impl Read for Cursor<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.inner.size().saturating_sub(self.pos);
        let n = buf.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.inner.read_exact_at(&mut buf[..n], self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Cursor<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.inner.size().checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };
        self.pos = target.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?;
        Ok(self.pos)
    }
}

const PAYLOAD_ENTRY: &str = "payload.bin";

/// Finds `payload.bin` inside an OTA zip archive.
///
/// A stored entry is read in place. A compressed entry is inflated into an
/// anonymous temporary file first, since payloads need random access.
pub(crate) fn payload_in_zip(archive: Arc<dyn ReadAt>) -> Result<Arc<dyn ReadAt>> {
    // OTA packages start with the archive, and searching for its start would
    // scan the whole file.
    let config = Config {
        archive_offset: ArchiveOffset::Known(0),
    };
    let cursor = Cursor {
        inner: &*archive,
        pos: 0,
    };
    let mut zip = ZipArchive::with_config(config, cursor)?;
    let index = zip
        .index_for_name(PAYLOAD_ENTRY)
        .or_else(|| {
            let suffix = format!("/{PAYLOAD_ENTRY}");
            (0..zip.len()).find(|&i| {
                zip.name_for_index(i)
                    .is_some_and(|name| name.is_ok_and(|name| name.ends_with(&suffix)))
            })
        })
        .ok_or(Error::NotPayload("zip archive contains no payload.bin".into()))?;
    let mut entry = zip.by_index(index)?;
    if entry.compression() == CompressionMethod::Stored {
        let start = entry
            .data_start()
            .ok_or(Error::invalid("cannot locate payload.bin data in the zip archive"))?;
        let slice = Slice::new(archive.clone(), start, entry.size())
            .map_err(|_| Error::invalid("payload.bin runs past the end of the zip archive"))?;
        return Ok(Arc::new(slice));
    }
    let mut file = tempfile::tempfile().map_err(Error::Unpack)?;
    let copied = io::copy(&mut entry, &mut file).map_err(Error::Unpack)?;
    ensure!(
        copied == entry.size(),
        Error::invalid("payload.bin in the zip archive is truncated")
    );
    Ok(Arc::new(LocalFile::from_file(file).map_err(Error::Unpack)?))
}
