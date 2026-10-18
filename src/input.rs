//! Random-access byte sources, such as local files.

use std::fs::File;
use std::io;
use std::path::Path;

use crate::error::{Error, Result};
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
