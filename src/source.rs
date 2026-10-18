//! Source images that incremental payloads patch.

use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result, ensure};
use crate::extent::total_len;
use crate::fsio;

pub(crate) struct SourceImage {
    file: File,
    size: u64,
    path: PathBuf,
}

impl SourceImage {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(Error::file(path))?;
        let size = file.metadata().map_err(Error::file(path))?.len();
        Ok(Self {
            file,
            size,
            path: path.to_owned(),
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads and concatenates `ranges`.
    pub fn read(&self, ranges: &[Range<u64>]) -> Result<Vec<u8>> {
        let mut data = vec![0u8; total_len(ranges) as usize];
        let mut filled = 0;
        for range in ranges {
            ensure!(
                range.end <= self.size,
                Error::Source(format!(
                    "{} is {} bytes, the payload reads it up to byte {}",
                    self.path.display(),
                    self.size,
                    range.end
                ))
            );
            let len = (range.end - range.start) as usize;
            fsio::read_exact_at(&self.file, &mut data[filled..filled + len], range.start)
                .map_err(Error::file(&self.path))?;
            filled += len;
        }
        Ok(data)
    }

    /// SHA-256 of the first `len` bytes.
    pub fn digest(&self, len: u64) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 4 << 20];
        let mut offset = 0;
        while offset < len {
            let n = (len - offset).min(buf.len() as u64) as usize;
            fsio::read_exact_at(&self.file, &mut buf[..n], offset).map_err(Error::file(&self.path))?;
            hasher.update(&buf[..n]);
            offset += n as u64;
        }
        Ok(hasher.finalize().to_vec())
    }
}
