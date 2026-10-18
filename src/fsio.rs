//! Positional file I/O that is safe to issue from several threads at once.

use std::fs::File;
use std::io;
use std::path::Path;

use crate::error::{Error, Result};

/// A file together with its path, which its I/O errors name.
#[derive(Clone, Copy)]
pub(crate) struct NamedFile<'a> {
    pub file: &'a File,
    pub path: &'a Path,
}

impl NamedFile<'_> {
    pub fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        read_exact_at(self.file, buf, offset).map_err(Error::file(self.path))
    }

    pub fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()> {
        write_all_at(self.file, buf, offset).map_err(Error::file(self.path))
    }
}

#[cfg(unix)]
pub fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(unix)]
pub fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, buf, offset)
}

#[cfg(windows)]
pub fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_write(buf, offset) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
