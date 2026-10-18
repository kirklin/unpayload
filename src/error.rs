use std::borrow::Cow;
use std::io;
use std::path::{Path, PathBuf};

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors carry their cause as [`std::error::Error::source`], not in their
/// message.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", path.display())]
    File {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("cannot read the payload")]
    Read(#[source] io::Error),

    #[error("{0}")]
    NotPayload(Cow<'static, str>),

    #[error("unsupported payload major version {0}")]
    UnsupportedVersion(u64),

    #[error("invalid payload: {0}")]
    InvalidPayload(Cow<'static, str>),

    #[error("cannot decode the payload manifest")]
    Manifest(#[from] prost::DecodeError),

    #[error("cannot start worker threads")]
    Threads(#[source] rayon::ThreadPoolBuildError),

    #[error("partitions not in payload: {}", .0.join(", "))]
    UnknownPartitions(Vec<String>),

    #[error("partition {0} is incremental and needs its source image {0}.img")]
    MissingSource(String),

    #[error("{0}")]
    Source(String),

    #[error("{} already exists", .0.display())]
    OutputExists(PathBuf),

    #[error("{what} sha256 mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        what: String,
        expected: String,
        actual: String,
    },

    #[error("{format} patch: {message}")]
    Patch {
        format: &'static str,
        message: Cow<'static, str>,
    },

    #[error("partition {partition}, operation {index} ({kind})")]
    Operation {
        partition: String,
        index: usize,
        kind: &'static str,
        #[source]
        source: Box<Error>,
    },

    #[error("partition {partition}")]
    Partition {
        partition: String,
        #[source]
        source: Box<Error>,
    },

    #[error("stopped after another partition failed")]
    Stopped,

    #[error("extraction was cancelled")]
    Cancelled,
}

impl Error {
    pub(crate) fn invalid(message: impl Into<Cow<'static, str>>) -> Self {
        Self::InvalidPayload(message.into())
    }

    pub(crate) fn patch(format: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self::Patch {
            format,
            message: message.into(),
        }
    }

    pub(crate) fn file(path: &Path) -> impl FnOnce(io::Error) -> Self + '_ {
        move |source| Self::File {
            path: path.to_owned(),
            source,
        }
    }

    pub(crate) fn hash_mismatch(what: impl Into<String>, expected: &[u8], actual: &[u8]) -> Self {
        Self::HashMismatch {
            what: what.into(),
            expected: hex(expected),
            actual: hex(actual),
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns early with `$err` unless `$cond` holds.
macro_rules! ensure {
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err);
        }
    };
}
pub(crate) use ensure;
