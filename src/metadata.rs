//! Protocol buffer messages of the update payload manifest.
//!
//! Only the fields needed to extract images and describe a payload are
//! declared; unknown fields are skipped while decoding.

use prost::{Enumeration, Message};

/// A run of `num_blocks` consecutive blocks starting at `start_block`.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct Extent {
    #[prost(uint64, optional, tag = "1")]
    pub start_block: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    pub num_blocks: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PartitionInfo {
    #[prost(uint64, optional, tag = "1")]
    pub size: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub hash: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
pub enum OperationType {
    Replace = 0,
    ReplaceBz = 1,
    Move = 2,
    Bsdiff = 3,
    SourceCopy = 4,
    SourceBsdiff = 5,
    Zero = 6,
    Discard = 7,
    ReplaceXz = 8,
    Puffdiff = 9,
    BrotliBsdiff = 10,
    Zucchini = 11,
    Lz4diffBsdiff = 12,
    Lz4diffPuffdiff = 13,
    ReplaceZstd = 14,
}

impl OperationType {
    pub fn name(self) -> &'static str {
        match self {
            Self::Replace => "REPLACE",
            Self::ReplaceBz => "REPLACE_BZ",
            Self::Move => "MOVE",
            Self::Bsdiff => "BSDIFF",
            Self::SourceCopy => "SOURCE_COPY",
            Self::SourceBsdiff => "SOURCE_BSDIFF",
            Self::Zero => "ZERO",
            Self::Discard => "DISCARD",
            Self::ReplaceXz => "REPLACE_XZ",
            Self::Puffdiff => "PUFFDIFF",
            Self::BrotliBsdiff => "BROTLI_BSDIFF",
            Self::Zucchini => "ZUCCHINI",
            Self::Lz4diffBsdiff => "LZ4DIFF_BSDIFF",
            Self::Lz4diffPuffdiff => "LZ4DIFF_PUFFDIFF",
            Self::ReplaceZstd => "REPLACE_ZSTD",
        }
    }

    /// Whether the operation derives its output from the source image.
    pub fn reads_source(self) -> bool {
        matches!(
            self,
            Self::Move
                | Self::Bsdiff
                | Self::SourceCopy
                | Self::SourceBsdiff
                | Self::Puffdiff
                | Self::BrotliBsdiff
                | Self::Zucchini
                | Self::Lz4diffBsdiff
                | Self::Lz4diffPuffdiff
        )
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct InstallOperation {
    #[prost(enumeration = "OperationType", required, tag = "1")]
    pub r#type: i32,
    #[prost(uint64, optional, tag = "2")]
    pub data_offset: Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub data_length: Option<u64>,
    #[prost(message, repeated, tag = "4")]
    pub src_extents: Vec<Extent>,
    #[prost(uint64, optional, tag = "5")]
    pub src_length: Option<u64>,
    #[prost(message, repeated, tag = "6")]
    pub dst_extents: Vec<Extent>,
    #[prost(uint64, optional, tag = "7")]
    pub dst_length: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub data_sha256_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "9")]
    pub src_sha256_hash: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PartitionUpdate {
    #[prost(string, required, tag = "1")]
    pub partition_name: String,
    #[prost(message, optional, tag = "6")]
    pub old_partition_info: Option<PartitionInfo>,
    #[prost(message, optional, tag = "7")]
    pub new_partition_info: Option<PartitionInfo>,
    #[prost(message, repeated, tag = "8")]
    pub operations: Vec<InstallOperation>,
    #[prost(message, optional, tag = "10")]
    pub hash_tree_data_extent: Option<Extent>,
    #[prost(message, optional, tag = "11")]
    pub hash_tree_extent: Option<Extent>,
    #[prost(string, optional, tag = "12")]
    pub hash_tree_algorithm: Option<String>,
    #[prost(bytes = "vec", optional, tag = "13")]
    pub hash_tree_salt: Option<Vec<u8>>,
    #[prost(message, optional, tag = "14")]
    pub fec_data_extent: Option<Extent>,
    #[prost(message, optional, tag = "15")]
    pub fec_extent: Option<Extent>,
    #[prost(uint32, optional, tag = "16", default = "2")]
    pub fec_roots: Option<u32>,
    #[prost(string, optional, tag = "17")]
    pub version: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DynamicPartitionGroup {
    #[prost(string, required, tag = "1")]
    pub name: String,
    #[prost(uint64, optional, tag = "2")]
    pub size: Option<u64>,
    #[prost(string, repeated, tag = "3")]
    pub partition_names: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DynamicPartitionMetadata {
    #[prost(message, repeated, tag = "1")]
    pub groups: Vec<DynamicPartitionGroup>,
    #[prost(bool, optional, tag = "2")]
    pub snapshot_enabled: Option<bool>,
    #[prost(bool, optional, tag = "3")]
    pub vabc_enabled: Option<bool>,
    #[prost(string, optional, tag = "4")]
    pub vabc_compression_param: Option<String>,
    #[prost(uint32, optional, tag = "5")]
    pub cow_version: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeltaArchiveManifest {
    #[prost(uint32, optional, tag = "3", default = "4096")]
    pub block_size: Option<u32>,
    #[prost(uint64, optional, tag = "4")]
    pub signatures_offset: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    pub signatures_size: Option<u64>,
    #[prost(uint32, optional, tag = "12", default = "0")]
    pub minor_version: Option<u32>,
    #[prost(message, repeated, tag = "13")]
    pub partitions: Vec<PartitionUpdate>,
    #[prost(int64, optional, tag = "14")]
    pub max_timestamp: Option<i64>,
    #[prost(message, optional, tag = "15")]
    pub dynamic_partition_metadata: Option<DynamicPartitionMetadata>,
    #[prost(bool, optional, tag = "16")]
    pub partial_update: Option<bool>,
    #[prost(string, optional, tag = "18")]
    pub security_patch_level: Option<String>,
}
