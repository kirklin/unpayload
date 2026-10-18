//! Facts about a single partition update.

use std::collections::BTreeMap;

use crate::metadata::{InstallOperation, OperationType, PartitionUpdate};

/// The operation type, or `None` for types this program does not know.
pub fn operation_type(op: &InstallOperation) -> Option<OperationType> {
    OperationType::try_from(op.r#type).ok()
}

/// Whether building the partition requires its source image.
pub fn reads_source(update: &PartitionUpdate) -> bool {
    update
        .operations
        .iter()
        .any(|op| !op.src_extents.is_empty() || operation_type(op).is_some_and(OperationType::reads_source))
}

/// Size of the resulting image in bytes.
pub fn new_size(update: &PartitionUpdate) -> Option<u64> {
    update.new_partition_info.as_ref().and_then(|info| info.size)
}

/// Number of operations of each type, keyed by type name. Unknown types are
/// reported by number.
pub fn operation_counts(update: &PartitionUpdate) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for op in &update.operations {
        let name = match operation_type(op) {
            Some(kind) => kind.name().to_owned(),
            None => format!("TYPE_{}", op.r#type),
        };
        *counts.entry(name).or_default() += 1;
    }
    counts
}

/// Whether the dm-verity hash tree is recomputed after the operations run.
pub fn has_hash_tree(update: &PartitionUpdate) -> bool {
    update.hash_tree_extent.is_some_and(|e| e.num_blocks() > 0)
}

/// Whether dm-verity FEC parity is recomputed after the operations run.
pub fn has_fec(update: &PartitionUpdate) -> bool {
    update.fec_extent.is_some_and(|e| e.num_blocks() > 0)
}
