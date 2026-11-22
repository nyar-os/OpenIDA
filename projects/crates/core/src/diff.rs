//! Byte-level comparison of two open binaries.
//!
//! Content hashes reuse the digest already reported by the inspection engine,
//! so `diff` never grows a second hashing convention. Differing ranges are
//! bounded to keep huge, completely different files cheap to report.

use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Maximum number of differing ranges kept in one report.
const MAX_RANGES: usize = 64;

/// One contiguous run of differing bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffRange {
    /// File offset where the run starts.
    pub offset: u64,
    /// Length of the run in bytes.
    pub length: u64,
}

/// Result of one [`crate::OpenIda::diff`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffReport {
    /// Size of the left file.
    pub left_size: u64,
    /// Size of the right file.
    pub right_size: u64,
    /// Content hash of the left file.
    pub left_hash: String,
    /// Content hash of the right file.
    pub right_hash: String,
    /// Whether both files are byte-for-byte identical.
    pub identical: bool,
    /// First offset that differs, or where one file ends.
    pub first_difference: Option<u64>,
    /// Differing ranges that survived the limit.
    pub differences: Vec<DiffRange>,
    /// Number of differing ranges before the limit was applied.
    pub total: usize,
    /// Whether the limit removed ranges.
    pub truncated: bool,
    /// Number of bytes compared: the shorter of the two sizes.
    pub compared_bytes: u64,
}

/// Compares two sessions.
pub(crate) fn compare(left: &BinarySession, right: &BinarySession) -> Result<DiffReport> {
    let left_size = left.size();
    let right_size = right.size();
    let left_bytes = left.read(0, left_size)?;
    let right_bytes = right.read(0, right_size)?;
    let left_hash = left.info()?.hash;
    let right_hash = right.info()?.hash;

    let compared = left_size.min(right_size) as usize;
    let mut differences = Vec::new();
    let mut first_difference = None;
    let mut open_start = None;

    for index in 0..compared {
        if left_bytes[index] != right_bytes[index] {
            if first_difference.is_none() {
                first_difference = Some(index as u64);
            }
            open_start.get_or_insert(index as u64);
        }
        else if let Some(start) = open_start.take() {
            differences.push(DiffRange { offset: start, length: index as u64 - start });
        }
    }
    if let Some(start) = open_start.take() {
        differences.push(DiffRange { offset: start, length: compared as u64 - start });
    }

    if left_size != right_size {
        let extra = left_size.max(right_size) - compared as u64;
        first_difference.get_or_insert(compared as u64);
        match differences.last_mut() {
            Some(last) if last.offset + last.length == compared as u64 => last.length += extra,
            _ => differences.push(DiffRange { offset: compared as u64, length: extra }),
        }
    }

    let total = differences.len();
    let truncated = total > MAX_RANGES;
    differences.truncate(MAX_RANGES);

    Ok(DiffReport {
        left_size,
        right_size,
        left_hash,
        right_hash,
        identical: left_size == right_size && first_difference.is_none(),
        first_difference,
        differences,
        total,
        truncated,
        compared_bytes: compared as u64,
    })
}
