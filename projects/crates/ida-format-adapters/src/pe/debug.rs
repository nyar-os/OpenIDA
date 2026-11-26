//! `PE` debug directory and `CodeView` record projection.
//!
//! The 28-byte entry walk, the `PointerToRawData`/`AddressOfRawData` fallback
//! and the `RSDS`/`NB10` payload fields come from the `data-binary-pe`
//! owner. This module keeps only the product JSON shape and the stable
//! `debugType` spellings (`stable_type_name`).

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// One `CodeView` record carried by a debug directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeViewInfo {
    /// Record magic: `RSDS` or `NB10`.
    pub signature: String,
    /// `RSDS` GUID, formatted as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    ///
    /// `None` for `NB10`, which stores an offset and a timestamp instead.
    pub guid: Option<String>,
    /// PDB age.
    pub age: u32,
    /// `NB10` record offset; `None` for `RSDS`.
    pub offset: Option<u32>,
    /// `NB10` timestamp; `None` for `RSDS`.
    pub timestamp: Option<u32>,
    /// PDB path as stored in the record, without the NUL terminator.
    pub path: String,
}

/// One `IMAGE_DEBUG_DIRECTORY` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugEntry {
    /// Debug type such as `codeview`, `fpo` or `pogo`.
    pub debug_type: String,
    /// COFF timestamp of the debug data.
    pub timestamp: u32,
    /// Major version of the debug data format.
    pub major_version: u16,
    /// Minor version of the debug data format.
    pub minor_version: u16,
    /// Size of the payload in bytes.
    pub size_of_data: u32,
    /// RVA of the payload.
    pub address_of_raw_data: u32,
    /// File offset of the payload.
    pub pointer_to_raw_data: u32,
    /// Decoded `CodeView` record, when this entry carries one.
    pub code_view: Option<CodeViewInfo>,
}

/// Bounded listing of [`DebugEntry`] values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugReport {
    /// Entries that survived the limit.
    pub entries: Vec<DebugEntry>,
    /// Number of entries before the limit was applied.
    pub total: usize,
    /// Whether the limit removed entries.
    pub truncated: bool,
}

/// Lists the debug directory of one open session.
pub fn analyze(session: &BinarySession, limit: Option<usize>) -> Result<DebugReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("the PE debug directory is only available for PE files"));
    }

    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let directory =
        pe::read_debug_directory(&image, bytes).map_err(|error| IdaError::parse(format!("PE debug directory: {error}")))?;

    let total = directory.len();
    let limit = limit.unwrap_or(usize::MAX);
    let truncated = total > limit;
    let entries = directory
        .iter()
        .take(limit)
        .map(|entry| DebugEntry {
            debug_type: entry.stable_type_name().to_string(),
            timestamp: entry.timestamp,
            major_version: entry.major_version,
            minor_version: entry.minor_version,
            size_of_data: entry.size_of_data,
            address_of_raw_data: entry.address_of_raw_data,
            pointer_to_raw_data: entry.pointer_to_raw_data,
            code_view: entry.code_view.as_ref().map(|record| CodeViewInfo {
                signature: record.signature.clone(),
                guid: record.guid_string(),
                age: record.age,
                offset: record.offset,
                timestamp: record.timestamp,
                path: record.path.clone(),
            }),
        })
        .collect();
    Ok(DebugReport { entries, total, truncated })
}
