//! `PE` debug directory and `CodeView` record decoding.
//!
//! The 28-byte entry walk, the `PointerToRawData`/`AddressOfRawData` fallback
//! and the `RSDS`/`NB10` payload fields come from the `data-binary-pe`
//! `read_debug_directory` owner. Two facts stay local because the owner does
//! not return them with the product semantics: the legacy `NB10` offset and
//! timestamp pair, and the stable `debug_type` name table. A non-PE file is a
//! stable unsupported error.

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
            debug_type: debug_type_name(entry.debug_type),
            timestamp: entry.timestamp,
            major_version: entry.major_version,
            minor_version: entry.minor_version,
            size_of_data: entry.size_of_data,
            address_of_raw_data: entry.address_of_raw_data,
            pointer_to_raw_data: entry.pointer_to_raw_data,
            code_view: code_view(bytes, &image, entry),
        })
        .collect();
    Ok(DebugReport { entries, total, truncated })
}

fn code_view(bytes: &[u8], image: &pe::PeImage, entry: &pe::PeDebugEntry) -> Option<CodeViewInfo> {
    let record = entry.code_view.as_ref()?;
    // The owner already resolved the payload location; reproducing the same
    // rule keeps the `NB10` fields aligned with the record it read.
    let offset = if entry.pointer_to_raw_data != 0 {
        entry.pointer_to_raw_data as usize
    }
    else {
        pe::rva_to_offset(&image.sections, entry.address_of_raw_data).ok()? as usize
    };
    let available = bytes.len().checked_sub(offset)?;
    let length = (entry.size_of_data as usize).min(available);
    let minimum = match record.signature.as_str() {
        "RSDS" => 24,
        "NB10" => 16,
        _ => return None,
    };
    if length < minimum {
        return None;
    }

    let (offset_field, timestamp) = if record.signature == "NB10" {
        let data = bytes.get(offset..offset.checked_add(12)?)?;
        (Some(le_u32(data, 4)), Some(le_u32(data, 8)))
    }
    else {
        (None, None)
    };
    Some(CodeViewInfo {
        signature: record.signature.clone(),
        guid: record.guid.map(|raw| code_view_guid(&raw)),
        age: record.age,
        offset: offset_field,
        timestamp,
        path: record.path.clone(),
    })
}

fn code_view_guid(raw: &[u8; 16]) -> String {
    let data1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let data2 = u16::from_le_bytes([raw[4], raw[5]]);
    let data3 = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{data1:08x}-{data2:04x}-{data3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    )
}

/// Product `debug_type` names.
///
/// Kept local: the owner's `PeDebugEntry::type_name` uses different spellings
/// for the same values (`vc_feature`, `reserved10`, `clsid`), so switching would
/// change the wire values.
fn debug_type_name(value: u32) -> String {
    match value {
        0 => "unknown",
        1 => "coff",
        2 => "codeview",
        3 => "fpo",
        4 => "misc",
        5 => "exception",
        6 => "fixup",
        7 => "omap-to-source",
        8 => "omap-from-source",
        9 => "borland",
        10 => "reserved",
        11 => "vc-feature",
        12 => "pogo",
        13 => "iltcg",
        14 => "mpx",
        16 => "repro",
        17 => "embedded-portable-pdb",
        _ => "other",
    }
    .to_string()
}

fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}
