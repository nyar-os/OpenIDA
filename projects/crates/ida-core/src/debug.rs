//! `PE` debug directory and `CodeView` record decoding.
//!
//! The debug data directory (index 6) is not part of the shared inspection
//! engine, so this module parses it directly from the file bytes and follows
//! the `RVA` mapping exported by `data-binary-pe`. Only the records that are
//! actually present are reported; a non-PE file is a stable unsupported error.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Data directory index of the debug directory.
const DEBUG_DIRECTORY_INDEX: usize = 6;
/// `IMAGE_DEBUG_DIRECTORY` is 28 bytes.
const DEBUG_DIRECTORY_ENTRY_SIZE: usize = 28;

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

impl DebugReport {
    fn empty() -> Self {
        Self { entries: Vec::new(), total: 0, truncated: false }
    }
}

/// Lists the debug directory of one open session.
pub(crate) fn analyze(session: &BinarySession, limit: Option<usize>) -> Result<DebugReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("the PE debug directory is only available for PE files"));
    }

    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let directory = image.optional.data_directories[DEBUG_DIRECTORY_INDEX];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(DebugReport::empty());
    }

    let directory_offset = pe::rva_to_offset(&image.sections, directory.rva)
        .map_err(|error| IdaError::parse(format!("PE debug directory: {error}")))? as usize;
    let available = bytes.len().saturating_sub(directory_offset);
    let directory_size = (directory.size as usize).min(available);
    let total = directory_size / DEBUG_DIRECTORY_ENTRY_SIZE;

    let mut entries = Vec::new();
    for index in 0..total {
        let offset = directory_offset + index * DEBUG_DIRECTORY_ENTRY_SIZE;
        let entry = &bytes[offset..offset + DEBUG_DIRECTORY_ENTRY_SIZE];
        entries.push(DebugEntry {
            timestamp: le_u32(entry, 4),
            major_version: le_u16(entry, 8),
            minor_version: le_u16(entry, 10),
            debug_type: debug_type_name(le_u32(entry, 12)),
            size_of_data: le_u32(entry, 16),
            address_of_raw_data: le_u32(entry, 20),
            pointer_to_raw_data: le_u32(entry, 24),
            code_view: code_view(bytes, &image, le_u32(entry, 16), le_u32(entry, 20), le_u32(entry, 24)),
        });
    }

    let limit = limit.unwrap_or(usize::MAX);
    let truncated = total > limit;
    entries.truncate(limit);
    Ok(DebugReport { entries, total, truncated })
}

fn code_view(bytes: &[u8], image: &pe::PeImage, size: u32, address: u32, pointer: u32) -> Option<CodeViewInfo> {
    if size == 0 {
        return None;
    }
    let offset = if pointer != 0 { pointer as usize } else { pe::rva_to_offset(&image.sections, address).ok()? as usize };
    let available = bytes.len().saturating_sub(offset);
    let size = (size as usize).min(available);
    let data = &bytes[offset..offset + size];
    if data.len() < 4 {
        return None;
    }

    match &data[..4] {
        b"RSDS" if data.len() >= 24 => Some(CodeViewInfo {
            signature: "RSDS".to_string(),
            guid: Some(code_view_guid(&data[4..20])),
            age: le_u32(data, 20),
            offset: None,
            timestamp: None,
            path: nul_terminated(&data[24..]),
        }),
        b"NB10" if data.len() >= 16 => Some(CodeViewInfo {
            signature: "NB10".to_string(),
            guid: None,
            age: le_u32(data, 12),
            offset: Some(le_u32(data, 4)),
            timestamp: Some(le_u32(data, 8)),
            path: nul_terminated(&data[16..]),
        }),
        _ => None,
    }
}

fn code_view_guid(raw: &[u8]) -> String {
    let data1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let data2 = u16::from_le_bytes([raw[4], raw[5]]);
    let data3 = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{data1:08x}-{data2:04x}-{data3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    )
}

fn nul_terminated(data: &[u8]) -> String {
    let end = data.iter().position(|&byte| byte == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

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

fn le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}
