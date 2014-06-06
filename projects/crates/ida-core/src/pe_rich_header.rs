//! PE Rich header decoding.
//!
//! The Rich header is an XOR-obfuscated build stamp that the MS linker writes
//! between the DOS stub and the PE header. The run ends with the ASCII `Rich`
//! signature followed by the four-byte XOR key; it starts with a `DanS`
//! marker and three key-width padding words, then each eight-byte entry is a
//! `(compid, build)` pair and a count, both XOR'd with the key. The decoder
//! locates `Rich` inside the DOS stub region, validates the `DanS` marker with
//! the key and decodes up to 64 entries. Well-known compids get a best-effort
//! tool name; every entry always carries its raw compid, build and count. An
//! image without a validated Rich header reports `present: false`. Nothing
//! here proves the toolchain was not spoofed.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const MAX_RICH_ENTRIES: usize = 64;
const DANS_MARKER: u32 = 0x536e_6144;
const RICH_SIGNATURE: &[u8] = b"Rich";

/// One decoded Rich header entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeRichEntry {
    /// Component id recorded by the linker.
    pub comp_id: u16,
    /// Build number of that component.
    pub build: u16,
    /// Number of objects produced by the component.
    pub count: u32,
    /// Best-effort tool name for the compid, absent when unknown.
    pub name: Option<String>,
}

/// Decoded PE Rich header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeRichHeaderReport {
    /// Whether a validated Rich header was found.
    pub present: bool,
    /// File offset of the `Rich` signature.
    pub rich_offset: u32,
    /// File offset of the `DanS` marker.
    pub dans_offset: u32,
    /// XOR key that obfuscates the run.
    pub key: u32,
    /// Entries that survived the limit, in run order.
    pub entries: Vec<PeRichEntry>,
    /// Total entries in the decoded run.
    pub total: usize,
    /// Whether the run was cut by the limit or was not entry-aligned.
    pub truncated: bool,
}

/// Decodes the Rich header of one PE session.
pub(crate) fn analyze(session: &BinarySession) -> Result<PeRichHeaderReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE Rich header decoding requires a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;

    let start = 0x40usize;
    let end = usize::try_from(image.dos.pe_offset).map_err(|_| IdaError::parse("PE: e_lfanew is out of bounds"))?;
    let empty = || {
        PeRichHeaderReport {
            present: false,
            rich_offset: 0,
            dans_offset: 0,
            key: 0,
            entries: Vec::new(),
            total: 0,
            truncated: false,
        }
    };
    if end <= start + 8 {
        return Ok(empty());
    }

    let mut rich_offset = None;
    for candidate in start..=(end - 8) {
        if bytes[candidate..candidate + 4] == *RICH_SIGNATURE {
            rich_offset = Some(candidate);
            break;
        }
    }
    let Some(rich) = rich_offset else { return Ok(empty()) };
    let Some(key) = read_u32(bytes, rich + 4) else { return Ok(empty()) };

    let mut dans = None;
    let mut probe = rich.saturating_sub(4);
    while probe >= start {
        if read_u32(bytes, probe).is_some_and(|value| value ^ key == DANS_MARKER) {
            dans = Some(probe);
            break;
        }
        if probe < start + 4 {
            break;
        }
        probe -= 4;
    }
    let Some(dans) = dans else { return Ok(empty()) };

    let run_start = dans + 16;
    let mut truncated = false;
    let run_bytes = rich.saturating_sub(run_start);
    if run_bytes % 8 != 0 {
        truncated = true;
    }
    let total = run_bytes / 8;
    if total > MAX_RICH_ENTRIES {
        truncated = true;
    }
    let mut entries = Vec::new();
    for index in 0..total.min(MAX_RICH_ENTRIES) {
        let at = run_start + index * 8;
        let (Some(id), Some(count)) = (read_u32(bytes, at), read_u32(bytes, at + 4)) else {
            truncated = true;
            break;
        };
        let id = id ^ key;
        let count = count ^ key;
        entries.push(PeRichEntry {
            comp_id: (id & 0xffff) as u16,
            build: (id >> 16) as u16,
            count,
            name: comp_id_name((id & 0xffff) as u16).map(str::to_owned),
        });
    }
    Ok(PeRichHeaderReport {
        present: true,
        rich_offset: rich as u32,
        dans_offset: dans as u32,
        key,
        entries,
        total,
        truncated,
    })
}

fn comp_id_name(comp_id: u16) -> Option<&'static str> {
    match comp_id {
        1 => Some("Microsoft Visual C++ 5.0"),
        2 => Some("Microsoft Visual C++ 6.0"),
        155 => Some("Microsoft Visual C++ 14.x (VS2017-2022)"),
        216 | 218 | 220 | 222 | 224 | 226 | 228 | 233 | 239 | 243 => {
            Some("Microsoft C/C++ linker or CRT (VS2017-2022 era)")
        }
        _ => None,
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}
