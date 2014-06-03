//! PE base relocation decoding.
//!
//! The report walks the `IMAGE_BASE_RELOCATION` blocks behind data directory 5
//! and summarises the relocation types. Each block covers one 4 KiB page and is
//! stored as a 16-bit entry per fixup: four type bits plus a twelve-bit page
//! offset. The pinned reader exposes the directory but not the blocks, so the
//! decode lives here.

use std::collections::BTreeMap;

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const DIRECTORY_BASE_RELOCATION: usize = 5;
const MAX_BLOCKS: usize = 4096;
const MAX_STORED_BLOCKS: usize = 128;

/// Number of fixups of one relocation type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelocationKindCount {
    /// Stable type name (`HIGHLOW`, `DIR64`, ...) or `#<n>` for an unknown type.
    pub kind: String,
    /// Fixups with this type.
    pub count: u32,
}

/// One `IMAGE_BASE_RELOCATION` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelocationBlock {
    /// `VirtualAddress` of the 4 KiB page this block fixes up.
    pub page_rva: u32,
    /// Declared block size in bytes, including the eight-byte header.
    pub block_size: u32,
    /// Number of fixup entries decoded from the block.
    pub entries: u32,
    /// Fixups per type inside this block, ordered by type number.
    pub kinds: Vec<RelocationKindCount>,
}

/// Bounded PE base relocation listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelocationsReport {
    /// Whether the image has a non-empty base relocation directory.
    pub present: bool,
    /// Blocks that survived the storage limit, in directory order.
    pub blocks: Vec<RelocationBlock>,
    /// Number of blocks declared by the directory.
    pub total_blocks: usize,
    /// Number of fixup entries across all blocks.
    pub total_entries: u64,
    /// Fixups per type across the whole image, ordered by type number.
    pub kinds: Vec<RelocationKindCount>,
    /// Whether a block or the listing was cut by a limit or a malformed tail.
    pub truncated: bool,
}

/// Decodes the PE base relocations of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<RelocationsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE relocations require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let directory = image.optional.data_directories[DIRECTORY_BASE_RELOCATION];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(RelocationsReport {
            present: false,
            blocks: Vec::new(),
            total_blocks: 0,
            total_entries: 0,
            kinds: Vec::new(),
            truncated: false,
        });
    }
    let base = pe::rva_to_offset(&image.sections, directory.rva)
        .map_err(|error| IdaError::parse(format!("PE relocations: {error}")))? as usize;

    let mut report = RelocationsReport {
        present: true,
        blocks: Vec::new(),
        total_blocks: 0,
        total_entries: 0,
        kinds: Vec::new(),
        truncated: false,
    };
    let mut totals: BTreeMap<u16, u32> = BTreeMap::new();
    let end = base.saturating_add(directory.size as usize);
    let mut offset = base;

    while offset.saturating_add(8) <= end {
        if report.total_blocks >= MAX_BLOCKS {
            report.truncated = true;
            break;
        }
        let Ok(page_rva) = read_u32(bytes, offset) else {
            report.truncated = true;
            break;
        };
        let Ok(block_size) = read_u32(bytes, offset + 4) else {
            report.truncated = true;
            break;
        };
        if block_size < 8 {
            report.truncated = true;
            break;
        }
        let block_end = offset.saturating_add(block_size as usize);
        if block_end > end || block_end > bytes.len() {
            report.truncated = true;
            break;
        }

        report.total_blocks += 1;
        let entries = (block_size - 8) / 2;
        let mut kinds: BTreeMap<u16, u32> = BTreeMap::new();
        for index in 0..entries {
            let at = offset + 8 + index as usize * 2;
            let Ok(raw) = read_u16(bytes, at) else {
                report.truncated = true;
                break;
            };
            let kind = raw >> 12;
            *kinds.entry(kind).or_insert(0) += 1;
            *totals.entry(kind).or_insert(0) += 1;
        }
        report.total_entries += u64::from(entries);

        if report.blocks.len() < MAX_STORED_BLOCKS {
            report.blocks.push(RelocationBlock {
                page_rva,
                block_size,
                entries,
                kinds: kinds.into_iter().map(|(kind, count)| RelocationKindCount { kind: kind_name(kind), count }).collect(),
            });
        }
        else {
            report.truncated = true;
        }

        offset = block_end;
    }

    if offset < end && !report.truncated {
        // A tail shorter than one block header means the directory size does
        // not describe whole blocks.
        report.truncated = true;
    }
    report.kinds = totals.into_iter().map(|(kind, count)| RelocationKindCount { kind: kind_name(kind), count }).collect();
    Ok(report)
}

fn kind_name(kind: u16) -> String {
    match kind {
        0 => "ABSOLUTE".to_string(),
        1 => "HIGH".to_string(),
        2 => "LOW".to_string(),
        3 => "HIGHLOW".to_string(),
        4 => "HIGHADJ".to_string(),
        5 => "MIPS_JMPADDR".to_string(),
        7 => "ARM_MOV32".to_string(),
        9 => "MIPS_JMPADDR16".to_string(),
        10 => "DIR64".to_string(),
        other => format!("#{other}"),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("a relocation entry lies outside the file"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("a relocation block header lies outside the file"))?;
    Ok(u32::from_le_bytes(raw))
}
