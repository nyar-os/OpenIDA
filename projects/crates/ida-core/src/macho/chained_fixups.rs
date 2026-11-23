//! The `LC_DYLD_CHAINED_FIXUPS` table: its header, import entries and the
//! starts-table summary. The chained fixup pointers themselves are not decoded.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::parse_macho;
use serde::{Deserialize, Serialize};

use super::{
    HEADER32_SIZE, HEADER64_SIZE, LC_DYLD_CHAINED_FIXUPS,
    util::{Reader, fat_header},
};
use crate::{IdaError, Result};

/// One import entry of the `LC_DYLD_CHAINED_FIXUPS` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOChainedImport {
    /// Library ordinal; negative values are special ordinals such as `-2` (flat lookup).
    pub lib_ordinal: i32,
    /// Whether the import is weak.
    pub weak_import: bool,
    /// Offset into the symbol string pool.
    pub name_offset: u32,
    /// Resolved symbol name; empty when the pool is compressed or the offset is out of range.
    pub name: String,
    /// Addend for the `ADDEND` / `ADDEND64` import formats.
    pub addend: Option<i64>,
}

/// Decoded `dyld_chained_fixups_header`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOChainedFixupsHeader {
    /// Structural version recorded by the linker; currently `0`.
    pub fixups_version: u32,
    /// Offset of `dyld_chained_starts_in_image`, relative to the start of the chain data.
    pub starts_offset: u32,
    /// Offset of the imports table, relative to the start of the chain data.
    pub imports_offset: u32,
    /// Offset of the symbol string pool, relative to the start of the chain data.
    pub symbols_offset: u32,
    /// Number of declared imports.
    pub imports_count: u32,
    /// Import entry layout: `1` import, `2` import with addend, `3` import with 64-bit addend.
    pub imports_format: u32,
    /// Symbol pool encoding: `0` uncompressed, `1` zlib.
    pub symbols_format: u32,
}

/// Summary of `LC_DYLD_CHAINED_FIXUPS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOChainedFixupsReport {
    /// Whether the image carries an `LC_DYLD_CHAINED_FIXUPS` command.
    pub present: bool,
    /// File offset of the chain data.
    pub data_offset: u32,
    /// Size of the chain data in bytes.
    pub data_size: u32,
    /// Decoded header, when the chain data is long enough.
    pub header: Option<MachOChainedFixupsHeader>,
    /// Imports that survived the limit.
    pub imports: Vec<MachOChainedImport>,
    /// Whether the import limit removed entries.
    pub truncated: bool,
    /// Segment count of `dyld_chained_starts_in_image`, when the starts table parses.
    pub starts_in_image: Option<u32>,
    /// Number of segments with a non-empty chained-start table.
    pub starts_in_segment_count: usize,
}

/// Upper bound on parsed imports, so a corrupt count cannot force a huge allocation.
const MAX_CHAINED_IMPORTS: usize = 512;
const DYLD_CHAINED_IMPORT: u32 = 1;
const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

fn chained_import(reader: &Reader, base: u64, index: usize, format: u32, symbols: &[u8]) -> Option<MachOChainedImport> {
    if format == DYLD_CHAINED_IMPORT_ADDEND64 {
        let entry = base.checked_add((index as u64).checked_mul(16)?)?;
        let raw = reader.u64(entry)?;
        let addend = reader.u64(entry + 8)?;
        let lib_ordinal = (raw & 0xffff) as u16 as i16 as i32;
        let weak_import = (raw >> 16) & 1 != 0;
        let name_offset = (raw >> 32) as u32;
        return Some(MachOChainedImport {
            lib_ordinal,
            weak_import,
            name_offset,
            name: chained_name(symbols, name_offset),
            addend: Some(addend as i64),
        });
    }

    let entry = base.checked_add((index as u64).checked_mul(if format == DYLD_CHAINED_IMPORT_ADDEND { 8 } else { 4 })?)?;
    let raw = reader.u32(entry)?;
    let lib_ordinal = (raw & 0xff) as u8 as i8 as i32;
    let weak_import = (raw >> 8) & 1 != 0;
    let name_offset = raw >> 9;
    let addend = match format {
        DYLD_CHAINED_IMPORT_ADDEND => reader.u32(entry + 4).map(|value| i64::from(value as i32)),
        _ => None,
    };
    if format == DYLD_CHAINED_IMPORT_ADDEND && addend.is_none() {
        return None;
    }
    Some(MachOChainedImport { lib_ordinal, weak_import, name_offset, name: chained_name(symbols, name_offset), addend })
}

fn chained_name(symbols: &[u8], offset: u32) -> String {
    let start = offset as usize;
    let Some(rest) = symbols.get(start..)
    else {
        return String::new();
    };
    let end = rest.iter().position(|byte| *byte == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

/// Decodes `LC_DYLD_CHAINED_FIXUPS`, its header, imports and starts table.
pub(crate) fn chained_fixups(session: &BinarySession) -> Result<MachOChainedFixupsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O chained fixups require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut command = None;
    for _ in 0..image.header.command_count {
        let (Some(kind), Some(size)) = (reader.u32(offset), reader.u32(offset + 4))
        else {
            break;
        };
        if size < 8 {
            break;
        }
        if kind == LC_DYLD_CHAINED_FIXUPS && size >= 16 {
            command = match (reader.u32(offset + 8), reader.u32(offset + 12)) {
                (Some(data_offset), Some(data_size)) => Some((data_offset, data_size)),
                _ => None,
            };
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let mut report = MachOChainedFixupsReport {
        present: false,
        data_offset: 0,
        data_size: 0,
        header: None,
        imports: Vec::new(),
        truncated: false,
        starts_in_image: None,
        starts_in_segment_count: 0,
    };
    let Some((data_offset, data_size)) = command
    else {
        return Ok(report);
    };
    report.present = true;
    report.data_offset = data_offset;
    report.data_size = data_size;

    let base = u64::from(data_offset);
    let (
        Some(fixups_version),
        Some(starts_offset),
        Some(imports_offset),
        Some(symbols_offset),
        Some(imports_count),
        Some(imports_format),
        Some(symbols_format),
    ) = (
        reader.u32(base),
        reader.u32(base + 4),
        reader.u32(base + 8),
        reader.u32(base + 12),
        reader.u32(base + 16),
        reader.u32(base + 20),
        reader.u32(base + 24),
    )
    else {
        return Ok(report);
    };
    report.header = Some(MachOChainedFixupsHeader {
        fixups_version,
        starts_offset,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
        symbols_format,
    });

    let symbols = match symbols_format {
        0 => reader.slice(base + u64::from(symbols_offset), u64::from(data_size)).unwrap_or(&[]),
        _ => &[],
    };
    let imports_base = base.saturating_add(u64::from(imports_offset));
    let declared = imports_count as usize;
    let limit = declared.min(MAX_CHAINED_IMPORTS);
    let known_format =
        matches!(imports_format, DYLD_CHAINED_IMPORT | DYLD_CHAINED_IMPORT_ADDEND | DYLD_CHAINED_IMPORT_ADDEND64);
    if known_format {
        for index in 0..limit {
            match chained_import(&reader, imports_base, index, imports_format, symbols) {
                Some(import) => report.imports.push(import),
                None => break,
            }
        }
    }
    report.truncated = declared > report.imports.len();

    if let Some(seg_count) = reader.u32(base + u64::from(starts_offset)) {
        report.starts_in_image = Some(seg_count);
        let max = (seg_count as usize).min(MAX_CHAINED_IMPORTS);
        let table = base + u64::from(starts_offset) + 4;
        for index in 0..max {
            match reader.u32(table + (index as u64) * 4) {
                Some(value) if value != 0 => report.starts_in_segment_count += 1,
                Some(_) => {}
                None => break,
            }
        }
    }

    Ok(report)
}
