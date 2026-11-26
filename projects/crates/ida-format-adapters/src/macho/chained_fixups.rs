//! The `LC_DYLD_CHAINED_FIXUPS` projection.
//!
//! The header, import entries and starts summary are owned by
//! `data-binary-mach-o` (`read_chained_fixups`). The chained pointers
//! themselves are not decoded by either side.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{fat_magic, parse_macho, read_chained_fixups};
use serde::{Deserialize, Serialize};

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

/// Decodes the chained fixup table of one session.
pub fn chained_fixups(session: &BinarySession) -> Result<MachOChainedFixupsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O chained fixups require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let fixups = read_chained_fixups(bytes, &image);

    Ok(MachOChainedFixupsReport {
        present: fixups.present,
        data_offset: fixups.data_offset,
        data_size: fixups.data_size,
        header: fixups.header.map(|header| MachOChainedFixupsHeader {
            fixups_version: header.fixups_version,
            starts_offset: header.starts_offset,
            imports_offset: header.imports_offset,
            symbols_offset: header.symbols_offset,
            imports_count: header.imports_count,
            imports_format: header.imports_format,
            symbols_format: header.symbols_format,
        }),
        imports: fixups
            .imports
            .into_iter()
            .map(|import| MachOChainedImport {
                lib_ordinal: import.lib_ordinal,
                weak_import: import.weak_import,
                name_offset: import.name_offset,
                name: import.name,
                addend: import.addend,
            })
            .collect(),
        truncated: fixups.truncated,
        starts_in_image: fixups.starts_in_image,
        starts_in_segment_count: fixups.starts_in_segment_count,
    })
}
