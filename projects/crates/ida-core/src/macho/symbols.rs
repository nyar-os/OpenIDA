//! The `LC_SYMTAB` symbol table of a Mach-O image and its `nlist` entries.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::parse_macho;
use serde::{Deserialize, Serialize};

use super::{
    HEADER32_SIZE, HEADER64_SIZE, LC_SYMTAB,
    util::{Reader, fat_header},
};
use crate::{IdaError, Result};

/// One `nlist` entry of the `LC_SYMTAB` symbol table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSymbol {
    /// Name resolved through the string table; empty when the index is out of range.
    pub name: String,
    /// `n_value`, which is a virtual address for defined symbols.
    pub address: u64,
    /// Symbol kind derived from `n_type & N_TYPE`: `undefined`, `absolute`,
    /// `section`, `indirect`, `prebound`, `debug` or `other`.
    pub kind: String,
    /// Whether the symbol is external (`N_EXT`).
    pub external: bool,
    /// Whether the entry is a debugging stab (`N_STAB`).
    pub debug: bool,
    /// `n_sect` for section-relative symbols, otherwise `None`.
    pub section: Option<u8>,
    /// Raw `n_desc`, for example the library ordinal of an undefined symbol.
    pub descriptor: u16,
}

/// Bounded listing of [`MachOSymbol`] values from `LC_SYMTAB`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSymbolsReport {
    /// Symbols that survived the limit.
    pub symbols: Vec<MachOSymbol>,
    /// Number of entries declared by `LC_SYMTAB`.
    pub total: usize,
    /// Whether the limit removed symbols.
    pub truncated: bool,
    /// Size of the linked string table in bytes.
    pub string_table_size: u32,
}

/// Decodes the `LC_SYMTAB` symbol table of one session.
pub(crate) fn symbols(session: &BinarySession, limit: Option<usize>) -> Result<MachOSymbolsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O symbols require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut table = None;
    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4))
        else {
            break;
        };
        if size < 8 {
            break;
        }
        if command == LC_SYMTAB && size >= 24 {
            table = match (reader.u32(offset + 8), reader.u32(offset + 12), reader.u32(offset + 16), reader.u32(offset + 20)) {
                (Some(symbol_offset), Some(count), Some(string_offset), Some(string_size)) => {
                    Some((symbol_offset, count, string_offset, string_size))
                }
                _ => None,
            };
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let Some((symbol_offset, count, string_offset, string_size)) = table
    else {
        return Err(IdaError::unsupported("the Mach-O has no LC_SYMTAB command"));
    };
    let symbol_offset = u64::from(symbol_offset);

    let strings = reader.slice(u64::from(string_offset), u64::from(string_size)).unwrap_or(&[]);
    let entry_size = if image.header.is_64 { 16 } else { 12 };
    let total = count as usize;
    let limit = limit.unwrap_or(usize::MAX);
    let mut symbols = Vec::new();

    for index in 0..total.min(limit) {
        let Some(entry) = symbol_offset.checked_add((index as u64).saturating_mul(entry_size))
        else {
            break;
        };
        let (Some(name_index), Some(symbol_type)) = (reader.u32(entry), reader.slice(entry + 4, 1))
        else {
            break;
        };
        let Some(section_index) = reader.slice(entry + 5, 1)
        else {
            break;
        };
        let Some(descriptor) = reader.u16(entry + 6)
        else {
            break;
        };
        let address = if image.header.is_64 { reader.u64(entry + 8) } else { reader.u32(entry + 8).map(u64::from) };
        let Some(address) = address
        else {
            break;
        };

        let debug = symbol_type[0] & 0xe0 == 0xe0;
        let kind = if debug { "debug" } else { symbol_kind(symbol_type[0]) };
        symbols.push(MachOSymbol {
            name: symbol_name(strings, name_index),
            address,
            kind: kind.to_string(),
            external: symbol_type[0] & 0x01 != 0,
            debug,
            section: (kind == "section").then_some(section_index[0]),
            descriptor,
        });
    }

    Ok(MachOSymbolsReport { truncated: total > symbols.len(), symbols, total, string_table_size: string_size })
}

fn symbol_kind(symbol_type: u8) -> &'static str {
    match symbol_type & 0x0e {
        0x0 => "undefined",
        0x2 => "absolute",
        0xa => "indirect",
        0xc => "prebound",
        0xe => "section",
        _ => "other",
    }
}

fn symbol_name(strings: &[u8], index: u32) -> String {
    let Some(rest) = strings.get(index as usize..)
    else {
        return String::new();
    };
    let end = rest.iter().position(|byte| *byte == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}
