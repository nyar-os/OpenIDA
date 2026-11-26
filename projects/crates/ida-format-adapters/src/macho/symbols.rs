//! The `LC_SYMTAB` symbol table of a Mach-O image and its `nlist` entries.
//!
//! `data-binary-mach-o` owns the `LC_SYMTAB` discovery, the 32/64-bit `nlist`
//! layout, the string table and the endianness. This projection adds the
//! product `kind`/`external`/`debug` classification and the limit, and keeps the
//! `binary/unsupported` answer for an image without a symbol table.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{fat_magic, parse_macho, read_macho_symbols};
use serde::{Deserialize, Serialize};

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
pub fn symbols(session: &BinarySession, limit: Option<usize>) -> Result<MachOSymbolsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O symbols require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let Some(symtab) = image.symtab
    else {
        return Err(IdaError::unsupported("the Mach-O has no LC_SYMTAB command"));
    };
    let entries = read_macho_symbols(bytes, &image).map_err(|error| IdaError::parse(format!("Mach-O symbols: {error}")))?;

    let total = entries.len();
    let limit = limit.unwrap_or(usize::MAX);
    let mut symbols = Vec::with_capacity(total.min(limit));
    for entry in entries.iter().take(limit) {
        let debug = entry.symbol_type & 0xe0 == 0xe0;
        let kind = if debug { "debug" } else { symbol_kind(entry.symbol_type) };
        symbols.push(MachOSymbol {
            name: entry.name.clone(),
            address: entry.value,
            kind: kind.to_string(),
            external: entry.symbol_type & 0x01 != 0,
            debug,
            section: (kind == "section").then_some(entry.section),
            descriptor: entry.description,
        });
    }

    Ok(MachOSymbolsReport { truncated: total > symbols.len(), symbols, total, string_table_size: symtab.string_size })
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
