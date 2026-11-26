//! The dyld export trie projection.
//!
//! `LC_DYLD_INFO` / `LC_DYLD_EXPORTS_TRIE` discovery and the trie walk are
//! owned by `data-binary-mach-o` (`read_exports`). This module keeps the
//! product JSON shape.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{fat_magic, parse_macho, read_exports};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// One symbol decoded from the dyld export trie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOExport {
    /// Accumulated symbol name.
    pub name: String,
    /// Raw export flags.
    pub flags: u64,
    /// Flag names: `WEAK`, `REEXPORT`, `STUB_AND_RESOLVER`.
    pub flag_names: Vec<String>,
    /// Symbol address for regular exports.
    pub address: Option<u64>,
    /// Library ordinal for reexports or stub address for stub-and-resolver.
    pub other: Option<u64>,
}

/// Bounded listing of symbols from the dyld export trie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOExportsReport {
    /// Whether the image carries an export trie.
    pub present: bool,
    /// Decoded exports in trie order.
    pub exports: Vec<MachOExport>,
    /// Entries found before the storage limit.
    pub total: usize,
    /// Whether the limit or a malformed node cut the walk.
    pub truncated: bool,
}

/// Decodes the dyld export trie of one session.
pub fn exports(session: &BinarySession) -> Result<MachOExportsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O exports require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let exports = read_exports(bytes, &image);

    Ok(MachOExportsReport {
        present: exports.present,
        exports: exports
            .exports
            .into_iter()
            .map(|export| MachOExport {
                name: export.name,
                flags: export.flags,
                flag_names: export.flag_names.into_iter().map(str::to_string).collect(),
                address: export.address,
                other: export.other,
            })
            .collect(),
        total: exports.total,
        truncated: exports.truncated,
    })
}
