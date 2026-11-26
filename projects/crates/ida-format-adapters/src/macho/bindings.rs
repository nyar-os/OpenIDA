//! Classic dyld bind opcode stream projection.
//!
//! The `LC_DYLD_INFO` bind / weak-bind / lazy-bind state machine is owned by
//! `data-binary-mach-o` (`read_bindings`). This module keeps the product JSON
//! shape and the product bound on the returned list.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{fat_magic, parse_macho, read_bindings};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// One binding decoded from a classic dyld bind opcode stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOBinding {
    /// Stream the binding came from: `bind`, `weak` or `lazy`.
    pub stream: String,
    /// Virtual address of the bound slot.
    pub address: u64,
    /// Name of the segment covering `address`, empty when no segment does.
    pub segment: String,
    /// Trailing symbol name of the last `SET_SYMBOL_TRAILING_FLAGS_IMM`.
    pub symbol: String,
    /// Install name for positive library ordinals; special ordinals render as
    /// `self`, `main-executable`, `flat-lookup`, `weak-lookup` or `special`.
    pub dylib: String,
    /// Bind type from `SET_TYPE_IMM`: `pointer`, `text-abs32`, `text-pcrel32` or raw `0xNN`.
    pub bind_type: String,
    /// Whether the symbol flags carry `BIND_SYMBOL_FLAGS_WEAK_IMPORT`.
    pub weak: bool,
    /// Addend from the last `SET_ADDEND_SLEB`.
    pub addend: i64,
}

/// Bounded listing of the classic dyld bind opcode streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOBindingsReport {
    /// Whether the image carries an `LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY` command.
    pub present: bool,
    /// Bindings that survived the limit.
    pub bindings: Vec<MachOBinding>,
    /// Bindings found before the walk was cut.
    pub total: usize,
    /// Whether the limit, an unsupported opcode or a malformed stream cut the walk.
    pub truncated: bool,
}

/// Upper bound on returned bindings, so one report stays small.
const MAX_BINDINGS: usize = 512;

/// Decodes the classic dyld bind, weak-bind and lazy-bind opcode streams.
pub fn bindings(session: &BinarySession) -> Result<MachOBindingsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O bindings require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let binds = read_bindings(bytes, &image).map_err(|error| IdaError::parse(format!("Mach-O bindings: {error}")))?;

    let total = binds.len();
    let truncated = total > MAX_BINDINGS;
    let bindings = binds
        .iter()
        .take(MAX_BINDINGS)
        .map(|bind| MachOBinding {
            stream: bind.stream_name().to_string(),
            address: bind.address,
            segment: bind.segment.clone(),
            symbol: bind.symbol.clone(),
            dylib: bind.dylib_name(),
            bind_type: bind.bind_type.name(),
            weak: bind.weak,
            addend: bind.addend,
        })
        .collect();

    Ok(MachOBindingsReport { present: image.dyld_info.is_some(), bindings, total, truncated })
}
