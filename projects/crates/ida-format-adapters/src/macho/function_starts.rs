//! The `LC_FUNCTION_STARTS` delta table projection.
//!
//! The ULEB128 walk and the `__TEXT` base are owned by `data-binary-mach-o`
//! (`read_function_starts`). This module keeps the product JSON shape and the
//! stable unsupported answer when the command is absent.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{MachOParseError, fat_magic, parse_macho, read_function_starts};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Bounded listing of function start addresses from `LC_FUNCTION_STARTS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOFunctionStartsReport {
    /// Virtual address of the `__TEXT` segment that the deltas start from.
    pub image_base: u64,
    /// Absolute function start addresses in table order.
    pub addresses: Vec<u64>,
    /// Entries declared by the encoded table.
    pub total: usize,
    /// Whether the limit removed addresses.
    pub truncated: bool,
}

/// Decodes the `LC_FUNCTION_STARTS` ULEB128 delta table of one session.
pub fn function_starts(session: &BinarySession, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O function starts require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let starts = read_function_starts(bytes, &image, limit).map_err(|error| match error {
        MachOParseError::FunctionStartsMissing => IdaError::unsupported("the Mach-O has no LC_FUNCTION_STARTS command"),
        other => IdaError::parse(format!("Mach-O: {other}")),
    })?;

    Ok(MachOFunctionStartsReport {
        image_base: starts.image_base,
        addresses: starts.addresses,
        total: starts.total,
        truncated: starts.truncated,
    })
}
