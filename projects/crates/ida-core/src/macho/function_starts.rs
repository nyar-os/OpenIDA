//! The `LC_FUNCTION_STARTS` ULEB128 delta table of a Mach-O image.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::parse_macho;
use serde::{Deserialize, Serialize};

use super::{
    HEADER32_SIZE, HEADER64_SIZE, LC_FUNCTION_STARTS,
    util::{Reader, fat_header},
};
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
pub(crate) fn function_starts(session: &BinarySession, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O function starts require a Mach-O container"));
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
        if command == LC_FUNCTION_STARTS && size >= 16 {
            table = match (reader.u32(offset + 8), reader.u32(offset + 12)) {
                (Some(data_offset), Some(data_size)) => Some((data_offset, data_size)),
                _ => None,
            };
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let Some((data_offset, data_size)) = table
    else {
        return Err(IdaError::unsupported("the Mach-O has no LC_FUNCTION_STARTS command"));
    };
    let data = reader.slice(u64::from(data_offset), u64::from(data_size)).unwrap_or(&[]);
    let image_base = image.segments.iter().find(|segment| segment.name == "__TEXT").map_or(0, |segment| segment.vm_address);

    let limit = limit.unwrap_or(usize::MAX);
    let mut addresses = Vec::new();
    let mut total = 0usize;
    let mut cursor = 0usize;
    let mut current = image_base;
    while cursor < data.len() {
        let mut delta = 0u64;
        let mut shift = 0u32;
        let mut terminated = false;
        loop {
            let Some(byte) = data.get(cursor)
            else {
                return Ok(MachOFunctionStartsReport { image_base, addresses, total, truncated: true });
            };
            cursor += 1;
            delta |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                terminated = true;
                break;
            }
            shift += 7;
            if shift >= 64 {
                break;
            }
        }
        if !terminated || delta == 0 {
            break;
        }
        current = current.saturating_add(delta);
        total += 1;
        if addresses.len() < limit {
            addresses.push(current);
        }
    }

    let truncated = total > addresses.len();
    Ok(MachOFunctionStartsReport { image_base, addresses, total, truncated })
}
