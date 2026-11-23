//! Fat/universal Mach-O containers: the architecture slice table and the
//! extraction of one slice to a caller-chosen path.

use std::path::Path;

use data_binary_inspect::BinarySession;
use data_binary_mach_o::mach_o::{architecture, macho_magic};
use serde::{Deserialize, Serialize};

use super::{
    MAX_FAT_SLICES,
    util::{be_u32, be_u64, fat_header},
};
use crate::{IdaError, Result};

/// One architecture slice of a fat/universal Mach-O.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSlice {
    /// Zero-based position in the fat architecture table.
    pub index: usize,
    /// Raw `cputype`.
    pub cpu_type: i32,
    /// Raw `cpusubtype`.
    pub cpu_subtype: i32,
    /// Instruction-set family derived from `cputype`.
    pub architecture: String,
    /// File offset of the slice.
    pub offset: u64,
    /// Size of the slice in bytes.
    pub size: u64,
    /// Alignment expressed as a power of two.
    pub alignment: u32,
    /// Slice header bitness, when the slice starts with a Mach-O magic.
    pub bits: Option<u32>,
}

/// Fat/universal Mach-O architecture table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSlicesReport {
    /// Whether the fat header uses the 64-bit `fat_arch_64` layout.
    pub is_fat64: bool,
    /// Slices in table order.
    pub slices: Vec<MachOSlice>,
}

/// Lists the architecture slices of a fat/universal Mach-O container.
pub(crate) fn slices(session: &BinarySession) -> Result<MachOSlicesReport> {
    let bytes = session.read(0, session.size())?;
    let Some((is_fat64, count)) = fat_header(bytes)
    else {
        return Err(IdaError::unsupported(
            "the file is not a fat/universal Mach-O container; a thin image is inspected with `macho`",
        ));
    };
    if count > MAX_FAT_SLICES {
        return Err(IdaError::parse(format!("the fat header declares {count} slices, above the {MAX_FAT_SLICES}-entry limit")));
    }

    let entry_size = if is_fat64 { 32 } else { 20 };
    let table_end = 8usize.saturating_add(count.saturating_mul(entry_size));
    let table = bytes.get(8..table_end).ok_or_else(|| IdaError::parse("the fat architecture table is truncated"))?;

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let entry = &table[index * entry_size..(index + 1) * entry_size];
        let cpu_type = be_u32(entry, 0)? as i32;
        let cpu_subtype = be_u32(entry, 4)? as i32;
        let (offset, size, alignment) = if is_fat64 {
            (be_u64(entry, 8)?, be_u64(entry, 16)?, be_u32(entry, 24)?)
        }
        else {
            (u64::from(be_u32(entry, 8)?), u64::from(be_u32(entry, 12)?), be_u32(entry, 16)?)
        };
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or_else(|| IdaError::parse(format!("slice {index} lies outside the file")))?;
        let bits = macho_magic(&bytes[offset as usize..end as usize]).map(|(is_64, _)| if is_64 { 64 } else { 32 });
        entries.push(MachOSlice {
            index,
            cpu_type,
            cpu_subtype,
            architecture: architecture(cpu_type).as_str().to_string(),
            offset,
            size,
            alignment,
            bits,
        });
    }

    Ok(MachOSlicesReport { is_fat64, slices: entries })
}

/// One fat slice written to a caller-chosen path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSliceExtraction {
    /// Zero-based position in the fat architecture table.
    pub index: usize,
    /// Instruction-set family of the extracted slice.
    pub architecture: String,
    /// Source file offset of the slice.
    pub offset: u64,
    /// Number of bytes written.
    pub size: u64,
    /// Destination path.
    pub output: String,
}

/// Writes one fat slice to `output`.
///
/// The source container is never modified: writing to the source path itself
/// is refused, and every other destination is replaced.
pub(crate) fn extract(session: &BinarySession, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
    if output == session.path() {
        return Err(IdaError::io("refusing to overwrite the source container"));
    }
    let report = slices(session)?;
    let slice = report.slices.get(index).ok_or_else(|| {
        IdaError::range(format!("slice {index} is out of range; the container has {} slice(s)", report.slices.len()))
    })?;
    let bytes = session.read(0, session.size())?;
    let start = usize::try_from(slice.offset).map_err(|_| IdaError::range("the slice offset does not fit this platform"))?;
    let end = start
        .checked_add(usize::try_from(slice.size).map_err(|_| IdaError::range("the slice size does not fit this platform"))?)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| IdaError::parse("the slice lies outside the file"))?;
    std::fs::write(output, &bytes[start..end])
        .map_err(|error| IdaError::io(format!("cannot write {}: {error}", output.display())))?;
    Ok(MachOSliceExtraction {
        index: slice.index,
        architecture: slice.architecture.clone(),
        offset: slice.offset,
        size: slice.size,
        output: output.display().to_string(),
    })
}
