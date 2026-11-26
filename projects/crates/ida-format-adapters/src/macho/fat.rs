//! Fat/universal Mach-O projection and slice extraction.
//!
//! The architecture table is owned by `data-binary-mach-o`
//! (`read_fat_slices`). This module keeps the product JSON shape and the
//! product extraction verb, which refuses to overwrite the source container.

use std::path::Path;

use data_binary_inspect::BinarySession;
use data_binary_mach_o::mach_o::{fat_magic, read_fat_slices};
use serde::{Deserialize, Serialize};

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
pub fn slices(session: &BinarySession) -> Result<MachOSlicesReport> {
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_none() {
        return Err(IdaError::unsupported(
            "the file is not a fat/universal Mach-O container; a thin image is inspected with `macho`",
        ));
    }
    let table = read_fat_slices(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;

    Ok(MachOSlicesReport {
        is_fat64: table.is_fat64,
        slices: table
            .slices
            .iter()
            .map(|slice| MachOSlice {
                index: slice.index,
                cpu_type: slice.cpu_type,
                cpu_subtype: slice.cpu_subtype,
                architecture: slice.architecture.as_str().to_string(),
                offset: slice.offset,
                size: slice.size,
                alignment: slice.alignment,
                bits: slice.bits,
            })
            .collect(),
    })
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
pub fn extract(session: &BinarySession, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
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
