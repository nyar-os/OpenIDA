//! ELF program header projection.
//!
//! The `e_phoff` walk and the 32/64-bit entry layout are owned by
//! `data-binary-pe::elf` (`read_program_headers`). This module keeps the
//! product JSON shape and the stable permission rendering.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::elf;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// One program header entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfSegment {
    /// Index in the program header table.
    pub index: usize,
    /// Stable segment type name, or `0x<type>` for an unknown value.
    pub segment_type: String,
    /// Raw `p_type`.
    pub type_value: u32,
    /// File offset of the segment payload.
    pub offset: u64,
    /// Segment virtual address.
    pub virtual_address: u64,
    /// Segment physical address.
    pub physical_address: u64,
    /// Bytes stored in the file.
    pub file_size: u64,
    /// Bytes occupied in memory.
    pub memory_size: u64,
    /// Raw `p_flags`.
    pub flags: u32,
    /// `p_flags` rendered as permissions, such as `R-X`.
    pub flag_text: String,
    /// Alignment requirement.
    pub alignment: u64,
}

/// ELF program header table summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfSegmentsReport {
    /// Whether the table contains at least one entry.
    pub present: bool,
    /// Whether the image uses the 64-bit program header layout.
    pub is64: bool,
    /// Entries that survived the limit, in table order.
    pub segments: Vec<ElfSegment>,
    /// Number of entries declared by the header.
    pub total: usize,
    /// Whether a limit or a malformed entry cut the listing.
    pub truncated: bool,
}

/// Decodes the ELF program header table of one session.
pub fn analyze(session: &BinarySession) -> Result<ElfSegmentsReport> {
    if session.format() != BinaryFormat::Elf {
        return Err(IdaError::unsupported("ELF program headers require an ELF container"));
    }
    let bytes = session.read(0, session.size())?;
    let headers = elf::read_program_headers(bytes).map_err(|error| IdaError::parse(format!("ELF: {error}")))?;

    let segments = headers
        .segments
        .iter()
        .map(|segment| ElfSegment {
            index: segment.index,
            segment_type: segment.segment_type.name(),
            type_value: segment.segment_type.value(),
            offset: segment.offset,
            virtual_address: segment.virtual_address,
            physical_address: segment.physical_address,
            file_size: segment.file_size,
            memory_size: segment.memory_size,
            flags: segment.flags,
            flag_text: segment.flag_text(),
            alignment: segment.alignment,
        })
        .collect();

    Ok(ElfSegmentsReport {
        present: headers.total > 0,
        is64: headers.is_64,
        segments,
        total: headers.total,
        truncated: headers.truncated,
    })
}
