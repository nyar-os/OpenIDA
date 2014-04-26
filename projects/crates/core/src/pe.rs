//! Portable Executable headers.
//!
//! The structural decode is delegated to `boost.rs/data-binary-pe`; this module
//! only maps the shared `PeImage` onto the fields OpenIDA reports and keeps the
//! product's zero-fill and file-boundary checks. Directories beyond the optional
//! header, imports and relocations stay out of scope for this build.

use data_binary_pe::pe::{self, SectionHeader};

use crate::{
    Architecture, Section,
    error::{IdaError, Result},
};

const PE32_MAGIC: u16 = 0x010b;
const PE32_PLUS_MAGIC: u16 = 0x020b;

const SECTION_READ: u32 = 0x4000_0000;
const SECTION_WRITE: u32 = 0x8000_0000;
const SECTION_EXECUTE: u32 = 0x2000_0000;
const SECTION_CODE: u32 = 0x0000_0020;

/// Decoded PE header.
pub(crate) struct PeHeader {
    pub magic: &'static str,
    pub machine: u16,
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_headers: u32,
    pub section_count: u16,
    pub sections: Vec<Section>,
    raw_sections: Vec<SectionHeader>,
}

/// Maps a COFF machine word onto a known architecture.
pub(crate) fn architecture(machine: u16) -> Architecture {
    match machine {
        0x014c => Architecture::X86,
        0x8664 => Architecture::X64,
        0xaa64 => Architecture::Arm64,
        _ => Architecture::Unknown,
    }
}

/// Decodes a PE image through the shared `data-binary-pe` parser.
pub(crate) fn parse(bytes: &[u8]) -> Result<PeHeader> {
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let magic = match image.optional.magic {
        PE32_MAGIC => "PE32",
        PE32_PLUS_MAGIC => "PE32+",
        other => return Err(IdaError::unsupported(format!("unknown PE optional header magic 0x{other:04x}"))),
    };

    let sections = image
        .sections
        .iter()
        .map(|section| {
            let flags = section.characteristics;
            Section {
                name: section.name.clone(),
                virtual_address: u64::from(section.virtual_address),
                virtual_size: u64::from(section.virtual_size),
                raw_pointer: u64::from(section.pointer_to_raw_data),
                raw_size: u64::from(section.size_of_raw_data),
                characteristics: u64::from(flags),
                readable: flags & SECTION_READ != 0,
                writable: flags & SECTION_WRITE != 0,
                executable: flags & (SECTION_EXECUTE | SECTION_CODE) != 0,
            }
        })
        .collect();

    Ok(PeHeader {
        magic,
        machine: image.coff.machine,
        image_base: image.optional.image_base,
        entry_rva: image.optional.address_of_entry_point,
        size_of_headers: image.optional.size_of_headers,
        section_count: image.coff.number_of_sections,
        sections,
        raw_sections: image.sections,
    })
}

/// Maps an RVA onto a file offset through the header window and section table.
pub(crate) fn rva_to_offset(header: &PeHeader, file_len: u64, rva: u64) -> Result<u64> {
    if rva < u64::from(header.size_of_headers) && rva < file_len {
        return Ok(rva);
    }
    let rva32 = u32::try_from(rva).map_err(|_| IdaError::range(format!("RVA 0x{rva:x} does not fit a 32-bit image")))?;
    let offset = match pe::rva_to_offset(&header.raw_sections, rva32) {
        Ok(offset) => u64::from(offset),
        Err(_) => fallback_offset(header, rva)?,
    };
    if let Some(section) = header.raw_sections.iter().find(|section| {
        let start = u64::from(section.virtual_address);
        rva >= start && rva < start.saturating_add(u64::from(section.virtual_size))
    }) {
        let delta = rva - u64::from(section.virtual_address);
        if delta >= u64::from(section.size_of_raw_data) {
            return Err(IdaError::range(format!("RVA 0x{rva:x} points at zero-filled memory in section {}", section.name)));
        }
    }
    if offset >= file_len {
        return Err(IdaError::range(format!("RVA 0x{rva:x} maps beyond the end of the file")));
    }
    Ok(offset)
}

/// Handles images whose section declares raw data but no virtual size.
fn fallback_offset(header: &PeHeader, rva: u64) -> Result<u64> {
    for section in &header.sections {
        let span = section.virtual_size.max(section.raw_size);
        if rva < section.virtual_address || rva >= section.virtual_address.saturating_add(span) {
            continue;
        }
        let delta = rva - section.virtual_address;
        if delta >= section.raw_size {
            return Err(IdaError::range(format!("RVA 0x{rva:x} points at zero-filled memory in section {}", section.name)));
        }
        return Ok(section.raw_pointer + delta);
    }
    Err(IdaError::range(format!("RVA 0x{rva:x} is not mapped by any section")))
}
