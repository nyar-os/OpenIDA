//! Portable Executable headers.
//!
//! Only the fields the product reports are decoded: the COFF machine, the
//! optional-header flavour, the image base, the entry RVA and the section table.
//! Directories, imports, exports and relocations stay out of scope.

use crate::{
    Architecture, Section,
    bytes::{name_at, span, u16_at, u32_at, u64_at},
    error::{IdaError, Result},
};

const DOS_SIGNATURE: u16 = 0x5a4d;
const PE_SIGNATURE: &[u8] = b"PE\0\0";
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

/// Parses the DOS stub, the PE signature, the optional header and the sections.
pub(crate) fn parse(bytes: &[u8]) -> Result<PeHeader> {
    if u16_at(bytes, 0)? != DOS_SIGNATURE {
        return Err(IdaError::parse("missing DOS MZ signature"));
    }
    let pe_offset = u32_at(bytes, 0x3c)? as u64;
    if span(bytes, pe_offset, 4)? != PE_SIGNATURE {
        return Err(IdaError::parse(format!("missing PE signature at 0x{pe_offset:x}")));
    }

    let coff = pe_offset + 4;
    let machine = u16_at(bytes, coff)?;
    let section_count = u16_at(bytes, coff + 2)?;
    let optional_size = u16_at(bytes, coff + 16)?;
    let optional = coff + 20;

    let magic = match u16_at(bytes, optional)? {
        PE32_MAGIC => "PE32",
        PE32_PLUS_MAGIC => "PE32+",
        other => return Err(IdaError::unsupported(format!("unknown PE optional header magic 0x{other:04x}"))),
    };
    if optional_size < 68 {
        return Err(IdaError::parse(format!("optional header is too small ({optional_size} bytes)")));
    }

    let entry_rva = u32_at(bytes, optional + 16)?;
    let (image_base, size_of_headers) = if magic == "PE32" {
        (u32_at(bytes, optional + 28)? as u64, u32_at(bytes, optional + 60)?)
    }
    else {
        (u64_at(bytes, optional + 24)?, u32_at(bytes, optional + 60)?)
    };

    let table = optional + optional_size as u64;
    let mut sections = Vec::with_capacity(section_count as usize);
    for index in 0..section_count as u64 {
        let entry = table + index * 40;
        let raw = span(bytes, entry, 40)?;
        let characteristics = u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]);
        sections.push(Section {
            name: name_at(raw, 0, 8),
            virtual_address: u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as u64,
            virtual_size: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as u64,
            raw_pointer: u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]) as u64,
            raw_size: u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]) as u64,
            characteristics: characteristics as u64,
            readable: characteristics & SECTION_READ != 0,
            writable: characteristics & SECTION_WRITE != 0,
            executable: characteristics & (SECTION_EXECUTE | SECTION_CODE) != 0,
        });
    }

    Ok(PeHeader { magic, machine, image_base, entry_rva, size_of_headers, section_count, sections })
}

/// Maps an RVA onto a file offset through the header window and section table.
pub(crate) fn rva_to_offset(header: &PeHeader, file_len: u64, rva: u64) -> Result<u64> {
    if rva < header.size_of_headers as u64 && rva < file_len {
        return Ok(rva);
    }
    for section in &header.sections {
        let span = section.virtual_size.max(section.raw_size);
        if rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span) {
            let delta = rva - section.virtual_address;
            if delta >= section.raw_size {
                return Err(IdaError::range(format!("RVA 0x{rva:x} points at zero-filled memory in section {}", section.name)));
            }
            let offset = section.raw_pointer + delta;
            if offset >= file_len {
                return Err(IdaError::range(format!("RVA 0x{rva:x} maps beyond the end of the file")));
            }
            return Ok(offset);
        }
    }
    Err(IdaError::range(format!("RVA 0x{rva:x} is not mapped by any section")))
}
