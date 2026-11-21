//! ELF headers.
//!
//! Both ELF32 and ELF64 little-endian files are decoded. Big-endian files are
//! rejected with `binary/unsupported` rather than being misread, and extended
//! section numbering (`e_shnum == 0` with a real table) is out of scope.

use crate::{
    Architecture, Section,
    bytes::{name_at, span, u16_at, u32_at, u64_at},
    error::{IdaError, Result},
};

const ELF_MAGIC: &[u8] = b"\x7fELF";
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXEC: u64 = 0x4;

struct RawSection {
    name_offset: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
}

/// Decoded ELF header.
pub(crate) struct ElfHeader {
    pub class: &'static str,
    pub machine: u16,
    pub entry: u64,
    pub sections: Vec<Section>,
}

/// Maps an ELF machine word onto a known architecture.
pub(crate) fn architecture(machine: u16) -> Architecture {
    match machine {
        3 => Architecture::X86,
        62 => Architecture::X64,
        183 => Architecture::Arm64,
        _ => Architecture::Unknown,
    }
}

/// Parses the ELF identification block, the file header and the section table.
pub(crate) fn parse(bytes: &[u8]) -> Result<ElfHeader> {
    if bytes.get(0..4) != Some(ELF_MAGIC) {
        return Err(IdaError::parse("missing ELF signature"));
    }
    let is_64 = match bytes.get(4) {
        Some(1) => false,
        Some(2) => true,
        Some(other) => return Err(IdaError::unsupported(format!("unknown ELF class {other}"))),
        None => return Err(IdaError::parse("truncated ELF identification block")),
    };
    match bytes.get(5) {
        Some(1) => {}
        Some(2) => return Err(IdaError::unsupported("big-endian ELF is not supported")),
        Some(other) => return Err(IdaError::unsupported(format!("unknown ELF data encoding {other}"))),
        None => return Err(IdaError::parse("truncated ELF identification block")),
    }
    let header_size = if is_64 { 64 } else { 52 };
    if (bytes.len() as u64) < header_size {
        return Err(IdaError::parse("truncated ELF file header"));
    }

    let machine = u16_at(bytes, 18)?;
    let entry = if is_64 { u64_at(bytes, 24)? } else { u32_at(bytes, 24)? as u64 };
    let table_offset = if is_64 { u64_at(bytes, 40)? } else { u32_at(bytes, 32)? as u64 };
    let entry_size = u16_at(bytes, if is_64 { 58 } else { 46 })?;
    let count = u16_at(bytes, if is_64 { 60 } else { 48 })?;
    let names_index = u16_at(bytes, if is_64 { 62 } else { 50 })?;
    let minimum_entry_size = if is_64 { 64 } else { 40 };

    if count == 0 || table_offset == 0 {
        return Ok(ElfHeader { class: if is_64 { "ELF64" } else { "ELF32" }, machine, entry, sections: Vec::new() });
    }
    if entry_size < minimum_entry_size {
        return Err(IdaError::parse(format!(
            "section header entry is {entry_size} bytes, expected at least {minimum_entry_size}"
        )));
    }
    if names_index != 0 && names_index >= count {
        return Err(IdaError::parse(format!("section name table index {names_index} is outside {count} sections")));
    }

    let table_bytes = entry_size as u64 * count as u64;
    span(bytes, table_offset, table_bytes as usize)?;

    let mut raw_sections = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        let base = table_offset + index * entry_size as u64;
        let raw_sections_entry = if is_64 {
            RawSection {
                name_offset: u32_at(bytes, base)?,
                flags: u64_at(bytes, base + 8)?,
                address: u64_at(bytes, base + 16)?,
                offset: u64_at(bytes, base + 24)?,
                size: u64_at(bytes, base + 32)?,
            }
        }
        else {
            RawSection {
                name_offset: u32_at(bytes, base)?,
                flags: u32_at(bytes, base + 8)? as u64,
                address: u32_at(bytes, base + 12)? as u64,
                offset: u32_at(bytes, base + 16)? as u64,
                size: u32_at(bytes, base + 20)? as u64,
            }
        };
        raw_sections.push(raw_sections_entry);
    }

    let names = match raw_sections.get(names_index as usize) {
        Some(section) => span(bytes, section.offset, usize::try_from(section.size).unwrap_or(usize::MAX))?,
        None => &[][..],
    };

    let sections = raw_sections
        .iter()
        .map(|section| Section {
            name: name_at(names, section.name_offset as usize, names.len()),
            virtual_address: section.address,
            virtual_size: section.size,
            raw_pointer: section.offset,
            raw_size: section.size,
            characteristics: section.flags,
            readable: section.flags & SHF_ALLOC != 0,
            writable: section.flags & SHF_WRITE != 0,
            executable: section.flags & SHF_EXEC != 0,
        })
        .collect();

    Ok(ElfHeader { class: if is_64 { "ELF64" } else { "ELF32" }, machine, entry, sections })
}

/// Maps a virtual address onto a file offset through the section table.
pub(crate) fn rva_to_offset(sections: &[Section], file_len: u64, address: u64) -> Result<u64> {
    for section in sections {
        if section.virtual_address == 0 || section.virtual_size == 0 {
            continue;
        }
        if address >= section.virtual_address && address < section.virtual_address.saturating_add(section.virtual_size) {
            let delta = address - section.virtual_address;
            let offset = section.raw_pointer + delta;
            if offset >= file_len {
                return Err(IdaError::range(format!("address 0x{address:x} maps beyond the end of the file")));
            }
            return Ok(offset);
        }
    }
    Err(IdaError::range(format!("address 0x{address:x} is not mapped by any section")))
}
