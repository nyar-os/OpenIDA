//! ELF headers and section tables.
//!
//! The structural decode is delegated to `boost.rs/data-binary-pe`; this module
//! only maps the shared `ElfImage` onto the fields OpenIDA reports. The product
//! keeps its little-endian scope and its own address-to-offset mapping.

use data_binary_pe::elf::{ElfClass, ElfParseError, parse_elf};

use crate::{
    Architecture, Section,
    error::{IdaError, Result},
};

/// `EI_DATA` value for big-endian files.
const ELFDATA2MSB: u8 = 2;
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXEC: u64 = 0x4;

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

/// Decodes the ELF identification block, the file header and the section table.
///
/// Extended section numbering is resolved upstream. Big-endian files stay out of
/// this build's declared surface and are rejected before the table is decoded.
pub(crate) fn parse(bytes: &[u8]) -> Result<ElfHeader> {
    if bytes.get(5) == Some(&ELFDATA2MSB) {
        return Err(IdaError::unsupported("big-endian ELF is not supported"));
    }
    let image = parse_elf(bytes).map_err(map_error)?;
    let sections = image
        .sections
        .iter()
        .map(|section| Section {
            name: section.name.clone(),
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

    Ok(ElfHeader {
        class: match image.header.class {
            ElfClass::Elf32 => "ELF32",
            ElfClass::Elf64 => "ELF64",
        },
        machine: image.header.machine,
        entry: image.header.entry,
        sections,
    })
}

/// Maps upstream ELF decode failures onto the product's error codes.
fn map_error(error: ElfParseError) -> IdaError {
    match error {
        ElfParseError::UnsupportedClass(class) => IdaError::unsupported(format!("unknown ELF class {class}")),
        ElfParseError::UnsupportedEncoding(encoding) => {
            IdaError::unsupported(format!("unknown ELF data encoding {encoding}"))
        }
        other => IdaError::parse(format!("ELF: {other}")),
    }
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
