//! Mach-O headers.
//!
//! Header decoding is delegated to `boost.rs/data-binary-mach-o`; this module
//! only maps the shared `MachHeader` onto the fields OpenIDA reports. Sections,
//! segments and load-command bodies stay outside this build's surface.

use data_binary_mach_o::mach_o::{MachOEndian, parse_macho_header};

use crate::{
    Architecture,
    error::{IdaError, Result},
};

/// Decoded Mach-O header basics.
pub(crate) struct MachoHeader {
    pub magic: &'static str,
    pub endian: &'static str,
    pub cpu_type: i32,
    pub file_type: u32,
    pub command_count: u32,
}

/// Maps a Mach-O CPU type onto a known architecture.
pub(crate) fn architecture(cpu_type: i32) -> Architecture {
    match cpu_type {
        7 => Architecture::X86,
        0x0100_0007 => Architecture::X64,
        0x0100_000c => Architecture::Arm64,
        _ => Architecture::Unknown,
    }
}

/// Parses the fixed header of a little- or big-endian Mach-O file.
pub(crate) fn parse(bytes: &[u8]) -> Result<MachoHeader> {
    let header = parse_macho_header(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    Ok(MachoHeader {
        magic: if header.is_64 { "Mach-O 64" } else { "Mach-O 32" },
        endian: match header.endian {
            MachOEndian::Little => "little",
            MachOEndian::Big => "big",
        },
        cpu_type: header.cpu_type,
        file_type: header.file_type,
        command_count: header.command_count,
    })
}
