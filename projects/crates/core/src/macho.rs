//! Mach-O headers.
//!
//! Only the leading fields are reported: magic flavour, CPU type, file type and
//! the load-command count. Sections, segments and symbol tables are not decoded.

use crate::{
    Architecture,
    bytes::{span, u32_at, u32_be_at},
    error::{IdaError, Result},
    format::macho_magic,
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
    let (is_64, big_endian) = macho_magic(bytes).ok_or_else(|| IdaError::parse("missing Mach-O magic"))?;
    span(bytes, 0, if is_64 { 32 } else { 28 })?;

    let read = |offset: u64| -> Result<u32> { if big_endian { u32_be_at(bytes, offset) } else { u32_at(bytes, offset) } };

    Ok(MachoHeader {
        magic: if is_64 { "Mach-O 64" } else { "Mach-O 32" },
        endian: if big_endian { "big" } else { "little" },
        cpu_type: read(4)? as i32,
        file_type: read(12)?,
        command_count: read(16)?,
    })
}
