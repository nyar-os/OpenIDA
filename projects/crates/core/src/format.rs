//! Container detection.
//!
//! Detection is deliberately shallow: it recognises the four answers the
//! product reports and never guesses a format from a file extension.

/// Containers this build can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// Portable Executable (Windows).
    Pe,
    /// Executable and Linkable Format (Linux, BSD).
    Elf,
    /// Mach-O (macOS, iOS).
    MachO,
    /// Unrecognised bytes.
    Unknown,
}

impl BinaryFormat {
    /// Stable lower-case name used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Unknown => "unknown",
        }
    }
}

/// Instruction-set family inferred from the container header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    X64,
    /// 64-bit ARM.
    Arm64,
    /// Not reported by the header.
    Unknown,
}

impl Architecture {
    /// Stable lower-case name used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
            Self::Unknown => "unknown",
        }
    }
}

/// Mach-O magic families: `(is_64_bit, is_big_endian)`.
pub(crate) fn macho_magic(bytes: &[u8]) -> Option<(bool, bool)> {
    match bytes.get(0..4)? {
        [0xcf, 0xfa, 0xed, 0xfe] => Some((true, false)),
        [0xce, 0xfa, 0xed, 0xfe] => Some((false, false)),
        [0xfe, 0xed, 0xfa, 0xcf] => Some((true, true)),
        [0xfe, 0xed, 0xfa, 0xce] => Some((false, true)),
        _ => None,
    }
}

/// Names the container from its leading bytes.
///
/// PE validation is delegated to the shared `boost.rs` reader, so a file that
/// merely starts with `MZ` is not reported as an executable image.
pub fn detect(bytes: &[u8]) -> BinaryFormat {
    if data_binary_pe::pe::parse_pe(bytes).is_ok() {
        return BinaryFormat::Pe;
    }
    if bytes.starts_with(b"\x7fELF") {
        return BinaryFormat::Elf;
    }
    if macho_magic(bytes).is_some() {
        return BinaryFormat::MachO;
    }
    BinaryFormat::Unknown
}
