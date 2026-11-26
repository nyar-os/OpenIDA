//! PE mitigation posture: a checksec-style summary.
//!
//! Everything here comes from the optional header, the section table and the
//! load-config directory. The report states facts; it does not claim that a
//! mitigation actually protects the process at run time.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const DIRECTORY_SECURITY: usize = 4;
const DIRECTORY_BASE_RELOCATION: usize = 5;
const DIRECTORY_LOAD_CONFIG: usize = 10;

const DYNAMIC_BASE: u16 = 0x0040;
const HIGH_ENTROPY_VA: u16 = 0x0020;
const NX_COMPAT: u16 = 0x0100;
const GUARD_CF: u16 = 0x4000;
const FORCE_INTEGRITY: u16 = 0x0080;
const NO_SEH: u16 = 0x0400;
const TERMINAL_SERVER_AWARE: u16 = 0x8000;

const SECTION_MEM_EXECUTE: u32 = 0x2000_0000;
const SECTION_MEM_WRITE: u32 = 0x8000_0000;

const LOAD_CONFIG_COOKIE32: usize = 0x3c;
const LOAD_CONFIG_COOKIE64: usize = 0x58;
const LOAD_CONFIG_GUARD_FLAGS32: usize = 0x58;
const LOAD_CONFIG_GUARD_FLAGS64: usize = 0x90;
const GUARD_CF_INSTRUMENTED: u32 = 0x100;

/// One section mapped with both write and execute permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WritableExecutableSection {
    /// Section name.
    pub name: String,
    /// Virtual address.
    pub address: u32,
    /// Virtual size.
    pub size: u32,
}

/// PE mitigation posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MitigationsReport {
    /// Raw `DllCharacteristics`.
    pub dll_characteristics: u16,
    /// Whether `DYNAMIC_BASE` (ASLR) is set.
    pub aslr: bool,
    /// Whether `HIGH_ENTROPY_VA` is set.
    pub high_entropy_va: bool,
    /// Whether `NX_COMPAT` (DEP) is set.
    pub dep: bool,
    /// Whether `GUARD_CF` is set in the header or the load config instruments CFG.
    pub cfg: bool,
    /// Whether `FORCE_INTEGRITY` is set.
    pub force_integrity: bool,
    /// Whether `NO_SEH` is set.
    pub no_seh: bool,
    /// Whether `TERMINAL_SERVER_AWARE` is set.
    pub terminal_server_aware: bool,
    /// Whether the base-relocation directory is non-empty.
    pub relocations_present: bool,
    /// Whether the certificate table is non-empty; the signature is not verified.
    pub signed: bool,
    /// Sections with write and execute permission.
    pub writable_executable_sections: Vec<WritableExecutableSection>,
    /// Whether the load-config security cookie pointer is non-zero; `None` when
    /// there is no load config.
    pub security_cookie: Option<bool>,
    /// Raw `GuardFlags` from the load config, when present.
    pub guard_flags: Option<u32>,
}

/// Summarises the PE mitigation posture of one session.
pub fn analyze(session: &BinarySession) -> Result<MitigationsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE mitigations require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let characteristics = dll_characteristics(bytes, &image)?;
    let directories = &image.optional.data_directories;

    let writable_executable_sections = image
        .sections
        .iter()
        .filter(|section| {
            section.characteristics & SECTION_MEM_EXECUTE != 0 && section.characteristics & SECTION_MEM_WRITE != 0
        })
        .map(|section| WritableExecutableSection {
            name: section.name.clone(),
            address: section.virtual_address,
            size: section.virtual_size,
        })
        .collect::<Vec<_>>();

    let relocations_present = directories[DIRECTORY_BASE_RELOCATION].size > 0;
    let signed = directories[DIRECTORY_SECURITY].size > 0;
    let (security_cookie, guard_flags) = load_config(bytes, &image);

    Ok(MitigationsReport {
        dll_characteristics: characteristics,
        aslr: characteristics & DYNAMIC_BASE != 0,
        high_entropy_va: characteristics & HIGH_ENTROPY_VA != 0,
        dep: characteristics & NX_COMPAT != 0,
        cfg: characteristics & GUARD_CF != 0 || guard_flags.is_some_and(|flags| flags & GUARD_CF_INSTRUMENTED != 0),
        force_integrity: characteristics & FORCE_INTEGRITY != 0,
        no_seh: characteristics & NO_SEH != 0,
        terminal_server_aware: characteristics & TERMINAL_SERVER_AWARE != 0,
        relocations_present,
        signed,
        writable_executable_sections,
        security_cookie,
        guard_flags,
    })
}

/// Reads `DllCharacteristics` at its real offset.
///
/// The pinned PE reader applies the PE32 offsets to some trailing optional-header
/// fields, so a PE32+ image would report the wrong value through
/// `optional.dll_characteristics`. The offset is layout-dependent, hence the
/// explicit read.
fn dll_characteristics(bytes: &[u8], image: &pe::PeImage) -> Result<u16> {
    let optional = (image.dos.pe_offset as usize).saturating_add(24);
    let offset = optional.saturating_add(if image.optional.magic == 0x20b { 0x4a } else { 0x46 });
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("the PE optional header is truncated"))?;
    Ok(u16::from_le_bytes(raw))
}

/// Reads the security cookie and `GuardFlags` fields of the load config.
fn load_config(bytes: &[u8], image: &pe::PeImage) -> (Option<bool>, Option<u32>) {
    let directory = image.optional.data_directories[DIRECTORY_LOAD_CONFIG];
    if directory.rva == 0 || directory.size == 0 {
        return (None, None);
    }
    let Ok(base) = pe::rva_to_offset(&image.sections, directory.rva)
    else {
        return (None, None);
    };
    let base = base as usize;
    let is_64 = image.optional.magic == 0x20b;
    let cookie = if is_64 {
        read_u64(bytes, base + LOAD_CONFIG_COOKIE64)
    }
    else {
        read_u32(bytes, base + LOAD_CONFIG_COOKIE32).map(u64::from)
    };
    let guard_flags = if is_64 {
        read_u32(bytes, base + LOAD_CONFIG_GUARD_FLAGS64)
    }
    else {
        read_u32(bytes, base + LOAD_CONFIG_GUARD_FLAGS32)
    };
    (cookie.map(|value| value != 0), guard_flags)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}
