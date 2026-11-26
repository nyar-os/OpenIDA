//! PE exception directory decoding.
//!
//! Data directory 3 holds the runtime function table used for stack walking:
//! a packed array of `RUNTIME_FUNCTION` records. The entry layout depends on the
//! machine: x64 stores three `u32` fields (begin, end, unwind info RVA) while
//! ARM and ARM64 pack the begin address flags into the low bits and follow with
//! one unwind word. Only the unwind header is decoded here; unwind opcodes are
//! left to a disassembler.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const DIRECTORY_EXCEPTION: usize = 3;
const MAX_RUNTIME_FUNCTIONS: usize = 512;

const MACHINE_I386: u16 = 0x014c;
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_ARMNT: u16 = 0x01c4;
const MACHINE_ARM64: u16 = 0xaa64;
const MACHINE_IA64: u16 = 0x0200;
const MACHINE_RISCV32: u16 = 0x5032;
const MACHINE_RISCV64: u16 = 0x5064;

/// Decoded `UNWIND_INFO` header, shared by x64 runtime functions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeUnwindInfo {
    /// Unwind info version (1 or 2 in practice).
    pub version: u8,
    /// Raw flag bits from the first header byte.
    pub flags: u8,
    /// Flag names: `EHANDLER`, `UHANDLER`, `CHAININFO`.
    pub flag_names: Vec<String>,
    /// Prologue size in bytes.
    pub prolog_size: u8,
    /// Number of unwind code slots.
    pub code_count: u8,
    /// Frame register index, non-zero only for frame-pointer functions.
    pub frame_register: u8,
    /// Scaled frame register offset.
    pub frame_offset: u8,
    /// Whether the `CHAININFO` flag is set.
    pub chained: bool,
}

/// One `RUNTIME_FUNCTION` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeRuntimeFunction {
    /// Begin RVA, with the ARM/ARM64 flag bits masked off.
    pub begin_address: u32,
    /// End RVA. Zero on ARM and ARM64, whose records omit it.
    pub end_address: u32,
    /// Unwind info RVA (x64) or unwind data word (ARM/ARM64).
    pub unwind_info: u32,
    /// File offset of the unwind info, when the RVA maps into an image.
    pub unwind_offset: Option<u32>,
    /// Decoded unwind header, x64 only.
    pub unwind: Option<PeUnwindInfo>,
}

/// Bounded PE exception directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeExceptionReport {
    /// Whether the image has a non-empty exception directory.
    pub present: bool,
    /// `COFF` machine type.
    pub machine: u16,
    /// Stable machine name or `#<n>` for an unknown value.
    pub machine_name: String,
    /// Entry layout: `x64`, `arm64`, `arm` or `unknown`.
    pub entry_format: String,
    /// Entry size in bytes, absent for an unknown layout.
    pub entry_size: Option<u32>,
    /// Entries that survived the storage limit, in directory order.
    pub functions: Vec<PeRuntimeFunction>,
    /// Entries declared by the directory size.
    pub total: usize,
    /// Whether the listing or the directory tail was cut.
    pub truncated: bool,
}

/// Decodes the PE exception directory of one session.
pub fn analyze(session: &BinarySession) -> Result<PeExceptionReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE exception directories require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let machine = image.coff.machine;
    let (entry_format, entry_size) = entry_layout(machine);
    let directory = image.optional.data_directories[DIRECTORY_EXCEPTION];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(PeExceptionReport {
            present: false,
            machine,
            machine_name: machine_name(machine),
            entry_format: entry_format.to_string(),
            entry_size,
            functions: Vec::new(),
            total: 0,
            truncated: false,
        });
    }

    let Some(entry_size) = entry_size
    else {
        return Ok(PeExceptionReport {
            present: true,
            machine,
            machine_name: machine_name(machine),
            entry_format: entry_format.to_string(),
            entry_size: None,
            functions: Vec::new(),
            total: 0,
            truncated: false,
        });
    };
    let base = pe::rva_to_offset(&image.sections, directory.rva)
        .map_err(|error| IdaError::parse(format!("PE exception directory: {error}")))? as usize;
    let size = directory.size as usize;
    let end = base.saturating_add(size);
    let declared = size / entry_size as usize;

    let mut report = PeExceptionReport {
        present: true,
        machine,
        machine_name: machine_name(machine),
        entry_format: entry_format.to_string(),
        entry_size: Some(entry_size),
        functions: Vec::new(),
        total: declared,
        truncated: !size.is_multiple_of(entry_size as usize),
    };

    let mut offset = base;
    while report.functions.len() < MAX_RUNTIME_FUNCTIONS && offset.saturating_add(entry_size as usize) <= end {
        let Some(begin_raw) = read_u32(bytes, offset)
        else {
            report.truncated = true;
            break;
        };
        let Some(second) = read_u32(bytes, offset + 4)
        else {
            report.truncated = true;
            break;
        };
        if entry_format == "x64" {
            let Some(unwind_info) = read_u32(bytes, offset + 8)
            else {
                report.truncated = true;
                break;
            };
            let unwind_offset = pe::rva_to_offset(&image.sections, unwind_info).ok();
            let unwind = unwind_offset.and_then(|value| decode_unwind(bytes, value as usize));
            report.functions.push(PeRuntimeFunction {
                begin_address: begin_raw,
                end_address: second,
                unwind_info,
                unwind_offset,
                unwind,
            });
        }
        else {
            // ARM and ARM64 pack the low two bits of the begin address with
            // per-record flags and store one unwind word after it.
            report.functions.push(PeRuntimeFunction {
                begin_address: begin_raw & !0x3,
                end_address: 0,
                unwind_info: second,
                unwind_offset: None,
                unwind: None,
            });
        }
        offset += entry_size as usize;
    }

    if report.functions.len() < declared && report.functions.len() >= MAX_RUNTIME_FUNCTIONS {
        report.truncated = true;
    }
    Ok(report)
}

fn entry_layout(machine: u16) -> (&'static str, Option<u32>) {
    match machine {
        MACHINE_AMD64 => ("x64", Some(12)),
        MACHINE_ARM64 => ("arm64", Some(8)),
        MACHINE_ARMNT => ("arm", Some(8)),
        _ => ("unknown", None),
    }
}

fn machine_name(machine: u16) -> String {
    match machine {
        MACHINE_I386 => "i386".to_string(),
        MACHINE_AMD64 => "amd64".to_string(),
        MACHINE_ARMNT => "armnt".to_string(),
        MACHINE_ARM64 => "arm64".to_string(),
        MACHINE_IA64 => "ia64".to_string(),
        MACHINE_RISCV32 => "riscv32".to_string(),
        MACHINE_RISCV64 => "riscv64".to_string(),
        other => format!("#{other}"),
    }
}

fn decode_unwind(bytes: &[u8], offset: usize) -> Option<PeUnwindInfo> {
    let header = bytes.get(offset..offset + 4)?;
    let version = header[0] & 0x07;
    if version == 0 {
        return None;
    }
    let flags = header[0] >> 3;
    Some(PeUnwindInfo {
        version,
        flags,
        flag_names: unwind_flag_names(flags),
        prolog_size: header[1],
        code_count: header[2],
        frame_register: header[3] & 0x0f,
        frame_offset: header[3] >> 4,
        chained: flags & 0x04 != 0,
    })
}

fn unwind_flag_names(flags: u8) -> Vec<String> {
    const NAMES: [(u8, &str); 3] = [(0x01, "EHANDLER"), (0x02, "UHANDLER"), (0x04, "CHAININFO")];
    NAMES.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, name)| (*name).to_string()).collect()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}
