//! PE delay-load import table decoding.
//!
//! Data directory 13 holds an array of `IMAGE_DELAYLOAD_DESCRIPTOR` records,
//! one per delay-loaded module, terminated by an all-zero descriptor. Each
//! record points at the DLL name, the module-handle slot and parallel Import
//! Name and Import Address Tables; INT entries are either the RVA of a
//! hint/name pair or an ordinal with bit 31 set. Only the v2 (RVA-based)
//! layout is resolved; legacy v1 records store virtual addresses, so their
//! names and tables are reported with the raw field values and simply fail to
//! map. Nothing here loads a module or runs the delay helper.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const DIRECTORY_DELAY_IMPORTS: usize = 13;
const DESCRIPTOR_SIZE: usize = 32;
const MAX_DELAY_MODULES: usize = 128;
const MAX_DELAY_THUNKS: usize = 256;
const MAX_DELAY_TOTAL_THUNKS: usize = 1_024;
const ORDINAL_FLAG: u32 = 0x8000_0000;

/// One delay thunk: the INT entry, its parallel IAT slot and the import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeDelayThunk {
    /// RVA of the INT entry this thunk was decoded from.
    pub int_rva: u32,
    /// RVA of the parallel IAT slot, absent when the descriptor has no IAT.
    pub iat_rva: Option<u32>,
    /// Import name, when the entry references a hint/name pair.
    pub name: Option<String>,
    /// Import ordinal, when bit 31 of the entry is set.
    pub ordinal: Option<u32>,
    /// Hint index of a name import.
    pub hint: Option<u16>,
}

/// One delay-loaded module and its decoded thunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeDelayModule {
    /// Module name read from its RVA, empty when it does not resolve.
    pub name: String,
    /// Raw `Attributes` field (the v1 DLL-name RVA).
    pub attributes: u32,
    /// `dwTimeStamp` recorded by the linker.
    pub timestamp: u32,
    /// RVA of the module-handle slot.
    pub module_handle_rva: u32,
    /// RVA of the delay IAT.
    pub iat_rva: u32,
    /// RVA of the delay INT.
    pub int_rva: u32,
    /// RVA of the bound IAT.
    pub bound_iat_rva: u32,
    /// RVA of the unload IAT.
    pub unload_iat_rva: u32,
    /// Thunks that survived the limits, in INT order.
    pub thunks: Vec<PeDelayThunk>,
}

/// Bounded PE delay-import listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeDelayImportsReport {
    /// Whether the image has a non-empty delay-import directory.
    pub present: bool,
    /// RVA of the descriptor array.
    pub directory_rva: u32,
    /// Declared size of the directory.
    pub directory_size: u32,
    /// Modules that survived the limits, in directory order.
    pub modules: Vec<PeDelayModule>,
    /// Descriptors seen before the terminator or a limit.
    pub total_modules: usize,
    /// Thunks listed across all modules.
    pub total_thunks: usize,
    /// Whether a limit or unreadable data stopped the walk.
    pub truncated: bool,
}

/// Decodes the PE delay-import directory of one session.
pub fn analyze(session: &BinarySession) -> Result<PeDelayImportsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE delay imports require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let directory = image.optional.data_directories[DIRECTORY_DELAY_IMPORTS];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(PeDelayImportsReport {
            present: false,
            directory_rva: 0,
            directory_size: 0,
            modules: Vec::new(),
            total_modules: 0,
            total_thunks: 0,
            truncated: false,
        });
    }

    let resolve = |rva: u32| pe::rva_to_offset(&image.sections, rva).ok().map(|value| value as usize);
    let base = resolve(directory.rva).ok_or_else(|| IdaError::parse("PE delay imports: directory RVA is outside the image"))?;
    let mut report = PeDelayImportsReport {
        present: true,
        directory_rva: directory.rva,
        directory_size: directory.size,
        modules: Vec::new(),
        total_modules: 0,
        total_thunks: 0,
        truncated: false,
    };

    let mut offset = base;
    loop {
        let Some(fields) = read_descriptor(bytes, offset)
        else {
            report.truncated = true;
            break;
        };
        if fields.iter().all(|value| *value == 0) {
            break;
        }
        report.total_modules += 1;
        if report.modules.len() >= MAX_DELAY_MODULES {
            report.truncated = true;
            break;
        }

        let name = resolve(fields[1]).and_then(|value| read_cstring(bytes, value)).unwrap_or_default();
        let mut thunks = Vec::new();
        if fields[4] != 0 {
            match resolve(fields[4]) {
                None => report.truncated = true,
                Some(table) => {
                    let mut budget = MAX_DELAY_TOTAL_THUNKS - report.total_thunks;
                    for index in 0..MAX_DELAY_THUNKS {
                        let Some(entry) = read_u32(bytes, table + index * 4)
                        else {
                            report.truncated = true;
                            break;
                        };
                        if entry == 0 {
                            break;
                        }
                        if budget == 0 {
                            report.truncated = true;
                            break;
                        }
                        budget -= 1;
                        let step = u32::try_from(index * 4).unwrap_or(u32::MAX);
                        let mut thunk = PeDelayThunk {
                            int_rva: fields[4].saturating_add(step),
                            iat_rva: if fields[3] == 0 { None } else { Some(fields[3].saturating_add(step)) },
                            name: None,
                            ordinal: None,
                            hint: None,
                        };
                        if entry & ORDINAL_FLAG != 0 {
                            thunk.ordinal = Some(entry & 0xffff);
                            thunks.push(thunk);
                            continue;
                        }
                        let Some(name_offset) = resolve(entry)
                        else {
                            report.truncated = true;
                            break;
                        };
                        let (Some(hint), Some(import_name)) =
                            (read_u16(bytes, name_offset), read_cstring(bytes, name_offset + 2))
                        else {
                            report.truncated = true;
                            break;
                        };
                        thunk.name = Some(import_name);
                        thunk.hint = Some(hint);
                        thunks.push(thunk);
                    }
                    if thunks.len() == MAX_DELAY_THUNKS {
                        report.truncated = true;
                    }
                }
            }
        }
        report.total_thunks += thunks.len();
        report.modules.push(build_module(fields, name, thunks));
        offset += DESCRIPTOR_SIZE;
    }
    Ok(report)
}

fn build_module(fields: [u32; 8], name: String, thunks: Vec<PeDelayThunk>) -> PeDelayModule {
    PeDelayModule {
        name,
        attributes: fields[0],
        timestamp: fields[7],
        module_handle_rva: fields[2],
        iat_rva: fields[3],
        int_rva: fields[4],
        bound_iat_rva: fields[5],
        unload_iat_rva: fields[6],
        thunks,
    }
}

fn read_descriptor(bytes: &[u8], offset: usize) -> Option<[u32; 8]> {
    let mut fields = [0u32; 8];
    for (index, field) in fields.iter_mut().enumerate() {
        *field = read_u32(bytes, offset.checked_add(index * 4)?)?;
    }
    Some(fields)
}

fn read_cstring(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}
