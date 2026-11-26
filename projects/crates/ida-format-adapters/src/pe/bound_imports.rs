//! PE bound-import table decoding.
//!
//! Data directory 11 holds an array of `IMAGE_BOUND_IMPORT_DESCRIPTOR`
//! records: a `u32` timestamp, a `u16` offset of the module name from the
//! start of the table and a `u16` forwarder count, followed inline by that
//! many `IMAGE_BOUND_FORWARDER_REF` records with the same first three fields.
//! An all-zero descriptor terminates the array. The table records the
//! timestamps the binder saw; nothing here re-binds or loads a module. A
//! missing terminator or an unreadable name offset sets `truncated` and stops
//! the walk.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const DIRECTORY_BOUND_IMPORTS: usize = 11;
const DESCRIPTOR_SIZE: usize = 8;
const MAX_BOUND_DESCRIPTORS: usize = 64;
const MAX_BOUND_FORWARDERS: usize = 32;

/// One forwarder reference inside a bound import descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeBoundForwarder {
    /// Timestamp the binder recorded for the forwarder module.
    pub timestamp: u32,
    /// Name offset from the start of the bound-import table.
    pub offset_module_name: u16,
    /// Module name read from that offset, empty when it does not resolve.
    pub name: String,
}

/// One bound import descriptor and its inline forwarder references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeBoundModule {
    /// Timestamp the binder recorded for this module.
    pub timestamp: u32,
    /// Name offset from the start of the bound-import table.
    pub offset_module_name: u16,
    /// Module name read from that offset, empty when it does not resolve.
    pub name: String,
    /// Forwarder references that survived the limits.
    pub forwarders: Vec<PeBoundForwarder>,
}

/// Bounded PE bound-import listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeBoundImportsReport {
    /// Whether the image has a non-empty bound-import directory.
    pub present: bool,
    /// RVA of the descriptor array.
    pub directory_rva: u32,
    /// Declared size of the directory.
    pub directory_size: u32,
    /// Descriptors that survived the limits, in table order.
    pub modules: Vec<PeBoundModule>,
    /// Descriptors seen before the terminator or a limit.
    pub total_modules: usize,
    /// Forwarders listed across all modules.
    pub total_forwarders: usize,
    /// Whether a limit or unreadable data stopped the walk.
    pub truncated: bool,
}

/// Decodes the PE bound-import directory of one session.
pub fn analyze(session: &BinarySession) -> Result<PeBoundImportsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE bound imports require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let directory = image.optional.data_directories[DIRECTORY_BOUND_IMPORTS];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(PeBoundImportsReport {
            present: false,
            directory_rva: 0,
            directory_size: 0,
            modules: Vec::new(),
            total_modules: 0,
            total_forwarders: 0,
            truncated: false,
        });
    }

    let resolve = |rva: u32| pe::rva_to_offset(&image.sections, rva).ok().map(|value| value as usize);
    let base = resolve(directory.rva).ok_or_else(|| IdaError::parse("PE bound imports: directory RVA is outside the image"))?;
    let mut report = PeBoundImportsReport {
        present: true,
        directory_rva: directory.rva,
        directory_size: directory.size,
        modules: Vec::new(),
        total_modules: 0,
        total_forwarders: 0,
        truncated: false,
    };

    let mut offset = base;
    loop {
        let (Some(timestamp), Some(name_offset), Some(forwarders)) =
            (read_u32(bytes, offset), read_u16(bytes, offset + 4), read_u16(bytes, offset + 6))
        else {
            report.truncated = true;
            break;
        };
        if timestamp == 0 && name_offset == 0 && forwarders == 0 {
            break;
        }
        report.total_modules += 1;
        if report.modules.len() >= MAX_BOUND_DESCRIPTORS {
            report.truncated = true;
            break;
        }

        let mut module =
            PeBoundModule { timestamp, offset_module_name: name_offset, name: String::new(), forwarders: Vec::new() };
        match read_name(bytes, &resolve, directory.rva, name_offset) {
            Some(name) => module.name = name,
            None => report.truncated = true,
        }

        let count = usize::from(forwarders);
        for index in 0..count {
            if module.forwarders.len() >= MAX_BOUND_FORWARDERS {
                report.truncated = true;
                break;
            }
            let at = offset + DESCRIPTOR_SIZE + index * DESCRIPTOR_SIZE;
            let (Some(ref_timestamp), Some(ref_name_offset)) = (read_u32(bytes, at), read_u16(bytes, at + 4))
            else {
                report.truncated = true;
                break;
            };
            let mut forwarder =
                PeBoundForwarder { timestamp: ref_timestamp, offset_module_name: ref_name_offset, name: String::new() };
            match read_name(bytes, &resolve, directory.rva, ref_name_offset) {
                Some(name) => forwarder.name = name,
                None => report.truncated = true,
            }
            module.forwarders.push(forwarder);
        }
        report.total_forwarders += module.forwarders.len();
        report.modules.push(module);
        offset += DESCRIPTOR_SIZE + count * DESCRIPTOR_SIZE;
    }
    Ok(report)
}

fn read_name(bytes: &[u8], resolve: &impl Fn(u32) -> Option<usize>, directory_rva: u32, offset: u16) -> Option<String> {
    resolve(directory_rva.saturating_add(u32::from(offset))).and_then(|value| read_cstring(bytes, value))
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
