//! PE TLS directory decoding.
//!
//! The TLS data directory (index 9) records the raw template range, the index
//! slot and an array of callback virtual addresses. The array is terminated by a
//! null pointer. Addresses are VAs, so they are mapped through the image base
//! and then through the section table. The report never calls a callback.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Data directory index of the TLS table.
const DIRECTORY_TLS: usize = 9;
const MAX_CALLBACKS: usize = 64;

/// One TLS callback address and its file mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeTlsCallback {
    /// Callback virtual address as stored in the array.
    pub address: u64,
    /// Image-relative address, when the callback lies inside the image.
    pub rva: Option<u64>,
    /// File offset of the callback code, when the RVA maps onto a section.
    pub offset: Option<u64>,
}

/// PE TLS table summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeTlsReport {
    /// Whether the image has a non-empty TLS directory.
    pub present: bool,
    /// Whether the image uses the 64-bit TLS layout.
    pub is64: bool,
    /// RVA of the TLS directory.
    pub directory_rva: u32,
    /// Declared size of the TLS directory.
    pub directory_size: u32,
    /// `StartAddressOfRawData` as a virtual address.
    pub raw_data_start: u64,
    /// `EndAddressOfRawData` as a virtual address.
    pub raw_data_end: u64,
    /// `AddressOfIndex` as a virtual address.
    pub index_address: u64,
    /// `AddressOfCallBacks` as a virtual address.
    pub callbacks_address: u64,
    /// Image-relative address of the callback array, when it lies inside the image.
    pub callbacks_rva: Option<u64>,
    /// `SizeOfZeroFill` in bytes.
    pub size_of_zero_fill: u32,
    /// Raw `Characteristics` field.
    pub characteristics: u32,
    /// Non-null callbacks that survived the limit, in array order.
    pub callbacks: Vec<PeTlsCallback>,
    /// Whether a limit or a malformed array stopped the listing.
    pub truncated: bool,
}

impl PeTlsReport {
    fn empty(is64: bool) -> Self {
        Self {
            present: false,
            is64,
            directory_rva: 0,
            directory_size: 0,
            raw_data_start: 0,
            raw_data_end: 0,
            index_address: 0,
            callbacks_address: 0,
            callbacks_rva: None,
            size_of_zero_fill: 0,
            characteristics: 0,
            callbacks: Vec::new(),
            truncated: false,
        }
    }
}

/// Decodes the PE TLS directory of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<PeTlsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE TLS requires a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let is64 = image.optional.magic == 0x20b;
    let directory = image.optional.data_directories[DIRECTORY_TLS];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(PeTlsReport::empty(is64));
    }

    let base = pe::rva_to_offset(&image.sections, directory.rva)
        .map_err(|error| IdaError::parse(format!("PE TLS: {error}")))? as usize;
    let mut report = PeTlsReport {
        present: true,
        is64,
        directory_rva: directory.rva,
        directory_size: directory.size,
        raw_data_start: 0,
        raw_data_end: 0,
        index_address: 0,
        callbacks_address: 0,
        callbacks_rva: None,
        size_of_zero_fill: 0,
        characteristics: 0,
        callbacks: Vec::new(),
        truncated: false,
    };

    let fields = if is64 {
        let (Some(start), Some(end), Some(index), Some(callbacks)) = (
            read_u64(bytes, base),
            read_u64(bytes, base + 8),
            read_u64(bytes, base + 16),
            read_u64(bytes, base + 24),
        )
        else {
            report.truncated = true;
            return Ok(report);
        };
        (start, end, index, callbacks)
    }
    else {
        let (Some(start), Some(end), Some(index), Some(callbacks)) = (
            read_u32(bytes, base),
            read_u32(bytes, base + 4),
            read_u32(bytes, base + 8),
            read_u32(bytes, base + 12),
        )
        else {
            report.truncated = true;
            return Ok(report);
        };
        (u64::from(start), u64::from(end), u64::from(index), u64::from(callbacks))
    };
    report.raw_data_start = fields.0;
    report.raw_data_end = fields.1;
    report.index_address = fields.2;
    report.callbacks_address = fields.3;
    let zero_fill_offset = if is64 { base + 32 } else { base + 16 };
    report.size_of_zero_fill = read_u32(bytes, zero_fill_offset).unwrap_or(0);
    report.characteristics = read_u32(bytes, zero_fill_offset + 4).unwrap_or(0);

    let Some(image_base) = image_base(bytes, &image) else {
        report.truncated = true;
        return Ok(report);
    };
    let Some(callbacks_rva) = report.callbacks_address.checked_sub(image_base) else {
        report.truncated = true;
        return Ok(report);
    };
    report.callbacks_rva = Some(callbacks_rva);
    let Ok(array_offset) = pe::rva_to_offset(&image.sections, callbacks_rva as u32) else {
        report.truncated = true;
        return Ok(report);
    };
    let array_offset = array_offset as usize;
    let pointer_size = if is64 { 8 } else { 4 };

    for index in 0..MAX_CALLBACKS {
        let at = array_offset.saturating_add(index.saturating_mul(pointer_size));
        let address = if is64 {
            read_u64(bytes, at)
        }
        else {
            read_u32(bytes, at).map(u64::from)
        };
        let Some(address) = address else {
            report.truncated = true;
            break;
        };
        if address == 0 {
            break;
        }
        let rva = address.checked_sub(image_base);
        let offset = rva
            .and_then(|value| u32::try_from(value).ok())
            .and_then(|value| pe::rva_to_offset(&image.sections, value).ok())
            .map(u64::from);
        report.callbacks.push(PeTlsCallback {
            address,
            rva,
            offset,
        });
    }
    if report.callbacks.len() == MAX_CALLBACKS {
        report.truncated = true;
    }
    Ok(report)
}

/// Reads `ImageBase` at its layout-dependent optional-header offset.
fn image_base(bytes: &[u8], image: &pe::PeImage) -> Option<u64> {
    let optional = (image.dos.pe_offset as usize).saturating_add(24);
    if image.optional.magic == 0x20b {
        read_u64(bytes, optional + 0x18)
    }
    else {
        read_u32(bytes, optional + 0x1c).map(u64::from)
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}
