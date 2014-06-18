//! Mach-O encryption information from `LC_ENCRYPTION_INFO` or
//! `LC_ENCRYPTION_INFO_64`.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::parse_macho;
use serde::{Deserialize, Serialize};

use super::{
    HEADER32_SIZE, HEADER64_SIZE, LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64,
    util::{Reader, fat_header},
};
use crate::{IdaError, Result};

/// Mach-O encryption information from `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOEncryptionReport {
    /// Whether the image carries an encryption info load command.
    pub present: bool,
    /// File offset of the encrypted range.
    pub crypt_offset: u32,
    /// Size of the encrypted range in bytes.
    pub crypt_size: u32,
    /// Encryption system identifier; `0` means the image is not encrypted.
    pub crypt_id: u32,
    /// Convenience flag derived from `crypt_id != 0`.
    pub encrypted: bool,
    /// Whether the fields came from `LC_ENCRYPTION_INFO_64`.
    pub is_64: bool,
}

/// Decodes `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` of one session.
pub(crate) fn encryption(session: &BinarySession) -> Result<MachOEncryptionReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O encryption info requires a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut report =
        MachOEncryptionReport { present: false, crypt_offset: 0, crypt_size: 0, crypt_id: 0, encrypted: false, is_64: false };

    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4))
        else {
            break;
        };
        if size < 8 {
            break;
        }
        let is_64 = match command {
            LC_ENCRYPTION_INFO if size >= 20 => false,
            LC_ENCRYPTION_INFO_64 if size >= 24 => true,
            _ => {
                offset = offset.saturating_add(u64::from(size));
                continue;
            }
        };
        let (Some(crypt_offset), Some(crypt_size), Some(crypt_id)) =
            (reader.u32(offset + 8), reader.u32(offset + 12), reader.u32(offset + 16))
        else {
            break;
        };
        report = MachOEncryptionReport { present: true, crypt_offset, crypt_size, crypt_id, encrypted: crypt_id != 0, is_64 };
        break;
    }

    Ok(report)
}
