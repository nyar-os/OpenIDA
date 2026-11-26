//! Mach-O encryption information projection.
//!
//! `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` are owned by
//! `data-binary-mach-o` (`MachOImage::encryption`). This module keeps the
//! product JSON shape and the `present`/`encrypted` convenience fields.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{fat_magic, parse_macho};
use serde::{Deserialize, Serialize};

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
pub fn encryption(session: &BinarySession) -> Result<MachOEncryptionReport> {
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O encryption info requires a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;

    Ok(match image.encryption {
        Some(info) => MachOEncryptionReport {
            present: true,
            crypt_offset: info.crypt_offset,
            crypt_size: info.crypt_size,
            crypt_id: info.crypt_id,
            encrypted: info.encrypted(),
            is_64: info.is_64,
        },
        None => MachOEncryptionReport {
            present: false,
            crypt_offset: 0,
            crypt_size: 0,
            crypt_id: 0,
            encrypted: false,
            is_64: false,
        },
    })
}
