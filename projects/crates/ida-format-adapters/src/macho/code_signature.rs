//! Mach-O embedded code signature projection.
//!
//! `LC_CODE_SIGNATURE`, the `SuperBlob` index and the first `CodeDirectory`
//! are owned by `data-binary-mach-o` (`read_code_signature`). Signatures are
//! parsed, never verified. This module keeps the product JSON shape.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{fat_magic, parse_macho, read_code_signature};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// One decoded `CodeDirectory` blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOCodeDirectory {
    /// Blob format version, such as `0x20200`.
    pub version: u32,
    /// Raw `flags` field.
    pub flags: u32,
    /// `flags` decoded into stable names.
    pub flag_text: Vec<String>,
    /// Hash algorithm name.
    pub hash_type: String,
    /// Size of one hash in bytes.
    pub hash_size: u8,
    /// Page size in bytes, derived from the log2 field.
    pub page_size: u32,
    /// Number of bytes covered by the signature.
    pub code_limit: u64,
    /// Signing identifier, usually the bundle id.
    pub identifier: String,
    /// Team identifier, when present.
    pub team_id: Option<String>,
    /// Number of code slots.
    pub code_slots: u32,
    /// Number of special slots.
    pub special_slots: u32,
}

/// Embedded signature summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOCodeSignatureReport {
    /// Whether the image has an `LC_CODE_SIGNATURE` command.
    pub present: bool,
    /// File offset of the signature blob.
    pub data_offset: u32,
    /// Declared signature size in bytes.
    pub data_size: u32,
    /// SuperBlob magic rendered as a stable name.
    pub magic: Option<String>,
    /// Number of entries in the SuperBlob index.
    pub blob_count: Option<u32>,
    /// Blob type names in index order.
    pub blob_types: Vec<String>,
    /// First `CodeDirectory`, when one is indexed.
    pub code_directory: Option<MachOCodeDirectory>,
    /// Whether a limit or a malformed structure cut the report.
    pub truncated: bool,
}

/// Decodes the embedded code signature of one Mach-O image.
pub fn analyze(session: &BinarySession) -> Result<MachOCodeSignatureReport> {
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O code signatures require a Mach-O container"));
    }
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_some() {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; use `macho-slices` and extract a slice first",
        ));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let signature = read_code_signature(bytes, &image);

    Ok(MachOCodeSignatureReport {
        present: signature.present,
        data_offset: signature.data_offset,
        data_size: signature.data_size,
        magic: signature.magic,
        blob_count: signature.blob_count,
        blob_types: signature.blob_types,
        code_directory: signature.code_directory.map(|directory| MachOCodeDirectory {
            version: directory.version,
            flags: directory.flags,
            flag_text: directory.flag_names.into_iter().map(str::to_string).collect(),
            hash_type: directory.hash_type,
            hash_size: directory.hash_size,
            page_size: directory.page_size,
            code_limit: directory.code_limit,
            identifier: directory.identifier,
            team_id: directory.team_id,
            code_slots: directory.code_slots,
            special_slots: directory.special_slots,
        }),
        truncated: signature.truncated,
    })
}
