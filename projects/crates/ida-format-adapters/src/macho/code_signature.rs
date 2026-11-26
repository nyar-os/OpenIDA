//! Mach-O embedded code signature decoding.
//!
//! `LC_CODE_SIGNATURE` points at an `EmbeddedSignature` `SuperBlob` in the file.
//! This module reports the blob table and the fields of the first
//! `CodeDirectory`, including the identifier, team id, hash type and code limit.
//! Signatures are parsed, never verified: no hash is recomputed and no
//! certificate chain is built.

use data_binary_inspect::{BinaryFormat, BinarySession};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const LC_CODE_SIGNATURE: u32 = 0x1d;
const EMBEDDED_SIGNATURE_MAGIC: u32 = 0xfade_0cc0;
const CODE_DIRECTORY_MAGIC: u32 = 0xfade_0c02;
const HEADER32_SIZE: u64 = 28;
const HEADER64_SIZE: u64 = 32;
const MAX_BLOBS: usize = 32;

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
    let header = Header::parse(bytes)?;
    if header.is_fat {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; use `macho-slices` and extract a slice first",
        ));
    }

    let mut offset = header.size;
    let mut signature = None;
    for _ in 0..header.command_count {
        if offset + 8 > bytes.len() as u64 {
            break;
        }
        let command = header.u32(bytes, offset).unwrap_or(0);
        let size = header.u32(bytes, offset + 4).unwrap_or(0);
        if size < 8 {
            break;
        }
        if command == LC_CODE_SIGNATURE && size >= 16 {
            signature = Some((header.u32(bytes, offset + 8).unwrap_or(0), header.u32(bytes, offset + 12).unwrap_or(0)));
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let Some((data_offset, data_size)) = signature
    else {
        return Ok(MachOCodeSignatureReport {
            present: false,
            data_offset: 0,
            data_size: 0,
            magic: None,
            blob_count: None,
            blob_types: Vec::new(),
            code_directory: None,
            truncated: false,
        });
    };

    let mut report = MachOCodeSignatureReport {
        present: true,
        data_offset,
        data_size,
        magic: None,
        blob_count: None,
        blob_types: Vec::new(),
        code_directory: None,
        truncated: false,
    };
    let base = data_offset as usize;
    let end = base.saturating_add(data_size as usize).min(bytes.len());
    if base >= bytes.len() {
        report.truncated = true;
        return Ok(report);
    }
    let blob = &bytes[base..end];
    let Some(magic) = be_u32(blob, 0)
    else {
        report.truncated = true;
        return Ok(report);
    };
    if magic != EMBEDDED_SIGNATURE_MAGIC {
        report.magic = Some(format!("0x{magic:08x}"));
        report.truncated = end < base.saturating_add(data_size as usize);
        return Ok(report);
    }
    report.magic = Some("embedded-signature".to_string());
    let count = be_u32(blob, 8).unwrap_or(0);
    report.blob_count = Some(count);

    for index in 0..(count as usize).min(MAX_BLOBS) {
        let entry = 12 + index * 8;
        let (Some(kind), Some(relative)) = (be_u32(blob, entry), be_u32(blob, entry + 4))
        else {
            report.truncated = true;
            break;
        };
        let relative = relative as usize;
        if relative >= blob.len() {
            report.truncated = true;
            continue;
        }
        report.blob_types.push(blob_type_name(kind));
        if kind == 0 && report.code_directory.is_none() {
            report.code_directory = decode_code_directory(&blob[relative..]);
        }
    }
    if (count as usize) > MAX_BLOBS {
        report.truncated = true;
    }
    Ok(report)
}

fn decode_code_directory(blob: &[u8]) -> Option<MachOCodeDirectory> {
    if be_u32(blob, 0)? != CODE_DIRECTORY_MAGIC {
        return None;
    }
    let version = be_u32(blob, 8)?;
    let flags = be_u32(blob, 12)?;
    let identifier_offset = be_u32(blob, 20)? as usize;
    let special_slots = be_u32(blob, 24)?;
    let code_slots = be_u32(blob, 28)?;
    let code_limit = be_u32(blob, 32)?;
    let hash_size = *blob.get(36)?;
    let hash_type = *blob.get(37)?;
    let page_shift = *blob.get(39)?;
    let team_offset = if version >= 0x20200 { be_u32(blob, 48) } else { None };

    let code_limit64 = if version >= 0x20300 { be_u64(blob, 56) } else { None };
    Some(MachOCodeDirectory {
        version,
        flags,
        flag_text: flag_names(flags),
        hash_type: hash_type_name(hash_type),
        hash_size,
        page_size: if page_shift == 0 { 0 } else { 1u32 << page_shift.min(31) },
        code_limit: code_limit64.filter(|value| *value != 0).unwrap_or(u64::from(code_limit)),
        identifier: c_string(blob, identifier_offset).unwrap_or_default(),
        team_id: team_offset.filter(|value| *value != 0).and_then(|offset| c_string(blob, offset as usize)),
        code_slots,
        special_slots,
    })
}

fn blob_type_name(kind: u32) -> String {
    match kind {
        0 => "CodeDirectory".to_string(),
        1 => "Info.plist".to_string(),
        2 => "Requirements".to_string(),
        3 => "ResourceDir".to_string(),
        4 => "Application".to_string(),
        5 => "Entitlements".to_string(),
        6 => "DMG".to_string(),
        7 => "DER Entitlements".to_string(),
        8 => "LaunchConstraint".to_string(),
        other => format!("0x{other:08x}"),
    }
}

fn hash_type_name(kind: u8) -> String {
    match kind {
        0 => "none".to_string(),
        1 => "SHA1".to_string(),
        2 => "SHA256".to_string(),
        3 => "SHA256-truncated".to_string(),
        4 => "SHA384".to_string(),
        5 => "SHA512".to_string(),
        other => format!("0x{other:02x}"),
    }
}

fn flag_names(flags: u32) -> Vec<String> {
    let known = [(0x0000_0001, "ADHOC"), (0x0000_0002, "HARD"), (0x0000_0100, "HOST"), (0x0000_0200, "LINKER_SIGNED")];
    known.into_iter().filter(|(bit, _)| flags & bit != 0).map(|(_, name)| name.to_string()).collect()
}

fn c_string(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0).unwrap_or(tail.len());
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn be_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}

struct Header {
    is_fat: bool,
    big_endian: bool,
    size: u64,
    command_count: u32,
}

impl Header {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let raw: [u8; 4] = bytes
            .get(0..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| IdaError::parse("the file is too short for a Mach-O header"))?;
        // Fat containers use the same magic in both byte orders.
        if matches!(
            raw,
            [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] | [0xca, 0xfe, 0xba, 0xbf] | [0xbf, 0xba, 0xfe, 0xca]
        ) {
            return Ok(Self { is_fat: true, big_endian: false, size: 0, command_count: 0 });
        }
        let (is64, big_endian) = match raw {
            [0xce, 0xfa, 0xed, 0xfe] => (false, false),
            [0xfe, 0xed, 0xfa, 0xce] => (false, true),
            [0xcf, 0xfa, 0xed, 0xfe] => (true, false),
            [0xfe, 0xed, 0xfa, 0xcf] => (true, true),
            other => return Err(IdaError::parse(format!("unsupported Mach-O magic {other:02x?}"))),
        };
        let header =
            Self { is_fat: false, big_endian, size: if is64 { HEADER64_SIZE } else { HEADER32_SIZE }, command_count: 0 };
        let command_count = header.u32(bytes, 16).unwrap_or(0);
        Ok(Self { command_count, ..header })
    }

    fn u32(&self, bytes: &[u8], offset: u64) -> Option<u32> {
        let raw: [u8; 4] = bytes.get(offset as usize..offset as usize + 4)?.try_into().ok()?;
        Some(if self.big_endian { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
    }
}
