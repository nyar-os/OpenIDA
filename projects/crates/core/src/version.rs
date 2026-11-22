//! `PE` version resources (`RT_VERSION`).
//!
//! The version resource is a three-level resource directory followed by a
//! `VS_VERSIONINFO` structure. This module walks the directory and decodes the
//! fixed file info and the `StringFileInfo` key/value pairs. Missing resources
//! are an empty report; a non-PE file is a stable unsupported error.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Data directory index of the resource table.
const RESOURCE_DIRECTORY_INDEX: usize = 2;
/// `RT_VERSION` resource type.
const RT_VERSION: u32 = 16;
/// Maximum bytes decoded from one version payload.
const MAX_VERSION_BYTES: usize = 64 * 1024;
/// Maximum directory entries visited per level.
const MAX_DIRECTORY_ENTRIES: usize = 256;
/// Maximum string pairs retained.
const MAX_STRINGS: usize = 128;
/// Maximum nesting walked inside `VS_VERSIONINFO`.
const MAX_BLOCK_DEPTH: usize = 4;
/// `VS_FIXEDFILEINFO` signature.
const FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;

/// Fixed part of a `VS_VERSIONINFO` resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixedFileInfo {
    /// `dwSignature`, always `0xFEEF04BD` when decoded.
    pub signature: u32,
    /// `dwStrucVersion`.
    pub struct_version: u32,
    /// `dwFileVersion` rendered as `major.minor.build.revision`.
    pub file_version: String,
    /// `dwProductVersion` rendered as `major.minor.build.revision`.
    pub product_version: String,
    /// `dwFileFlagsMask`.
    pub file_flags_mask: u32,
    /// `dwFileFlags`.
    pub file_flags: u32,
    /// `dwFileOS`.
    pub file_os: u32,
    /// `dwFileType`.
    pub file_type: u32,
    /// `dwFileSubtype`.
    pub file_subtype: u32,
    /// `dwFileDate` as a 64-bit Windows timestamp.
    pub file_date: u64,
}

/// One `StringFileInfo` key/value pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionString {
    /// Key such as `CompanyName`.
    pub key: String,
    /// Decoded value.
    pub value: String,
    /// Language id from the string-table key.
    pub language_id: u16,
    /// Code page from the string-table key.
    pub codepage: u16,
}

/// Decoded version resource of one PE file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionReport {
    /// Whether an `RT_VERSION` resource was found.
    pub present: bool,
    /// Fixed file info, when the payload carries a valid `VS_FIXEDFILEINFO`.
    pub fixed: Option<FixedFileInfo>,
    /// String pairs that survived the limit.
    pub strings: Vec<VersionString>,
    /// Number of string pairs before the limit was applied.
    pub total: usize,
    /// Whether the limit removed strings.
    pub truncated: bool,
    /// Human-readable reason when the resource exists but cannot be decoded.
    pub note: Option<String>,
}

/// Decodes the version resource of one open session.
pub(crate) fn analyze(session: &BinarySession) -> Result<VersionReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("version resources are only available for PE files"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let directory = image.optional.data_directories[RESOURCE_DIRECTORY_INDEX];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(empty_report());
    }
    let base = pe::rva_to_offset(&image.sections, directory.rva)
        .map_err(|error| IdaError::parse(format!("PE resource directory: {error}")))? as usize;
    if base >= bytes.len() {
        return Ok(note_report("resource directory starts outside the file"));
    }

    let Some(type_directory) = find_type_directory(bytes, base) else {
        return Ok(empty_report());
    };
    let Some(name_directory) = find_first_subdirectory(bytes, base, type_directory) else {
        return Ok(note_report("RT_VERSION has no name directory"));
    };
    let leaves = directory_entries(bytes, base, name_directory);
    if leaves.is_empty() {
        return Ok(note_report("RT_VERSION has no language entries"));
    }

    let mut fixed = None;
    let mut strings = Vec::new();
    let mut total = 0usize;
    let mut note = None;

    for (identifier, entry) in leaves {
        if entry.is_directory {
            continue;
        }
        let data = match read_data_entry(bytes, &image, base, entry.offset) {
            Some(data) => data,
            None => {
                note = Some(format!("language 0x{identifier:04x} points outside the file"));
                continue;
            }
        };
        let decoded = decode_version_info(data);
        if decoded.fixed.is_none() && decoded.strings.is_empty() {
            note = Some(format!("language 0x{identifier:04x} has no decodable VS_VERSIONINFO"));
            continue;
        }
        if fixed.is_none() {
            fixed = decoded.fixed;
        }
        total += decoded.strings.len();
        if strings.len() < MAX_STRINGS {
            strings.extend(decoded.strings.into_iter().take(MAX_STRINGS - strings.len()));
        }
    }

    let truncated = total > strings.len();
    Ok(VersionReport { present: true, fixed, strings, total, truncated, note })
}

fn empty_report() -> VersionReport {
    VersionReport { present: false, fixed: None, strings: Vec::new(), total: 0, truncated: false, note: None }
}

fn note_report(note: impl Into<String>) -> VersionReport {
    VersionReport { present: true, fixed: None, strings: Vec::new(), total: 0, truncated: false, note: Some(note.into()) }
}

#[derive(Clone, Copy)]
struct Entry {
    is_directory: bool,
    offset: usize,
}

fn find_type_directory(bytes: &[u8], base: usize) -> Option<usize> {
    directory_entries(bytes, base, base)
        .into_iter()
        .find(|(identifier, entry)| *identifier == RT_VERSION && entry.is_directory)
        .map(|(_, entry)| entry.offset)
}

fn find_first_subdirectory(bytes: &[u8], base: usize, directory: usize) -> Option<usize> {
    directory_entries(bytes, base, directory)
        .into_iter()
        .find(|(_, entry)| entry.is_directory)
        .map(|(_, entry)| entry.offset)
}

fn directory_entries(bytes: &[u8], base: usize, directory: usize) -> Vec<(u32, Entry)> {
    let Some(header) = bytes.get(directory..directory.saturating_add(16))
    else {
        return Vec::new();
    };
    let named = u16::from_le_bytes([header[12], header[13]]) as usize;
    let identifiers = u16::from_le_bytes([header[14], header[15]]) as usize;
    let count = named.saturating_add(identifiers).min(MAX_DIRECTORY_ENTRIES);
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = directory.saturating_add(16).saturating_add(index.saturating_mul(8));
        let Some(raw) = bytes.get(offset..offset.saturating_add(8))
        else {
            break;
        };
        let name = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let target = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let is_directory = target & 0x8000_0000 != 0;
        let relative = (target & 0x7fff_ffff) as usize;
        entries.push((
            name & 0xffff,
            Entry { is_directory, offset: base.saturating_add(relative) },
        ));
    }
    entries
}

fn read_data_entry<'a>(bytes: &'a [u8], image: &pe::PeImage, base: usize, entry: usize) -> Option<&'a [u8]> {
    let raw = bytes.get(entry..entry.saturating_add(16))?;
    let rva = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let size = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let offset = pe::rva_to_offset(&image.sections, rva).ok()? as usize;
    if offset < base || size == 0 {
        return None;
    }
    let available = bytes.len().saturating_sub(offset);
    let size = size.min(available).min(MAX_VERSION_BYTES);
    bytes.get(offset..offset + size)
}

struct Decoded {
    fixed: Option<FixedFileInfo>,
    strings: Vec<VersionString>,
}

fn decode_version_info(data: &[u8]) -> Decoded {
    let mut decoded = Decoded { fixed: None, strings: Vec::new() };
    let Some(root) = parse_block(data, 0, data.len(), 0) else {
        return decoded;
    };
    if root.key != "VS_VERSION_INFO" {
        return decoded;
    }
    decoded.fixed = parse_fixed(root.value);
    if let Some(string_file_info) = child(&root, "StringFileInfo") {
        collect_strings(string_file_info, &mut decoded.strings);
    }
    decoded
}

struct Block<'a> {
    key: String,
    value: Option<&'a [u8]>,
    children: Vec<Block<'a>>,
}

fn child<'a, 'b>(block: &'b Block<'a>, key: &str) -> Option<&'b Block<'a>> {
    block.children.iter().find(|child| child.key == key)
}

fn collect_strings(block: &Block<'_>, out: &mut Vec<VersionString>) {
    for table in &block.children {
        let (language_id, codepage) = table_key(&table.key);
        for entry in &table.children {
            let Some(value) = entry.value else {
                continue;
            };
            let text = utf16_lossy(value);
            if text.is_empty() && entry.key.is_empty() {
                continue;
            }
            out.push(VersionString { key: entry.key.clone(), value: text, language_id, codepage });
        }
    }
}

/// Splits a `StringTable` key such as `040904B0` into language and code page.
fn table_key(key: &str) -> (u16, u16) {
    if key.len() < 8 {
        return (0, 0);
    }
    let language = u16::from_str_radix(&key[..4], 16).unwrap_or(0);
    let codepage = u16::from_str_radix(&key[4..8], 16).unwrap_or(0);
    (language, codepage)
}

fn parse_block(data: &[u8], start: usize, end: usize, depth: usize) -> Option<Block<'_>> {
    let limit = end.min(data.len());
    if depth > MAX_BLOCK_DEPTH || start + 6 > limit {
        return None;
    }
    let length = u16::from_le_bytes([data[start], data[start + 1]]) as usize;
    let value_length = u16::from_le_bytes([data[start + 2], data[start + 3]]) as usize;
    let value_type = u16::from_le_bytes([data[start + 4], data[start + 5]]);
    let block_end = start.saturating_add(length).min(limit);
    if block_end <= start + 6 {
        return None;
    }

    let (key, key_end) = utf16_key(data, start + 6, block_end)?;
    let value_bytes = if value_type == 1 { value_length.saturating_mul(2) } else { value_length };
    let value_start = align4(key_end);
    let value_end = value_start.saturating_add(value_bytes).min(block_end);
    let value = (value_end > value_start).then(|| &data[value_start..value_end]);

    let mut children = Vec::new();
    let mut cursor = align4(value_end);
    while cursor + 6 <= block_end {
        let child_length = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
        if child_length < 6 || cursor.saturating_add(child_length) > block_end {
            break;
        }
        match parse_block(data, cursor, cursor + child_length, depth + 1) {
            Some(child) => {
                children.push(child);
                cursor = cursor.saturating_add(align4(child_length));
            }
            None => break,
        }
    }

    Some(Block { key, value, children })
}

fn utf16_key(data: &[u8], start: usize, end: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let mut cursor = start;
    while cursor + 2 <= end {
        let unit = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        cursor += 2;
        if unit == 0 {
            return Some((String::from_utf16_lossy(&units), cursor));
        }
        units.push(unit);
    }
    None
}

fn utf16_lossy(data: &[u8]) -> String {
    let mut units = Vec::with_capacity(data.len() / 2);
    let mut cursor = 0;
    while cursor + 2 <= data.len() {
        let unit = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        cursor += 2;
    }
    String::from_utf16_lossy(&units)
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn parse_fixed(value: Option<&[u8]>) -> Option<FixedFileInfo> {
    let raw = value?;
    if raw.len() < 52 {
        return None;
    }
    let read = |offset: usize| u32::from_le_bytes([raw[offset], raw[offset + 1], raw[offset + 2], raw[offset + 3]]);
    let signature = read(0);
    if signature != FIXED_FILE_INFO_SIGNATURE {
        return None;
    }
    Some(FixedFileInfo {
        signature,
        struct_version: read(4),
        file_version: render_four(read(8), read(12)),
        product_version: render_four(read(16), read(20)),
        file_flags_mask: read(24),
        file_flags: read(28),
        file_os: read(32),
        file_type: read(36),
        file_subtype: read(40),
        file_date: (u64::from(read(44)) << 32) | u64::from(read(48)),
    })
}

fn render_four(ms: u32, ls: u32) -> String {
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff)
}
