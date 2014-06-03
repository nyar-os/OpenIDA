//! Mach-O load commands, segments, sections, dylibs and image identity.
//!
//! The header, segment and section tables come from `data-binary-mach-o`.
//! The pinned release does not expose `LC_UUID`, `LC_BUILD_VERSION`,
//! `LC_VERSION_MIN_*`, the dylib commands or `LC_SYMTAB`, so those are decoded
//! here from the same load-command stream. Dyld bindings stay out of scope.
//! Fat/universal containers are reported as an architecture table; a thin
//! image is inspected directly and does not have slices.

use std::path::Path;

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{MachOEndian, MachOImage, architecture, macho_magic, parse_macho};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const LC_SYMTAB: u32 = 0x2;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const MAX_EXPORTS: usize = 512;
const MAX_EXPORT_NODES: usize = 8192;
const MAX_EXPORT_DEPTH: usize = 64;
const LC_LOAD_DYLIB: u32 = 0x0c;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// Upper bound on the declared slice count, so a corrupt header cannot force a
/// huge allocation.
const MAX_FAT_SLICES: usize = 256;
const LC_ID_DYLIB: u32 = 0x0d;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_VERSION_MIN_TVOS: u32 = 0x2f;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_UUID: u32 = 0x1b;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;

const HEADER32_SIZE: usize = 28;
const HEADER64_SIZE: usize = 32;

/// One linked or identifying dylib command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachODylib {
    /// Command kind: `load`, `id`, `weak`, `reexport`, `lazy` or `upward`.
    pub kind: String,
    /// Install name stored in the command.
    pub name: String,
    /// Build timestamp recorded by the linker.
    pub timestamp: u32,
    /// Packed current version rendered as `major.minor.patch`.
    pub current_version: String,
    /// Packed compatibility version rendered as `major.minor.patch`.
    pub compatibility_version: String,
}

/// One segment load command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSegment {
    /// Segment name, such as `__TEXT`.
    pub name: String,
    /// Virtual address of the first byte.
    pub vm_address: u64,
    /// Size in memory.
    pub vm_size: u64,
    /// File offset of the first byte.
    pub file_offset: u64,
    /// Size in the file.
    pub file_size: u64,
    /// Whether the segment is readable.
    pub readable: bool,
    /// Whether the segment is writable.
    pub writable: bool,
    /// Whether the segment is executable.
    pub executable: bool,
}

/// One section entry with its owning segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSection {
    /// Owning segment name.
    pub segment: String,
    /// Section name, such as `__text`.
    pub name: String,
    /// Virtual address of the first byte.
    pub address: u64,
    /// Size in bytes.
    pub size: u64,
    /// File offset of the first byte.
    pub file_offset: u64,
    /// Alignment expressed as a power of two.
    pub alignment: u32,
    /// Raw `S_*` section flags.
    pub flags: u32,
    /// Whether the owning segment is readable.
    pub readable: bool,
    /// Whether the owning segment is writable.
    pub writable: bool,
    /// Whether the owning segment is executable.
    pub executable: bool,
}

/// Full Mach-O image summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOReport {
    /// Whether the file uses the 64-bit header layout.
    pub is_64: bool,
    /// Byte order as `little` or `big`.
    pub endian: String,
    /// Raw `cputype`.
    pub cpu_type: i32,
    /// Raw `cpusubtype`.
    pub cpu_subtype: i32,
    /// Instruction-set family derived from `cputype`.
    pub architecture: String,
    /// Raw `filetype`.
    pub file_type: u32,
    /// `filetype` rendered as a stable name.
    pub kind: String,
    /// Raw header flags.
    pub flags: u32,
    /// Number of load commands.
    pub command_count: u32,
    /// Declared size of the load-command area.
    pub size_of_commands: u32,
    /// `LC_UUID` rendered as a canonical UUID.
    pub uuid: Option<String>,
    /// Platform from `LC_BUILD_VERSION` or `LC_VERSION_MIN_*`.
    pub platform: Option<String>,
    /// Minimum OS version rendered as `major.minor.patch`.
    pub min_os: Option<String>,
    /// SDK version rendered as `major.minor.patch`.
    pub sdk: Option<String>,
    /// `LC_MAIN` entry file offset.
    pub entry_offset: Option<u64>,
    /// Entry point mapped onto a virtual address, when a segment or section covers it.
    pub entry_address: Option<u64>,
    /// Dylib load commands in file order.
    pub dylibs: Vec<MachODylib>,
    /// Segments in load-command order.
    pub segments: Vec<MachOSegment>,
    /// Sections in file order.
    pub sections: Vec<MachOSection>,
}

/// One `nlist` entry of the `LC_SYMTAB` symbol table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSymbol {
    /// Name resolved through the string table; empty when the index is out of range.
    pub name: String,
    /// `n_value`, which is a virtual address for defined symbols.
    pub address: u64,
    /// Symbol kind derived from `n_type & N_TYPE`: `undefined`, `absolute`,
    /// `section`, `indirect`, `prebound`, `debug` or `other`.
    pub kind: String,
    /// Whether the symbol is external (`N_EXT`).
    pub external: bool,
    /// Whether the entry is a debugging stab (`N_STAB`).
    pub debug: bool,
    /// `n_sect` for section-relative symbols, otherwise `None`.
    pub section: Option<u8>,
    /// Raw `n_desc`, for example the library ordinal of an undefined symbol.
    pub descriptor: u16,
}

/// Bounded listing of [`MachOSymbol`] values from `LC_SYMTAB`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSymbolsReport {
    /// Symbols that survived the limit.
    pub symbols: Vec<MachOSymbol>,
    /// Number of entries declared by `LC_SYMTAB`.
    pub total: usize,
    /// Whether the limit removed symbols.
    pub truncated: bool,
    /// Size of the linked string table in bytes.
    pub string_table_size: u32,
}

/// Decodes the `LC_SYMTAB` symbol table of one session.
pub(crate) fn symbols(session: &BinarySession, limit: Option<usize>) -> Result<MachOSymbolsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice",
        ));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O symbols require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut table = None;
    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4)) else {
            break;
        };
        if size < 8 {
            break;
        }
        if command == LC_SYMTAB && size >= 24 {
            table = match (
                reader.u32(offset + 8),
                reader.u32(offset + 12),
                reader.u32(offset + 16),
                reader.u32(offset + 20),
            ) {
                (Some(symbol_offset), Some(count), Some(string_offset), Some(string_size)) => {
                    Some((symbol_offset, count, string_offset, string_size))
                }
                _ => None,
            };
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let Some((symbol_offset, count, string_offset, string_size)) = table else {
        return Err(IdaError::unsupported("the Mach-O has no LC_SYMTAB command"));
    };
    let symbol_offset = u64::from(symbol_offset);

    let strings = reader.slice(u64::from(string_offset), u64::from(string_size)).unwrap_or(&[]);
    let entry_size = if image.header.is_64 { 16 } else { 12 };
    let total = count as usize;
    let limit = limit.unwrap_or(usize::MAX);
    let mut symbols = Vec::new();

    for index in 0..total.min(limit) {
        let Some(entry) = symbol_offset.checked_add((index as u64).saturating_mul(entry_size)) else {
            break;
        };
        let (Some(name_index), Some(symbol_type)) = (reader.u32(entry), reader.slice(entry + 4, 1)) else {
            break;
        };
        let Some(section_index) = reader.slice(entry + 5, 1) else {
            break;
        };
        let Some(descriptor) = reader.u16(entry + 6) else {
            break;
        };
        let address = if image.header.is_64 {
            reader.u64(entry + 8)
        } else {
            reader.u32(entry + 8).map(u64::from)
        };
        let Some(address) = address else {
            break;
        };

        let debug = symbol_type[0] & 0xe0 == 0xe0;
        let kind = if debug { "debug" } else { symbol_kind(symbol_type[0]) };
        symbols.push(MachOSymbol {
            name: symbol_name(strings, name_index),
            address,
            kind: kind.to_string(),
            external: symbol_type[0] & 0x01 != 0,
            debug,
            section: (kind == "section").then_some(section_index[0]),
            descriptor,
        });
    }

    Ok(MachOSymbolsReport { truncated: total > symbols.len(), symbols, total, string_table_size: string_size })
}

fn symbol_kind(symbol_type: u8) -> &'static str {
    match symbol_type & 0x0e {
        0x0 => "undefined",
        0x2 => "absolute",
        0xa => "indirect",
        0xc => "prebound",
        0xe => "section",
        _ => "other",
    }
}

fn symbol_name(strings: &[u8], index: u32) -> String {
    let Some(rest) = strings.get(index as usize..) else {
        return String::new();
    };
    let end = rest.iter().position(|byte| *byte == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

/// Bounded listing of function start addresses from `LC_FUNCTION_STARTS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOFunctionStartsReport {
    /// Virtual address of the `__TEXT` segment that the deltas start from.
    pub image_base: u64,
    /// Absolute function start addresses in table order.
    pub addresses: Vec<u64>,
    /// Entries declared by the encoded table.
    pub total: usize,
    /// Whether the limit removed addresses.
    pub truncated: bool,
}

/// Decodes the `LC_FUNCTION_STARTS` ULEB128 delta table of one session.
pub(crate) fn function_starts(session: &BinarySession, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice",
        ));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O function starts require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut table = None;
    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4)) else {
            break;
        };
        if size < 8 {
            break;
        }
        if command == LC_FUNCTION_STARTS && size >= 16 {
            table = match (reader.u32(offset + 8), reader.u32(offset + 12)) {
                (Some(data_offset), Some(data_size)) => Some((data_offset, data_size)),
                _ => None,
            };
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let Some((data_offset, data_size)) = table else {
        return Err(IdaError::unsupported("the Mach-O has no LC_FUNCTION_STARTS command"));
    };
    let data = reader.slice(u64::from(data_offset), u64::from(data_size)).unwrap_or(&[]);
    let image_base = image.segments.iter().find(|segment| segment.name == "__TEXT").map_or(0, |segment| segment.vm_address);

    let limit = limit.unwrap_or(usize::MAX);
    let mut addresses = Vec::new();
    let mut total = 0usize;
    let mut cursor = 0usize;
    let mut current = image_base;
    while cursor < data.len() {
        let mut delta = 0u64;
        let mut shift = 0u32;
        let mut terminated = false;
        loop {
            let Some(byte) = data.get(cursor) else {
                return Ok(MachOFunctionStartsReport { image_base, addresses, total, truncated: true });
            };
            cursor += 1;
            delta |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                terminated = true;
                break;
            }
            shift += 7;
            if shift >= 64 {
                break;
            }
        }
        if !terminated || delta == 0 {
            break;
        }
        current = current.saturating_add(delta);
        total += 1;
        if addresses.len() < limit {
            addresses.push(current);
        }
    }

    let truncated = total > addresses.len();
    Ok(MachOFunctionStartsReport { image_base, addresses, total, truncated })
}

/// One symbol decoded from the dyld export trie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOExport {
    /// Accumulated symbol name.
    pub name: String,
    /// Raw export flags.
    pub flags: u64,
    /// Flag names: `WEAK`, `REEXPORT`, `STUB_AND_RESOLVER`.
    pub flag_names: Vec<String>,
    /// Symbol address for regular exports.
    pub address: Option<u64>,
    /// Library ordinal for reexports or stub address for stub-and-resolver.
    pub other: Option<u64>,
}

/// Bounded listing of symbols from the dyld export trie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOExportsReport {
    /// Whether the image carries an export trie.
    pub present: bool,
    /// Decoded exports in trie order.
    pub exports: Vec<MachOExport>,
    /// Entries found before the storage limit.
    pub total: usize,
    /// Whether the limit or a malformed node cut the walk.
    pub truncated: bool,
}

/// Decodes the dyld export trie of one session.
pub(crate) fn exports(session: &BinarySession) -> Result<MachOExportsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice",
        ));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O exports require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut trie = None;
    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4)) else {
            break;
        };
        if size < 8 {
            break;
        }
        match command {
            LC_DYLD_EXPORTS_TRIE if size >= 16 => {
                trie = match (reader.u32(offset + 8), reader.u32(offset + 12)) {
                    (Some(data_offset), Some(data_size)) => Some((data_offset, data_size)),
                    _ => None,
                };
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY if size >= 48 => {
                trie = match (reader.u32(offset + 40), reader.u32(offset + 44)) {
                    (Some(data_offset), Some(data_size)) if data_size > 0 => Some((data_offset, data_size)),
                    _ => None,
                };
            }
            _ => {}
        }
        if trie.is_some() {
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    if trie.is_none() {
        return Ok(MachOExportsReport { present: false, exports: Vec::new(), total: 0, truncated: false });
    }
    let (data_offset, data_size) = trie.unwrap();
    let data = reader.slice(u64::from(data_offset), u64::from(data_size)).unwrap_or(&[]);

    let mut report = MachOExportsReport { present: true, exports: Vec::new(), total: 0, truncated: false };
    let mut nodes = 0usize;
    let mut stack = vec![(0usize, String::new(), 0usize)];
    while let Some((node, prefix, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_EXPORT_NODES || depth > MAX_EXPORT_DEPTH || report.exports.len() >= MAX_EXPORTS {
            report.truncated = true;
            continue;
        }
        let Some((terminal_size, terminal_start)) = read_uleb(data, node) else {
            report.truncated = true;
            continue;
        };
        let child_start = terminal_start.saturating_add(terminal_size as usize);
        if terminal_size > 0 {
            let Some((flags, next)) = read_uleb(data, terminal_start) else {
                report.truncated = true;
                continue;
            };
            let mut cursor = next;
            let address = if flags & 0x02 != 0 || flags & 0x04 != 0 {
                None
            }
            else {
                match read_uleb(data, cursor) {
                    Some((address, next)) => {
                        cursor = next;
                        Some(address)
                    }
                    None => {
                        report.truncated = true;
                        continue;
                    }
                }
            };
            let other = if flags & 0x02 != 0 || flags & 0x04 != 0 {
                match read_uleb(data, cursor) {
                    Some((other, _)) => Some(other),
                    None => {
                        report.truncated = true;
                        continue;
                    }
                }
            }
            else {
                None
            };
            report.total += 1;
            if report.exports.len() < MAX_EXPORTS {
                report.exports.push(MachOExport {
                    name: prefix.clone(),
                    flags,
                    flag_names: export_flag_names(flags),
                    address,
                    other,
                });
            }
            else {
                report.truncated = true;
            }
        }
        let Some(children) = data.get(child_start) else {
            report.truncated = true;
            continue;
        };
        let mut position = child_start + 1;
        let mut pending = Vec::new();
        for _ in 0..*children {
            let Some(end) = data.get(position..).and_then(|rest| rest.iter().position(|byte| *byte == 0)) else {
                report.truncated = true;
                break;
            };
            let edge = String::from_utf8_lossy(&data[position..position + end]).into_owned();
            position += end + 1;
            let Some((child, next)) = read_uleb(data, position) else {
                report.truncated = true;
                break;
            };
            position = next;
            pending.push((child as usize, format!("{prefix}{edge}"), depth + 1));
        }
        pending.reverse();
        stack.extend(pending);
    }
    report.truncated |= report.total > report.exports.len();
    Ok(report)
}

fn export_flag_names(flags: u64) -> Vec<String> {
    const NAMES: [(u64, &str); 3] = [(0x01, "WEAK"), (0x02, "REEXPORT"), (0x04, "STUB_AND_RESOLVER")];
    NAMES.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, name)| (*name).to_string()).collect()
}

fn read_uleb(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut cursor = offset;
    loop {
        let byte = *data.get(cursor)?;
        cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, cursor));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

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
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice",
        ));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O encryption info requires a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut report = MachOEncryptionReport {
        present: false,
        crypt_offset: 0,
        crypt_size: 0,
        crypt_id: 0,
        encrypted: false,
        is_64: false,
    };

    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4)) else {
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
        report = MachOEncryptionReport {
            present: true,
            crypt_offset,
            crypt_size,
            crypt_id,
            encrypted: crypt_id != 0,
            is_64,
        };
        break;
    }

    Ok(report)
}

/// One import entry of the `LC_DYLD_CHAINED_FIXUPS` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOChainedImport {
    /// Library ordinal; negative values are special ordinals such as `-2` (flat lookup).
    pub lib_ordinal: i32,
    /// Whether the import is weak.
    pub weak_import: bool,
    /// Offset into the symbol string pool.
    pub name_offset: u32,
    /// Resolved symbol name; empty when the pool is compressed or the offset is out of range.
    pub name: String,
    /// Addend for the `ADDEND` / `ADDEND64` import formats.
    pub addend: Option<i64>,
}

/// Decoded `dyld_chained_fixups_header`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOChainedFixupsHeader {
    /// Structural version recorded by the linker; currently `0`.
    pub fixups_version: u32,
    /// Offset of `dyld_chained_starts_in_image`, relative to the start of the chain data.
    pub starts_offset: u32,
    /// Offset of the imports table, relative to the start of the chain data.
    pub imports_offset: u32,
    /// Offset of the symbol string pool, relative to the start of the chain data.
    pub symbols_offset: u32,
    /// Number of declared imports.
    pub imports_count: u32,
    /// Import entry layout: `1` import, `2` import with addend, `3` import with 64-bit addend.
    pub imports_format: u32,
    /// Symbol pool encoding: `0` uncompressed, `1` zlib.
    pub symbols_format: u32,
}

/// Summary of `LC_DYLD_CHAINED_FIXUPS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOChainedFixupsReport {
    /// Whether the image carries an `LC_DYLD_CHAINED_FIXUPS` command.
    pub present: bool,
    /// File offset of the chain data.
    pub data_offset: u32,
    /// Size of the chain data in bytes.
    pub data_size: u32,
    /// Decoded header, when the chain data is long enough.
    pub header: Option<MachOChainedFixupsHeader>,
    /// Imports that survived the limit.
    pub imports: Vec<MachOChainedImport>,
    /// Whether the import limit removed entries.
    pub truncated: bool,
    /// Segment count of `dyld_chained_starts_in_image`, when the starts table parses.
    pub starts_in_image: Option<u32>,
    /// Number of segments with a non-empty chained-start table.
    pub starts_in_segment_count: usize,
}

/// Upper bound on parsed imports, so a corrupt count cannot force a huge allocation.
const MAX_CHAINED_IMPORTS: usize = 512;
const DYLD_CHAINED_IMPORT: u32 = 1;
const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

fn chained_import(reader: &Reader, base: u64, index: usize, format: u32, symbols: &[u8]) -> Option<MachOChainedImport> {
    if format == DYLD_CHAINED_IMPORT_ADDEND64 {
        let entry = base.checked_add((index as u64).checked_mul(16)?)?;
        let raw = reader.u64(entry)?;
        let addend = reader.u64(entry + 8)?;
        let lib_ordinal = (raw & 0xffff) as u16 as i16 as i32;
        let weak_import = (raw >> 16) & 1 != 0;
        let name_offset = (raw >> 32) as u32;
        return Some(MachOChainedImport {
            lib_ordinal,
            weak_import,
            name_offset,
            name: chained_name(symbols, name_offset),
            addend: Some(addend as i64),
        });
    }

    let entry = base.checked_add((index as u64).checked_mul(if format == DYLD_CHAINED_IMPORT_ADDEND { 8 } else { 4 })?)?;
    let raw = reader.u32(entry)?;
    let lib_ordinal = (raw & 0xff) as u8 as i8 as i32;
    let weak_import = (raw >> 8) & 1 != 0;
    let name_offset = raw >> 9;
    let addend = match format {
        DYLD_CHAINED_IMPORT_ADDEND => reader.u32(entry + 4).map(|value| i64::from(value as i32)),
        _ => None,
    };
    if format == DYLD_CHAINED_IMPORT_ADDEND && addend.is_none() {
        return None;
    }
    Some(MachOChainedImport { lib_ordinal, weak_import, name_offset, name: chained_name(symbols, name_offset), addend })
}

fn chained_name(symbols: &[u8], offset: u32) -> String {
    let start = offset as usize;
    let Some(rest) = symbols.get(start..) else {
        return String::new();
    };
    let end = rest.iter().position(|byte| *byte == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

/// Decodes `LC_DYLD_CHAINED_FIXUPS`, its header, imports and starts table.
pub(crate) fn chained_fixups(session: &BinarySession) -> Result<MachOChainedFixupsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice",
        ));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O chained fixups require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut command = None;
    for _ in 0..image.header.command_count {
        let (Some(kind), Some(size)) = (reader.u32(offset), reader.u32(offset + 4)) else {
            break;
        };
        if size < 8 {
            break;
        }
        if kind == LC_DYLD_CHAINED_FIXUPS && size >= 16 {
            command = match (reader.u32(offset + 8), reader.u32(offset + 12)) {
                (Some(data_offset), Some(data_size)) => Some((data_offset, data_size)),
                _ => None,
            };
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let mut report = MachOChainedFixupsReport {
        present: false,
        data_offset: 0,
        data_size: 0,
        header: None,
        imports: Vec::new(),
        truncated: false,
        starts_in_image: None,
        starts_in_segment_count: 0,
    };
    let Some((data_offset, data_size)) = command else {
        return Ok(report);
    };
    report.present = true;
    report.data_offset = data_offset;
    report.data_size = data_size;

    let base = u64::from(data_offset);
    let (Some(fixups_version), Some(starts_offset), Some(imports_offset), Some(symbols_offset), Some(imports_count), Some(imports_format), Some(symbols_format)) =
        (
            reader.u32(base),
            reader.u32(base + 4),
            reader.u32(base + 8),
            reader.u32(base + 12),
            reader.u32(base + 16),
            reader.u32(base + 20),
            reader.u32(base + 24),
        )
    else {
        return Ok(report);
    };
    report.header = Some(MachOChainedFixupsHeader {
        fixups_version,
        starts_offset,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
        symbols_format,
    });

    let symbols = match symbols_format {
        0 => reader.slice(base + u64::from(symbols_offset), u64::from(data_size)).unwrap_or(&[]),
        _ => &[],
    };
    let imports_base = base.saturating_add(u64::from(imports_offset));
    let declared = imports_count as usize;
    let limit = declared.min(MAX_CHAINED_IMPORTS);
    let known_format = matches!(
        imports_format,
        DYLD_CHAINED_IMPORT | DYLD_CHAINED_IMPORT_ADDEND | DYLD_CHAINED_IMPORT_ADDEND64
    );
    if known_format {
        for index in 0..limit {
            match chained_import(&reader, imports_base, index, imports_format, symbols) {
                Some(import) => report.imports.push(import),
                None => break,
            }
        }
    }
    report.truncated = declared > report.imports.len();

    if let Some(seg_count) = reader.u32(base + u64::from(starts_offset)) {
        report.starts_in_image = Some(seg_count);
        let max = (seg_count as usize).min(MAX_CHAINED_IMPORTS);
        let table = base + u64::from(starts_offset) + 4;
        for index in 0..max {
            match reader.u32(table + (index as u64) * 4) {
                Some(value) if value != 0 => report.starts_in_segment_count += 1,
                Some(_) => {}
                None => break,
            }
        }
    }

    Ok(report)
}

/// One architecture slice of a fat/universal Mach-O.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSlice {
    /// Zero-based position in the fat architecture table.
    pub index: usize,
    /// Raw `cputype`.
    pub cpu_type: i32,
    /// Raw `cpusubtype`.
    pub cpu_subtype: i32,
    /// Instruction-set family derived from `cputype`.
    pub architecture: String,
    /// File offset of the slice.
    pub offset: u64,
    /// Size of the slice in bytes.
    pub size: u64,
    /// Alignment expressed as a power of two.
    pub alignment: u32,
    /// Slice header bitness, when the slice starts with a Mach-O magic.
    pub bits: Option<u32>,
}

/// Fat/universal Mach-O architecture table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSlicesReport {
    /// Whether the fat header uses the 64-bit `fat_arch_64` layout.
    pub is_fat64: bool,
    /// Slices in table order.
    pub slices: Vec<MachOSlice>,
}

/// Lists the architecture slices of a fat/universal Mach-O container.
pub(crate) fn slices(session: &BinarySession) -> Result<MachOSlicesReport> {
    let bytes = session.read(0, session.size())?;
    let Some((is_fat64, count)) = fat_header(bytes) else {
        return Err(IdaError::unsupported(
            "the file is not a fat/universal Mach-O container; a thin image is inspected with `macho`",
        ));
    };
    if count > MAX_FAT_SLICES {
        return Err(IdaError::parse(format!(
            "the fat header declares {count} slices, above the {MAX_FAT_SLICES}-entry limit"
        )));
    }

    let entry_size = if is_fat64 { 32 } else { 20 };
    let table_end = 8usize.saturating_add(count.saturating_mul(entry_size));
    let table = bytes
        .get(8..table_end)
        .ok_or_else(|| IdaError::parse("the fat architecture table is truncated"))?;

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let entry = &table[index * entry_size..(index + 1) * entry_size];
        let cpu_type = be_u32(entry, 0)? as i32;
        let cpu_subtype = be_u32(entry, 4)? as i32;
        let (offset, size, alignment) = if is_fat64 {
            (be_u64(entry, 8)?, be_u64(entry, 16)?, be_u32(entry, 24)?)
        } else {
            (u64::from(be_u32(entry, 8)?), u64::from(be_u32(entry, 12)?), be_u32(entry, 16)?)
        };
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or_else(|| IdaError::parse(format!("slice {index} lies outside the file")))?;
        let bits = macho_magic(&bytes[offset as usize..end as usize]).map(|(is_64, _)| if is_64 { 64 } else { 32 });
        entries.push(MachOSlice {
            index,
            cpu_type,
            cpu_subtype,
            architecture: architecture(cpu_type).as_str().to_string(),
            offset,
            size,
            alignment,
            bits,
        });
    }

    Ok(MachOSlicesReport { is_fat64, slices: entries })
}

/// One fat slice written to a caller-chosen path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOSliceExtraction {
    /// Zero-based position in the fat architecture table.
    pub index: usize,
    /// Instruction-set family of the extracted slice.
    pub architecture: String,
    /// Source file offset of the slice.
    pub offset: u64,
    /// Number of bytes written.
    pub size: u64,
    /// Destination path.
    pub output: String,
}

/// Writes one fat slice to `output`.
///
/// The source container is never modified: writing to the source path itself
/// is refused, and every other destination is replaced.
pub(crate) fn extract(session: &BinarySession, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
    if output == session.path() {
        return Err(IdaError::io("refusing to overwrite the source container"));
    }
    let report = slices(session)?;
    let slice = report.slices.get(index).ok_or_else(|| {
        IdaError::range(format!("slice {index} is out of range; the container has {} slice(s)", report.slices.len()))
    })?;
    let bytes = session.read(0, session.size())?;
    let start = usize::try_from(slice.offset).map_err(|_| IdaError::range("the slice offset does not fit this platform"))?;
    let end = start
        .checked_add(usize::try_from(slice.size).map_err(|_| IdaError::range("the slice size does not fit this platform"))?)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| IdaError::parse("the slice lies outside the file"))?;
    std::fs::write(output, &bytes[start..end])
        .map_err(|error| IdaError::io(format!("cannot write {}: {error}", output.display())))?;
    Ok(MachOSliceExtraction {
        index: slice.index,
        architecture: slice.architecture.clone(),
        offset: slice.offset,
        size: slice.size,
        output: output.display().to_string(),
    })
}

fn fat_header(bytes: &[u8]) -> Option<(bool, usize)> {
    let head = bytes.get(0..8)?;
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let is_fat64 = match magic {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        _ => return None,
    };
    Some((is_fat64, u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize))
}

fn be_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("the fat architecture table is truncated"))?;
    Ok(u32::from_be_bytes(raw))
}

fn be_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("the fat architecture table is truncated"))?;
    Ok(u64::from_be_bytes(raw))
}

/// Decodes the Mach-O load commands of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<MachOReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice",
        ));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O inspection requires a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut uuid = None;
    let mut platform = None;
    let mut min_os = None;
    let mut sdk = None;
    let mut dylibs = Vec::new();

    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4))
        else {
            break;
        };
        if size < 8 {
            break;
        }
        match command {
            LC_UUID if size >= 24 => uuid = reader.uuid(offset + 8),
            LC_BUILD_VERSION if size >= 24 => {
                platform = reader.u32(offset + 8).map(platform_name).map(str::to_string);
                min_os = reader.u32(offset + 12).map(render_version);
                sdk = reader.u32(offset + 16).map(render_version);
            }
            LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS | LC_VERSION_MIN_TVOS | LC_VERSION_MIN_WATCHOS if size >= 16 => {
                platform = Some(version_min_platform(command).to_string());
                min_os = reader.u32(offset + 8).map(render_version);
                sdk = reader.u32(offset + 12).map(render_version);
            }
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB
                if size >= 24 =>
            {
                if let Some(dylib) = reader.dylib(offset, size, command) {
                    dylibs.push(dylib);
                }
            }
            _ => {}
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let segments = image
        .segments
        .iter()
        .map(|segment| MachOSegment {
            name: segment.name.clone(),
            vm_address: segment.vm_address,
            vm_size: segment.vm_size,
            file_offset: segment.file_offset,
            file_size: segment.file_size,
            readable: segment.initial_protection & 1 != 0,
            writable: segment.initial_protection & 2 != 0,
            executable: segment.initial_protection & 4 != 0,
        })
        .collect::<Vec<_>>();

    let sections = image
        .sections
        .iter()
        .map(|section| {
            let segment = image.segments.iter().find(|segment| segment.name == section.segment);
            let protection = segment.map(|segment| segment.initial_protection).unwrap_or(0);
            MachOSection {
                segment: section.segment.clone(),
                name: section.name.clone(),
                address: section.address,
                size: section.size,
                file_offset: section.file_offset,
                alignment: section.alignment,
                flags: section.flags,
                readable: protection & 1 != 0,
                writable: protection & 2 != 0,
                executable: protection & 4 != 0,
            }
        })
        .collect::<Vec<_>>();

    let entry_offset = image.entry_offset;
    let entry_address = entry_offset.and_then(|offset| map_file_offset(&image, offset));

    Ok(MachOReport {
        is_64: image.header.is_64,
        endian: match image.header.endian {
            MachOEndian::Little => "little".to_string(),
            MachOEndian::Big => "big".to_string(),
        },
        cpu_type: image.header.cpu_type,
        cpu_subtype: image.header.cpu_subtype,
        architecture: architecture(image.header.cpu_type).as_str().to_string(),
        file_type: image.header.file_type,
        kind: file_type_name(image.header.file_type).to_string(),
        flags: image.header.flags,
        command_count: image.header.command_count,
        size_of_commands: image.header.size_of_commands,
        uuid,
        platform,
        min_os,
        sdk,
        entry_offset,
        entry_address,
        dylibs,
        segments,
        sections,
    })
}

/// Maps a file offset onto a virtual address through one section or segment.
fn map_file_offset(image: &MachOImage, offset: u64) -> Option<u64> {
    for section in &image.sections {
        if section.size > 0 && offset >= section.file_offset && offset < section.file_offset.saturating_add(section.size) {
            return Some(section.address.saturating_add(offset - section.file_offset));
        }
    }
    for segment in &image.segments {
        if segment.file_size > 0 && offset >= segment.file_offset && offset < segment.file_offset.saturating_add(segment.file_size)
        {
            return Some(segment.vm_address.saturating_add(offset - segment.file_offset));
        }
    }
    None
}

fn file_type_name(file_type: u32) -> &'static str {
    match file_type {
        0x1 => "object",
        0x2 => "executable",
        0x3 => "fvmlib",
        0x4 => "core",
        0x5 => "preload",
        0x6 => "dylib",
        0x7 => "dylinker",
        0x8 => "bundle",
        0x9 => "dylib-stub",
        0xa => "dsym",
        0xb => "kext-bundle",
        _ => "other",
    }
}

fn platform_name(platform: u32) -> &'static str {
    match platform {
        1 => "macos",
        2 => "ios",
        3 => "tvos",
        4 => "watchos",
        5 => "bridgeos",
        6 => "mac-catalyst",
        7 => "ios-simulator",
        8 => "tvos-simulator",
        9 => "watchos-simulator",
        10 => "driverkit",
        11 => "visionos",
        12 => "visionos-simulator",
        _ => "unknown",
    }
}

fn version_min_platform(command: u32) -> &'static str {
    match command {
        LC_VERSION_MIN_MACOSX => "macos",
        LC_VERSION_MIN_IPHONEOS => "ios",
        LC_VERSION_MIN_TVOS => "tvos",
        _ => "watchos",
    }
}

/// Renders a packed `x.y.z` version such as `0x000D0100` as `13.1.0`.
fn render_version(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}

fn dylib_kind(command: u32) -> &'static str {
    match command {
        LC_ID_DYLIB => "id",
        LC_LOAD_WEAK_DYLIB => "weak",
        LC_REEXPORT_DYLIB => "reexport",
        LC_LAZY_LOAD_DYLIB => "lazy",
        LC_LOAD_UPWARD_DYLIB => "upward",
        _ => "load",
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    endian: MachOEndian,
}

impl Reader<'_> {
    fn slice(&self, offset: u64, length: u64) -> Option<&[u8]> {
        let end = offset.checked_add(length)?;
        self.bytes.get(offset as usize..end as usize)
    }

    fn u32(&self, offset: u64) -> Option<u32> {
        let raw: [u8; 4] = self.slice(offset, 4)?.try_into().ok()?;
        Some(match self.endian {
            MachOEndian::Little => u32::from_le_bytes(raw),
            MachOEndian::Big => u32::from_be_bytes(raw),
        })
    }

    fn u16(&self, offset: u64) -> Option<u16> {
        let raw: [u8; 2] = self.slice(offset, 2)?.try_into().ok()?;
        Some(match self.endian {
            MachOEndian::Little => u16::from_le_bytes(raw),
            MachOEndian::Big => u16::from_be_bytes(raw),
        })
    }

    fn u64(&self, offset: u64) -> Option<u64> {
        let raw: [u8; 8] = self.slice(offset, 8)?.try_into().ok()?;
        Some(match self.endian {
            MachOEndian::Little => u64::from_le_bytes(raw),
            MachOEndian::Big => u64::from_be_bytes(raw),
        })
    }

    fn uuid(&self, offset: u64) -> Option<String> {
        let raw = self.slice(offset, 16)?;
        let hex = raw.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        Some(format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32]))
    }

    fn dylib(&self, offset: u64, size: u32, command: u32) -> Option<MachODylib> {
        let name_offset = self.u32(offset + 8)?;
        let timestamp = self.u32(offset + 12)?;
        let current = self.u32(offset + 16)?;
        let compatibility = self.u32(offset + 20)?;
        let name_start = offset.checked_add(u64::from(name_offset))?;
        let command_end = offset.checked_add(u64::from(size))?;
        if name_start >= command_end {
            return None;
        }
        let raw = self.slice(name_start, command_end - name_start)?;
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        Some(MachODylib {
            kind: dylib_kind(command).to_string(),
            name: String::from_utf8_lossy(&raw[..end]).into_owned(),
            timestamp,
            current_version: render_version(current),
            compatibility_version: render_version(compatibility),
        })
    }
}
