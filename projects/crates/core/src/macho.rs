//! Mach-O load commands, segments, sections, dylibs and image identity.
//!
//! The header, segment and section tables come from `data-binary-mach-o`.
//! The pinned release does not expose `LC_UUID`, `LC_BUILD_VERSION`,
//! `LC_VERSION_MIN_*`, the dylib commands or `LC_SYMTAB`, so those are decoded
//! here from the same load-command stream. Dyld bindings stay out of scope.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{MachOEndian, MachOImage, architecture, macho_magic, parse_macho};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_DYLIB: u32 = 0x0c;
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
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O symbols require a Mach-O container"));
    }
    let bytes = session.read(0, session.size())?;
    if macho_magic(bytes).is_none() {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; select a slice before inspecting its symbols",
        ));
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

/// Decodes the Mach-O load commands of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<MachOReport> {
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O inspection requires a Mach-O container"));
    }
    let bytes = session.read(0, session.size())?;
    if macho_magic(bytes).is_none() {
        return Err(IdaError::unsupported(
            "the Mach-O is a fat/universal container; select a slice before inspecting it",
        ));
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
