//! Mach-O image identity: the header summary, segment and section tables and
//! the dylib load commands decoded by `analyze`.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{MachOEndian, MachOImage, architecture, parse_macho};
use serde::{Deserialize, Serialize};

use super::{
    HEADER32_SIZE, HEADER64_SIZE, LC_BUILD_VERSION, LC_ID_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB,
    LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_UUID, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
    util::{Reader, fat_header},
};
use crate::{IdaError, Result};

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

/// Decodes the Mach-O load commands of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<MachOReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
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
        if segment.file_size > 0
            && offset >= segment.file_offset
            && offset < segment.file_offset.saturating_add(segment.file_size)
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
pub(super) fn render_version(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}

pub(super) fn dylib_kind(command: u32) -> &'static str {
    match command {
        LC_ID_DYLIB => "id",
        LC_LOAD_WEAK_DYLIB => "weak",
        LC_REEXPORT_DYLIB => "reexport",
        LC_LAZY_LOAD_DYLIB => "lazy",
        LC_LOAD_UPWARD_DYLIB => "upward",
        _ => "load",
    }
}
