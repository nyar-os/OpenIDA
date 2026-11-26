//! Mach-O image identity projection.
//!
//! The header, segment/section tables, dylib commands, `LC_UUID`,
//! `LC_BUILD_VERSION`/`LC_VERSION_MIN_*` and `LC_MAIN` are owned by
//! `data-binary-mach-o` (`parse_macho`). This module only maps the owner types
//! into the product report shape.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{
    MachBuildInfo, MachOEndian, MachOImage, architecture, fat_magic, parse_macho, render_version,
};
use serde::{Deserialize, Serialize};

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
pub fn analyze(session: &BinarySession) -> Result<MachOReport> {
    let bytes = session.read(0, session.size())?;
    if fat_magic(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O inspection requires a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;

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
            let protection = image
                .segments
                .iter()
                .find(|segment| segment.name == section.segment)
                .map_or(0, |segment| segment.initial_protection);
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

    let dylibs = image
        .dylibs
        .iter()
        .map(|dylib| MachODylib {
            kind: dylib.kind.as_str().to_string(),
            name: dylib.name.clone(),
            timestamp: dylib.timestamp,
            current_version: render_version(dylib.current_version),
            compatibility_version: render_version(dylib.compatibility_version),
        })
        .collect::<Vec<_>>();

    let build = image.build.as_ref();
    let entry_offset = image.entry_offset;

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
        uuid: image.uuid_string(),
        platform: build.map(|build| build.platform.as_str().to_string()),
        min_os: build.map(MachBuildInfo::min_os_version),
        sdk: build.map(MachBuildInfo::sdk_version),
        entry_offset,
        entry_address: entry_offset.and_then(|offset| map_file_offset(&image, offset)),
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
