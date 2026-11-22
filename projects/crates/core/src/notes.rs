//! ELF note decoding.
//!
//! GNU build ids, ABI tags and GNU properties live in `PT_NOTE` segments, or in
//! `SHT_NOTE` sections when the program headers were stripped. The pinned
//! inspection engine does not expose notes, so this module walks the note
//! records itself. A malformed record stops the listing and sets `truncated`
//! instead of failing the whole report.

use data_binary_inspect::{BinaryFormat, BinarySession};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const PT_NOTE: u32 = 4;
const SHT_NOTE: u32 = 7;

const NT_GNU_ABI_TAG: u64 = 1;
const NT_GNU_BUILD_ID: u64 = 3;
const NT_GNU_GOLD_VERSION: u64 = 4;
const NT_GNU_PROPERTY_TYPE_0: u64 = 5;

const NOTE_HEADER_SIZE: u64 = 12;
const MAX_REGIONS: usize = 64;
const MAX_NOTES: usize = 128;
const MAX_PROPERTIES: usize = 32;
const MAX_DESCRIPTION_PREVIEW: usize = 32;
const MAX_BUILD_ID: usize = 64;

/// Decoded `NT_GNU_ABI_TAG` description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfAbiTag {
    /// Target operating system recorded by the tag.
    pub os: String,
    /// Major kernel version.
    pub major: u32,
    /// Minor kernel version.
    pub minor: u32,
    /// Sub-minor kernel version.
    pub subminor: u32,
}

/// One entry of a `NT_GNU_PROPERTY_TYPE_0` note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfGnuProperty {
    /// Stable property name, or `0x<type>` for an unknown value.
    pub property_type: String,
    /// Declared size of this property's data.
    pub data_size: u32,
    /// Property data as lowercase hex, bounded by the preview limit.
    pub data: String,
}

/// One note record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfNote {
    /// Note owner without its NUL terminator, such as `GNU`.
    pub owner: String,
    /// Stable note type name, or `type <n>` for an unknown value.
    pub note_type: String,
    /// Declared description size in bytes.
    pub description_size: u32,
    /// Decoded description: build id hex, ABI tag version, property count or a
    /// bounded hex preview.
    pub description: String,
}

/// ELF note facts of one image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfNotesReport {
    /// Whether at least one note region exists.
    pub present: bool,
    /// Where the notes were read from: `segments` or `sections`.
    pub source: Option<String>,
    /// `NT_GNU_BUILD_ID` as lowercase hex, when present.
    pub build_id: Option<String>,
    /// Decoded `NT_GNU_ABI_TAG`, when present.
    pub abi_tag: Option<ElfAbiTag>,
    /// Entries of the first `NT_GNU_PROPERTY_TYPE_0` note.
    pub properties: Vec<ElfGnuProperty>,
    /// Notes that survived the listing limit, in file order.
    pub notes: Vec<ElfNote>,
    /// Number of notes read before the limit was applied.
    pub total: usize,
    /// Whether a limit or a malformed record cut the listing.
    pub truncated: bool,
}

impl ElfNotesReport {
    fn empty() -> Self {
        Self {
            present: false,
            source: None,
            build_id: None,
            abi_tag: None,
            properties: Vec::new(),
            notes: Vec::new(),
            total: 0,
            truncated: false,
        }
    }
}

/// Decodes the ELF notes of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<ElfNotesReport> {
    if session.format() != BinaryFormat::Elf {
        return Err(IdaError::unsupported("ELF notes require an ELF container"));
    }
    let bytes = session.read(0, session.size())?;
    let reader = Reader::new(bytes)?;

    let mut regions = reader.note_segments()?;
    let mut source = "segments";
    if regions.is_empty() {
        regions = reader.note_sections()?;
        source = "sections";
    }
    if regions.is_empty() {
        return Ok(ElfNotesReport::empty());
    }

    let mut report = ElfNotesReport { present: true, source: Some(source.to_string()), ..ElfNotesReport::empty() };
    for (offset, size) in regions.into_iter().take(MAX_REGIONS) {
        parse_region(&reader, offset, size, &mut report);
    }
    Ok(report)
}

fn parse_region(reader: &Reader<'_>, offset: u64, size: u64, report: &mut ElfNotesReport) {
    let end = offset.saturating_add(size);
    let mut at = offset;
    while at.saturating_add(NOTE_HEADER_SIZE) <= end {
        let (Ok(namesz), Ok(descsz), Ok(kind)) = (reader.u32(at), reader.u32(at + 4), reader.u32(at + 8)) else {
            report.truncated = true;
            return;
        };
        if namesz == 0 && descsz == 0 && kind == 0 {
            // Zero padding after the last note is not a note.
            break;
        }
        let name_start = at + NOTE_HEADER_SIZE;
        let name_end = name_start.saturating_add(u64::from(namesz));
        let desc_start = align_u64(name_end, 4);
        let desc_end = desc_start.saturating_add(u64::from(descsz));
        let next = align_u64(desc_end, 4);
        if desc_end > end || next > end {
            report.truncated = true;
            return;
        }
        let (Ok(name), Ok(description)) = (reader.slice(name_start, u64::from(namesz)), reader.slice(desc_start, u64::from(descsz))) else {
            report.truncated = true;
            return;
        };

        report.total += 1;
        let owner = String::from_utf8_lossy(name).trim_end_matches('\u{0}').to_string();
        let note_type = note_type_name(&owner, kind as u64);
        let rendered = describe(&owner, kind as u64, description, report);

        if report.notes.len() < MAX_NOTES {
            report.notes.push(ElfNote {
                owner,
                note_type,
                description_size: descsz,
                description: rendered,
            });
        }
        else {
            report.truncated = true;
        }
        at = next;
    }
    if at < end {
        // A tail shorter than one note header is padding when it is all zero,
        // and a malformed region otherwise.
        let padding = reader.slice(at, end - at).is_ok_and(|tail| tail.iter().all(|byte| *byte == 0));
        if !padding {
            report.truncated = true;
        }
    }
}

fn describe(owner: &str, kind: u64, description: &[u8], report: &mut ElfNotesReport) -> String {
    if owner != "GNU" {
        return hex_preview(description);
    }
    match kind {
        NT_GNU_BUILD_ID => {
            let build_id = hex_preview_bounded(description, MAX_BUILD_ID);
            if report.build_id.is_none() {
                report.build_id = Some(build_id.clone());
            }
            build_id
        }
        NT_GNU_ABI_TAG => {
            if description.len() < 16 {
                return hex_preview(description);
            }
            let os = u32::from_le_bytes([description[0], description[1], description[2], description[3]]);
            let major = u32::from_le_bytes([description[4], description[5], description[6], description[7]]);
            let minor = u32::from_le_bytes([description[8], description[9], description[10], description[11]]);
            let subminor = u32::from_le_bytes([description[12], description[13], description[14], description[15]]);
            let tag = ElfAbiTag { os: abi_os_name(os), major, minor, subminor };
            let rendered = format!("{} {}.{}.{}", tag.os, tag.major, tag.minor, tag.subminor);
            let _ = report.abi_tag.insert(tag);
            rendered
        }
        NT_GNU_PROPERTY_TYPE_0 => {
            let count = read_properties(description, report);
            format!("{count} property entr{}", if count == 1 { "y" } else { "ies" })
        }
        NT_GNU_GOLD_VERSION => {
            let end = description.iter().position(|byte| *byte == 0).unwrap_or(description.len());
            String::from_utf8_lossy(&description[..end]).into_owned()
        }
        _ => hex_preview(description),
    }
}

fn read_properties(data: &[u8], report: &mut ElfNotesReport) -> usize {
    let mut at = 0;
    let mut count = 0;
    while at + 8 <= data.len() {
        let property_type = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        let size = u32::from_le_bytes([data[at + 4], data[at + 5], data[at + 6], data[at + 7]]);
        let start = at + 8;
        let end = start.saturating_add(size as usize);
        if end > data.len() {
            report.truncated = true;
            break;
        }
        count += 1;
        if report.properties.len() < MAX_PROPERTIES {
            report.properties.push(ElfGnuProperty {
                property_type: property_type_name(property_type),
                data_size: size,
                data: hex_preview(&data[start..end]),
            });
        }
        else {
            report.truncated = true;
        }
        at = align_u64(end as u64, 8) as usize;
    }
    if at < data.len() {
        report.truncated = true;
    }
    count
}

fn note_type_name(owner: &str, kind: u64) -> String {
    if owner == "GNU" {
        match kind {
            NT_GNU_ABI_TAG => return "NT_GNU_ABI_TAG".to_string(),
            NT_GNU_BUILD_ID => return "NT_GNU_BUILD_ID".to_string(),
            NT_GNU_GOLD_VERSION => return "NT_GNU_GOLD_VERSION".to_string(),
            NT_GNU_PROPERTY_TYPE_0 => return "NT_GNU_PROPERTY_TYPE_0".to_string(),
            other => return format!("type {other}"),
        }
    }
    format!("type {kind}")
}

fn property_type_name(value: u32) -> String {
    match value {
        1 => "STACK_SIZE".to_string(),
        2 => "NO_COPY_ON_PROTECTED".to_string(),
        0xc000_0000 => "AARCH64_FEATURE_1_AND".to_string(),
        0xc000_0001 => "AARCH64_PAUTH_1_AND".to_string(),
        0xc000_0002 => "X86_FEATURE_1_AND".to_string(),
        0xc000_8001 => "X86_FEATURE_2_NEEDED".to_string(),
        0xc000_8002 => "X86_ISA_1_NEEDED".to_string(),
        0xc001_0001 => "X86_FEATURE_2_USED".to_string(),
        0xc001_0002 => "X86_ISA_1_USED".to_string(),
        other => format!("0x{other:08x}"),
    }
}

fn abi_os_name(os: u32) -> String {
    match os {
        0 => "Linux".to_string(),
        1 => "Hurd".to_string(),
        2 => "Solaris".to_string(),
        3 => "FreeBSD".to_string(),
        other => format!("#{other}"),
    }
}

fn hex_preview(data: &[u8]) -> String {
    hex_preview_bounded(data, MAX_DESCRIPTION_PREVIEW)
}

fn hex_preview_bounded(data: &[u8], limit: usize) -> String {
    let shown = data.len().min(limit);
    let mut text = String::with_capacity(shown * 2 + 3);
    for byte in &data[..shown] {
        text.push_str(&format!("{byte:02x}"));
    }
    if data.len() > limit {
        text.push_str("...");
    }
    text
}

fn align_u64(value: u64, alignment: u64) -> u64 {
    value.saturating_add(alignment - 1) & !(alignment - 1)
}

struct Reader<'a> {
    bytes: &'a [u8],
    endian: Endian,
    is_64: bool,
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 16 || &bytes[0..4] != b"\x7fELF" {
            return Err(IdaError::parse("the file does not start with an ELF header"));
        }
        let is_64 = match bytes[4] {
            1 => false,
            2 => true,
            other => return Err(IdaError::parse(format!("unsupported ELF class {other}"))),
        };
        let endian = match bytes[5] {
            1 => Endian::Little,
            2 => Endian::Big,
            other => return Err(IdaError::parse(format!("unsupported ELF data encoding {other}"))),
        };
        Ok(Self { bytes, endian, is_64 })
    }

    fn slice(&self, offset: u64, length: u64) -> Result<&'a [u8]> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| IdaError::range("an ELF note range overflows the file"))?;
        self.bytes
            .get(offset as usize..end as usize)
            .ok_or_else(|| IdaError::range(format!("bytes 0x{offset:x}+{length} lie outside the file")))
    }

    fn u16(&self, offset: u64) -> Result<u16> {
        let raw = self.slice(offset, 2)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes([raw[0], raw[1]]),
            Endian::Big => u16::from_be_bytes([raw[0], raw[1]]),
        })
    }

    fn u32(&self, offset: u64) -> Result<u32> {
        let raw = self.slice(offset, 4)?;
        let raw = [raw[0], raw[1], raw[2], raw[3]];
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(raw),
            Endian::Big => u32::from_be_bytes(raw),
        })
    }

    fn u64(&self, offset: u64) -> Result<u64> {
        let raw = self.slice(offset, 8)?;
        let raw = [raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]];
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(raw),
            Endian::Big => u64::from_be_bytes(raw),
        })
    }

    fn program_header_layout(&self) -> Result<(u64, u16, usize)> {
        if self.is_64 {
            Ok((self.u64(32)?, self.u16(54)?, usize::from(self.u16(56)?)))
        }
        else {
            Ok((u64::from(self.u32(28)?), self.u16(42)?, usize::from(self.u16(44)?)))
        }
    }

    fn section_header_layout(&self) -> Result<(u64, u16, usize)> {
        if self.is_64 {
            Ok((self.u64(40)?, self.u16(58)?, usize::from(self.u16(60)?)))
        }
        else {
            Ok((u64::from(self.u32(32)?), self.u16(46)?, usize::from(self.u16(48)?)))
        }
    }

    /// Returns `(file offset, file size)` of one program header.
    fn program_ranges(&self, base: u64) -> Result<(u64, u64)> {
        if self.is_64 {
            Ok((self.u64(base + 8)?, self.u64(base + 32)?))
        }
        else {
            Ok((u64::from(self.u32(base + 4)?), u64::from(self.u32(base + 16)?)))
        }
    }

    /// Returns `(type, file offset, file size)` of one section header.
    fn section_ranges(&self, base: u64) -> Result<(u32, u64, u64)> {
        if self.is_64 {
            Ok((self.u32(base + 4)?, self.u64(base + 24)?, self.u64(base + 32)?))
        }
        else {
            Ok((self.u32(base + 4)?, u64::from(self.u32(base + 16)?), u64::from(self.u32(base + 20)?)))
        }
    }

    fn note_segments(&self) -> Result<Vec<(u64, u64)>> {
        let (offset, entry_size, count) = self.program_header_layout()?;
        if offset == 0 || entry_size == 0 {
            return Ok(Vec::new());
        }
        let mut regions = Vec::new();
        for index in 0..count.min(MAX_REGIONS) {
            let base = offset.saturating_add((index as u64).saturating_mul(u64::from(entry_size)));
            let Ok(kind) = self.u32(base) else {
                break;
            };
            if kind != PT_NOTE {
                continue;
            }
            let Ok((file_offset, file_size)) = self.program_ranges(base) else {
                break;
            };
            if file_size > 0 {
                regions.push((file_offset, file_size));
            }
        }
        Ok(regions)
    }

    fn note_sections(&self) -> Result<Vec<(u64, u64)>> {
        let (offset, entry_size, count) = self.section_header_layout()?;
        if offset == 0 || entry_size == 0 {
            return Ok(Vec::new());
        }
        let mut regions = Vec::new();
        for index in 0..count.min(MAX_REGIONS) {
            let base = offset.saturating_add((index as u64).saturating_mul(u64::from(entry_size)));
            let Ok((kind, file_offset, file_size)) = self.section_ranges(base) else {
                break;
            };
            if kind != SHT_NOTE || file_size == 0 {
                continue;
            }
            regions.push((file_offset, file_size));
        }
        Ok(regions)
    }
}
