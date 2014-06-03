//! ELF program header decoding.
//!
//! The inspection engine exposes sections but not the segment table, so this
//! module walks `e_phoff` itself. Segments describe how the loader maps the file
//! (`PT_LOAD`), where the interpreter and dynamic tables live and which GNU
//! hardening segments are present. A malformed entry stops the listing instead
//! of failing the report.

use data_binary_inspect::{BinaryFormat, BinarySession};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const MAX_SEGMENTS: usize = 128;

/// One program header entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfSegment {
    /// Index in the program header table.
    pub index: usize,
    /// Stable segment type name, or `0x<type>` for an unknown value.
    pub segment_type: String,
    /// Raw `p_type`.
    pub type_value: u32,
    /// File offset of the segment payload.
    pub offset: u64,
    /// Segment virtual address.
    pub virtual_address: u64,
    /// Segment physical address.
    pub physical_address: u64,
    /// Bytes stored in the file.
    pub file_size: u64,
    /// Bytes occupied in memory.
    pub memory_size: u64,
    /// Raw `p_flags`.
    pub flags: u32,
    /// `p_flags` rendered as permissions, such as `R-X`.
    pub flag_text: String,
    /// Alignment requirement.
    pub alignment: u64,
}

/// ELF program header table summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfSegmentsReport {
    /// Whether the table contains at least one entry.
    pub present: bool,
    /// Whether the image uses the 64-bit program header layout.
    pub is64: bool,
    /// Entries that survived the limit, in table order.
    pub segments: Vec<ElfSegment>,
    /// Number of entries declared by the header.
    pub total: usize,
    /// Whether a limit or a malformed entry cut the listing.
    pub truncated: bool,
}

/// Decodes the ELF program header table of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<ElfSegmentsReport> {
    if session.format() != BinaryFormat::Elf {
        return Err(IdaError::unsupported("ELF program headers require an ELF container"));
    }
    let bytes = session.read(0, session.size())?;
    let reader = Reader::new(bytes)?;
    let (offset, entry_size, count) = reader.program_header_layout()?;
    let mut report = ElfSegmentsReport {
        present: count > 0 && offset != 0 && entry_size != 0,
        is64: reader.is_64,
        segments: Vec::new(),
        total: count,
        truncated: false,
    };
    if !report.present {
        return Ok(report);
    }

    for index in 0..count.min(MAX_SEGMENTS) {
        let base = offset.saturating_add((index as u64).saturating_mul(u64::from(entry_size)));
        let Ok(segment) = reader.segment(base) else {
            report.truncated = true;
            break;
        };
        report.segments.push(ElfSegment {
            index,
            segment_type: segment_type_name(segment.kind),
            type_value: segment.kind,
            offset: segment.offset,
            virtual_address: segment.virtual_address,
            physical_address: segment.physical_address,
            file_size: segment.file_size,
            memory_size: segment.memory_size,
            flags: segment.flags,
            flag_text: flag_text(segment.flags),
            alignment: segment.alignment,
        });
    }
    if report.segments.len() < report.total {
        report.truncated = true;
    }
    Ok(report)
}

fn segment_type_name(kind: u32) -> String {
    match kind {
        0 => "PT_NULL".to_string(),
        1 => "PT_LOAD".to_string(),
        2 => "PT_DYNAMIC".to_string(),
        3 => "PT_INTERP".to_string(),
        4 => "PT_NOTE".to_string(),
        5 => "PT_SHLIB".to_string(),
        6 => "PT_PHDR".to_string(),
        7 => "PT_TLS".to_string(),
        0x6474_e550 => "PT_GNU_EH_FRAME".to_string(),
        0x6474_e551 => "PT_GNU_STACK".to_string(),
        0x6474_e552 => "PT_GNU_RELRO".to_string(),
        0x6474_e553 => "PT_GNU_PROPERTY".to_string(),
        other => format!("0x{other}"),
    }
}

fn flag_text(flags: u32) -> String {
    let mut text = String::with_capacity(3);
    if flags & 4 != 0 {
        text.push('R');
    }
    if flags & 2 != 0 {
        text.push('W');
    }
    if flags & 1 != 0 {
        text.push('X');
    }
    text
}

struct Segment {
    kind: u32,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_size: u64,
    memory_size: u64,
    flags: u32,
    alignment: u64,
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
            .ok_or_else(|| IdaError::range("an ELF program header range overflows the file"))?;
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

    fn segment(&self, base: u64) -> Result<Segment> {
        if self.is_64 {
            Ok(Segment {
                kind: self.u32(base)?,
                flags: self.u32(base + 4)?,
                offset: self.u64(base + 8)?,
                virtual_address: self.u64(base + 16)?,
                physical_address: self.u64(base + 24)?,
                file_size: self.u64(base + 32)?,
                memory_size: self.u64(base + 40)?,
                alignment: self.u64(base + 48)?,
            })
        }
        else {
            Ok(Segment {
                kind: self.u32(base)?,
                offset: u64::from(self.u32(base + 4)?),
                virtual_address: u64::from(self.u32(base + 8)?),
                physical_address: u64::from(self.u32(base + 12)?),
                file_size: u64::from(self.u32(base + 16)?),
                memory_size: u64::from(self.u32(base + 20)?),
                flags: self.u32(base + 24)?,
                alignment: u64::from(self.u32(base + 28)?),
            })
        }
    }
}
