//! ELF static symbol table listing.
//!
//! The upstream `symbols` view reports the dynamic symbol table; this module
//! walks the section headers to the first `SHT_SYMTAB` (`.symtab`) and reads
//! its entries together with the linked string table, so stripped-of-nothing
//! images expose their local and file-scope symbols too. Each entry carries
//! its name, value, size, `STT_*` type, `STB_*` binding, visibility and the
//! section it belongs to: real indices resolve through the section header
//! table, while `SHN_UNDEF`, `SHN_ABS` and `SHN_COMMON` render as `UND`,
//! `ABS` and `COM`. ELF32 and ELF64 layouts are decoded at the container's
//! own endianness, matching the other ELF modules. A stripped image without
//! `.symtab` reports `present: false`.

use data_binary_inspect::{BinaryFormat, BinarySession};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;

const MAX_STATIC_SYMBOLS: usize = 4_096;
const MAX_SECTIONS: usize = 4_096;

/// One `.symtab` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfStaticSymbol {
    /// Name read from the linked string table, empty for the null symbol.
    pub name: String,
    /// `st_value`.
    pub value: u64,
    /// `st_size`.
    pub size: u64,
    /// `STT_*` name, or `0x<value>` for an unknown type.
    pub symbol_type: String,
    /// `STB_*` name, or `0x<value>` for an unknown binding.
    pub binding: String,
    /// Visibility name, or `0x<value>` for an unknown one.
    pub visibility: String,
    /// Owning section name, or `UND`, `ABS`, `COM` and `sec <index>` fallbacks.
    pub section: String,
}

/// Bounded ELF static symbol listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfStaticSymbolsReport {
    /// Whether the image has a `SHT_SYMTAB` section.
    pub present: bool,
    /// Whether the image uses the ELF64 layout.
    pub is64: bool,
    /// Symbols that survived the limit, in table order.
    pub symbols: Vec<ElfStaticSymbol>,
    /// Entries declared by the section size.
    pub total: usize,
    /// Whether a limit or unreadable data cut the listing.
    pub truncated: bool,
}

/// Lists the `.symtab` symbols of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<ElfStaticSymbolsReport> {
    if session.format() != BinaryFormat::Elf {
        return Err(IdaError::unsupported("ELF static symbols require an ELF container"));
    }
    let bytes = session.read(0, session.size())?;
    let reader = Reader::new(bytes)?;
    let layout = reader.section_layout()?;
    let empty = ElfStaticSymbolsReport {
        present: false,
        is64: reader.is64,
        symbols: Vec::new(),
        total: 0,
        truncated: false,
    };
    let Some((table_offset, entry_size, count, shstrndx)) = layout else {
        return Ok(empty);
    };

    let mut sections: Vec<Section> = Vec::new();
    let mut symtab: Option<Section> = None;
    for index in 0..count {
        let base = table_offset.saturating_add((index as u64).saturating_mul(u64::from(entry_size)));
        let section = reader.section(base)?;
        if section.section_type == SHT_SYMTAB && symtab.is_none() {
            symtab = Some(section.clone());
        }
        sections.push(section);
    }
    let Some(symtab) = symtab else { return Ok(empty) };
    let strtab = sections
        .get(usize::from(symtab.link))
        .filter(|section| section.section_type == SHT_STRTAB)
        .ok_or_else(|| IdaError::parse("the ELF symbol table links to a missing string table"))?;
    let shstrtab = sections.get(usize::from(shstrndx));

    let symbol_size = if reader.is64 { 24 } else { 16 };
    let total = (symtab.size / symbol_size) as usize;
    let mut report = ElfStaticSymbolsReport {
        present: true,
        is64: reader.is64,
        symbols: Vec::new(),
        total,
        truncated: total > MAX_STATIC_SYMBOLS,
    };
    for index in 0..total.min(MAX_STATIC_SYMBOLS) {
        let base = symtab.offset.saturating_add((index as u64).saturating_mul(symbol_size));
        let Ok(entry) = reader.symbol(base) else {
            report.truncated = true;
            break;
        };
        let name = strtab
            .offset
            .checked_add(u64::from(entry.name))
            .filter(|at| *at < strtab.offset.saturating_add(strtab.size))
            .and_then(|at| reader.string(at, strtab.offset.saturating_add(strtab.size)).ok())
            .unwrap_or_default();
        let section = match entry.section {
            SHN_UNDEF => "UND".to_string(),
            SHN_ABS => "ABS".to_string(),
            SHN_COMMON => "COM".to_string(),
            index => match (sections.get(usize::from(index)), shstrtab) {
                (Some(section), Some(names)) => reader
                    .string(
                        names.offset.saturating_add(u64::from(section.name_offset)),
                        names.offset.saturating_add(names.size),
                    )
                    .unwrap_or_else(|_| format!("sec {index}")),
                _ => format!("sec {index}"),
            },
        };
        report.symbols.push(ElfStaticSymbol {
            name,
            value: entry.value,
            size: entry.size,
            symbol_type: symbol_type_name(entry.info & 0xf).to_string(),
            binding: binding_name(entry.info >> 4).to_string(),
            visibility: visibility_name(entry.other & 3).to_string(),
            section,
        });
    }
    Ok(report)
}

#[derive(Clone)]
struct Section {
    name_offset: u32,
    section_type: u32,
    offset: u64,
    size: u64,
    link: u16,
}

struct SymbolEntry {
    name: u32,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    section: u16,
}

fn symbol_type_name(kind: u8) -> &'static str {
    match kind {
        0 => "NOTYPE",
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        6 => "TLS",
        10 => "GNU_IFUNC",
        _ => "",
    }
}

fn binding_name(binding: u8) -> &'static str {
    match binding {
        0 => "LOCAL",
        1 => "GLOBAL",
        2 => "WEAK",
        10 => "GNU_UNIQUE",
        _ => "",
    }
}

fn visibility_name(visibility: u8) -> &'static str {
    match visibility {
        0 => "DEFAULT",
        1 => "INTERNAL",
        2 => "HIDDEN",
        3 => "PROTECTED",
        _ => "",
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    endian: Endian,
    is64: bool,
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
        let is64 = match bytes[4] {
            1 => false,
            2 => true,
            other => return Err(IdaError::parse(format!("unsupported ELF class {other}"))),
        };
        let endian = match bytes[5] {
            1 => Endian::Little,
            2 => Endian::Big,
            other => return Err(IdaError::parse(format!("unsupported ELF data encoding {other}"))),
        };
        Ok(Self { bytes, endian, is64 })
    }

    fn slice(&self, offset: u64, length: u64) -> Result<&'a [u8]> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| IdaError::range("an ELF read range overflows the file"))?;
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

    /// Returns `(section table offset, entry size, entry count, shstrndx)`;
    /// `None` when the image carries no section headers.
    fn section_layout(&self) -> Result<Option<(u64, u16, usize, u16)>> {
        let (table, entry_size, count, shstrndx) = if self.is64 {
            (self.u64(40)?, self.u16(58)?, usize::from(self.u16(60)?), self.u16(62)?)
        }
        else {
            (
                u64::from(self.u32(32)?),
                self.u16(46)?,
                usize::from(self.u16(48)?),
                self.u16(50)?,
            )
        };
        if table == 0 || entry_size == 0 {
            return Ok(None);
        }
        let count = if count == 0 {
            let first = if self.is64 { self.u64(table + 32)? } else { u64::from(self.u32(table + 16)?) };
            first as usize
        }
        else {
            count
        };
        Ok(Some((table, entry_size, count.min(MAX_SECTIONS), shstrndx)))
    }

    fn section(&self, base: u64) -> Result<Section> {
        if self.is64 {
            Ok(Section {
                name_offset: self.u32(base)?,
                section_type: self.u32(base + 4)?,
                offset: self.u64(base + 24)?,
                size: self.u64(base + 32)?,
                link: self.u32(base + 40)? as u16,
            })
        }
        else {
            Ok(Section {
                name_offset: self.u32(base)?,
                section_type: self.u32(base + 4)?,
                offset: u64::from(self.u32(base + 16)?),
                size: u64::from(self.u32(base + 20)?),
                link: self.u32(base + 24)? as u16,
            })
        }
    }

    fn symbol(&self, base: u64) -> Result<SymbolEntry> {
        if self.is64 {
            Ok(SymbolEntry {
                name: self.u32(base)?,
                info: self.slice(base + 4, 1)?[0],
                other: self.slice(base + 5, 1)?[0],
                section: self.u16(base + 6)?,
                value: self.u64(base + 8)?,
                size: self.u64(base + 16)?,
            })
        }
        else {
            Ok(SymbolEntry {
                name: self.u32(base)?,
                value: u64::from(self.u32(base + 4)?),
                size: u64::from(self.u32(base + 8)?),
                info: self.slice(base + 12, 1)?[0],
                other: self.slice(base + 13, 1)?[0],
                section: self.u16(base + 14)?,
            })
        }
    }

    /// Reads one NUL-terminated string starting at `offset`, stopping at `limit`.
    fn string(&self, offset: u64, limit: u64) -> Result<String> {
        let end = limit.min(self.bytes.len() as u64);
        if offset >= end {
            return Err(IdaError::range("an ELF string read starts outside the file"));
        }
        let region = &self.bytes[offset as usize..end as usize];
        let stop = region.iter().position(|byte| *byte == 0).unwrap_or(region.len());
        Ok(String::from_utf8_lossy(&region[..stop]).into_owned())
    }
}
