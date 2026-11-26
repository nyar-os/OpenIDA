//! ELF dynamic dependencies.
//!
//! Reads the program headers, then `PT_INTERP` and `PT_DYNAMIC`: the requested
//! `DT_NEEDED` libraries, `DT_SONAME`, `DT_RPATH` / `DT_RUNPATH` and the
//! dynamic string table. Virtual addresses are mapped to file offsets through
//! the `PT_LOAD` segments, so the report still works when section headers were
//! stripped.

use data_binary_inspect::{BinaryFormat, BinarySession};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_RUNPATH: i64 = 29;

const MAX_DYNAMIC_ENTRIES: usize = 4096;
const MAX_NEEDED: usize = 256;
const MAX_SEARCH_PATHS: usize = 64;

/// Dynamic linking facts of one ELF image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfDynamicReport {
    /// Whether a `PT_DYNAMIC` segment exists.
    pub present: bool,
    /// `PT_INTERP` program interpreter, when the segment exists.
    pub interpreter: Option<String>,
    /// `DT_SONAME` of the image, when set.
    pub soname: Option<String>,
    /// `DT_NEEDED` library names, in dynamic entry order.
    pub needed: Vec<String>,
    /// Entries of `DT_RPATH`, split on `:`.
    pub rpath: Vec<String>,
    /// Entries of `DT_RUNPATH`, split on `:`.
    pub runpath: Vec<String>,
    /// `DT_*` entries read before `DT_NULL`.
    pub dynamic_entries: usize,
    /// Whether a limit cut the listing.
    pub truncated: bool,
}

/// Decodes the ELF dynamic dependencies of one session.
pub fn analyze(session: &BinarySession) -> Result<ElfDynamicReport> {
    if session.format() != BinaryFormat::Elf {
        return Err(IdaError::unsupported("ELF dynamic dependencies require an ELF container"));
    }
    let bytes = session.read(0, session.size())?;
    let reader = Reader::new(bytes)?;
    let (program_offset, program_entry_size, program_count) = reader.program_header_layout()?;

    let mut loads: Vec<Load> = Vec::new();
    let mut interpreter: Option<(u64, u64)> = None;
    let mut dynamic: Option<(u64, u64)> = None;
    for index in 0..program_count {
        let base = program_offset.saturating_add((index as u64).saturating_mul(u64::from(program_entry_size)));
        let kind = reader.u32(base)?;
        let (offset, virtual_address, file_size) = reader.program_ranges(base)?;
        match kind {
            PT_LOAD => loads.push(Load { virtual_address, offset, file_size }),
            PT_INTERP => interpreter = Some((offset, file_size)),
            PT_DYNAMIC => dynamic = Some((offset, file_size)),
            _ => {}
        }
    }

    let mut report = ElfDynamicReport {
        present: dynamic.is_some(),
        interpreter: None,
        soname: None,
        needed: Vec::new(),
        rpath: Vec::new(),
        runpath: Vec::new(),
        dynamic_entries: 0,
        truncated: false,
    };
    if let Some((offset, size)) = interpreter {
        report.interpreter = Some(reader.string_at(offset, size)?);
    }
    let Some((offset, size)) = dynamic
    else {
        return Ok(report);
    };

    let mut strtab_address: Option<u64> = None;
    let mut strtab_size: Option<u64> = None;
    let mut needed: Vec<u64> = Vec::new();
    let mut soname: Option<u64> = None;
    let mut rpath: Option<u64> = None;
    let mut runpath: Option<u64> = None;

    let entry_size = reader.dynamic_entry_size();
    let count = (size / entry_size) as usize;
    for index in 0..count.min(MAX_DYNAMIC_ENTRIES) {
        let base = offset.saturating_add((index as u64).saturating_mul(entry_size));
        let (tag, value) = reader.dynamic_entry(base)?;
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_NEEDED => needed.push(value),
            DT_STRTAB => strtab_address = Some(value),
            DT_STRSZ => strtab_size = Some(value),
            DT_SONAME => soname = Some(value),
            DT_RPATH => rpath = Some(value),
            DT_RUNPATH => runpath = Some(value),
            _ => {}
        }
        report.dynamic_entries += 1;
    }
    if count > MAX_DYNAMIC_ENTRIES {
        report.truncated = true;
    }

    let references =
        needed.len() + usize::from(soname.is_some()) + usize::from(rpath.is_some()) + usize::from(runpath.is_some());
    if references == 0 {
        return Ok(report);
    }
    let Some(address) = strtab_address
    else {
        return Err(IdaError::parse("the ELF dynamic segment has no DT_STRTAB"));
    };
    let strtab = map_address(&loads, address)
        .ok_or_else(|| IdaError::parse("the ELF dynamic string table is not mapped by a PT_LOAD segment"))?;
    let limit = strtab_size.unwrap_or(u64::MAX);

    if needed.len() > MAX_NEEDED {
        report.truncated = true;
    }
    for name in needed.iter().take(MAX_NEEDED) {
        report.needed.push(reader.string_in(strtab, limit, *name)?);
    }
    report.soname = soname.map(|name| reader.string_in(strtab, limit, name)).transpose()?;
    report.rpath = split_paths(rpath.map(|name| reader.string_in(strtab, limit, name)).transpose()?);
    report.runpath = split_paths(runpath.map(|name| reader.string_in(strtab, limit, name)).transpose()?);
    if report.rpath.len() > MAX_SEARCH_PATHS || report.runpath.len() > MAX_SEARCH_PATHS {
        report.truncated = true;
        report.rpath.truncate(MAX_SEARCH_PATHS);
        report.runpath.truncate(MAX_SEARCH_PATHS);
    }
    Ok(report)
}

struct Load {
    virtual_address: u64,
    offset: u64,
    file_size: u64,
}

fn map_address(loads: &[Load], address: u64) -> Option<u64> {
    loads.iter().find_map(|load| {
        if load.file_size == 0 {
            return None;
        }
        let end = load.virtual_address.saturating_add(load.file_size);
        if address >= load.virtual_address && address < end {
            Some(load.offset.saturating_add(address - load.virtual_address))
        }
        else {
            None
        }
    })
}

fn split_paths(value: Option<String>) -> Vec<String> {
    value.map(|raw| raw.split(':').filter(|part| !part.is_empty()).map(str::to_string).collect()).unwrap_or_default()
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
        let end = offset.checked_add(length).ok_or_else(|| IdaError::range("an ELF read range overflows the file"))?;
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

    /// Returns `(file offset, virtual address, file size)` of one program header.
    fn program_ranges(&self, base: u64) -> Result<(u64, u64, u64)> {
        if self.is_64 {
            Ok((self.u64(base + 8)?, self.u64(base + 16)?, self.u64(base + 32)?))
        }
        else {
            Ok((u64::from(self.u32(base + 4)?), u64::from(self.u32(base + 8)?), u64::from(self.u32(base + 16)?)))
        }
    }

    fn dynamic_entry_size(&self) -> u64 {
        if self.is_64 { 16 } else { 8 }
    }

    fn dynamic_entry(&self, base: u64) -> Result<(i64, u64)> {
        if self.is_64 {
            let tag = self.u64(base)? as i64;
            Ok((tag, self.u64(base + 8)?))
        }
        else {
            let tag = self.u32(base)? as i32 as i64;
            Ok((tag, u64::from(self.u32(base + 4)?)))
        }
    }

    /// Reads one NUL-terminated string at `offset`, bounded by `length`.
    fn string_at(&self, offset: u64, length: u64) -> Result<String> {
        let region = self.slice(offset, length)?;
        let end = region.iter().position(|byte| *byte == 0).unwrap_or(region.len());
        Ok(String::from_utf8_lossy(&region[..end]).into_owned())
    }

    /// Reads a NUL-terminated string at `base + index`, bounded by `length`.
    fn string_in(&self, base: u64, length: u64, index: u64) -> Result<String> {
        if index >= length {
            return Err(IdaError::parse("an ELF dynamic string offset lies outside DT_STRSZ"));
        }
        self.string_at(base.saturating_add(index), length.saturating_sub(index))
    }
}
