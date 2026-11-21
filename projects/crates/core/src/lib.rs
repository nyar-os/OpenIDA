//! Minimal binary inspection kernel for OpenIDA.
//!
//! The kernel owns the parts of binary analysis that can be stated precisely:
//! container detection, header and section decoding, string extraction, hex
//! dumps, byte reads, RVA mapping and atomic patching. Disassembly,
//! decompilation, debugging and symbol resolution are declared as unsupported
//! instead of being approximated.

#![deny(missing_docs)]

mod bytes;
mod elf;
mod error;
mod format;
mod macho;
mod pe;
mod section;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::json;

pub use error::{IdaError, Result};
pub use format::{Architecture, BinaryFormat};
pub use section::Section;

/// One printable ASCII run found in a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StringHit {
    /// File offset of the first byte.
    pub offset: u64,
    /// Number of bytes in the run.
    pub length: u64,
    /// The run as UTF-8 text (ASCII only, so this is lossless).
    pub value: String,
}

/// Header summary returned for any open file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryInfo {
    /// Absolute or caller-supplied path.
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// Detected container: `pe`, `elf`, `macho` or `unknown`.
    pub format: String,
    /// Detected architecture: `x86`, `x64`, `arm64` or `unknown`.
    pub architecture: String,
    /// XXH64 hash of the whole file, as 16 hex digits.
    pub hash: String,
    /// Container header flavour, such as `PE32+`, `ELF64` or `Mach-O 64`.
    pub magic: Option<String>,
    /// Byte order reported by the container, when it has one.
    pub endian: Option<String>,
    /// Absolute entry point, when the container reports one.
    pub entry: Option<u64>,
    /// Entry point relative to the image base (PE only).
    pub entry_rva: Option<u64>,
    /// Image base (PE only).
    pub image_base: Option<u64>,
    /// Number of section table entries.
    pub section_count: u64,
    /// Mach-O CPU type.
    pub cpu_type: Option<i64>,
    /// Mach-O file type.
    pub file_type: Option<u32>,
    /// Mach-O load-command count.
    pub command_count: Option<u32>,
}

/// Result of one atomic patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchReport {
    /// File that received the patched bytes.
    pub path: String,
    /// Offset that was changed.
    pub offset: u64,
    /// Number of bytes written.
    pub length: u64,
    /// XXH64 hash of the file before patching.
    pub before_hash: String,
    /// XXH64 hash of the file after patching.
    pub after_hash: String,
}

/// One opened file with its bytes and detected container.
#[derive(Debug, Clone)]
pub struct BinaryView {
    path: PathBuf,
    bytes: Vec<u8>,
    format: BinaryFormat,
}

impl BinaryView {
    /// Opens a file from disk and detects its container.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let bytes = fs::read(&path).map_err(|error| IdaError::io(format!("cannot read {}: {error}", path.display())))?;
        let format = format::detect(&bytes);
        Ok(Self { path, bytes, format })
    }

    /// Builds a view over bytes already in memory.
    pub fn from_bytes(path: impl Into<PathBuf>, bytes: Vec<u8>) -> Self {
        let format = format::detect(&bytes);
        Self { path: path.into(), bytes, format }
    }

    /// Path this view was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Detected container.
    pub fn format(&self) -> BinaryFormat {
        self.format
    }

    /// Detected architecture, or `unknown` when the header is absent.
    pub fn architecture(&self) -> Architecture {
        match self.format {
            BinaryFormat::Pe => pe::parse(&self.bytes).map(|header| pe::architecture(header.machine)),
            BinaryFormat::Elf => elf::parse(&self.bytes).map(|header| elf::architecture(header.machine)),
            BinaryFormat::MachO => macho::parse(&self.bytes).map(|header| macho::architecture(header.cpu_type)),
            BinaryFormat::Unknown => Ok(Architecture::Unknown),
        }
        .unwrap_or(Architecture::Unknown)
    }

    /// Reports the container, architecture, hash and header fields.
    pub fn info(&self) -> Result<BinaryInfo> {
        let mut info = BinaryInfo {
            path: self.path.display().to_string(),
            size: self.size(),
            format: self.format.as_str().to_string(),
            architecture: self.architecture().as_str().to_string(),
            hash: content_hash(&self.bytes),
            magic: None,
            endian: None,
            entry: None,
            entry_rva: None,
            image_base: None,
            section_count: 0,
            cpu_type: None,
            file_type: None,
            command_count: None,
        };

        match self.format {
            BinaryFormat::Pe => {
                let header = pe::parse(&self.bytes)?;
                info.magic = Some(header.magic.to_string());
                info.endian = Some("little".to_string());
                info.entry = Some(header.image_base.saturating_add(header.entry_rva as u64));
                info.entry_rva = Some(header.entry_rva as u64);
                info.image_base = Some(header.image_base);
                info.section_count = header.section_count as u64;
            }
            BinaryFormat::Elf => {
                let header = elf::parse(&self.bytes)?;
                info.magic = Some(header.class.to_string());
                info.endian = Some("little".to_string());
                info.entry = Some(header.entry);
                info.section_count = header.sections.len() as u64;
            }
            BinaryFormat::MachO => {
                let header = macho::parse(&self.bytes)?;
                info.magic = Some(header.magic.to_string());
                info.endian = Some(header.endian.to_string());
                info.cpu_type = Some(header.cpu_type as i64);
                info.file_type = Some(header.file_type);
                info.command_count = Some(header.command_count);
            }
            BinaryFormat::Unknown => {}
        }
        Ok(info)
    }

    /// Decodes the section table. Mach-O and unknown files are unsupported.
    pub fn sections(&self) -> Result<Vec<Section>> {
        match self.format {
            BinaryFormat::Pe => pe::parse(&self.bytes).map(|header| header.sections),
            BinaryFormat::Elf => elf::parse(&self.bytes).map(|header| header.sections),
            BinaryFormat::MachO => Err(IdaError::unsupported("Mach-O section tables are not implemented")),
            BinaryFormat::Unknown => Err(IdaError::unsupported("sections are only available for PE and ELF files")),
        }
    }

    /// Extracts printable ASCII runs of at least `min_len` bytes.
    pub fn strings(&self, min_len: usize) -> Vec<StringHit> {
        let minimum = min_len.max(1);
        let mut hits = Vec::new();
        let mut start: Option<usize> = None;
        for (index, byte) in self.bytes.iter().copied().enumerate() {
            let printable = (0x20..=0x7e).contains(&byte);
            match (printable, start) {
                (true, None) => start = Some(index),
                (false, Some(begin)) => {
                    if index - begin >= minimum {
                        push_hit(&mut hits, begin, &self.bytes[begin..index]);
                    }
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(begin) = start
            && self.bytes.len() - begin >= minimum
        {
            push_hit(&mut hits, begin, &self.bytes[begin..]);
        }
        hits
    }

    /// Renders a canonical `offset  bytes  |ascii|` dump.
    pub fn hexdump(&self, offset: u64, length: u64) -> Result<String> {
        let data = self.read_bytes(offset, length)?;
        let mut output = String::new();
        for (row, chunk) in data.chunks(16).enumerate() {
            let row_offset = offset + row as u64 * 16;
            output.push_str(&format!("{row_offset:08x}  "));
            for index in 0..16 {
                if index == 8 {
                    output.push(' ');
                }
                match chunk.get(index) {
                    Some(byte) => output.push_str(&format!("{byte:02x} ")),
                    None => output.push_str("   "),
                }
            }
            output.push_str(" |");
            for byte in chunk {
                output.push(if (0x20..=0x7e).contains(byte) { *byte as char } else { '.' });
            }
            output.push_str("|\n");
        }
        Ok(output)
    }

    /// Reads a byte range from the file.
    pub fn read_bytes(&self, offset: u64, length: u64) -> Result<&[u8]> {
        let end = offset.checked_add(length).ok_or_else(|| IdaError::range(format!("read at 0x{offset:x} overflows")))?;
        if end > self.bytes.len() as u64 {
            return Err(IdaError::range(format!(
                "read of {length} byte(s) at 0x{offset:x} is outside the file (size {})",
                self.bytes.len()
            )));
        }
        Ok(&self.bytes[offset as usize..end as usize])
    }

    /// Writes patched bytes back to the opened file, atomically.
    pub fn patch(&mut self, offset: u64, data: &[u8]) -> Result<PatchReport> {
        self.patch_to(offset, data, None)
    }

    /// Writes a patched copy to `output`, or back to the source when omitted.
    ///
    /// The range is validated before anything is written. The target is written
    /// to a sibling temporary file and renamed into place, and the report keeps
    /// the whole-file hash before and after the change.
    pub fn patch_to(&mut self, offset: u64, data: &[u8], output: Option<&Path>) -> Result<PatchReport> {
        let end =
            offset.checked_add(data.len() as u64).ok_or_else(|| IdaError::range(format!("patch at 0x{offset:x} overflows")))?;
        if end > self.bytes.len() as u64 {
            return Err(IdaError::range(format!(
                "patch of {} byte(s) at 0x{offset:x} is outside the file (size {})",
                data.len(),
                self.bytes.len()
            )));
        }

        let before_hash = content_hash(&self.bytes);
        let mut updated = self.bytes.clone();
        updated[offset as usize..end as usize].copy_from_slice(data);
        let after_hash = content_hash(&updated);
        let target = output.map_or_else(|| self.path.clone(), Path::to_path_buf);
        atomic_write(&target, &updated)?;
        if output.is_none() {
            self.bytes = updated;
        }

        Ok(PatchReport { path: target.display().to_string(), offset, length: data.len() as u64, before_hash, after_hash })
    }

    /// Maps an RVA (PE) or virtual address (ELF) onto a file offset.
    pub fn rva_to_offset(&self, rva: u64) -> Result<u64> {
        match self.format {
            BinaryFormat::Pe => pe::rva_to_offset(&pe::parse(&self.bytes)?, self.size(), rva),
            BinaryFormat::Elf => elf::rva_to_offset(&elf::parse(&self.bytes)?.sections, self.size(), rva),
            BinaryFormat::MachO => Err(IdaError::unsupported("RVA mapping for Mach-O is not implemented")),
            BinaryFormat::Unknown => Err(IdaError::unsupported("RVA mapping needs a PE or ELF header")),
        }
    }
}

/// Reports what this build implements and what it explicitly does not.
pub fn capabilities() -> serde_json::Value {
    json!({
        "engine": { "package": "open-ida-core", "version": env!("CARGO_PKG_VERSION") },
        "upstream": {
            "binary": "boost.rs/data-binary-pe",
            "digest": "boost.rs/data-checksum",
        },
        "formats": {
            "pe": "supported",
            "elf": "supported",
            "macho": "partial",
            "unknown": "unsupported",
        },
        "features": {
            "info": "supported",
            "sections": "supported",
            "strings": "supported",
            "hexdump": "supported",
            "read": "supported",
            "patch": "supported",
            "rva": "supported",
        },
        "unsupported": {
            "disassembly": "not-implemented",
            "decompilation": "not-implemented",
            "debugger": "not-implemented",
            "symbols": "not-implemented",
            "macho-sections": "not-implemented",
            "big-endian-elf": "not-implemented",
        },
        "architectures": {
            "x86": "supported",
            "x64": "supported",
            "arm64": "supported",
        },
    })
}

/// Parses a hex byte string such as `90,90` or `0x90 0x90`.
pub fn parse_hex(text: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for token in text.split(|value: char| value == ',' || value == ':' || value == '-' || value.is_whitespace()) {
        if token.is_empty() {
            continue;
        }
        let digits = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")).unwrap_or(token);
        if digits.is_empty() || digits.len() % 2 != 0 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(IdaError::parse(format!("`{token}` is not a hex byte string")));
        }
        for pair in digits.as_bytes().chunks(2) {
            let pair = std::str::from_utf8(pair).map_err(|_| IdaError::parse("invalid hex byte string"))?;
            let byte = u8::from_str_radix(pair, 16).map_err(|_| IdaError::parse(format!("invalid hex byte `{pair}`")))?;
            output.push(byte);
        }
    }
    if output.is_empty() {
        return Err(IdaError::parse("no hex bytes were provided"));
    }
    Ok(output)
}

fn push_hit(hits: &mut Vec<StringHit>, offset: usize, bytes: &[u8]) {
    hits.push(StringHit {
        offset: offset as u64,
        length: bytes.len() as u64,
        value: String::from_utf8_lossy(bytes).into_owned(),
    });
}

/// XXH64 hash from the shared `data-checksum` crate, rendered as 16 hex digits.
fn content_hash(bytes: &[u8]) -> String {
    let mut hash = data_checksum::XxHash64::new();
    hash.write(bytes);
    format!("{:016x}", hash.finish())
}

/// Writes bytes to a sibling temporary file and renames it into place.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().filter(|value| !value.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| IdaError::io(format!("{} is not a file path", path.display())))?;
    let temporary = parent.join(format!(".{}.{}.tmp", name.to_string_lossy(), std::process::id()));

    let write = || -> std::io::Result<()> {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    };

    if write().is_ok() {
        return Ok(());
    }
    // Windows cannot rename over an existing file; replace it explicitly.
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path).ok();
        if fs::rename(&temporary, path).is_ok() {
            return Ok(());
        }
    }
    fs::remove_file(&temporary).ok();
    Err(IdaError::io(format!("cannot write patched bytes to {}", path.display())))
}
