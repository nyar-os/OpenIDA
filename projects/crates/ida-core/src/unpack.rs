//! Unified decoding of `7z`, `asar`, `NSIS` and PyInstaller containers.
//!
//! One semantic verb — unpack — covers every supported container format; the
//! format is a parameter. `auto` sniffs the bytes at the requested offset:
//! the `7z` signature header, the `asar` pickle magic followed by a JSON
//! object, the `NullsoftInst` first header (scanning the file when no
//! offset is given), the `PYZ\0` archive magic, or the PyInstaller cookie
//! magic in the final kilobyte. Explicit formats skip the sniff and answer
//! with the stable parse error of their own decoder.
//!
//! `7z` indexing and entry decoding run through the internalized
//! `data-binary-sevenz` crate over a [`boost_source`] adapter of the open
//! session; `asar`, `NSIS` and PyInstaller reuse their engine modules.
//! PyInstaller `CArchive` entries and nested `PYZ` modules inflate with the
//! bundled `miniz_oxide` zlib decoder and the engine's own `marshal` reader.
//! Nothing is executed and no external process is spawned; extraction writes
//! only traversal-safe paths under the caller-chosen directory.

use std::io;
use std::path::{Component, Path};

use boost_source::binary::{ByteSource, ContentIdentity, ReadOutcome, ReadResult, SourceCapabilities};
use data_binary_inspect::BinarySession;
use data_binary_sevenz::{SevenZDecodeError, SevenZIndexError, decode_entry, index_7z};
use data_compression::CodecLimits;
use serde::{Deserialize, Serialize};

use crate::asar::{self, AsarOptions};
use crate::nsis::{self, NsisOptions};
use crate::pyinstaller::{self, PyInstallerOptions, PyInstallerReport};
use crate::{IdaError, Result};

/// The 7z signature header magic.
const SEVENZ_SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Value of the first `asar` header word.
const ASAR_MAGIC: u32 = 4;

/// Default cap on listed container entries.
const DEFAULT_ENTRIES_LIMIT: usize = 4096;

/// Default cap on rendered script commands.
const DEFAULT_COMMANDS_LIMIT: usize = 4096;

/// Default cap on rendered strings.
const DEFAULT_STRINGS_LIMIT: usize = 8192;

/// Default cap on one extracted file.
const DEFAULT_EXTRACT_LIMIT: usize = 256 * 1024 * 1024;

/// Which container format [`analyze`] decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnpackFormat {
    /// Sniff the bytes at `offset` and pick the matching decoder.
    #[default]
    Auto,
    /// A `7z` container indexed by `data-binary-sevenz`.
    #[serde(rename = "7z")]
    SevenZ,
    /// An Electron `asar` archive.
    Asar,
    /// An `NSIS` installer container.
    Nsis,
    /// A PyInstaller `CArchive` bundle appended to an executable.
    Pyinstaller,
    /// A standalone PyInstaller `PYZ` archive.
    Pyz,
}

/// Inputs of one [`crate::OpenIda::unpack`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UnpackOptions {
    /// Container format; `auto` sniffs the bytes.
    #[serde(default)]
    pub format: UnpackFormat,
    /// Absolute offset of the container start; `None` uses the file start
    /// (and scans for an `NSIS` header in `auto` mode).
    #[serde(default)]
    pub offset: Option<u64>,
    /// Cap on listed entries; clamped to 65536.
    #[serde(default = "default_entries_limit")]
    pub entries_limit: usize,
    /// Cap on rendered `NSIS` script commands; clamped to 65536.
    #[serde(default = "default_commands_limit")]
    pub commands_limit: usize,
    /// Cap on rendered `NSIS` strings; clamped to 65536.
    #[serde(default = "default_strings_limit")]
    pub strings_limit: usize,
    /// Optional directory to extract container entries into.
    #[serde(default)]
    pub extract_dir: Option<String>,
    /// Cap on one extracted file in bytes; clamped to 1 GiB.
    #[serde(default = "default_extract_limit")]
    pub extract_limit: usize,
}

impl Default for UnpackOptions {
    fn default() -> Self {
        Self {
            format: UnpackFormat::Auto,
            offset: None,
            entries_limit: default_entries_limit(),
            commands_limit: default_commands_limit(),
            strings_limit: default_strings_limit(),
            extract_dir: None,
            extract_limit: default_extract_limit(),
        }
    }
}

/// One packed `7z` folder range inside the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SevenZPackRange {
    /// Absolute offset of the pack stream inside the file.
    pub start: u64,
    /// Packed byte length.
    pub length: u64,
}

/// One packed `7z` folder: a coder chain feeding the entry sub-streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SevenZFolder {
    /// Zero-based folder index.
    pub index: usize,
    /// Coder method ids as lowercase hex, in header order.
    pub coders: Vec<String>,
    /// Absolute file ranges of this folder's pack streams.
    pub pack_ranges: Vec<SevenZPackRange>,
    /// Total unpack size of the folder output.
    pub unpack_size: u64,
    /// Folder CRC-32 when the header declares one.
    pub crc: Option<u32>,
    /// Number of file sub-streams carved out of the folder output.
    pub sub_stream_count: usize,
}

/// One `7z` archive entry (file or directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SevenZEntry {
    /// Zero-based entry index.
    pub index: usize,
    /// Decoded entry name.
    pub name: String,
    /// Unpacked size, absent for empty-stream entries.
    pub size: Option<u64>,
    /// Start of the entry's sub-stream inside its decoded folder output.
    pub offset: Option<u64>,
    /// Windows attributes when the header declares them.
    pub attributes: Option<u32>,
    /// Whether the entry is a directory.
    pub is_dir: bool,
    /// Whether the entry is an anti-item.
    pub is_anti: bool,
    /// Folder providing this entry's data, absent for empty-stream entries.
    pub folder_index: Option<usize>,
    /// Entry CRC-32 when the header declares one.
    pub crc: Option<u32>,
    /// Destination file written during extraction, when requested.
    pub extracted: Option<String>,
}

/// Facts indexed from one `7z` container header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SevenZReport {
    /// Absolute offset of the signature header.
    pub start_offset: u64,
    /// Declared container version as `major.minor`.
    pub version: String,
    /// Distinct coder method ids across all folders, as lowercase hex.
    pub methods: Vec<String>,
    /// Total packed folders in the container.
    pub folder_count: usize,
    /// Total entries in the container, before the listing limit.
    pub entry_count: usize,
    /// Sum of all folder unpack sizes.
    pub total_unpack_size: u64,
    /// Folders in header order, cut at the listing limit.
    pub folders: Vec<SevenZFolder>,
    /// Entries in header order, cut at the listing limit.
    pub entries: Vec<SevenZEntry>,
    /// Whether any list was cut at the limit.
    pub truncated: bool,
}

/// The decoded container, tagged by the format that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "lowercase")]
pub enum UnpackReport {
    /// A `7z` container indexed by `data-binary-sevenz`.
    #[serde(rename = "7z")]
    SevenZ(SevenZReport),
    /// An Electron `asar` archive.
    Asar(asar::AsarReport),
    /// An `NSIS` installer container.
    Nsis(nsis::NsisReport),
    /// A PyInstaller `CArchive` bundle or standalone `PYZ` archive.
    Pyinstaller(PyInstallerReport),
}

fn default_entries_limit() -> usize {
    DEFAULT_ENTRIES_LIMIT
}

fn default_commands_limit() -> usize {
    DEFAULT_COMMANDS_LIMIT
}

fn default_strings_limit() -> usize {
    DEFAULT_STRINGS_LIMIT
}

fn default_extract_limit() -> usize {
    DEFAULT_EXTRACT_LIMIT
}

/// Decodes the container selected (or sniffed) from one open session.
pub fn analyze(session: &BinarySession, options: &UnpackOptions) -> Result<UnpackReport> {
    let format = match options.format {
        UnpackFormat::Auto => sniff(session, options.offset)?,
        explicit => explicit,
    };
    match format {
        UnpackFormat::SevenZ => sevenz(session, options).map(UnpackReport::SevenZ),
        UnpackFormat::Asar => asar::analyze(session, &asar_options(options)).map(UnpackReport::Asar),
        UnpackFormat::Nsis => nsis::analyze(session, &nsis_options(options)).map(UnpackReport::Nsis),
        UnpackFormat::Pyinstaller => pyinstaller_carchive(session, options).map(UnpackReport::Pyinstaller),
        UnpackFormat::Pyz => pyinstaller_pyz(session, options).map(UnpackReport::Pyinstaller),
        UnpackFormat::Auto => Err(IdaError::parse("the auto sniff did not resolve a format")),
    }
}

/// Picks the container format from the bytes at `offset`.
fn sniff(session: &BinarySession, offset: Option<u64>) -> Result<UnpackFormat> {
    let start = offset.unwrap_or(0);
    let size = session.size();
    if start < size {
        let head = session.read(start, 20u64.min(size - start))?;
        if head.len() >= SEVENZ_SIGNATURE.len() && head[..SEVENZ_SIGNATURE.len()] == SEVENZ_SIGNATURE {
            return Ok(UnpackFormat::SevenZ);
        }
        if head.len() >= 17 && word(head, 0) == ASAR_MAGIC && head[16] == b'{' {
            return Ok(UnpackFormat::Asar);
        }
        if head.len() == 20 && head[4..20] == *nsis::SIGNATURE {
            return Ok(UnpackFormat::Nsis);
        }
        if pyinstaller::looks_like_pyz(head) {
            return Ok(UnpackFormat::Pyz);
        }
    }
    if offset.is_none_or(|value| value == 0) && pyinstaller::locate_cookie(&|start, length| session.read(start, length).map(|bytes| bytes.to_vec()).map_err(IdaError::from), size).is_some() {
        return Ok(UnpackFormat::Pyinstaller);
    }
    if offset.is_none() && nsis::locate(session, None).is_ok() {
        return Ok(UnpackFormat::Nsis);
    }
    Err(IdaError::parse("no 7z, asar, NSIS or PyInstaller container signature was found at the probe offset"))
}

/// Reads one little-endian word from a fetched header window.
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four-byte window"))
}

/// Maps one `UnpackOptions` onto the `asar` engine inputs.
fn asar_options(options: &UnpackOptions) -> AsarOptions {
    AsarOptions {
        offset: options.offset,
        entries_limit: options.entries_limit,
        extract_dir: options.extract_dir.clone(),
        extract_limit: options.extract_limit,
    }
}

/// Maps one `UnpackOptions` onto the `NSIS` engine inputs.
fn nsis_options(options: &UnpackOptions) -> NsisOptions {
    NsisOptions {
        offset: options.offset,
        commands_limit: options.commands_limit,
        strings_limit: options.strings_limit,
        extract_dir: options.extract_dir.clone(),
        extract_limit: options.extract_limit,
    }
}

/// Maps one `UnpackOptions` onto the PyInstaller engine inputs.
fn pyinstaller_options(options: &UnpackOptions) -> PyInstallerOptions {
    PyInstallerOptions {
        offset: options.offset,
        entries_limit: options.entries_limit,
        extract_dir: options.extract_dir.clone(),
        extract_limit: options.extract_limit,
    }
}

/// Decodes the PyInstaller `CArchive` whose cookie ends the file.
fn pyinstaller_carchive(session: &BinarySession, options: &UnpackOptions) -> Result<PyInstallerReport> {
    let engine = pyinstaller_options(options);
    let read = |start: u64, length: u64| session.read(start, length).map(|bytes| bytes.to_vec()).map_err(IdaError::from);
    let dir = engine.extract_dir.clone().unwrap_or_default();
    let write = |name: &str, bytes: &[u8]| write_entry(Path::new(&dir), name, bytes);
    pyinstaller::analyze_carchive(&read, &write, session.size(), &engine)
}

/// Decodes a standalone PyInstaller `PYZ` archive at the offset.
fn pyinstaller_pyz(session: &BinarySession, options: &UnpackOptions) -> Result<PyInstallerReport> {
    let engine = pyinstaller_options(options);
    let read = |start: u64, length: u64| session.read(start, length).map(|bytes| bytes.to_vec()).map_err(IdaError::from);
    let dir = engine.extract_dir.clone().unwrap_or_default();
    let write = |name: &str, bytes: &[u8]| write_entry(Path::new(&dir), name, bytes);
    pyinstaller::analyze_pyz(&read, &write, session.size(), &engine)
}

/// Indexes one `7z` container and optionally extracts its entries.
fn sevenz(session: &BinarySession, options: &UnpackOptions) -> Result<SevenZReport> {
    let base = options.offset.unwrap_or(0);
    let source = SessionSource { session, base };
    let index = index_7z(&source).map_err(index_error)?;

    let limit = options.entries_limit.clamp(1, 65536);
    let mut truncated = false;

    let folders = index
        .folders
        .iter()
        .enumerate()
        .map(|(position, folder)| SevenZFolder {
            index: position,
            coders: folder.coders.iter().map(|coder| hex(&coder.method)).collect(),
            pack_ranges: folder.pack_ranges.iter().map(|range| SevenZPackRange { start: range.start, length: range.len }).collect(),
            unpack_size: folder.unpack_size,
            crc: folder.crc,
            sub_stream_count: folder.num_sub_streams,
        })
        .take(limit)
        .collect();
    if index.folder_count() > limit {
        truncated = true;
    }

    let mut entries = Vec::new();
    for (position, entry) in index.entries.iter().enumerate() {
        if entries.len() == limit {
            truncated = true;
            break;
        }
        entries.push(SevenZEntry {
            index: position,
            name: entry.name.clone(),
            size: entry.size,
            offset: entry.offset,
            attributes: entry.attributes,
            is_dir: entry.is_dir,
            is_anti: entry.is_anti,
            folder_index: entry.folder_index,
            crc: entry.crc,
            extracted: None,
        });
    }

    if let Some(dir) = &options.extract_dir {
        let cap = options.extract_limit.clamp(1, 1024 * 1024 * 1024) as u64;
        let limits = CodecLimits::new().with_max_output_bytes(cap);
        for entry in &mut entries {
            if entry.is_dir || entry.is_anti || entry.folder_index.is_none() {
                continue;
            }
            if entry.size.is_none_or(|size| size == 0 || size > cap) {
                continue;
            }
            let bytes = decode_entry(&source, &index, entry.index, limits).map_err(decode_error)?;
            let written = write_entry(Path::new(dir), &entry.name, &bytes)?;
            entry.extracted = Some(written);
        }
    }

    Ok(SevenZReport {
        start_offset: base,
        version: format!("{}.{}", index.version.0, index.version.1),
        methods: index.methods.iter().map(|method| hex(method)).collect(),
        folder_count: index.folder_count(),
        entry_count: index.entry_count(),
        total_unpack_size: index.total_unpack_size,
        folders,
        entries,
        truncated,
    })
}

/// Formats method id bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Maps one indexing failure onto the stable error surface.
fn index_error(error: SevenZIndexError) -> IdaError {
    match error {
        SevenZIndexError::UnsupportedVersion { .. } => IdaError::unsupported(error.to_string()),
        other => IdaError::parse(other.to_string()),
    }
}

/// Maps one entry decode failure onto the stable error surface.
fn decode_error(error: SevenZDecodeError) -> IdaError {
    match error {
        SevenZDecodeError::UnsupportedCoder { .. } => IdaError::unsupported(error.to_string()),
        other => IdaError::parse(other.to_string()),
    }
}

/// Writes one extracted entry under `directory`, mirroring its archive name.
fn write_entry(directory: &Path, name: &str, bytes: &[u8]) -> Result<String> {
    let mut target = directory.to_path_buf();
    for part in name.split(['/', '\\']).filter(|part| !part.is_empty() && *part != ".") {
        let mut components = Path::new(part).components();
        if components.next() != Some(Component::Normal(part.as_ref())) || components.next().is_some() {
            return Err(IdaError::parse(format!("unsafe container entry name: {name}")));
        }
        target.push(part);
    }
    if target == directory {
        return Err(IdaError::parse(format!("container entry name resolves to the extraction directory: {name}")));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, bytes)?;
    Ok(target.display().to_string())
}

/// A [`ByteSource`] view of one open session window starting at `base`.
struct SessionSource<'a> {
    session: &'a BinarySession,
    base: u64,
}

impl ByteSource for SessionSource<'_> {
    fn length(&self) -> Option<u64> {
        self.session.size().checked_sub(self.base)
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> ReadResult {
        let Some(start) = self.base.checked_add(offset) else {
            return Ok(ReadOutcome::Eof);
        };
        let size = self.session.size();
        if start >= size {
            return Ok(ReadOutcome::Eof);
        }
        let want = destination.len() as u64;
        let take = want.min(size - start);
        let bytes = self.session.read(start, take).map_err(|error| io::Error::other(error.message().to_string()))?;
        destination[..bytes.len()].copy_from_slice(bytes);
        if take == want {
            Ok(ReadOutcome::Complete)
        }
        else {
            Ok(ReadOutcome::Partial { bytes_read: take })
        }
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            random_access: true,
            known_length: true,
            repeatable: true,
            concurrent_reads: true,
            stable_identity: true,
            decoded_views: false,
        }
    }

    fn identity(&self) -> ContentIdentity {
        ContentIdentity::new(self.session.path().display().to_string())
    }
}
