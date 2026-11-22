//! OpenIDA kernel.
//!
//! The inspection engine lives in `boost.rs/data-binary-inspect`; this crate
//! owns the product policy on top of it: session defaults, the `OpenIda` API,
//! the stable error codes and the capability matrix. Container decoding,
//! imports, exports, symbols, pattern search, string scanning, hex dumps,
//! address mapping and atomic patching are not re-implemented here.
//!
//! The `PE` debug directory, `CodeView` records and ELF program-header
//! dependencies are parsed here because the pinned upstream release does not
//! expose them. Disassembly, decompilation and debugging stay declared as
//! unsupported instead of being approximated.

#![deny(missing_docs)]
#![recursion_limit = "256"]

mod certificates;
mod code_signature;
mod debug;
mod diff;
mod disasm;
mod dynamic;
mod entropy;
mod error;
mod load_config;
mod macho;
mod mitigations;
mod notes;
mod pe_exception;
mod relocations;
mod resources;
mod segments;
mod text;
mod tls;
mod version;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

pub use data_binary_inspect::{
    Architecture, BinaryFormat, BinaryInfo, BinarySession, ExportEntry, ExportsReport, ImportEntry, ImportsReport,
    InspectOptions, PatchReport, SearchHit, SearchMode, SearchOptions, SearchReport, SectionInfo as Section, StringHit,
    StringsReport, SymbolEntry, SymbolsReport,
};
pub use certificates::{CertificatesReport, PeCertificate};
pub use code_signature::{MachOCodeDirectory, MachOCodeSignatureReport};
pub use debug::{CodeViewInfo, DebugEntry, DebugReport};
pub use diff::{DiffRange, DiffReport};
pub use disasm::{DisassembleOptions, DisassemblyInstruction, DisassemblyReport, DisassemblySyntax};
pub use dynamic::ElfDynamicReport;
pub use entropy::{EntropyReport, OverlayInfo, SectionEntropy};
pub use error::{IdaError, Result};
pub use load_config::{CodeIntegrityInfo, PeLoadConfigReport};
pub use macho::{
    MachODylib, MachOExport, MachOExportsReport, MachOFunctionStartsReport, MachOReport, MachOSection, MachOSegment,
    MachOSlice, MachOSliceExtraction, MachOSlicesReport, MachOSymbol, MachOSymbolsReport,
};
pub use mitigations::{MitigationsReport, WritableExecutableSection};
pub use notes::{ElfAbiTag, ElfGnuProperty, ElfNote, ElfNotesReport};
pub use pe_exception::{PeExceptionReport, PeRuntimeFunction, PeUnwindInfo};
pub use relocations::{RelocationBlock, RelocationKindCount, RelocationsReport};
pub use resources::{PeResource, ResourcesReport};
pub use segments::{ElfSegment, ElfSegmentsReport};
pub use text::{EncodedStringHit, EncodedStringsReport, StringEncoding, StringsOptions};
pub use tls::{PeTlsCallback, PeTlsReport};
pub use version::{FixedFileInfo, VersionReport, VersionString};

impl From<data_binary_inspect::InspectError> for IdaError {
    fn from(error: data_binary_inspect::InspectError) -> Self {
        Self::new(error.code(), error.message().to_string())
    }
}

/// Parses a hex byte string such as `90,90` or `0x90 0x90`.
pub fn parse_hex(text: &str) -> Result<Vec<u8>> {
    data_binary_inspect::parse_hex(text).map_err(IdaError::from)
}

/// One opened file with the kernel-facing method names.
///
/// The inspection itself lives in [`BinarySession`]; this wrapper keeps the
/// `BinaryView` surface that callers and tests already use.
#[derive(Debug, Clone)]
pub struct BinaryView {
    session: BinarySession,
}

impl BinaryView {
    /// Opens a file from disk and detects its container.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let session = BinarySession::open(InspectOptions::new(path.as_ref()))?;
        Ok(Self { session })
    }

    /// Builds a view over bytes already in memory.
    pub fn from_bytes(path: impl Into<PathBuf>, bytes: Vec<u8>) -> Self {
        Self { session: BinarySession::from_bytes(path, bytes) }
    }

    /// Path this view was opened from.
    pub fn path(&self) -> &Path {
        self.session.path()
    }

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        self.session.size()
    }

    /// Detected container.
    pub fn format(&self) -> BinaryFormat {
        self.session.format()
    }

    /// Detected architecture, or `unknown`.
    pub fn architecture(&self) -> Architecture {
        self.session.architecture()
    }

    /// Reports the container, architecture, hash and header fields.
    pub fn info(&self) -> Result<BinaryInfo> {
        self.session.info().map_err(IdaError::from)
    }

    /// Decodes the section table.
    pub fn sections(&self) -> Result<Vec<Section>> {
        self.session.sections().map_err(IdaError::from)
    }

    /// Extracts printable ASCII runs of at least `min_len` bytes.
    pub fn strings(&self, min_len: usize) -> Vec<StringHit> {
        self.session.strings(Some(min_len), None).hits
    }

    /// Extracts ASCII or ASCII-in-UTF-16LE runs with the requested encoding.
    pub fn strings_encoded(&self, options: &StringsOptions) -> Result<EncodedStringsReport> {
        text::scan(&self.session, options)
    }

    /// Lists imported functions.
    pub fn imports(&self, limit: Option<usize>) -> Result<ImportsReport> {
        self.session.imports(limit).map_err(IdaError::from)
    }

    /// Lists exported symbols.
    pub fn exports(&self, limit: Option<usize>) -> Result<ExportsReport> {
        self.session.exports(limit).map_err(IdaError::from)
    }

    /// Lists debug or dynamic symbols.
    pub fn symbols(&self, limit: Option<usize>) -> Result<SymbolsReport> {
        self.session.symbols(limit).map_err(IdaError::from)
    }

    /// Lists PE debug directory entries and `CodeView` PDB records.
    pub fn debug(&self, limit: Option<usize>) -> Result<DebugReport> {
        debug::analyze(&self.session, limit)
    }

    /// Decodes the PE version resource (`RT_VERSION`).
    pub fn version(&self) -> Result<VersionReport> {
        version::analyze(&self.session)
    }

    /// Decodes Mach-O load commands, segments, sections, dylibs and identity.
    pub fn macho(&self) -> Result<MachOReport> {
        macho::analyze(&self.session)
    }

    /// Lists the Mach-O `LC_SYMTAB` symbol table.
    pub fn macho_symbols(&self, limit: Option<usize>) -> Result<MachOSymbolsReport> {
        macho::symbols(&self.session, limit)
    }

    /// Decodes the Mach-O `LC_FUNCTION_STARTS` delta table.
    pub fn macho_function_starts(&self, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
        macho::function_starts(&self.session, limit)
    }

    /// Decodes the dyld export trie of a Mach-O image.
    pub fn macho_exports(&self) -> Result<MachOExportsReport> {
        macho::exports(&self.session)
    }

    /// Lists the architecture slices of a fat/universal Mach-O container.
    pub fn macho_slices(&self) -> Result<MachOSlicesReport> {
        macho::slices(&self.session)
    }

    /// Decodes the Mach-O embedded code signature and its first `CodeDirectory`.
    pub fn code_signature(&self) -> Result<MachOCodeSignatureReport> {
        code_signature::analyze(&self.session)
    }

    /// Writes one fat/universal Mach-O slice to a caller-chosen path.
    pub fn extract_slice(&self, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
        macho::extract(&self.session, index, output)
    }

    /// Summarises the PE mitigation posture.
    pub fn mitigations(&self) -> Result<MitigationsReport> {
        mitigations::analyze(&self.session)
    }

    /// Lists the PE resource directory leaves.
    pub fn resources(&self) -> Result<ResourcesReport> {
        resources::analyze(&self.session)
    }

    /// Decodes the PE exception directory runtime functions.
    pub fn exception(&self) -> Result<PeExceptionReport> {
        pe_exception::analyze(&self.session)
    }

    /// Decodes the PE base relocation blocks.
    pub fn relocations(&self) -> Result<RelocationsReport> {
        relocations::analyze(&self.session)
    }

    /// Reports ELF `PT_INTERP` and `PT_DYNAMIC` dependencies.
    pub fn dynamic(&self) -> Result<ElfDynamicReport> {
        dynamic::analyze(&self.session)
    }

    /// Decodes the ELF program header table.
    pub fn segments(&self) -> Result<ElfSegmentsReport> {
        segments::analyze(&self.session)
    }

    /// Decodes ELF notes: build id, GNU ABI tag and GNU properties.
    pub fn notes(&self) -> Result<ElfNotesReport> {
        notes::analyze(&self.session)
    }

    /// Lists the PE attribute certificate table entries.
    pub fn certificates(&self) -> Result<CertificatesReport> {
        certificates::analyze(&self.session)
    }

    /// Decodes the PE TLS directory and its callback array.
    pub fn tls(&self) -> Result<PeTlsReport> {
        tls::analyze(&self.session)
    }

    /// Decodes the PE load configuration directory.
    pub fn load_config(&self) -> Result<PeLoadConfigReport> {
        load_config::analyze(&self.session)
    }

    /// Decodes `x86` / `x64` instructions from one file offset.
    pub fn disasm(&self, options: &DisassembleOptions) -> Result<DisassemblyReport> {
        disasm::analyze(&self.session, options)
    }

    /// Compares this binary against another open binary.
    pub fn diff(&self, other: &Self) -> Result<DiffReport> {
        diff::compare(&self.session, &other.session)
    }

    /// Computes whole-file and per-section entropy plus the PE overlay.
    pub fn entropy(&self) -> Result<EntropyReport> {
        entropy::analyze(&self.session)
    }

    /// Searches for a hex, ASCII or UTF-16LE pattern.
    pub fn search(&self, options: &SearchOptions) -> Result<SearchReport> {
        self.session.search(options).map_err(IdaError::from)
    }

    /// Renders a canonical hex dump.
    pub fn hexdump(&self, offset: u64, length: u64) -> Result<String> {
        self.session.hexdump(Some(offset), Some(length)).map_err(IdaError::from)
    }

    /// Reads a byte range from the file.
    pub fn read_bytes(&self, offset: u64, length: u64) -> Result<&[u8]> {
        self.session.read(offset, length).map_err(IdaError::from)
    }

    /// Writes patched bytes back to the opened file, atomically.
    pub fn patch(&mut self, offset: u64, data: &[u8]) -> Result<PatchReport> {
        self.session.patch(offset, data, None).map_err(IdaError::from)
    }

    /// Writes a patched copy to `output`, or back to the source when omitted.
    pub fn patch_to(&mut self, offset: u64, data: &[u8], output: Option<&Path>) -> Result<PatchReport> {
        self.session.patch(offset, data, output).map_err(IdaError::from)
    }

    /// Maps an RVA or virtual address onto a file offset.
    pub fn rva_to_offset(&self, address: u64) -> Result<u64> {
        self.session.rva_to_offset(address).map_err(IdaError::from)
    }

    /// Maps a file offset onto an absolute virtual address.
    pub fn offset_to_va(&self, offset: u64) -> Result<u64> {
        self.session.offset_to_va(offset).map_err(IdaError::from)
    }

    /// Maps a file offset onto a PE image-relative address.
    pub fn offset_to_rva(&self, offset: u64) -> Result<u64> {
        self.session.offset_to_rva(offset).map_err(IdaError::from)
    }
}

fn default_min_string_len() -> usize {
    4
}

fn default_strings_limit() -> Option<usize> {
    Some(100)
}

fn default_hexdump_length() -> u64 {
    256
}

/// Inputs of one [`OpenIda`] session.
///
/// Serialized as JSON with camelCase keys, so `{ "path": "...", "minStringLen": 4 }`
/// is the wire form the addon and the TypeScript client both use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenIdaOptions {
    /// Binary to open.
    pub path: PathBuf,
    /// Minimum printable run length used by [`OpenIda::strings`] when no override is given.
    #[serde(default = "default_min_string_len")]
    pub min_string_len: usize,
    /// Default hit limit used by [`OpenIda::strings`]; `null` means unlimited.
    #[serde(default = "default_strings_limit")]
    pub strings_limit: Option<usize>,
    /// Default byte count used by [`OpenIda::hexdump`].
    #[serde(default = "default_hexdump_length")]
    pub hexdump_length: u64,
}

impl OpenIdaOptions {
    /// Builds options with the documented defaults for one path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            min_string_len: default_min_string_len(),
            strings_limit: default_strings_limit(),
            hexdump_length: default_hexdump_length(),
        }
    }

    fn inspect_options(&self) -> InspectOptions {
        InspectOptions {
            path: self.path.clone(),
            min_string_len: self.min_string_len,
            strings_limit: self.strings_limit,
            hexdump_length: self.hexdump_length,
        }
    }
}

/// One open binary plus the defaults every operation should use.
///
/// This is the product API: construct it with [`OpenIdaOptions`], then call the
/// orthogonal methods. Explicit arguments win over the defaults carried by the
/// options, so a session can be reused for several bounded queries.
#[derive(Debug, Clone)]
pub struct OpenIda {
    session: BinarySession,
    options: OpenIdaOptions,
}

impl OpenIda {
    /// Opens the binary named by `options`.
    pub fn new(options: OpenIdaOptions) -> Result<Self> {
        let session = BinarySession::open(options.inspect_options())?;
        Ok(Self { session, options })
    }

    /// Builds a session from its JSON wire form.
    pub fn from_options_json(raw: &str) -> Result<Self> {
        let options: OpenIdaOptions =
            serde_json::from_str(raw).map_err(|error| IdaError::parse(format!("invalid OpenIdaOptions: {error}")))?;
        Self::new(options)
    }

    /// Options this session was built from.
    pub fn options(&self) -> &OpenIdaOptions {
        &self.options
    }

    /// Path of the open binary.
    pub fn path(&self) -> &Path {
        self.session.path()
    }

    /// Header summary.
    pub fn info(&self) -> Result<BinaryInfo> {
        self.session.info().map_err(IdaError::from)
    }

    /// Section table.
    pub fn sections(&self) -> Result<Vec<Section>> {
        self.session.sections().map_err(IdaError::from)
    }

    /// Extracts printable strings, falling back to the session defaults.
    pub fn strings(&self, min_len: Option<usize>, limit: Option<usize>) -> StringsReport {
        self.session.strings(min_len, limit)
    }

    /// Extracts ASCII or ASCII-in-UTF-16LE strings described by `options`.
    pub fn strings_encoded(&self, options: &StringsOptions) -> Result<EncodedStringsReport> {
        text::scan(&self.session, options)
    }

    /// Lists imported functions.
    pub fn imports(&self, limit: Option<usize>) -> Result<ImportsReport> {
        self.session.imports(limit).map_err(IdaError::from)
    }

    /// Lists exported symbols.
    pub fn exports(&self, limit: Option<usize>) -> Result<ExportsReport> {
        self.session.exports(limit).map_err(IdaError::from)
    }

    /// Lists debug or dynamic symbols.
    pub fn symbols(&self, limit: Option<usize>) -> Result<SymbolsReport> {
        self.session.symbols(limit).map_err(IdaError::from)
    }

    /// Lists PE debug directory entries and `CodeView` PDB records.
    pub fn debug(&self, limit: Option<usize>) -> Result<DebugReport> {
        debug::analyze(&self.session, limit)
    }

    /// Decodes the PE version resource (`RT_VERSION`).
    pub fn version(&self) -> Result<VersionReport> {
        version::analyze(&self.session)
    }

    /// Decodes Mach-O load commands, segments, sections, dylibs and identity.
    pub fn macho(&self) -> Result<MachOReport> {
        macho::analyze(&self.session)
    }

    /// Lists the Mach-O `LC_SYMTAB` symbol table.
    pub fn macho_symbols(&self, limit: Option<usize>) -> Result<MachOSymbolsReport> {
        macho::symbols(&self.session, limit)
    }

    /// Decodes the Mach-O `LC_FUNCTION_STARTS` delta table.
    pub fn macho_function_starts(&self, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
        macho::function_starts(&self.session, limit)
    }

    /// Decodes the dyld export trie of a Mach-O image.
    pub fn macho_exports(&self) -> Result<MachOExportsReport> {
        macho::exports(&self.session)
    }

    /// Lists the architecture slices of a fat/universal Mach-O container.
    pub fn macho_slices(&self) -> Result<MachOSlicesReport> {
        macho::slices(&self.session)
    }

    /// Decodes the Mach-O embedded code signature and its first `CodeDirectory`.
    pub fn code_signature(&self) -> Result<MachOCodeSignatureReport> {
        code_signature::analyze(&self.session)
    }

    /// Writes one fat/universal Mach-O slice to a caller-chosen path.
    pub fn extract_slice(&self, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
        macho::extract(&self.session, index, output)
    }

    /// Summarises the PE mitigation posture.
    pub fn mitigations(&self) -> Result<MitigationsReport> {
        mitigations::analyze(&self.session)
    }

    /// Lists the PE resource directory leaves.
    pub fn resources(&self) -> Result<ResourcesReport> {
        resources::analyze(&self.session)
    }

    /// Decodes the PE exception directory runtime functions.
    pub fn exception(&self) -> Result<PeExceptionReport> {
        pe_exception::analyze(&self.session)
    }

    /// Decodes the PE base relocation blocks.
    pub fn relocations(&self) -> Result<RelocationsReport> {
        relocations::analyze(&self.session)
    }

    /// Reports ELF `PT_INTERP` and `PT_DYNAMIC` dependencies.
    pub fn dynamic(&self) -> Result<ElfDynamicReport> {
        dynamic::analyze(&self.session)
    }

    /// Decodes the ELF program header table.
    pub fn segments(&self) -> Result<ElfSegmentsReport> {
        segments::analyze(&self.session)
    }

    /// Decodes ELF notes: build id, GNU ABI tag and GNU properties.
    pub fn notes(&self) -> Result<ElfNotesReport> {
        notes::analyze(&self.session)
    }

    /// Lists the PE attribute certificate table entries.
    pub fn certificates(&self) -> Result<CertificatesReport> {
        certificates::analyze(&self.session)
    }

    /// Decodes the PE TLS directory and its callback array.
    pub fn tls(&self) -> Result<PeTlsReport> {
        tls::analyze(&self.session)
    }

    /// Decodes the PE load configuration directory.
    pub fn load_config(&self) -> Result<PeLoadConfigReport> {
        load_config::analyze(&self.session)
    }

    /// Decodes `x86` / `x64` instructions from one file offset.
    pub fn disasm(&self, options: &DisassembleOptions) -> Result<DisassemblyReport> {
        disasm::analyze(&self.session, options)
    }

    /// Compares this binary against another open binary.
    pub fn diff(&self, other: &Self) -> Result<DiffReport> {
        diff::compare(&self.session, &other.session)
    }

    /// Computes whole-file and per-section entropy plus the PE overlay.
    pub fn entropy(&self) -> Result<EntropyReport> {
        entropy::analyze(&self.session)
    }

    /// Searches for a hex, ASCII or UTF-16LE pattern.
    pub fn search(&self, options: &SearchOptions) -> Result<SearchReport> {
        self.session.search(options).map_err(IdaError::from)
    }

    /// Renders a hex dump, falling back to the session defaults.
    pub fn hexdump(&self, offset: Option<u64>, length: Option<u64>) -> Result<String> {
        self.session.hexdump(offset, length).map_err(IdaError::from)
    }

    /// Reads a byte range from the file.
    pub fn read(&self, offset: u64, length: u64) -> Result<&[u8]> {
        self.session.read(offset, length).map_err(IdaError::from)
    }

    /// Writes patched bytes back to the source, or to `output` when given.
    pub fn patch(&mut self, offset: u64, data: &[u8], output: Option<&Path>) -> Result<PatchReport> {
        self.session.patch(offset, data, output).map_err(IdaError::from)
    }

    /// Maps an RVA or virtual address onto a file offset.
    pub fn rva(&self, address: u64) -> Result<u64> {
        self.session.rva_to_offset(address).map_err(IdaError::from)
    }

    /// Maps a file offset onto an absolute virtual address.
    pub fn offset_to_va(&self, offset: u64) -> Result<u64> {
        self.session.offset_to_va(offset).map_err(IdaError::from)
    }

    /// Maps a file offset onto a PE image-relative address.
    pub fn offset_to_rva(&self, offset: u64) -> Result<u64> {
        self.session.offset_to_rva(offset).map_err(IdaError::from)
    }

    /// Borrows the underlying session for callers that need the raw engine.
    pub fn session(&self) -> &BinarySession {
        &self.session
    }
}

/// Reports what this build implements and what it explicitly does not.
pub fn capabilities() -> serde_json::Value {
    json!({
        "engine": { "package": "open-ida-core", "version": env!("CARGO_PKG_VERSION"), "api": "OpenIda" },
        "upstream": {
            "inspect": "boost.rs/data-binary-inspect",
            "binary": "boost.rs/data-binary-pe",
            "machO": "boost.rs/data-binary-mach-o",
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
            "imports": "supported",
            "exports": "supported",
            "symbols": "supported",
            "debug": "supported",
            "version": "supported",
            "macho-load-commands": "supported",
            "macho-segments": "supported",
            "macho-sections": "supported",
            "macho-dylibs": "supported",
            "macho-build-version": "supported",
            "macho-symbols": "supported",
            "macho-fat-slices": "supported",
            "macho-function-starts": "supported",
            "macho-exports": "supported",
            "macho-slice-extraction": "supported",
            "macho-code-signature": "supported",
            "pe-mitigations": "supported",
            "pe-resources": "supported",
            "pe-relocations": "supported",
            "pe-exception": "supported",
            "pe-certificates": "supported",
            "pe-tls": "supported",
            "pe-load-config": "supported",
            "elf-dynamic": "supported",
            "elf-notes": "supported",
            "elf-program-headers": "supported",
            "disassembly": "supported",
            "diff": "supported",
            "entropy": "supported",
            "overlay": "supported",
            "search": "supported",
            "offset-to-va": "supported",
            "offset-to-rva": "supported",
        },
        "unsupported": {
            "decompilation": "not-implemented",
            "debugger": "not-implemented",
            "macho-import-bindings": "not-implemented",
        },
        "architectures": {
            "x86": "supported",
            "x64": "supported",
            "arm64": "supported",
        },
    })
}
