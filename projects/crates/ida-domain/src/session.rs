//! Product session: options, the read-only `BinaryView` and the `OpenIda` API.
//!
//! The session owns the defaults each verb reuses and forwards every operation
//! to the workflow layer or to the format adapters. No format parsing and no
//! byte-observation algorithm lives here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{IdaError, Result, report::*};

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
        crate::workflow::inspect::strings::scan(&self.session, options)
    }

    /// Searches the whole file with a byte regex described by `options`.
    pub fn find(&self, options: &FindOptions) -> Result<FindReport> {
        crate::workflow::inspect::find::find(&self.session, options)
    }

    /// Exports a raw byte range from the file into a caller-chosen path.
    pub fn dump(&self, options: &DumpOptions) -> Result<DumpReport> {
        crate::workflow::extract::dump::dump(&self.session, options)
    }

    /// Extracts the printable regions around every marker match.
    pub fn carve(&self, options: &CarveOptions) -> Result<CarveReport> {
        crate::workflow::extract::carve::carve(&self.session, options)
    }

    /// Extracts the embedded assets of a Tauri v2 container.
    pub fn tauri_assets(&self, options: &TauriAssetsOptions) -> Result<TauriAssetsReport> {
        crate::workflow::extract::tauri::tauri_assets(&self.session, options)
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
        ida_format_adapters::pe::debug::analyze(&self.session, limit)
    }

    /// Decodes the PE version resource (`RT_VERSION`).
    pub fn version(&self) -> Result<VersionReport> {
        ida_format_adapters::pe::version::analyze(&self.session)
    }

    /// Decodes Mach-O load commands, segments, sections, dylibs and identity.
    pub fn macho(&self) -> Result<MachOReport> {
        ida_format_adapters::macho::image::analyze(&self.session)
    }

    /// Lists the Mach-O `LC_SYMTAB` symbol table.
    pub fn macho_symbols(&self, limit: Option<usize>) -> Result<MachOSymbolsReport> {
        ida_format_adapters::macho::symbols::symbols(&self.session, limit)
    }

    /// Decodes the Mach-O `LC_FUNCTION_STARTS` delta table.
    pub fn macho_function_starts(&self, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
        ida_format_adapters::macho::function_starts::function_starts(&self.session, limit)
    }

    /// Decodes the dyld export trie of a Mach-O image.
    pub fn macho_exports(&self) -> Result<MachOExportsReport> {
        ida_format_adapters::macho::exports::exports(&self.session)
    }

    /// Lists the architecture slices of a fat/universal Mach-O container.
    pub fn macho_slices(&self) -> Result<MachOSlicesReport> {
        ida_format_adapters::macho::fat::slices(&self.session)
    }

    /// Decodes `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`.
    pub fn macho_encryption(&self) -> Result<MachOEncryptionReport> {
        ida_format_adapters::macho::encryption::encryption(&self.session)
    }

    /// Decodes `LC_DYLD_CHAINED_FIXUPS` imports and its starts table.
    pub fn macho_chained_fixups(&self) -> Result<MachOChainedFixupsReport> {
        ida_format_adapters::macho::chained_fixups::chained_fixups(&self.session)
    }

    /// Decodes the classic dyld bind, weak-bind and lazy-bind opcode streams.
    pub fn macho_bindings(&self) -> Result<MachOBindingsReport> {
        ida_format_adapters::macho::bindings::bindings(&self.session)
    }

    /// Decodes the Mach-O embedded code signature and its first `CodeDirectory`.
    pub fn code_signature(&self) -> Result<MachOCodeSignatureReport> {
        ida_format_adapters::macho::code_signature::analyze(&self.session)
    }

    /// Writes one fat/universal Mach-O slice to a caller-chosen path.
    pub fn extract_slice(&self, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
        ida_format_adapters::macho::fat::extract(&self.session, index, output)
    }

    /// Summarises the PE mitigation posture.
    pub fn mitigations(&self) -> Result<MitigationsReport> {
        ida_format_adapters::pe::mitigations::analyze(&self.session)
    }

    /// Lists the PE resource directory leaves.
    pub fn resources(&self) -> Result<ResourcesReport> {
        ida_format_adapters::pe::resources::analyze(&self.session)
    }

    /// Decodes the PE exception directory runtime functions.
    pub fn exception(&self) -> Result<PeExceptionReport> {
        ida_format_adapters::pe::exception::analyze(&self.session)
    }

    /// Decodes the PE delay-import descriptors and their thunks.
    pub fn delay_imports(&self) -> Result<PeDelayImportsReport> {
        ida_format_adapters::pe::delay_imports::analyze(&self.session)
    }

    /// Decodes the PE bound-import descriptors and their forwarder refs.
    pub fn bound_imports(&self) -> Result<PeBoundImportsReport> {
        ida_format_adapters::pe::bound_imports::analyze(&self.session)
    }

    /// Decodes the Rich header build stamp between the DOS stub and the PE header.
    pub fn rich_header(&self) -> Result<PeRichHeaderReport> {
        ida_format_adapters::pe::rich_header::analyze(&self.session)
    }

    /// Decodes the PE base relocation blocks.
    pub fn relocations(&self) -> Result<RelocationsReport> {
        ida_format_adapters::pe::relocations::analyze(&self.session)
    }

    /// Reports ELF `PT_INTERP` and `PT_DYNAMIC` dependencies.
    pub fn dynamic(&self) -> Result<ElfDynamicReport> {
        ida_format_adapters::elf::dynamic::analyze(&self.session)
    }

    /// Lists the ELF static symbol table (`.symtab`) entries.
    pub fn static_symbols(&self) -> Result<ElfStaticSymbolsReport> {
        ida_format_adapters::elf::symbols::analyze(&self.session)
    }

    /// Decodes the ELF program header table.
    pub fn segments(&self) -> Result<ElfSegmentsReport> {
        ida_format_adapters::elf::segments::analyze(&self.session)
    }

    /// Decodes ELF notes: build id, GNU ABI tag and GNU properties.
    pub fn notes(&self) -> Result<ElfNotesReport> {
        ida_format_adapters::elf::notes::analyze(&self.session)
    }

    /// Lists the PE attribute certificate table entries.
    pub fn certificates(&self) -> Result<CertificatesReport> {
        ida_format_adapters::pe::certificates::analyze(&self.session)
    }

    /// Decodes the PE TLS directory and its callback array.
    pub fn tls(&self) -> Result<PeTlsReport> {
        ida_format_adapters::pe::tls::analyze(&self.session)
    }

    /// Decodes the PE load configuration directory.
    pub fn load_config(&self) -> Result<PeLoadConfigReport> {
        ida_format_adapters::pe::load_config::analyze(&self.session)
    }

    /// Decodes `x86` / `x64` instructions from one file offset.
    pub fn disasm(&self, options: &DisassembleOptions) -> Result<DisassemblyReport> {
        crate::workflow::disassemble::analyze(&self.session, options)
    }

    /// Compares this binary against another open binary.
    pub fn diff(&self, other: &Self) -> Result<DiffReport> {
        crate::workflow::compare::compare(&self.session, &other.session)
    }

    /// Computes whole-file and per-section entropy plus the PE overlay.
    pub fn entropy(&self) -> Result<EntropyReport> {
        ida_format_adapters::containers::entropy::analyze(&self.session)
    }

    /// Reports the overlay offset, size, entropy and embedded container signatures.
    pub fn overlay(&self) -> Result<OverlayReport> {
        ida_format_adapters::containers::overlay::analyze(&self.session)
    }

    /// Decodes one embedded zlib, gzip or raw DEFLATE stream.
    pub fn inflate(&self, options: &InflateOptions) -> Result<InflateReport> {
        crate::workflow::extract::inflate::decode(&self.session, options)
    }

    /// Decodes one container (`7z`, `asar` or `NSIS`) selected or sniffed by `format`.
    pub fn unpack(&self, options: &UnpackOptions) -> Result<UnpackReport> {
        crate::workflow::extract::unpack::analyze(&self.session, options)
    }

    /// Decodes a CPython marshal stream or pyc container and disassembles it.
    pub fn pyc(&self, options: &PycOptions) -> Result<PycReport> {
        ida_format_adapters::python::pyc::analyze(&self.session, options)
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
        crate::workflow::patch::apply(&mut self.session, offset, data, None)
    }

    /// Writes a patched copy to `output`, or back to the source when omitted.
    pub fn patch_to(&mut self, offset: u64, data: &[u8], output: Option<&Path>) -> Result<PatchReport> {
        crate::workflow::patch::apply(&mut self.session, offset, data, output)
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
        crate::workflow::inspect::strings::scan(&self.session, options)
    }

    /// Searches the whole file with a byte regex described by `options`.
    pub fn find(&self, options: &FindOptions) -> Result<FindReport> {
        crate::workflow::inspect::find::find(&self.session, options)
    }

    /// Exports a raw byte range from the file into a caller-chosen path.
    pub fn dump(&self, options: &DumpOptions) -> Result<DumpReport> {
        crate::workflow::extract::dump::dump(&self.session, options)
    }

    /// Extracts the printable regions around every marker match.
    pub fn carve(&self, options: &CarveOptions) -> Result<CarveReport> {
        crate::workflow::extract::carve::carve(&self.session, options)
    }

    /// Extracts the embedded assets of a Tauri v2 container.
    pub fn tauri_assets(&self, options: &TauriAssetsOptions) -> Result<TauriAssetsReport> {
        crate::workflow::extract::tauri::tauri_assets(&self.session, options)
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
        ida_format_adapters::pe::debug::analyze(&self.session, limit)
    }

    /// Decodes the PE version resource (`RT_VERSION`).
    pub fn version(&self) -> Result<VersionReport> {
        ida_format_adapters::pe::version::analyze(&self.session)
    }

    /// Decodes Mach-O load commands, segments, sections, dylibs and identity.
    pub fn macho(&self) -> Result<MachOReport> {
        ida_format_adapters::macho::image::analyze(&self.session)
    }

    /// Lists the Mach-O `LC_SYMTAB` symbol table.
    pub fn macho_symbols(&self, limit: Option<usize>) -> Result<MachOSymbolsReport> {
        ida_format_adapters::macho::symbols::symbols(&self.session, limit)
    }

    /// Decodes the Mach-O `LC_FUNCTION_STARTS` delta table.
    pub fn macho_function_starts(&self, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
        ida_format_adapters::macho::function_starts::function_starts(&self.session, limit)
    }

    /// Decodes the dyld export trie of a Mach-O image.
    pub fn macho_exports(&self) -> Result<MachOExportsReport> {
        ida_format_adapters::macho::exports::exports(&self.session)
    }

    /// Lists the architecture slices of a fat/universal Mach-O container.
    pub fn macho_slices(&self) -> Result<MachOSlicesReport> {
        ida_format_adapters::macho::fat::slices(&self.session)
    }

    /// Decodes `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`.
    pub fn macho_encryption(&self) -> Result<MachOEncryptionReport> {
        ida_format_adapters::macho::encryption::encryption(&self.session)
    }

    /// Decodes `LC_DYLD_CHAINED_FIXUPS` imports and its starts table.
    pub fn macho_chained_fixups(&self) -> Result<MachOChainedFixupsReport> {
        ida_format_adapters::macho::chained_fixups::chained_fixups(&self.session)
    }

    /// Decodes the classic dyld bind, weak-bind and lazy-bind opcode streams.
    pub fn macho_bindings(&self) -> Result<MachOBindingsReport> {
        ida_format_adapters::macho::bindings::bindings(&self.session)
    }

    /// Decodes the Mach-O embedded code signature and its first `CodeDirectory`.
    pub fn code_signature(&self) -> Result<MachOCodeSignatureReport> {
        ida_format_adapters::macho::code_signature::analyze(&self.session)
    }

    /// Writes one fat/universal Mach-O slice to a caller-chosen path.
    pub fn extract_slice(&self, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
        ida_format_adapters::macho::fat::extract(&self.session, index, output)
    }

    /// Summarises the PE mitigation posture.
    pub fn mitigations(&self) -> Result<MitigationsReport> {
        ida_format_adapters::pe::mitigations::analyze(&self.session)
    }

    /// Lists the PE resource directory leaves.
    pub fn resources(&self) -> Result<ResourcesReport> {
        ida_format_adapters::pe::resources::analyze(&self.session)
    }

    /// Decodes the PE exception directory runtime functions.
    pub fn exception(&self) -> Result<PeExceptionReport> {
        ida_format_adapters::pe::exception::analyze(&self.session)
    }

    /// Decodes the PE delay-import descriptors and their thunks.
    pub fn delay_imports(&self) -> Result<PeDelayImportsReport> {
        ida_format_adapters::pe::delay_imports::analyze(&self.session)
    }

    /// Decodes the PE bound-import descriptors and their forwarder refs.
    pub fn bound_imports(&self) -> Result<PeBoundImportsReport> {
        ida_format_adapters::pe::bound_imports::analyze(&self.session)
    }

    /// Decodes the Rich header build stamp between the DOS stub and the PE header.
    pub fn rich_header(&self) -> Result<PeRichHeaderReport> {
        ida_format_adapters::pe::rich_header::analyze(&self.session)
    }

    /// Decodes the PE base relocation blocks.
    pub fn relocations(&self) -> Result<RelocationsReport> {
        ida_format_adapters::pe::relocations::analyze(&self.session)
    }

    /// Reports ELF `PT_INTERP` and `PT_DYNAMIC` dependencies.
    pub fn dynamic(&self) -> Result<ElfDynamicReport> {
        ida_format_adapters::elf::dynamic::analyze(&self.session)
    }

    /// Lists the ELF static symbol table (`.symtab`) entries.
    pub fn static_symbols(&self) -> Result<ElfStaticSymbolsReport> {
        ida_format_adapters::elf::symbols::analyze(&self.session)
    }

    /// Decodes the ELF program header table.
    pub fn segments(&self) -> Result<ElfSegmentsReport> {
        ida_format_adapters::elf::segments::analyze(&self.session)
    }

    /// Decodes ELF notes: build id, GNU ABI tag and GNU properties.
    pub fn notes(&self) -> Result<ElfNotesReport> {
        ida_format_adapters::elf::notes::analyze(&self.session)
    }

    /// Lists the PE attribute certificate table entries.
    pub fn certificates(&self) -> Result<CertificatesReport> {
        ida_format_adapters::pe::certificates::analyze(&self.session)
    }

    /// Decodes the PE TLS directory and its callback array.
    pub fn tls(&self) -> Result<PeTlsReport> {
        ida_format_adapters::pe::tls::analyze(&self.session)
    }

    /// Decodes the PE load configuration directory.
    pub fn load_config(&self) -> Result<PeLoadConfigReport> {
        ida_format_adapters::pe::load_config::analyze(&self.session)
    }

    /// Decodes `x86` / `x64` instructions from one file offset.
    pub fn disasm(&self, options: &DisassembleOptions) -> Result<DisassemblyReport> {
        crate::workflow::disassemble::analyze(&self.session, options)
    }

    /// Compares this binary against another open binary.
    pub fn diff(&self, other: &Self) -> Result<DiffReport> {
        crate::workflow::compare::compare(&self.session, &other.session)
    }

    /// Computes whole-file and per-section entropy plus the PE overlay.
    pub fn entropy(&self) -> Result<EntropyReport> {
        ida_format_adapters::containers::entropy::analyze(&self.session)
    }

    /// Reports the overlay offset, size, entropy and embedded container signatures.
    pub fn overlay(&self) -> Result<OverlayReport> {
        ida_format_adapters::containers::overlay::analyze(&self.session)
    }

    /// Decodes one embedded zlib, gzip or raw DEFLATE stream.
    pub fn inflate(&self, options: &InflateOptions) -> Result<InflateReport> {
        crate::workflow::extract::inflate::decode(&self.session, options)
    }

    /// Decodes one container (`7z`, `asar` or `NSIS`) selected or sniffed by `format`.
    pub fn unpack(&self, options: &UnpackOptions) -> Result<UnpackReport> {
        crate::workflow::extract::unpack::analyze(&self.session, options)
    }

    /// Decodes a CPython marshal stream or pyc container and disassembles it.
    pub fn pyc(&self, options: &PycOptions) -> Result<PycReport> {
        ida_format_adapters::python::pyc::analyze(&self.session, options)
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
        crate::workflow::patch::apply(&mut self.session, offset, data, output)
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
