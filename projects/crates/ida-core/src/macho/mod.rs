//! Mach-O load commands, segments, sections, dylibs and image identity.
//!
//! The header, segment and section tables come from `data-binary-mach-o`.
//! The pinned release does not expose `LC_UUID`, `LC_BUILD_VERSION`,
//! `LC_VERSION_MIN_*`, the dylib commands or `LC_SYMTAB`, so those are decoded
//! here from the same load-command stream. The classic dyld bind, weak-bind and
//! lazy-bind opcode streams are decoded by `bindings`; the rebase stream and
//! the chained fixup pointers are not.
//! Fat/universal containers are reported as an architecture table; a thin
//! image is inspected directly and does not have slices.

mod bindings;
mod chained_fixups;
mod encryption;
mod exports;
mod fat;
mod function_starts;
mod image;
mod symbols;
mod util;

pub(crate) use bindings::bindings;
pub(crate) use chained_fixups::chained_fixups;
pub(crate) use encryption::encryption;
pub(crate) use exports::exports;
pub(crate) use fat::{extract, slices};
pub(crate) use function_starts::function_starts;
pub(crate) use image::analyze;
pub(crate) use symbols::symbols;

pub use bindings::{MachOBinding, MachOBindingsReport};
pub use chained_fixups::{MachOChainedFixupsHeader, MachOChainedFixupsReport, MachOChainedImport};
pub use encryption::MachOEncryptionReport;
pub use exports::{MachOExport, MachOExportsReport};
pub use fat::{MachOSlice, MachOSliceExtraction, MachOSlicesReport};
pub use function_starts::MachOFunctionStartsReport;
pub use image::{MachODylib, MachOReport, MachOSection, MachOSegment};
pub use symbols::{MachOSymbol, MachOSymbolsReport};

const LC_SYMTAB: u32 = 0x2;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_LOAD_DYLIB: u32 = 0x0c;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// Upper bound on the declared slice count, so a corrupt header cannot force a
/// huge allocation.
const MAX_FAT_SLICES: usize = 256;
const LC_ID_DYLIB: u32 = 0x0d;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_VERSION_MIN_TVOS: u32 = 0x2f;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_UUID: u32 = 0x1b;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;

const HEADER32_SIZE: usize = 28;
const HEADER64_SIZE: usize = 32;
