//! Mach-O format projections.
//!
//! `data-binary-mach-o` owns the header, the load-command stream, segments,
//! sections, `LC_SYMTAB`, `LC_UUID`, `LC_BUILD_VERSION` / `LC_VERSION_MIN_*`,
//! the dylib commands, the classic bind streams, the export trie, encryption,
//! chained fixups, function starts, the embedded code signature and the fat
//! slice table. Every module here maps those owner types onto the product JSON
//! reports and keeps no decoder of its own.

pub mod bindings;
pub mod chained_fixups;
pub mod code_signature;
pub mod encryption;
pub mod exports;
pub mod fat;
pub mod function_starts;
pub mod image;
pub mod symbols;

pub use bindings::{MachOBinding, MachOBindingsReport};
pub use chained_fixups::{MachOChainedFixupsHeader, MachOChainedFixupsReport, MachOChainedImport};
pub use code_signature::{MachOCodeDirectory, MachOCodeSignatureReport};
pub use encryption::MachOEncryptionReport;
pub use exports::{MachOExport, MachOExportsReport};
pub use fat::{MachOSlice, MachOSliceExtraction, MachOSlicesReport};
pub use function_starts::MachOFunctionStartsReport;
pub use image::{MachODylib, MachOReport, MachOSection, MachOSegment};
pub use symbols::{MachOSymbol, MachOSymbolsReport};
