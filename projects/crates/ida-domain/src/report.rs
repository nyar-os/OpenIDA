//! Public report surface.
//!
//! One place lists every report the product exposes: the upstream observation
//! types, the format projections owned by `ida-format-adapters` and the
//! workflow reports owned here. Fields and serde names are contract; a report
//! always carries `total` and `truncated` when the answer is bounded.

pub use data_binary_inspect::{
    Architecture, BinaryFormat, BinaryInfo, BinarySession, ExportEntry, ExportsReport, ImportEntry, ImportsReport,
    InspectOptions, PatchReport, SearchHit, SearchMode, SearchOptions, SearchReport, SectionInfo as Section, StringHit,
    StringsReport, SymbolEntry, SymbolsReport,
};

/// Whether a byte window looks like a `marshal` stream or a `.pyc` container.
pub use ida_format_adapters::python::pyc::sniff as sniff_pyc;
pub use ida_format_adapters::{
    containers::{
        asar::{AsarEntry, AsarHeader, AsarReport},
        entropy::{EntropyReport, OverlayInfo, SectionEntropy},
        nsis::{NsisBlock, NsisCommand, NsisFile, NsisHeader, NsisReport},
        overlay::{OverlayReport, OverlaySignature},
    },
    elf::{
        dynamic::ElfDynamicReport,
        notes::{ElfAbiTag, ElfGnuProperty, ElfNote, ElfNotesReport},
        segments::{ElfSegment, ElfSegmentsReport},
        symbols::{ElfStaticSymbol, ElfStaticSymbolsReport},
    },
    macho::{
        MachOBinding, MachOBindingsReport, MachOChainedFixupsHeader, MachOChainedFixupsReport, MachOChainedImport,
        MachOCodeDirectory, MachOCodeSignatureReport, MachODylib, MachOEncryptionReport, MachOExport, MachOExportsReport,
        MachOFunctionStartsReport, MachOReport, MachOSection, MachOSegment, MachOSlice, MachOSliceExtraction,
        MachOSlicesReport, MachOSymbol, MachOSymbolsReport,
    },
    pe::{
        bound_imports::{PeBoundForwarder, PeBoundImportsReport, PeBoundModule},
        certificates::{CertificatesReport, PeCertificate},
        debug::{CodeViewInfo, DebugEntry, DebugReport},
        delay_imports::{PeDelayImportsReport, PeDelayModule, PeDelayThunk},
        exception::{PeExceptionReport, PeRuntimeFunction, PeUnwindInfo},
        load_config::{CodeIntegrityInfo, PeLoadConfigReport},
        mitigations::{MitigationsReport, WritableExecutableSection},
        relocations::{RelocationBlock, RelocationKindCount, RelocationsReport},
        resources::{PeResource, ResourcesReport},
        rich_header::{PeRichEntry, PeRichHeaderReport},
        tls::{PeTlsCallback, PeTlsReport},
        version::{FixedFileInfo, VersionReport, VersionString},
    },
    python::{
        pyc::{PycCodeObject, PycConst, PycFormat, PycInstruction, PycOptions, PycReport},
        pyinstaller::{PyInstallerEntry, PyInstallerModule, PyInstallerOptions, PyInstallerReport},
    },
};

pub use crate::workflow::{
    compare::{DiffRange, DiffReport},
    disassemble::{DisassembleOptions, DisassemblyInstruction, DisassemblyReport, DisassemblySyntax},
    extract::{
        carve::{CarveOptions, CarveRegion, CarveReport},
        dump::{DumpOptions, DumpReport},
        inflate::{InflateFormat, InflateOptions, InflateReport},
        tauri::{TauriAsset, TauriAssetsOptions, TauriAssetsReport, scan_assets},
        unpack::{SevenZEntry, SevenZFolder, SevenZPackRange, SevenZReport, UnpackFormat, UnpackOptions, UnpackReport},
    },
    inspect::{
        find::{FindHit, FindOptions, FindReport},
        strings::{EncodedStringHit, EncodedStringsReport, StringEncoding, StringsOptions},
    },
};
