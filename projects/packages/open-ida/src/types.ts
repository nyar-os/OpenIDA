/**
 * Report shapes of `@wae/open-ida`.
 *
 * These interfaces mirror the JSON the built-in engine returns. Numbers are
 * plain JavaScript numbers: every offset, size and hash in this domain fits a
 * safe integer, and hashes travel as hex strings.
 */

/** Detected container. */
export type BinaryFormat = 'pe' | 'elf' | 'macho' | 'unknown';

/** Detected architecture. */
export type Architecture = 'x86' | 'x64' | 'arm' | 'arm64' | 'unknown';

/** One section or segment. */
export interface Section {
    readonly name: string;
    readonly virtualAddress: number;
    readonly virtualSize: number;
    readonly rawPointer: number;
    readonly rawSize: number;
    readonly characteristics: number;
    readonly readable: boolean;
    readonly writable: boolean;
    readonly executable: boolean;
}

/** Header summary of an open binary. */
export interface BinaryInfo {
    readonly path: string;
    readonly size: number;
    readonly format: BinaryFormat;
    readonly architecture: Architecture;
    readonly hash: string;
    readonly magic: string | null;
    readonly endian: string | null;
    readonly entry: number | null;
    readonly entryRva: number | null;
    readonly imageBase: number | null;
    readonly sectionCount: number;
    readonly cpuType: number | null;
    readonly fileType: number | null;
    readonly commandCount: number | null;
}

/** One printable ASCII run. */
export interface StringHit {
    readonly offset: number;
    readonly length: number;
    readonly value: string;
}

/** Encoding used to scan for strings. */
export type StringEncoding = 'ascii' | 'utf16le' | 'both';

/** Inputs of one `stringsEncoded()` call. */
export interface StringsOptions {
    /** Minimum number of characters in a run; defaults to 4. */
    readonly minLength?: number;
    /** Maximum number of hits; defaults to 100 and is capped at 10000. */
    readonly limit?: number;
    /** Encoding to scan for; defaults to `ascii`. */
    readonly encoding?: StringEncoding;
}

/** One decoded string run. */
export interface EncodedStringHit {
    readonly offset: number;
    readonly length: number;
    readonly encoding: StringEncoding;
    readonly value: string;
}

/** Bounded result of one encoded string scan. */
export interface EncodedStringsReport {
    readonly encoding: StringEncoding;
    readonly minLength: number;
    readonly limit: number;
    readonly hits: readonly EncodedStringHit[];
    readonly total: number;
    readonly truncated: boolean;
}

/** Result of one atomic patch. */
export interface PatchReport {
    readonly path: string;
    readonly offset: number;
    readonly length: number;
    readonly beforeHash: string;
    readonly afterHash: string;
}

/** What the installed engine implements and what it does not. */
export interface Capabilities {
    readonly engine: { readonly package: string; readonly version: string; readonly api: string };
    readonly formats: Readonly<Record<string, string>>;
    readonly features: Readonly<Record<string, string>>;
    readonly unsupported: Readonly<Record<string, string>>;
    readonly architectures: Readonly<Record<string, string>>;
}

/** An open binary handle plus its header summary. */
export interface BinaryHandle {
    readonly handle: number;
    readonly info: BinaryInfo;
}

/** Section listing. */
export interface SectionsReport {
    readonly sections: readonly Section[];
}

/** Bounded string extraction. */
export interface StringsReport {
    readonly hits: readonly StringHit[];
    readonly total: number;
    readonly truncated: boolean;
}

/** One imported function. */
export interface ImportEntry {
    readonly module: string;
    readonly name: string | null;
    readonly ordinal: number | null;
    readonly address: number | null;
}

/** Bounded import listing. */
export interface ImportsReport {
    readonly entries: readonly ImportEntry[];
    readonly total: number;
    readonly truncated: boolean;
}

/** One exported symbol. */
export interface ExportEntry {
    readonly name: string | null;
    readonly ordinal: number | null;
    readonly address: number | null;
    readonly forwarder: string | null;
}

/** Bounded export listing. */
export interface ExportsReport {
    readonly entries: readonly ExportEntry[];
    readonly total: number;
    readonly truncated: boolean;
}

/** One debug or dynamic symbol. */
export interface SymbolEntry {
    readonly name: string;
    readonly address: number;
    readonly size: number;
    readonly kind: string;
    readonly binding: string;
    readonly section: string | null;
}

/** Bounded symbol listing. */
export interface SymbolsReport {
    readonly entries: readonly SymbolEntry[];
    readonly total: number;
    readonly truncated: boolean;
}

/** One `CodeView` payload from a PE debug directory. */
export interface CodeViewInfo {
    readonly signature: string;
    readonly guid: string | null;
    readonly age: number;
    /** `NB10` record offset; `null` for `RSDS`. */
    readonly offset: number | null;
    /** `NB10` timestamp; `null` for `RSDS`. */
    readonly timestamp: number | null;
    readonly path: string;
}

/** One PE debug directory entry. */
export interface DebugEntry {
    readonly debugType: string;
    readonly timestamp: number;
    readonly majorVersion: number;
    readonly minorVersion: number;
    readonly sizeOfData: number;
    readonly addressOfRawData: number;
    readonly pointerToRawData: number;
    readonly codeView: CodeViewInfo | null;
}

/** Bounded PE debug directory listing. */
export interface DebugReport {
    readonly entries: readonly DebugEntry[];
    readonly total: number;
    readonly truncated: boolean;
}

/** Fixed part of a PE `VS_VERSIONINFO` resource. */
export interface FixedFileInfo {
    readonly signature: number;
    readonly structVersion: number;
    readonly fileVersion: string;
    readonly productVersion: string;
    readonly fileFlagsMask: number;
    readonly fileFlags: number;
    readonly fileOs: number;
    readonly fileType: number;
    readonly fileSubtype: number;
    readonly fileDate: number;
}

/** One `StringFileInfo` key/value pair. */
export interface VersionString {
    readonly key: string;
    readonly value: string;
    readonly languageId: number;
    readonly codepage: number;
}

/** Decoded PE version resource. */
export interface VersionReport {
    readonly present: boolean;
    readonly fixed: FixedFileInfo | null;
    readonly strings: readonly VersionString[];
    readonly total: number;
    readonly truncated: boolean;
    readonly note: string | null;
}

/** One linked or identifying Mach-O dylib command. */
export interface MachODylib {
    readonly kind: 'load' | 'id' | 'weak' | 'reexport' | 'lazy' | 'upward';
    readonly name: string;
    readonly timestamp: number;
    readonly currentVersion: string;
    readonly compatibilityVersion: string;
}

/** One Mach-O segment. */
export interface MachOSegment {
    readonly name: string;
    readonly vmAddress: number;
    readonly vmSize: number;
    readonly fileOffset: number;
    readonly fileSize: number;
    readonly readable: boolean;
    readonly writable: boolean;
    readonly executable: boolean;
}

/** One Mach-O section with its owning segment. */
export interface MachOSection {
    readonly segment: string;
    readonly name: string;
    readonly address: number;
    readonly size: number;
    readonly fileOffset: number;
    readonly alignment: number;
    readonly flags: number;
    readonly readable: boolean;
    readonly writable: boolean;
    readonly executable: boolean;
}

/** Full Mach-O image summary. */
export interface MachOReport {
    readonly is64: boolean;
    readonly endian: 'little' | 'big';
    readonly cpuType: number;
    readonly cpuSubtype: number;
    readonly architecture: string;
    readonly fileType: number;
    readonly kind: string;
    readonly flags: number;
    readonly commandCount: number;
    readonly sizeOfCommands: number;
    readonly uuid: string | null;
    readonly platform: string | null;
    readonly minOs: string | null;
    readonly sdk: string | null;
    readonly entryOffset: number | null;
    readonly entryAddress: number | null;
    readonly dylibs: readonly MachODylib[];
    readonly segments: readonly MachOSegment[];
    readonly sections: readonly MachOSection[];
}

/** One `LC_SYMTAB` symbol. */
export interface MachOSymbol {
    readonly name: string;
    readonly address: number;
    readonly kind: 'undefined' | 'absolute' | 'section' | 'indirect' | 'prebound' | 'debug' | 'other';
    readonly external: boolean;
    readonly debug: boolean;
    readonly section: number | null;
    readonly descriptor: number;
}

/** Bounded Mach-O symbol table listing. */
export interface MachOSymbolsReport {
    readonly symbols: readonly MachOSymbol[];
    readonly total: number;
    readonly truncated: boolean;
    readonly stringTableSize: number;
}

/** One architecture slice of a fat/universal Mach-O. */
export interface MachOSlice {
    readonly index: number;
    readonly cpuType: number;
    readonly cpuSubtype: number;
    readonly architecture: string;
    readonly offset: number;
    readonly size: number;
    readonly alignment: number;
    readonly bits: 32 | 64 | null;
}

/** Fat/universal Mach-O architecture table. */
export interface MachOSlicesReport {
    readonly isFat64: boolean;
    readonly slices: readonly MachOSlice[];
}

/** One fat slice written to a caller-chosen path. */
export interface MachOSliceExtraction {
    readonly index: number;
    readonly architecture: string;
    readonly offset: number;
    readonly size: number;
    readonly output: string;
}

/** A section mapped with both write and execute permission. */
export interface WritableExecutableSection {
    readonly name: string;
    readonly address: number;
    readonly size: number;
}

/** PE mitigation posture. */
export interface MitigationsReport {
    readonly dllCharacteristics: number;
    readonly aslr: boolean;
    readonly highEntropyVa: boolean;
    readonly dep: boolean;
    readonly cfg: boolean;
    readonly forceIntegrity: boolean;
    readonly noSeh: boolean;
    readonly terminalServerAware: boolean;
    readonly relocationsPresent: boolean;
    readonly signed: boolean;
    readonly writableExecutableSections: readonly WritableExecutableSection[];
    readonly securityCookie: boolean | null;
    readonly guardFlags: number | null;
}

/** One leaf entry of the PE resource directory. */
export interface PeResource {
    readonly resourceType: string;
    readonly name: string;
    readonly language: number;
    readonly dataRva: number;
    readonly size: number;
    readonly codePage: number;
}

/** Bounded PE resource listing. */
export interface ResourcesReport {
    readonly present: boolean;
    readonly resources: readonly PeResource[];
    readonly total: number;
    readonly truncated: boolean;
}

/** Number of fixups of one PE relocation type. */
export interface RelocationKindCount {
    readonly kind: string;
    readonly count: number;
}

/** One `IMAGE_BASE_RELOCATION` block. */
export interface RelocationBlock {
    readonly pageRva: number;
    readonly blockSize: number;
    readonly entries: number;
    readonly kinds: readonly RelocationKindCount[];
}

/** Bounded PE base relocation listing. */
export interface RelocationsReport {
    readonly present: boolean;
    readonly blocks: readonly RelocationBlock[];
    readonly totalBlocks: number;
    readonly totalEntries: number;
    readonly kinds: readonly RelocationKindCount[];
    readonly truncated: boolean;
}

/** Dynamic linking facts of one ELF image. */
export interface ElfDynamicReport {
    readonly present: boolean;
    readonly interpreter: string | null;
    readonly soname: string | null;
    readonly needed: readonly string[];
    readonly rpath: readonly string[];
    readonly runpath: readonly string[];
    readonly dynamicEntries: number;
    readonly truncated: boolean;
}

/** Decoded `NT_GNU_ABI_TAG` description. */
export interface ElfAbiTag {
    readonly os: string;
    readonly major: number;
    readonly minor: number;
    readonly subminor: number;
}

/** One entry of a `NT_GNU_PROPERTY_TYPE_0` note. */
export interface ElfGnuProperty {
    readonly propertyType: string;
    readonly dataSize: number;
    readonly data: string;
}

/** One ELF note record. */
export interface ElfNote {
    readonly owner: string;
    readonly noteType: string;
    readonly descriptionSize: number;
    readonly description: string;
}

/** ELF note facts of one image. */
export interface ElfNotesReport {
    readonly present: boolean;
    readonly source: string | null;
    readonly buildId: string | null;
    readonly abiTag: ElfAbiTag | null;
    readonly properties: readonly ElfGnuProperty[];
    readonly notes: readonly ElfNote[];
    readonly total: number;
    readonly truncated: boolean;
}

/** One `WIN_CERTIFICATE` entry of the PE attribute certificate table. */
export interface PeCertificate {
    readonly offset: number;
    readonly length: number;
    readonly revision: string;
    readonly certificateType: string;
    readonly payloadSize: number;
    readonly pkcs7: boolean;
}

/** Attribute certificate table summary. */
export interface CertificatesReport {
    readonly present: boolean;
    readonly certificates: readonly PeCertificate[];
    readonly total: number;
    readonly directorySize: number;
    readonly truncated: boolean;
}

/** One PE TLS callback address and its file mapping. */
export interface PeTlsCallback {
    readonly address: number;
    readonly rva: number | null;
    readonly offset: number | null;
}

/** PE TLS table summary. */
export interface PeTlsReport {
    readonly present: boolean;
    readonly is64: boolean;
    readonly directoryRva: number;
    readonly directorySize: number;
    readonly rawDataStart: number;
    readonly rawDataEnd: number;
    readonly indexAddress: number;
    readonly callbacksAddress: number;
    readonly callbacksRva: number | null;
    readonly sizeOfZeroFill: number;
    readonly characteristics: number;
    readonly callbacks: readonly PeTlsCallback[];
    readonly truncated: boolean;
}

/** Entropy of one section payload. */
export interface SectionEntropy {
    readonly name: string;
    readonly offset: number;
    readonly size: number;
    readonly entropy: number;
}

/** Bytes that follow the last PE section payload. */
export interface OverlayInfo {
    readonly offset: number;
    readonly size: number;
}

/** Entropy summary of one binary. */
export interface EntropyReport {
    readonly fileSize: number;
    readonly fileEntropy: number;
    readonly sections: readonly SectionEntropy[];
    readonly overlay: OverlayInfo | null;
}

/** One contiguous run of differing bytes. */
export interface DiffRange {
    readonly offset: number;
    readonly length: number;
}

/** Result of one `diff()` call. */
export interface DiffReport {
    readonly leftSize: number;
    readonly rightSize: number;
    readonly leftHash: string;
    readonly rightHash: string;
    readonly identical: boolean;
    readonly firstDifference: number | null;
    readonly differences: readonly DiffRange[];
    readonly total: number;
    readonly truncated: boolean;
    readonly comparedBytes: number;
}

/** Assembly syntax accepted by `disasm()`. */
export type DisassemblySyntax = 'intel' | 'masm' | 'nasm';

/** Inputs of one `disasm()` call. */
export interface DisassembleOptions {
    /** File offset to start decoding from. Defaults to 0. */
    readonly offset?: number;
    /** Maximum number of instructions; defaults to 64 and is capped at 4096. */
    readonly count?: number;
    /** Rendered syntax; defaults to `intel`. */
    readonly syntax?: DisassemblySyntax;
}

/** One decoded instruction. */
export interface DisassemblyInstruction {
    readonly address: number;
    readonly offset: number;
    readonly length: number;
    readonly bytes: string;
    readonly text: string;
}

/** Result of one disassembly request. */
export interface DisassemblyReport {
    readonly architecture: string;
    readonly bitness: number;
    readonly startOffset: number;
    readonly startAddress: number;
    readonly syntax: string;
    readonly instructions: readonly DisassemblyInstruction[];
    readonly truncated: boolean;
}

/** Pattern kinds accepted by `search()`. */
export type SearchMode = 'hex' | 'ascii' | 'utf16le';

/** Inputs of one `search()` call. */
export interface SearchOptions {
    readonly mode: SearchMode;
    readonly pattern: string;
    /** Whether ASCII letters must match case. Defaults to false. */
    readonly caseSensitive?: boolean;
    /** Whether matches must be surrounded by non-word characters. Defaults to false. */
    readonly wholeWord?: boolean;
    /** Maximum number of hits to return. Defaults to 100; `null` means unlimited. */
    readonly limit?: number | null;
    /** First file offset to scan. */
    readonly start?: number;
    /** One past the last file offset to scan. */
    readonly end?: number;
}

/** One pattern match. */
export interface SearchHit {
    readonly offset: number;
    readonly preview: string;
}

/** Bounded search result. */
export interface SearchReport {
    readonly mode: string;
    readonly hits: readonly SearchHit[];
    readonly total: number;
    readonly truncated: boolean;
}

/** File offset mapped onto an absolute virtual address. */
export interface OffsetToVaReport {
    readonly offset: number;
    readonly va: number;
}

/** File offset mapped onto a PE image-relative address. */
export interface OffsetToRvaReport {
    readonly offset: number;
    readonly rva: number;
}

/** Hex dump of one byte range. */
export interface HexdumpReport {
    readonly offset: number;
    readonly length: number;
    readonly text: string;
}

/** Raw byte read rendered as hex. */
export interface ReadReport {
    readonly offset: number;
    readonly length: number;
    readonly hex: string;
}

/** RVA to file-offset mapping. */
export interface RvaReport {
    readonly rva: number;
    readonly offset: number;
}
