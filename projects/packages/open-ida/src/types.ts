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
