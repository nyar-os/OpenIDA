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
export type Architecture = 'x86' | 'x64' | 'arm64' | 'unknown';

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
    readonly engine: { readonly package: string; readonly version: string };
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
