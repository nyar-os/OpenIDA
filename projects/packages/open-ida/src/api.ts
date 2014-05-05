/**
 * The OpenIDA API.
 *
 * `new OpenIDA(options)` opens one binary and carries the defaults every
 * operation uses; the instance methods are the product surface. The CLI is a
 * thin renderer over this class, so the two can never disagree about a file.
 * No analysis is re-implemented in TypeScript.
 */

import { NotImplementedError, translateNativeError } from './errors.js';
import { nativeBinding } from './native.js';
import type {
    BinaryHandle,
    BinaryInfo,
    Capabilities,
    ExportsReport,
    HexdumpReport,
    ImportsReport,
    OffsetToRvaReport,
    OffsetToVaReport,
    PatchReport,
    ReadReport,
    RvaReport,
    SearchOptions,
    SearchReport,
    SectionsReport,
    StringsReport,
    SymbolsReport,
} from './types.js';

/** Inputs of one engine session. Defaults mirror `open-ida-core`. */
export interface OpenIdaOptions {
    /** Binary to open. */
    readonly path: string;
    /** Minimum printable run length used when `strings()` gets no explicit minimum. */
    readonly minStringLen?: number;
    /** Hit limit used when `strings()` gets no explicit limit; `null` means unlimited. */
    readonly stringsLimit?: number | null;
    /** Byte count used when `hexdump()` gets no explicit length. */
    readonly hexdumpLength?: number;
}

function binding(feature: string) {
    const native = nativeBinding();
    if (!native) {
        throw new NotImplementedError(feature);
    }
    return native;
}

function decode<T>(work: () => string): T {
    try {
        return JSON.parse(work()) as T;
    } catch (error) {
        throw translateNativeError(error);
    }
}

/** Reads the capability matrix of the installed engine. */
export function capabilities(): Capabilities {
    return decode<Capabilities>(() => binding('capabilities').capabilities());
}

/** One open binary and the defaults its operations use. */
export class OpenIDA {
    private readonly id: number;

    /** Opens `options.path`; a JSON string is accepted for custom clients. */
    constructor(options: OpenIdaOptions | string) {
        const encoded = typeof options === 'string' ? options : JSON.stringify(options);
        this.id = decode<BinaryHandle>(() => binding('binary.open').binary_open(encoded)).handle;
    }

    /** Native handle backing this session. */
    get handle(): number {
        return this.id;
    }

    /** Header summary. */
    info(): BinaryInfo {
        return decode<BinaryInfo>(() => binding('binary.info').binary_info(this.id));
    }

    /** Section table. */
    sections(): SectionsReport {
        return decode<SectionsReport>(() => binding('binary.sections').binary_sections(this.id));
    }

    /** Extracts printable strings, falling back to the session defaults. */
    strings(minLen?: number, limit?: number): StringsReport {
        return decode<StringsReport>(() => binding('binary.strings').binary_strings(this.id, minLen, limit));
    }

    /** Lists imported functions. */
    imports(limit?: number): ImportsReport {
        return decode<ImportsReport>(() => binding('binary.imports').binary_imports(this.id, limit));
    }

    /** Lists exported symbols. */
    exports(limit?: number): ExportsReport {
        return decode<ExportsReport>(() => binding('binary.exports').binary_exports(this.id, limit));
    }

    /** Lists debug or dynamic symbols. */
    symbols(limit?: number): SymbolsReport {
        return decode<SymbolsReport>(() => binding('binary.symbols').binary_symbols(this.id, limit));
    }

    /** Searches for a hex, ASCII or UTF-16LE pattern. */
    search(options: SearchOptions): SearchReport {
        return decode<SearchReport>(() => binding('binary.search').binary_search(this.id, JSON.stringify(options)));
    }

    /** Renders a hex dump, falling back to the session defaults. */
    hexdump(offset?: number, length?: number): HexdumpReport {
        return decode<HexdumpReport>(() => binding('binary.hexdump').binary_hexdump(this.id, offset, length));
    }

    /** Reads one byte range and returns it as a hex string. */
    read(offset: number, length: number): ReadReport {
        return decode<ReadReport>(() => binding('binary.read').binary_read(this.id, offset, length));
    }

    /** Patches bytes atomically, writing a copy when `output` is given. */
    patch(offset: number, hexBytes: string, output?: string): PatchReport {
        return decode<PatchReport>(() =>
            output === undefined
                ? binding('binary.patch').binary_patch(this.id, offset, hexBytes)
                : binding('binary.patch').binary_patch(this.id, offset, hexBytes, output),
        );
    }

    /** Maps an RVA or virtual address onto a file offset. */
    rva(address: number): RvaReport {
        return decode<RvaReport>(() => binding('binary.rva').binary_rva(this.id, address));
    }

    /** Maps a file offset onto an absolute virtual address. */
    offsetToVa(offset: number): OffsetToVaReport {
        return decode<OffsetToVaReport>(() => binding('binary.offset_to_va').binary_offset_to_va(this.id, offset));
    }

    /** Maps a file offset onto a PE image-relative address. */
    offsetToRva(offset: number): OffsetToRvaReport {
        return decode<OffsetToRvaReport>(() => binding('binary.offset_to_rva').binary_offset_to_rva(this.id, offset));
    }

    /** Releases the native handle. Closing twice is reported by the engine. */
    close(): void {
        binding('binary.close').binary_close(this.id);
    }
}
