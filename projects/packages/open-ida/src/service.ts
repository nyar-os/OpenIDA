/**
 * Orthogonal native operations.
 *
 * One function performs one operation and returns data; argument parsing, help
 * text and exit codes belong to `cli.ts`. Nothing here knows about a command
 * line, and no analysis is re-implemented in TypeScript.
 */

import { NotImplementedError, translateNativeError } from './errors.js';
import { nativeBinding } from './native.js';
import type {
    BinaryHandle,
    BinaryInfo,
    Capabilities,
    HexdumpReport,
    PatchReport,
    ReadReport,
    RvaReport,
    SectionsReport,
    StringsReport,
} from './types.js';

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

/** Opens a binary and returns its handle and header summary. */
export function open(path: string): BinaryHandle {
    return decode<BinaryHandle>(() => binding('binary.open').binary_open(path));
}

/** Reads the header summary of one handle. */
export function info(handle: number): BinaryInfo {
    return decode<BinaryInfo>(() => binding('binary.info').binary_info(handle));
}

/** Reads the section table of one handle. */
export function sections(handle: number): SectionsReport {
    return decode<SectionsReport>(() => binding('binary.sections').binary_sections(handle));
}

/** Extracts printable strings, bounded by a minimum length and an optional limit. */
export function strings(handle: number, minLen = 4, limit?: number): StringsReport {
    return decode<StringsReport>(() =>
        limit === undefined
            ? binding('binary.strings').binary_strings(handle, minLen)
            : binding('binary.strings').binary_strings(handle, minLen, limit),
    );
}

/** Renders a canonical hex dump of one byte range. */
export function hexdump(handle: number, offset = 0, length = 256): HexdumpReport {
    return decode<HexdumpReport>(() => binding('binary.hexdump').binary_hexdump(handle, offset, length));
}

/** Reads one byte range and returns it as a hex string. */
export function read(handle: number, offset: number, length: number): ReadReport {
    return decode<ReadReport>(() => binding('binary.read').binary_read(handle, offset, length));
}

/** Patches bytes atomically, writing a copy when `output` is given. */
export function patch(handle: number, offset: number, hexBytes: string, output?: string): PatchReport {
    return decode<PatchReport>(() =>
        output === undefined
            ? binding('binary.patch').binary_patch(handle, offset, hexBytes)
            : binding('binary.patch').binary_patch(handle, offset, hexBytes, output),
    );
}

/** Maps an RVA or virtual address onto a file offset. */
export function rva(handle: number, address: number): RvaReport {
    return decode<RvaReport>(() => binding('binary.rva').binary_rva(handle, address));
}

/** Releases one binary handle. */
export function close(handle: number): void {
    binding('binary.close').binary_close(handle);
}
