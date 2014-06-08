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
    CertificatesReport,
    DebugReport,
    DiffReport,
    DisassembleOptions,
    DisassemblyReport,
    ElfDynamicReport,
    ElfNotesReport,
    ElfSegmentsReport,
    ElfStaticSymbolsReport,
    EncodedStringsReport,
    EntropyReport,
    ExportsReport,
    HexdumpReport,
    ImportsReport,
    MachOReport,
    MachOSlicesReport,
    MachOSliceExtraction,
    MachOExportsReport,
    MachOEncryptionReport,
    MachOChainedFixupsReport,
    MachOFunctionStartsReport,
    MachOSymbolsReport,
    MachOCodeSignatureReport,
    MitigationsReport,
    OffsetToRvaReport,
    OffsetToVaReport,
    PatchReport,
    PeBoundImportsReport,
    PeDelayImportsReport,
    PeExceptionReport,
    PeRichHeaderReport,
    PeLoadConfigReport,
    PeTlsReport,
    ReadReport,
    RelocationsReport,
    ResourcesReport,
    RvaReport,
    SearchOptions,
    SearchReport,
    SectionsReport,
    StringsOptions,
    StringsReport,
    SymbolsReport,
    VersionReport,
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

    /** Extracts ASCII or ASCII-in-UTF-16LE strings with the requested encoding. */
    stringsEncoded(options: StringsOptions = {}): EncodedStringsReport {
        return decode<EncodedStringsReport>(() =>
            binding('binary.strings_encoded').binary_strings_encoded(this.id, JSON.stringify(options)),
        );
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

    /** Lists PE debug directory entries and `CodeView` PDB records. */
    debug(limit?: number): DebugReport {
        return decode<DebugReport>(() => binding('binary.debug').binary_debug(this.id, limit));
    }

    /** Decodes the PE version resource (`RT_VERSION`). */
    version(): VersionReport {
        return decode<VersionReport>(() => binding('binary.version').binary_version(this.id));
    }

    /** Decodes Mach-O load commands, segments, sections, dylibs and identity. */
    macho(): MachOReport {
        return decode<MachOReport>(() => binding('binary.macho').binary_macho(this.id));
    }

    /** Lists the Mach-O `LC_SYMTAB` symbol table. */
    machoSymbols(limit?: number): MachOSymbolsReport {
        return decode<MachOSymbolsReport>(() => binding('binary.macho_symbols').binary_macho_symbols(this.id, limit));
    }

    /** Decodes the dyld export trie of a Mach-O image. */
    machoExports(): MachOExportsReport {
        return decode<MachOExportsReport>(() => binding('binary.macho_exports').binary_macho_exports(this.id));
    }

    /** Decodes `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`. */
    machoEncryption(): MachOEncryptionReport {
        return decode<MachOEncryptionReport>(() => binding('binary.macho_encryption').binary_macho_encryption(this.id));
    }

    /** Decodes `LC_DYLD_CHAINED_FIXUPS` imports and its starts table. */
    machoChainedFixups(): MachOChainedFixupsReport {
        return decode<MachOChainedFixupsReport>(() =>
            binding('binary.macho_chained_fixups').binary_macho_chained_fixups(this.id),
        );
    }

    /** Decodes the Mach-O `LC_FUNCTION_STARTS` delta table. */
    machoFunctionStarts(limit?: number): MachOFunctionStartsReport {
        return decode<MachOFunctionStartsReport>(() =>
            binding('binary.macho_function_starts').binary_macho_function_starts(this.id, limit),
        );
    }

    /** Lists the architecture slices of a fat/universal Mach-O container. */
    machoSlices(): MachOSlicesReport {
        return decode<MachOSlicesReport>(() => binding('binary.macho_slices').binary_macho_slices(this.id));
    }

    /** Decodes the Mach-O embedded code signature and its first `CodeDirectory`. */
    codeSignature(): MachOCodeSignatureReport {
        return decode<MachOCodeSignatureReport>(() => binding('binary.code_signature').binary_code_signature(this.id));
    }

    /** Writes one fat/universal Mach-O slice to `output`. */
    extractSlice(index: number, output: string): MachOSliceExtraction {
        return decode<MachOSliceExtraction>(() =>
            binding('binary.macho_extract').binary_macho_extract(this.id, index, output),
        );
    }

    /** Summarises the PE mitigation posture. */
    mitigations(): MitigationsReport {
        return decode<MitigationsReport>(() => binding('binary.mitigations').binary_mitigations(this.id));
    }

    /** Lists the PE resource directory leaves. */
    resources(): ResourcesReport {
        return decode<ResourcesReport>(() => binding('binary.resources').binary_resources(this.id));
    }

    /** Decodes the PE exception directory runtime functions. */
    exception(): PeExceptionReport {
        return decode<PeExceptionReport>(() => binding('binary.exception').binary_exception(this.id));
    }

    /** Decodes the PE delay-import descriptors and their thunks. */
    delayImports(): PeDelayImportsReport {
        return decode<PeDelayImportsReport>(() => binding('binary.delay_imports').binary_delay_imports(this.id));
    }

    /** Decodes the PE bound-import descriptors and their forwarder refs. */
    boundImports(): PeBoundImportsReport {
        return decode<PeBoundImportsReport>(() => binding('binary.bound_imports').binary_bound_imports(this.id));
    }

    /** Decodes the Rich header build stamp between the DOS stub and the PE header. */
    richHeader(): PeRichHeaderReport {
        return decode<PeRichHeaderReport>(() => binding('binary.rich_header').binary_rich_header(this.id));
    }

    /** Lists the ELF static symbol table (`.symtab`) entries. */
    staticSymbols(): ElfStaticSymbolsReport {
        return decode<ElfStaticSymbolsReport>(() => binding('binary.static_symbols').binary_static_symbols(this.id));
    }

    /** Decodes the PE base relocation blocks. */
    relocations(): RelocationsReport {
        return decode<RelocationsReport>(() => binding('binary.relocations').binary_relocations(this.id));
    }

    /** Reports ELF `PT_INTERP` and `PT_DYNAMIC` dependencies. */
    dynamic(): ElfDynamicReport {
        return decode<ElfDynamicReport>(() => binding('binary.dynamic').binary_dynamic(this.id));
    }

    /** Decodes the ELF program header table. */
    segments(): ElfSegmentsReport {
        return decode<ElfSegmentsReport>(() => binding('binary.segments').binary_segments(this.id));
    }

    /** Decodes ELF notes: build id, GNU ABI tag and GNU properties. */
    notes(): ElfNotesReport {
        return decode<ElfNotesReport>(() => binding('binary.notes').binary_notes(this.id));
    }

    /** Lists the PE attribute certificate table entries. */
    certificates(): CertificatesReport {
        return decode<CertificatesReport>(() => binding('binary.certificates').binary_certificates(this.id));
    }

    /** Decodes the PE TLS directory and its callback array. */
    tls(): PeTlsReport {
        return decode<PeTlsReport>(() => binding('binary.tls').binary_tls(this.id));
    }

    /** Decodes the PE load configuration directory. */
    loadConfig(): PeLoadConfigReport {
        return decode<PeLoadConfigReport>(() => binding('binary.load-config').binary_load_config(this.id));
    }

    /** Decodes x86 / x64 instructions from one file offset. */
    disasm(options: DisassembleOptions = {}): DisassemblyReport {
        return decode<DisassemblyReport>(() => binding('binary.disasm').binary_disasm(this.id, JSON.stringify(options)));
    }

    /** Compares this binary against another open binary. */
    diff(other: OpenIDA): DiffReport {
        return decode<DiffReport>(() => binding('binary.diff').binary_diff(this.id, other.handle));
    }

    /** Computes whole-file and per-section entropy plus the PE overlay. */
    entropy(): EntropyReport {
        return decode<EntropyReport>(() => binding('binary.entropy').binary_entropy(this.id));
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
