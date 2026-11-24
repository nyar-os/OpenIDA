/**
 * Native addon discovery.
 *
 * The addon only maps values: binary semantics stay in the built-in engine. An
 * absent addon is a declarative state, so capability calls report
 * `capability/not-implemented` instead of inventing an analysis result.
 */

import { createRequire } from 'node:module';

const requireNative = createRequire(import.meta.url);

/** Orthogonal exports of the built addon. Binary calls return JSON; close returns a boolean. */
export interface NativeBinding {
    version(): string;
    capabilities(): string;
    binary_open(optionsJson: string): string;
    binary_info(handle: number): string;
    binary_sections(handle: number): string;
    binary_strings(handle: number, minLen?: number, limit?: number): string;
    binary_strings_encoded(handle: number, optionsJson: string): string;
    binary_hexdump(handle: number, offset?: number, length?: number): string;
    binary_read(handle: number, offset: number, length: number): string;
    binary_patch(handle: number, offset: number, hexBytes: string, outputPath?: string): string;
    binary_rva(handle: number, rva: number): string;
    binary_imports(handle: number, limit?: number): string;
    binary_exports(handle: number, limit?: number): string;
    binary_symbols(handle: number, limit?: number): string;
    binary_debug(handle: number, limit?: number): string;
    binary_version(handle: number): string;
    binary_macho(handle: number): string;
    binary_macho_symbols(handle: number, limit?: number): string;
    binary_macho_function_starts(handle: number, limit?: number): string;
    binary_macho_exports(handle: number): string;
    binary_macho_encryption(handle: number): string;
    binary_macho_chained_fixups(handle: number): string;
    binary_macho_bindings(handle: number): string;
    binary_macho_slices(handle: number): string;
    binary_code_signature(handle: number): string;
    binary_macho_extract(handle: number, index: number, output: string): string;
    binary_mitigations(handle: number): string;
    binary_resources(handle: number): string;
    binary_relocations(handle: number): string;
    binary_exception(handle: number): string;
    binary_delay_imports(handle: number): string;
    binary_bound_imports(handle: number): string;
    binary_rich_header(handle: number): string;
    binary_static_symbols(handle: number): string;
    binary_dynamic(handle: number): string;
    binary_segments(handle: number): string;
    binary_notes(handle: number): string;
    binary_certificates(handle: number): string;
    binary_tls(handle: number): string;
    binary_load_config(handle: number): string;
    binary_disasm(handle: number, optionsJson: string): string;
    binary_diff(leftHandle: number, rightHandle: number): string;
    binary_entropy(handle: number): string;
    binary_search(handle: number, optionsJson: string): string;
    binary_find(handle: number, optionsJson: string): string;
    binary_dump(handle: number, optionsJson: string): string;
    binary_carve(handle: number, optionsJson: string): string;
    binary_tauri_assets(handle: number, optionsJson: string): string;
    binary_inflate(handle: number, optionsJson: string): string;
    binary_nsis(handle: number, optionsJson: string): string;
    binary_overlay(handle: number): string;
    binary_offset_to_va(handle: number, offset: number): string;
    binary_offset_to_rva(handle: number, offset: number): string;
    binary_close(handle: number): boolean;
    openGui(options?: { title?: string; contentDir?: string; width?: number; height?: number }): string;
    pumpEvents(): string;
    closeGui(): string;
    isGuiOpen(): boolean;
}

let cached: NativeBinding | null | undefined;

/** Loads the addon once, or returns `undefined` when it is not installed. */
export function nativeBinding(): NativeBinding | undefined {
    if (cached === undefined) {
        cached = load();
    }
    return cached ?? undefined;
}

function load(): NativeBinding | null {
    for (const candidate of candidates()) {
        try {
            return requireNative(candidate) as NativeBinding;
        } catch (error) {
            if (candidate === explicitPath()) {
                throw error;
            }
            if (!isModuleNotFound(error, candidate)) {
                throw error;
            }
        }
    }
    return null;
}

function candidates(): string[] {
    const explicit = explicitPath();
    if (explicit) {
        return [explicit];
    }
    return [`@wae/open-ida-${process.platform}-${process.arch}`];
}

function explicitPath(): string | undefined {
    const value = process.env.OPEN_IDA_NATIVE;
    return value !== undefined && value.length > 0 ? value : undefined;
}

function isModuleNotFound(error: unknown, candidate: string): boolean {
    if (typeof error !== 'object' || error === null) {
        return false;
    }
    const code = (error as { code?: unknown }).code;
    // Node prints the resolved path, which uses the platform separator on
    // Windows. Normalize it so a linked platform package without a built
    // addon is still treated as "not installed" instead of a fatal error.
    const message = (error as Error).message.replace(/\\/g, '/');
    return code === 'MODULE_NOT_FOUND' && message.includes(candidate);
}
