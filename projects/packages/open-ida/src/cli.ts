#!/usr/bin/env node
/**
 * Command-line assembly only.
 *
 * Every command parses arguments, constructs the `OpenIDA` API and renders its
 * result; binary semantics stay in the built-in engine. Help text and errors
 * come from `@wae/commander`, so the CLI does not grow its own parser.
 */

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { createCli } from '@wae/commander';

import { OpenIDA, capabilities } from './api.js';
import { runGui } from './gui.js';
import type {
    BinaryInfo,
    Capabilities,
    DebugReport,
    DiffReport,
    DisassemblyReport,
    EncodedStringsReport,
    EntropyReport,
    ExportsReport,
    ImportsReport,
    MachOReport,
    MachOSlicesReport,
    MachOSymbolsReport,
    MitigationsReport,
    RelocationsReport,
    ResourcesReport,
    SearchOptions,
    SearchReport,
    Section,
    StringEncoding,
    SymbolsReport,
    VersionReport,
} from './types.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const cli = createCli('open-ida').locales(path.join(here, '..', 'locales')).intro('cli.intro');

// Exported for contract audits that import the built entry to inspect the
// command tree. Nothing runs until the file is executed as the program entry.
export { cli };

interface ParsedOptions {
    readonly _?: readonly string[];
    readonly [key: string]: unknown;
}

const text = (options: ParsedOptions, key: string): string | undefined =>
    typeof options[key] === 'string' ? (options[key] as string) : undefined;

const input = (options: ParsedOptions): string | undefined => options._?.[0];

function parseNumber(value: string | undefined): number | undefined {
    if (value === undefined || value.trim().length === 0) {
        return undefined;
    }
    const trimmed = value.trim();
    const parsed = /^0x/i.test(trimmed) ? Number.parseInt(trimmed.slice(2), 16) : Number.parseInt(trimmed, 10);
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function hex(value: number): string {
    return `0x${value.toString(16)}`;
}

function describeCapabilities(matrix: Capabilities): string {
    const formats = Object.entries(matrix.formats).map(([name, state]) => `${name}=${state}`);
    const features = Object.entries(matrix.features)
        .filter(([, state]) => state === 'supported')
        .map(([name]) => name);
    const missing = Object.entries(matrix.unsupported).map(([name, state]) => `${name}=${state}`);
    return [
        `engine: ${matrix.engine.package} ${matrix.engine.version}`,
        `formats: ${formats.join(', ')}`,
        `features: ${features.length > 0 ? features.join(', ') : 'none supported'}`,
        `unsupported: ${missing.length > 0 ? missing.join(', ') : 'nothing declared'}`,
    ].join('\n');
}

function describeInfo(info: BinaryInfo): string {
    const lines = [
        info.path,
        `format: ${info.format}${info.magic ? ` (${info.magic})` : ''} · arch ${info.architecture} · size ${info.size} bytes`,
        `sections: ${info.sectionCount} · hash: ${info.hash}`,
    ];
    if (info.entry !== null) {
        const rva = info.entryRva === null ? '' : ` (RVA ${hex(info.entryRva)})`;
        lines.push(`entry: ${hex(info.entry)}${rva}`);
    }
    if (info.imageBase !== null) {
        lines.push(`image base: ${hex(info.imageBase)}`);
    }
    if (info.commandCount !== null) {
        lines.push(`mach-o: cpuType=${hex(info.cpuType ?? 0)} fileType=${info.fileType ?? 0} commands=${info.commandCount}`);
    }
    return lines.join('\n');
}

function accessFlags(section: Section): string {
    return `${section.readable ? 'r' : '-'}${section.writable ? 'w' : '-'}${section.executable ? 'x' : '-'}`;
}

function describeSections(sections: readonly Section[]): string {
    if (sections.length === 0) {
        return 'no sections';
    }
    const lines = [`${sections.length} section(s)`];
    for (const section of sections) {
        lines.push(
            `  ${(section.name || '(unnamed)').padEnd(12)} vaddr=${hex(section.virtualAddress)} vsize=${hex(section.virtualSize)} file=${hex(section.rawPointer)}+${hex(section.rawSize)} ${accessFlags(section)}`,
        );
    }
    return lines.join('\n');
}

function describeStrings(report: EncodedStringsReport): string {
    const header = `${report.hits.length} of ${report.total} ${report.encoding} string(s)${report.truncated ? ' (truncated)' : ''}`;
    if (report.hits.length === 0) {
        return `${header}\n  no printable runs matched the minimum length`;
    }
    const lines = [header];
    const tagEncoding = report.encoding === 'both';
    for (const hit of report.hits) {
        const tag = tagEncoding ? `  ${hit.encoding.padEnd(7)}` : '';
        lines.push(`  ${hex(hit.offset).padStart(10)}  ${String(hit.length).padStart(4)}${tag}  ${hit.value}`);
    }
    return lines.join('\n');
}

function entriesHeader(count: number, total: number, noun: string, truncated: boolean): string {
    return `${count} of ${total} ${noun}${truncated ? ' (truncated)' : ''}`;
}

function describeImports(report: ImportsReport): string {
    const header = entriesHeader(report.entries.length, report.total, 'import(s)', report.truncated);
    if (report.entries.length === 0) {
        return `${header}\n  no imports`;
    }
    const lines = [header];
    for (const entry of report.entries) {
        const symbol = entry.name ?? `#${entry.ordinal ?? '?'}`;
        const module = entry.module.length > 0 ? `${entry.module}!` : '';
        const address = entry.address === null ? '' : `  ${hex(entry.address)}`;
        lines.push(`  ${`${module}${symbol}`.padEnd(40)}${address}`);
    }
    return lines.join('\n');
}

function describeExports(report: ExportsReport): string {
    const header = entriesHeader(report.entries.length, report.total, 'export(s)', report.truncated);
    if (report.entries.length === 0) {
        return `${header}\n  no exports`;
    }
    const lines = [header];
    for (const entry of report.entries) {
        const symbol = entry.name ?? `#${entry.ordinal ?? '?'}`;
        const address = entry.address === null ? '' : `  ${hex(entry.address)}`;
        const forwarder = entry.forwarder === null ? '' : `  -> ${entry.forwarder}`;
        lines.push(`  ${symbol.padEnd(40)}${address}${forwarder}`);
    }
    return lines.join('\n');
}

function describeSymbols(report: SymbolsReport): string {
    const header = entriesHeader(report.entries.length, report.total, 'symbol(s)', report.truncated);
    if (report.entries.length === 0) {
        return `${header}\n  no symbols`;
    }
    const lines = [header];
    for (const entry of report.entries) {
        const section = entry.section === null ? '' : `  (${entry.section})`;
        lines.push(`  ${hex(entry.address).padStart(12)}  ${entry.kind.padEnd(9)} ${entry.binding.padEnd(6)} ${entry.name}${section}`);
    }
    return lines.join('\n');
}

function describeDebug(report: DebugReport): string {
    const header = entriesHeader(report.entries.length, report.total, 'debug entry(ies)', report.truncated);
    if (report.entries.length === 0) {
        return `${header}\n  no debug directory entries`;
    }
    const lines = [header];
    for (const entry of report.entries) {
        lines.push(
            `  ${entry.debugType.padEnd(20)} ts=${hex(entry.timestamp)} v${entry.majorVersion}.${entry.minorVersion} size=${entry.sizeOfData} raw=${hex(entry.pointerToRawData)} rva=${hex(entry.addressOfRawData)}`,
        );
        if (entry.codeView !== null) {
            const record = entry.codeView;
            const identity =
                record.guid !== null
                    ? `guid=${record.guid}`
                    : `offset=${hex(record.offset ?? 0)} timestamp=${hex(record.timestamp ?? 0)}`;
            lines.push(`    ${record.signature} age=${record.age} ${identity} path=${record.path}`);
        }
    }
    return lines.join('\n');
}

function describeVersion(report: VersionReport): string {
    if (!report.present) {
        return 'no RT_VERSION resource';
    }
    const lines: string[] = [];
    if (report.fixed !== null) {
        lines.push(`file version: ${report.fixed.fileVersion}`);
        lines.push(`product version: ${report.fixed.productVersion}`);
        lines.push(
            `flags: ${hex(report.fixed.fileFlags)} / mask ${hex(report.fixed.fileFlagsMask)} · os ${hex(report.fixed.fileOs)} · type ${report.fixed.fileType}.${report.fixed.fileSubtype}`,
        );
    }
    if (report.note !== null) {
        lines.push(`note: ${report.note}`);
    }
    lines.push(`${report.strings.length} of ${report.total} string(s)${report.truncated ? ' (truncated)' : ''}`);
    for (const entry of report.strings) {
        lines.push(`  ${entry.key.padEnd(22)} ${entry.value}  (lang ${hex(entry.languageId)}, cp ${hex(entry.codepage)})`);
    }
    return lines.join('\n');
}

function describeResources(report: ResourcesReport): string {
    if (!report.present) {
        return 'no resource directory';
    }
    const header = entriesHeader(report.resources.length, report.total, 'resource(s)', report.truncated);
    if (report.resources.length === 0) {
        return `${header}\n  no resources`;
    }
    const lines = [header];
    for (const entry of report.resources) {
        lines.push(
            `  ${entry.resourceType.padEnd(14)} ${entry.name.padEnd(16)} lang ${hex(entry.language)} rva ${hex(entry.dataRva)} size ${hex(entry.size)}`,
        );
    }
    return lines.join('\n');
}

function describeRelocations(report: RelocationsReport): string {
    if (!report.present) {
        return 'no base relocations';
    }
    const header = entriesHeader(report.blocks.length, report.totalBlocks, 'block(s)', report.truncated);
    const lines = [
        `${header} · ${report.totalEntries} fixup(s)${report.truncated ? ' (truncated)' : ''}`,
        `kinds: ${report.kinds.map((entry) => `${entry.kind}=${entry.count}`).join(', ') || 'none'}`,
    ];
    for (const block of report.blocks) {
        const kinds = block.kinds.map((entry) => `${entry.kind}=${entry.count}`).join(' ');
        lines.push(`  page ${hex(block.pageRva)} · ${block.entries} entr${block.entries === 1 ? 'y' : 'ies'} · ${kinds}`);
    }
    return lines.join('\n');
}

function describeMitigations(report: MitigationsReport): string {
    const on = (value: boolean) => (value ? 'yes' : 'no');
    const lines = [
        `dll characteristics ${hex(report.dllCharacteristics)}`,
        `  aslr              ${on(report.aslr)}`,
        `  high-entropy va   ${on(report.highEntropyVa)}`,
        `  dep (nx)          ${on(report.dep)}`,
        `  cfg               ${on(report.cfg)}`,
        `  force integrity   ${on(report.forceIntegrity)}`,
        `  no seh            ${on(report.noSeh)}`,
        `  terminal server   ${on(report.terminalServerAware)}`,
        `  relocations       ${report.relocationsPresent ? 'present' : 'stripped'}`,
        `  certificate table ${report.signed ? 'present (not verified)' : 'absent'}`,
        `  gs cookie         ${report.securityCookie === null ? 'no load config' : on(report.securityCookie)}`,
    ];
    if (report.guardFlags !== null) {
        lines.push(`  guard flags       ${hex(report.guardFlags)}`);
    }
    if (report.writableExecutableSections.length === 0) {
        lines.push('  w+x sections      none');
    } else {
        lines.push(`  w+x sections      ${report.writableExecutableSections.map((section) => section.name).join(', ')}`);
    }
    return lines.join('\n');
}

function describeMachO(report: MachOReport): string {
    const bits = report.is64 ? 64 : 32;
    const lines = [
        `mach-o ${bits}-bit ${report.endian}-endian · ${report.architecture} · ${report.kind} (fileType ${report.fileType})`,
        `commands: ${report.commandCount} (${report.sizeOfCommands} bytes) · flags ${hex(report.flags)}`,
    ];
    if (report.uuid !== null) {
        lines.push(`uuid: ${report.uuid}`);
    }
    if (report.platform !== null) {
        const sdk = report.sdk === null ? '' : ` · sdk ${report.sdk}`;
        lines.push(`platform: ${report.platform}${report.minOs === null ? '' : ` · min ${report.minOs}`}${sdk}`);
    }
    if (report.entryOffset !== null) {
        const address = report.entryAddress === null ? '' : ` -> ${hex(report.entryAddress)}`;
        lines.push(`entry: file ${hex(report.entryOffset)}${address}`);
    }
    if (report.dylibs.length > 0) {
        lines.push(`dylibs: ${report.dylibs.length}`);
        for (const dylib of report.dylibs) {
            lines.push(`  ${dylib.kind.padEnd(9)} ${dylib.name} (${dylib.currentVersion})`);
        }
    }
    if (report.segments.length > 0) {
        lines.push(`segments: ${report.segments.length}`);
        for (const segment of report.segments) {
            const access = `${segment.readable ? 'r' : '-'}${segment.writable ? 'w' : '-'}${segment.executable ? 'x' : '-'}`;
            lines.push(
                `  ${segment.name.padEnd(12)} vm=${hex(segment.vmAddress)}+${hex(segment.vmSize)} file=${hex(segment.fileOffset)}+${hex(segment.fileSize)} ${access}`,
            );
        }
    }
    if (report.sections.length > 0) {
        lines.push(`sections: ${report.sections.length}`);
        for (const section of report.sections) {
            const access = `${section.readable ? 'r' : '-'}${section.writable ? 'w' : '-'}${section.executable ? 'x' : '-'}`;
            lines.push(
                `  ${`${section.segment},${section.name}`.padEnd(24)} addr=${hex(section.address)} size=${hex(section.size)} file=${hex(section.fileOffset)} ${access}`,
            );
        }
    }
    return lines.join('\n');
}

function describeMachOSymbols(report: MachOSymbolsReport): string {
    const header = entriesHeader(report.symbols.length, report.total, 'Mach-O symbol(s)', report.truncated);
    if (report.symbols.length === 0) {
        return `${header}\n  no symbols`;
    }
    const lines = [header, `string table: ${report.stringTableSize} bytes`];
    for (const symbol of report.symbols) {
        const flags = `${symbol.external ? 'ext' : 'int'}${symbol.debug ? ',dbg' : ''}`;
        const section = symbol.section === null ? '' : `  sect ${symbol.section}`;
        lines.push(
            `  ${hex(symbol.address).padStart(12)}  ${symbol.kind.padEnd(9)} ${flags.padEnd(7)} ${symbol.name}${section}`,
        );
    }
    return lines.join('\n');
}

function describeMachOSlices(report: MachOSlicesReport): string {
    if (report.slices.length === 0) {
        return 'no architecture slices';
    }
    const layout = report.isFat64 ? 'fat_arch_64' : 'fat_arch';
    const lines = [`${report.slices.length} slice(s) · ${layout}`];
    for (const slice of report.slices) {
        const bits = slice.bits === null ? '' : ` ${slice.bits}-bit`;
        lines.push(
            `  [${slice.index}] ${slice.architecture.padEnd(6)} cpu=${hex(slice.cpuType)}/${hex(slice.cpuSubtype)}${bits} offset=${hex(slice.offset)} size=${hex(slice.size)} align=2^${slice.alignment}`,
        );
    }
    return lines.join('\n');
}

function describeDisassembly(report: DisassemblyReport): string {
    const header = `${report.instructions.length} instruction(s) · ${report.architecture} ${report.bitness}-bit · ${report.syntax} · start ${hex(report.startOffset)} @ ${hex(report.startAddress)}${report.truncated ? ' (truncated)' : ''}`;
    if (report.instructions.length === 0) {
        return `${header}\n  no instructions`;
    }
    const lines = [header];
    for (const instruction of report.instructions) {
        lines.push(
            `  ${hex(instruction.address).padStart(12)}  ${hex(instruction.offset).padStart(8)}  ${instruction.bytes.padEnd(18)}  ${instruction.text}`,
        );
    }
    return lines.join('\n');
}

function describeEntropy(report: EntropyReport): string {
    const lines = [`file ${report.fileSize} B · entropy ${report.fileEntropy.toFixed(4)} bits/byte`];
    lines.push(
        report.overlay === null
            ? 'overlay: none'
            : `overlay ${hex(report.overlay.offset)} + ${report.overlay.size} byte(s)`,
    );
    for (const section of report.sections) {
        lines.push(
            `  ${section.name.padEnd(12)} ${hex(section.offset).padStart(10)} + ${section.size} B  ${section.entropy.toFixed(4)}`,
        );
    }
    return lines.join('\n');
}

function describeDiff(report: DiffReport): string {
    const header = `left ${report.leftSize} B · right ${report.rightSize} B · ${report.identical ? 'identical' : 'different'} · compared ${report.comparedBytes} B`;
    if (report.identical) {
        return header;
    }
    const lines = [header];
    if (report.firstDifference !== null) {
        lines.push(`  first difference at ${hex(report.firstDifference)}`);
    }
    lines.push(`  ${entriesHeader(report.differences.length, report.total, 'differing range(s)', report.truncated)}`);
    for (const range of report.differences) {
        lines.push(`  ${hex(range.offset)} + ${range.length} byte(s)`);
    }
    return lines.join('\n');
}

function describeSearch(report: SearchReport): string {
    const header = `${report.hits.length} of ${report.total} ${report.mode} hit(s)${report.truncated ? ' (truncated)' : ''}`;
    if (report.hits.length === 0) {
        return `${header}\n  no matches`;
    }
    const lines = [header];
    for (const hit of report.hits) {
        lines.push(`  ${hex(hit.offset).padStart(10)}  ${hit.preview}`);
    }
    return lines.join('\n');
}

cli.command('capabilities', 'cli.cmd.capabilities').actionCtx(async (_options, _args, ctx) => {
    const matrix = capabilities();
    ctx.emitResult(matrix, describeCapabilities(matrix));
    return 0;
});

cli.command('info', 'cli.cmd.info').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const info = ida.info();
        ctx.emitResult(info, describeInfo(info));
        return 0;
    } finally {
        ida.close();
    }
});

cli.command('sections', 'cli.cmd.sections').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const report = ida.sections();
        ctx.emitResult(report, describeSections(report.sections));
        return 0;
    } finally {
        ida.close();
    }
});

cli
    .command('strings', 'cli.cmd.strings')
    .option('--min <len>', 'cli.opt.min')
    .option('--limit <count>', 'cli.opt.limit')
    .option('--encoding <encoding>', 'cli.opt.encoding')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const minText = text(options, 'min');
        const min = minText === undefined ? 4 : parseNumber(minText);
        if (min === undefined || min < 1) {
            ctx.fail('open-ida.cli.min', { message: '`--min <len>` must be a positive integer' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? 100 : parseNumber(limitText);
        if (limit === undefined || limit < 1) {
            ctx.fail('open-ida.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const encodings = ['ascii', 'utf16le', 'both'] as const;
        const encodingText = text(options, 'encoding') ?? 'ascii';
        if (!(encodings as readonly string[]).includes(encodingText)) {
            ctx.fail('cli.err.encoding', { message: '`--encoding` must be ascii, utf16le or both' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.stringsEncoded({ minLength: min, limit, encoding: encodingText as StringEncoding });
            ctx.emitResult(report, describeStrings(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli
    .command('hexdump', 'cli.cmd.hexdump')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--length <length>', 'cli.opt.length')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? 0 : parseNumber(offsetText);
        if (offset === undefined) {
            ctx.fail('open-ida.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? 256 : parseNumber(lengthText);
        if (length === undefined) {
            ctx.fail('open-ida.cli.length', { message: '`--length <length>` must be a non-negative integer' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.hexdump(offset, length);
            ctx.emitResult(report, report.text.length > 0 ? report.text : 'no bytes in the requested range');
            return 0;
        } finally {
            ida.close();
        }
    });

cli.command('rva', 'cli.cmd.rva').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    const addressText = options._?.[1];
    if (file === undefined || addressText === undefined) {
        ctx.fail('open-ida.cli.rva-args', { message: 'a binary file and an RVA are required' });
        return 2;
    }
    const address = parseNumber(addressText);
    if (address === undefined) {
        ctx.fail('open-ida.cli.rva', { message: 'the RVA must be a non-negative integer, decimal or 0x-prefixed' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const report = ida.rva(address);
        ctx.emitResult(report, `RVA ${hex(report.rva)} -> file offset ${hex(report.offset)}`);
        return 0;
    } finally {
        ida.close();
    }
});

cli
    .command('imports', 'cli.cmd.imports')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ida.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.imports(limit);
            ctx.emitResult(report, describeImports(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli
    .command('exports', 'cli.cmd.exports')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ida.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.exports(limit);
            ctx.emitResult(report, describeExports(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli
    .command('symbols', 'cli.cmd.symbols')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ida.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.symbols(limit);
            ctx.emitResult(report, describeSymbols(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli
    .command('debug', 'cli.cmd.debug')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ida.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.debug(limit);
            ctx.emitResult(report, describeDebug(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli.command('version', 'cli.cmd.version').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const report = ida.version();
        ctx.emitResult(report, describeVersion(report));
        return 0;
    } finally {
        ida.close();
    }
});

cli.command('resources', 'cli.cmd.resources').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const report = ida.resources();
        ctx.emitResult(report, describeResources(report));
        return 0;
    } finally {
        ida.close();
    }
});

cli.command('mitigations', 'cli.cmd.mitigations').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const report = ida.mitigations();
        ctx.emitResult(report, describeMitigations(report));
        return 0;
    } finally {
        ida.close();
    }
});

cli.command('relocations', 'cli.cmd.relocations').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const report = ida.relocations();
        ctx.emitResult(report, describeRelocations(report));
        return 0;
    } finally {
        ida.close();
    }
});

cli.command('macho', 'cli.cmd.macho').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const report = ida.macho();
        ctx.emitResult(report, describeMachO(report));
        return 0;
    } finally {
        ida.close();
    }
});

cli
    .command('macho-symbols', 'cli.cmd.machoSymbols')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ida.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.machoSymbols(limit);
            ctx.emitResult(report, describeMachOSymbols(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli.command('macho-slices', 'cli.cmd.machoSlices').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const report = ida.machoSlices();
        ctx.emitResult(report, describeMachOSlices(report));
        return 0;
    } finally {
        ida.close();
    }
});

cli
    .command('disasm', 'cli.cmd.disasm')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--count <count>', 'cli.opt.count')
    .option('--syntax <syntax>', 'cli.opt.syntax')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? 0 : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ida.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const countText = text(options, 'count');
        const count = countText === undefined ? undefined : parseNumber(countText);
        if (countText !== undefined && (count === undefined || count < 1)) {
            ctx.fail('open-ida.cli.count', { message: '`--count <count>` must be a positive integer' });
            return 2;
        }
        const syntax = text(options, 'syntax') ?? 'intel';
        if (syntax !== 'intel' && syntax !== 'masm' && syntax !== 'nasm') {
            ctx.fail('open-ida.cli.syntax', { message: '`--syntax` must be intel, masm or nasm' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.disasm({ offset, count, syntax });
            ctx.emitResult(report, describeDisassembly(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli
    .command('entropy', 'cli.cmd.entropy')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.entropy();
            ctx.emitResult(report, describeEntropy(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli.command('diff', 'cli.cmd.diff').actionCtx(async (options, _args, ctx) => {
    const leftPath = options._?.[0];
    const rightPath = options._?.[1];
    if (leftPath === undefined || rightPath === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'two binary files are required' });
        return 2;
    }
    const left = new OpenIDA({ path: leftPath });
    try {
        const right = new OpenIDA({ path: rightPath });
        try {
            const report = left.diff(right);
            ctx.emitResult(report, describeDiff(report));
            return 0;
        } finally {
            right.close();
        }
    } finally {
        left.close();
    }
});

cli
    .command('search', 'cli.cmd.search')
    .option('--mode <mode>', 'cli.opt.mode')
    .option('--case-sensitive', 'cli.opt.case')
    .option('--whole-word', 'cli.opt.word')
    .option('--limit <count>', 'cli.opt.limit')
    .option('--start <offset>', 'cli.opt.start')
    .option('--end <offset>', 'cli.opt.end')
    .actionCtx(async (options, _args, ctx) => {
        const file = options._?.[0];
        const pattern = options._?.[1];
        if (file === undefined || pattern === undefined) {
            ctx.fail('open-ida.cli.search-args', { message: 'a binary file and a pattern are required' });
            return 2;
        }
        const modes = ['hex', 'ascii', 'utf16le'] as const;
        const modeText = text(options, 'mode') ?? 'ascii';
        if (!(modes as readonly string[]).includes(modeText)) {
            ctx.fail('open-ida.cli.mode', { message: '`--mode` must be hex, ascii or utf16le' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ida.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const start = text(options, 'start') === undefined ? undefined : parseNumber(text(options, 'start'));
        if (text(options, 'start') !== undefined && start === undefined) {
            ctx.fail('open-ida.cli.offset', { message: '`--start <offset>` must be a non-negative integer' });
            return 2;
        }
        const end = text(options, 'end') === undefined ? undefined : parseNumber(text(options, 'end'));
        if (text(options, 'end') !== undefined && end === undefined) {
            ctx.fail('open-ida.cli.offset', { message: '`--end <offset>` must be a non-negative integer' });
            return 2;
        }
        const searchOptions: SearchOptions = {
            mode: modeText as SearchOptions['mode'],
            pattern,
            caseSensitive: options['case-sensitive'] === true,
            wholeWord: options['whole-word'] === true,
            ...(limit === undefined ? {} : { limit }),
            ...(start === undefined ? {} : { start }),
            ...(end === undefined ? {} : { end }),
        };
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.search(searchOptions);
            ctx.emitResult(report, describeSearch(report));
            return 0;
        } finally {
            ida.close();
        }
    });

cli.command('offset', 'cli.cmd.offset').actionCtx(async (options, _args, ctx) => {
    const file = options._?.[0];
    const offsetText = options._?.[1];
    if (file === undefined || offsetText === undefined) {
        ctx.fail('open-ida.cli.offset-args', { message: 'a binary file and a file offset are required' });
        return 2;
    }
    const offset = parseNumber(offsetText);
    if (offset === undefined) {
        ctx.fail('open-ida.cli.offset', { message: 'the offset must be a non-negative integer, decimal or 0x-prefixed' });
        return 2;
    }
    const ida = new OpenIDA({ path: file });
    try {
        const mapped = ida.offsetToVa(offset);
        let rva: number | null = null;
        try {
            rva = ida.offsetToRva(offset).rva;
        } catch {
            rva = null;
        }
        const detail = rva === null ? `offset ${hex(offset)} -> VA ${hex(mapped.va)}` : `offset ${hex(offset)} -> RVA ${hex(rva)} · VA ${hex(mapped.va)}`;
        ctx.emitResult({ offset, rva, va: mapped.va }, detail);
        return 0;
    } finally {
        ida.close();
    }
});

cli
    .command('patch', 'cli.cmd.patch')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--bytes <hex>', 'cli.opt.bytes')
    .option('--out <file>', 'cli.opt.out')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = parseNumber(offsetText);
        if (offset === undefined) {
            ctx.fail('open-ida.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const bytes = text(options, 'bytes');
        if (bytes === undefined || bytes.trim().length === 0) {
            ctx.fail('open-ida.cli.bytes', { message: '`--bytes <hex>` is required, such as 90,90' });
            return 2;
        }
        const out = text(options, 'out');
        const ida = new OpenIDA({ path: file });
        try {
            const report = ida.patch(offset, bytes, out);
            ctx.emitResult(
                report,
                `patched ${report.path} at ${hex(report.offset)} (${report.length} byte(s))\n  before: ${report.beforeHash}\n  after:  ${report.afterHash}`,
            );
            return 0;
        } finally {
            ida.close();
        }
    });

cli.command('gui', 'cli.cmd.gui').actionCtx(async (_options, _args, ctx) => {
    try {
        const status = await runGui({});
        ctx.emitResult(status, `window ${status.state}`);
        return 0;
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        ctx.fail('open-ida.cli.gui-failed', { message });
        return 1;
    }
});

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
    const code = await cli.parse(process.argv);
    process.exitCode = code;
}
