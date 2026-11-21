#!/usr/bin/env node
/**
 * Command-line assembly only.
 *
 * Every command maps options onto one operation of `service.ts`; binary
 * semantics stay in the built-in engine. Help text and errors come from
 * `@wae/commander`, so the CLI does not grow its own parser.
 */

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { createCli } from '@wae/commander';

import * as service from './service.js';
import { runGui } from './gui.js';
import type { BinaryInfo, Capabilities, Section, StringsReport } from './types.js';

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

function describeStrings(report: StringsReport): string {
    const header = `${report.hits.length} of ${report.total} string(s)${report.truncated ? ' (truncated)' : ''}`;
    if (report.hits.length === 0) {
        return `${header}\n  no printable runs matched the minimum length`;
    }
    const lines = [header];
    for (const hit of report.hits) {
        lines.push(`  ${hex(hit.offset).padStart(10)}  ${String(hit.length).padStart(4)}  ${hit.value}`);
    }
    return lines.join('\n');
}

cli.command('capabilities', 'cli.cmd.capabilities').actionCtx(async (_options, _args, ctx) => {
    const matrix = service.capabilities();
    ctx.emitResult(matrix, describeCapabilities(matrix));
    return 0;
});

cli.command('info', 'cli.cmd.info').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const opened = service.open(file);
    try {
        ctx.emitResult(opened.info, describeInfo(opened.info));
        return 0;
    } finally {
        service.close(opened.handle);
    }
});

cli.command('sections', 'cli.cmd.sections').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ida.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const opened = service.open(file);
    try {
        const report = service.sections(opened.handle);
        ctx.emitResult(report, describeSections(report.sections));
        return 0;
    } finally {
        service.close(opened.handle);
    }
});

cli
    .command('strings', 'cli.cmd.strings')
    .option('--min <len>', 'cli.opt.min')
    .option('--limit <count>', 'cli.opt.limit')
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
        const opened = service.open(file);
        try {
            const report = service.strings(opened.handle, min, limit);
            ctx.emitResult(report, describeStrings(report));
            return 0;
        } finally {
            service.close(opened.handle);
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
        const opened = service.open(file);
        try {
            const report = service.hexdump(opened.handle, offset, length);
            ctx.emitResult(report, report.text.length > 0 ? report.text : 'no bytes in the requested range');
            return 0;
        } finally {
            service.close(opened.handle);
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
    const opened = service.open(file);
    try {
        const report = service.rva(opened.handle, address);
        ctx.emitResult(report, `RVA ${hex(report.rva)} -> file offset ${hex(report.offset)}`);
        return 0;
    } finally {
        service.close(opened.handle);
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
        const opened = service.open(file);
        try {
            const report = service.patch(opened.handle, offset, bytes, out);
            ctx.emitResult(
                report,
                `patched ${report.path} at ${hex(report.offset)} (${report.length} byte(s))\n  before: ${report.beforeHash}\n  after:  ${report.afterHash}`,
            );
            return 0;
        } finally {
            service.close(opened.handle);
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
