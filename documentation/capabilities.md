# OpenIDA capabilities

`open-ida capabilities` prints this matrix from the installed engine. The
TypeScript `capabilities()` returns the same object as JSON, including the
`unsupported` block. A flag name, a file suffix or a method name is never a
support claim.

## Format matrix

| Container | State | What is decoded |
| --- | --- | --- |
| PE (`MZ`) | `supported` | Headers, image base, entry RVA, sections, imports, exports, COFF symbols, debug directory, `RSDS` / `NB10` CodeView records, overlay. |
| ELF 32/64-bit little-endian | `supported` | Headers, sections, entry point, dynamic symbols and section entropy. |
| Mach-O | `partial` | Headers, `LC_UUID`, `LC_BUILD_VERSION` / `LC_VERSION_MIN_*`, dylib commands, segments, sections and the `LC_SYMTAB` symbol table. Fat containers report their architecture table only. No dyld bindings. |
| Mach-O fat/universal | `partial` | The `fat_arch` / `fat_arch_64` architecture table (CPU, range, alignment, slice bitness). Thin-image inspection and symbols still answer `binary/unsupported` until a slice is selected. |
| Unknown | `unsupported` | Rejected with `binary/unsupported`. |

Big-endian ELF is rejected rather than decoded with a guessed byte order.

## Feature matrix

| Feature | State | Notes |
| --- | --- | --- |
| `info` | `supported` | Format, architecture, size, hash, entry, image base, section count. |
| `sections` | `supported` | Virtual address, virtual size, raw offset, raw size, characteristics, r/w/x. |
| `strings` | `supported` | ASCII by default; `utf16le` and `both` add ASCII-in-UTF-16LE runs. |
| `hexdump` | `supported` | Canonical `offset  bytes  \|ascii\|` layout. |
| `read` | `supported` | Raw byte range as hex (SDK surface). |
| `patch` | `supported` | Atomic write with before/after whole-file hashes. |
| `rva` | `supported` | PE RVA or ELF VA to file offset. |
| `imports` | `supported` | PE import table with module, name or ordinal, and slot address. |
| `exports` | `supported` | PE export table with ordinal, address and forwarder. |
| `symbols` | `supported` | COFF symbols for PE; dynamic symbols for ELF. |
| `debug` | `supported` | PE debug directory and CodeView records. Non-PE answers `binary/unsupported`. |
| `version` | `supported` | PE `RT_VERSION` fixed file info and `StringFileInfo` pairs. A PE without the resource reports `present: false`; non-PE answers `binary/unsupported`. |
| `macho` | `supported` | Mach-O header, file type, UUID, platform/min OS/SDK, dylibs, segments, sections and entry point. Non-Mach-O answers `binary/unsupported`. |
| `macho-symbols` | `supported` | Mach-O `LC_SYMTAB` entries with name, address, kind, external/debug flags, section index and descriptor. A Mach-O without `LC_SYMTAB` answers `binary/unsupported`. |
| `macho-fat-slices` | `supported` | Fat/universal architecture table: index, CPU type/subtype, architecture, offset, size, alignment and slice bitness. A thin image answers `binary/unsupported`. |
| `disassembly` | `supported` | x86 and x64 only, Intel/MASM/NASM syntax. |
| `diff` | `supported` | Byte-level comparison plus the first differing offset. |
| `entropy` | `supported` | Whole file; per section for PE, ELF and Mach-O. |
| `overlay` | `supported` | PE only: bytes after the last section payload. |
| `search` | `supported` | Hex, ASCII and UTF-16LE patterns with optional range, case and whole-word filters. |
| `offset-to-va` | `supported` | File offset to absolute virtual address. |
| `offset-to-rva` | `supported` | File offset to PE image-relative address. |
| `decompilation` | `not-implemented` | No pseudo-code, control-flow graph or type recovery. |
| `debugger` | `not-implemented` | No attach, breakpoints or live process access. |
| `macho-import-bindings` | `not-implemented` | Mach-O imports are not bound or resolved. |

## Architecture matrix

| Architecture | State | Notes |
| --- | --- | --- |
| x86 | `supported` | Detection and disassembly. |
| x64 | `supported` | Detection and disassembly. |
| arm64 | `supported` | Detection only. Disassembly answers `binary/unsupported`. |

32-bit ARM is not a declared architecture in this build.

## Limits

| Request | Default | Maximum | Behaviour when exceeded |
| --- | --- | --- | --- |
| `strings --min` | 4 characters | — | Runs shorter than the minimum are skipped. |
| `strings --limit` | 100 hits | 10,000 | `total` keeps the full count, `truncated` is `true`. |
| `search --limit` | 100 hits | — | `total` keeps the full count, `truncated` is `true`. Omit for the engine default; the SDK also accepts `null` for unlimited. |
| `disasm --count` | 64 instructions | 4,096 | `truncated` is `true` when the count limit stopped decoding. |
| `diff` ranges | — | 64 ranges | `total` keeps the full count, `truncated` is `true`. |
| `imports` / `exports` / `symbols` / `macho-symbols` / `debug --limit` | Unlimited | — | `total` and `truncated` describe the cut. |
| `hexdump --length` | 256 bytes | File size | A range outside the file is `binary/range`. |

## Encoding boundaries

- `ascii` matches printable ASCII runs.
- `utf16le` matches ASCII characters stored as `char, 0x00`. It is not a
  general UTF-16 decoder: non-ASCII code units are not produced.
- `both` runs both scans and tags every hit with its encoding.
- `search --mode utf16le` follows the same zero-high-byte convention.

## Boundaries by format

| Boundary | Behaviour |
| --- | --- |
| Mach-O dyld bindings | Not decoded; `formats.macho = partial`. Load commands, segments, sections, dylibs, build versions and the `LC_SYMTAB` symbol table are decoded. |
| Fat/universal Mach-O | `macho-slices` lists the architecture table. `macho` and `macho-symbols` answer `binary/unsupported` until a slice is selected; this build does not carve slices. |
| Big-endian ELF | `binary/unsupported`. |
| Unknown container | `binary/unsupported`. |
| PE on a non-PE file | `debug` answers `binary/unsupported`. |
| ARM / ARM64 disassembly | `binary/unsupported`. |
| Patch outside the file | `binary/range`; the file is unchanged. |
| Closed handle | `handle/invalid`. |
| Missing addon | `capability/not-implemented`. |

## Checking support from code

```ts
import { capabilities } from '@wae/open-ida';

const matrix = capabilities();
const supported = matrix.features.disassembly === 'supported';
const missing = Object.keys(matrix.unsupported);
```

Branch on the reported state, not on a file extension. If a route is not
`supported`, report the stable code instead of substituting another analysis.
