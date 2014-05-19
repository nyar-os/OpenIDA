# open-ida CLI reference

Every command opens the named file, runs one inspection, prints one report and
closes the handle. Offsets accept decimal or `0x`-prefixed hexadecimal. Usage
failures print a stable `open-ida.cli.*` code and exit `2`; engine and IO
failures exit non-zero. A successful command exits `0`.

## Global flags

| Flag | Meaning |
| --- | --- |
| `--help`, `-h` | Print help derived from the command tree and `locales/en-US/cli.json`. |
| `--locale <id>` | Select a locale registered by `locales/locales.json`. Only `en-US` ships today. |

## Commands

### `capabilities`

```bash
open-ida capabilities
```

Prints the engine package and version, the format states, the supported
features and the explicit `unsupported` block. No file is opened.

### `info <file>`

```bash
open-ida info ./samples/app.exe
```

Reports path, format, magic, architecture, size, section count, whole-file hash,
entry point (with RVA for PE), image base and, for Mach-O, CPU type, file type
and load-command count.

### `sections <file>`

```bash
open-ida sections ./samples/app.exe
```

Prints each section name, virtual address, virtual size, raw offset and size,
and `r` / `w` / `x` access flags.

### `strings <file>`

```bash
open-ida strings ./samples/app.exe --min 6 --limit 200 --encoding both
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--min <len>` | `4` | Minimum printable run length. |
| `--limit <count>` | `100` | Maximum hits; the engine caps the requested value at 10,000. |
| `--encoding <encoding>` | `ascii` | `ascii`, `utf16le` or `both`. |

Hits are reported with their file offset and byte length. In `both` mode every
hit is tagged with its encoding.

### `hexdump <file>`

```bash
open-ida hexdump ./samples/app.exe --offset 0x1000 --length 128
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--offset <offset>` | `0` | First byte to render. |
| `--length <length>` | `256` | Number of bytes to render. |

Renders the canonical `offset  bytes  |ascii|` layout. A range outside the file
is `binary/range`.

### `rva <file> <address>`

```bash
open-ida rva ./samples/app.exe 0x1000
```

Maps a PE RVA or an ELF virtual address onto a file offset and prints
`RVA 0x... -> file offset 0x...`.

### `offset <file> <offset>`

```bash
open-ida offset ./samples/app.exe 0x400
```

Maps a file offset back to addresses. Always prints the virtual address and adds
the PE RVA when the container has one; for ELF the JSON field `rva` is `null`.

### `imports <file>`

```bash
open-ida imports ./samples/app.exe --limit 50
```

PE only. Prints `module!symbol` or `module!#ordinal` with the import-slot
address. `--limit` caps the listing; `total` and `truncated` describe the cut.

### `exports <file>`

```bash
open-ida exports ./samples/app.exe --limit 50
```

PE only. Prints the export name or ordinal, its address and, when present, the
forwarder target.

### `symbols <file>`

```bash
open-ida symbols ./samples/app.exe --limit 50
```

Prints COFF symbols for PE and dynamic symbols for ELF: address, kind, binding,
name and owning section.

### `debug <file>`

```bash
open-ida debug ./samples/app.exe
```

PE only. Prints each debug directory entry (type, timestamp, version, data size,
raw pointer, RVA) and, for CodeView entries, the signature, GUID or `NB10`
offset/timestamp, age and PDB path. A non-PE file answers `binary/unsupported`.

### `version <file>`

```bash
open-ida version ./samples/app.exe
```

PE only. Walks the resource directory to `RT_VERSION` and prints the fixed file
info (file and product versions, flags, OS and type) plus the `StringFileInfo`
pairs with their language id and code page. A PE with no version resource prints
`no RT_VERSION resource` and reports `present: false` rather than failing.

### `macho <file>`

```bash
open-ida macho ./samples/app.macho
```

Mach-O only. Prints the header (bitness, byte order, CPU, file type, flags,
command count), `LC_UUID`, platform, minimum OS and SDK, the `LC_MAIN` entry
offset mapped onto a virtual address, every dylib command with its version,
and the segment and section tables with r/w/x access. Fat/universal containers
answer `binary/unsupported`; run `macho-slices` to see their architecture table.

### `macho-slices <file>`

```bash
open-ida macho-slices ./samples/universal.macho
```

Fat/universal Mach-O only. Prints the `fat_arch` or `fat_arch_64` layout and one
line per slice: CPU type and subtype, architecture, file offset, size, alignment
and the bitness read from the slice header. A thin Mach-O answers
`binary/unsupported` and is inspected with `macho` directly. This build lists
slices but does not extract them, so `macho` and `macho-symbols` still require a
thin image.

### `macho-symbols <file>`

```bash
open-ida macho-symbols ./samples/app.macho --limit 200
```

Mach-O only. Walks `LC_SYMTAB`, resolves each `nlist` / `nlist_64` name through
the string table and prints its address, kind (`undefined`, `absolute`,
`section`, `indirect`, `prebound`, `debug`), external/debug flags and section
index. `--limit` defaults to unlimited and reports `truncated` when it cuts the
table. A Mach-O without `LC_SYMTAB` answers `binary/unsupported`.

### `disasm <file>`

```bash
open-ida disasm ./samples/app.exe --offset 0x1000 --count 20 --syntax intel
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--offset <offset>` | `0` | File offset to start decoding. |
| `--count <count>` | `64` | Maximum instructions; capped at 4,096. |
| `--syntax <syntax>` | `intel` | `intel`, `masm` or `nasm`. |

Only x86 and x64 are decoded. PE reports virtual addresses derived from the
image base; other architectures answer `binary/unsupported`.

### `entropy <file>`

```bash
open-ida entropy ./samples/app.exe
```

Prints whole-file entropy in bits per byte, per-section entropy for PE, ELF and
Mach-O, and the PE overlay offset and size when one exists.

### `diff <left> <right>`

```bash
open-ida diff build/app.exe build/app-patched.exe
```

Prints both sizes and hashes, the compared byte count, `identical` or
`different`, the first differing offset and up to 64 differing ranges. The
report sets `truncated` when more ranges exist.

### `search <file> <pattern>`

```bash
open-ida search ./samples/app.exe "ws2_32.dll" --mode ascii --limit 20
open-ida search ./samples/app.exe "48 8B" --mode hex
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--mode <mode>` | `ascii` | `hex`, `ascii` or `utf16le`. |
| `--case-sensitive` | off | ASCII letters must match case. |
| `--whole-word` | off | Matches must be surrounded by non-word characters. |
| `--limit <count>` | `100` | Maximum hits. |
| `--start <offset>` | `0` | First byte to scan. |
| `--end <offset>` | end of file | One past the last byte to scan. |

Every hit carries the file offset and a preview.

### `patch <file>`

```bash
open-ida patch ./samples/app.exe --offset 0x200 --bytes 90,90 --out ./samples/app-patched.exe
```

| Flag | Required | Meaning |
| --- | --- | --- |
| `--offset <offset>` | yes | First byte to replace. |
| `--bytes <hex>` | yes | Replacement bytes, such as `90,90` or `0x90 0x90`. |
| `--out <file>` | no | Write a patched copy here instead of overwriting the source. |

The write is atomic and the report carries the whole-file hash before and after.
A range outside the file is `binary/range` and the file is unchanged.

### `gui`

```bash
open-ida gui
```

Opens the Studio window. If the window cannot start, the command exits `1` with
`open-ida.cli.gui-failed`.

## Stable CLI error codes

| Code | Cause |
| --- | --- |
| `open-ida.cli.file-required` | A required file argument is missing. |
| `open-ida.cli.rva-args` | `rva` was called without a file and an address. |
| `open-ida.cli.offset-args` | `offset` was called without a file and an offset. |
| `open-ida.cli.search-args` | `search` was called without a file and a pattern. |
| `open-ida.cli.min` | `--min` is not a positive integer. |
| `open-ida.cli.limit` | `--limit` is not a positive integer. |
| `open-ida.cli.offset` | An offset is not a non-negative integer. |
| `open-ida.cli.length` | `--length` is not a non-negative integer. |
| `open-ida.cli.count` | `--count` is not a positive integer. |
| `open-ida.cli.encoding` / `cli.err.encoding` | `--encoding` is not `ascii`, `utf16le` or `both`. |
| `open-ida.cli.mode` | `--mode` is not `hex`, `ascii` or `utf16le`. |
| `open-ida.cli.syntax` | `--syntax` is not `intel`, `masm` or `nasm`. |
| `open-ida.cli.bytes` | `--bytes` is missing or empty. |
| `open-ida.cli.gui-failed` | The Studio window failed to open. |
