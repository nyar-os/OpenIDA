# open-ida CLI reference

Every command opens the named file, runs one inspection, prints one report and
closes the handle. Offsets accept decimal or `0x`-prefixed hexadecimal. Usage
failures print a stable `open-ida.cli.*` code and exit `2`; engine and IO
failures exit non-zero. A successful command exits `0`.

## Global flags

| Flag            | Meaning                                                                         |
|-----------------|---------------------------------------------------------------------------------|
| `--help`, `-h`  | Print help derived from the command tree and `locales/en-US/cli.json`.          |
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
open-ida strings ./samples/app.exe --min 6 --limit 200 --skip 200
open-ida strings ./samples/app.exe --min 6 --all
```

| Flag                    | Default | Meaning                                                        |
|-------------------------|---------|----------------------------------------------------------------|
| `--min <len>`           | `4`     | Minimum printable run length.                                  |
| `--limit <count>`       | `100`   | Maximum hits; the engine caps the requested value at 10,000.   |
| `--skip <count>`        | `0`     | Leading hits dropped before the limit, for paging.             |
| `--all`                 | off     | Ignore `--limit` and return up to the 2,000,000 hard cap.      |
| `--encoding <encoding>` | `ascii` | `ascii`, `utf16le` or `both`.                                  |

Hits are reported with their file offset and byte length. In `both` mode every
hit is tagged with its encoding.

### `hexdump <file>`

```bash
open-ida hexdump ./samples/app.exe --offset 0x1000 --length 128
```

| Flag                | Default | Meaning                    |
|---------------------|---------|----------------------------|
| `--offset <offset>` | `0`     | First byte to render.      |
| `--length <length>` | `256`   | Number of bytes to render. |

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

### `resources <file>`

```bash
open-ida resources ./samples/app.exe
```

PE only. Walks the three-level resource tree (type, name, language) and prints
each leaf with type, name, language id, data RVA, size and code page. Standard
types are named (`VERSION`, `MANIFEST`, `GROUP_ICON`, ...); numeric names print
as `#<id>` and custom names print as written. A PE without a resource directory
prints `no resource directory`. The list is capped at 256 leaves, with `total`
and `truncated` describing the cut.

### `relocations <file>`

```bash
open-ida relocations ./samples/app.exe
```

PE only. Walks the `IMAGE_BASE_RELOCATION` blocks behind data directory 5 and
prints each block's 4 KiB page RVA, entry count and per-type fixup counts, then
the whole-image totals. Types use the standard names (`ABSOLUTE`, `HIGH`,
`LOW`, `HIGHLOW`, `HIGHADJ`, `DIR64`, ...); unknown numbers print as `#<n>`. A
PE without base relocations prints `no base relocations`. At most 128 blocks are
listed and 4,096 are decoded, with `truncated` set when a limit or a malformed
block stops the walk.

The report describes the fixup table; it does not apply relocations or claim
that a module was loaded at a different base.

### `exception <file>`

```bash
open-ida exception ./samples/app.exe
```

PE only. Walks the runtime function table behind data directory 3 and prints
each entry's begin/end RVA and unwind info RVA. The layout follows the `COFF`
machine: x64 records are three `u32` fields and their `UNWIND_INFO` header is
decoded (version, `EHANDLER` / `UHANDLER` / `CHAININFO` flags, prologue size,
code count, frame register and offset); ARM and ARM64 records are two words with
the begin-address flag bits masked off. At most 512 entries are listed. A PE
without the directory prints `no exception directory`. Unwind opcodes are not
disassembled, and chained info is reported as a flag only.

### `pe-delay-imports <file>`

```bash
open-ida pe-delay-imports ./samples/app.exe
```

PE only. Walks the delay-load descriptors behind data directory 13 and prints
each module's name, timestamp and handle/IAT/INT/bound-IAT/unload-IAT RVAs,
then each thunk's INT and IAT slot RVAs with the resolved name and hint or the
ordinal (bit 31). At most 128 modules, 256 thunks per module and 1,024 thunks
overall are listed; `truncated` marks a cut. Only the v2 RVA-based descriptor
layout is mapped — legacy v1 records store virtual addresses and are reported
with their raw fields. A PE without the directory prints
`no delay-import directory`. Nothing is loaded or executed.

### `pe-bound-imports <file>`

```bash
open-ida pe-bound-imports ./samples/app.exe
```

PE only. Walks the bound-import descriptors behind data directory 11 and
prints each module's timestamp, name offset and resolved name, then its inline
forwarder references. The array is terminated by an all-zero descriptor; a
missing terminator, a cap hit (64 descriptors, 32 forwarders each) or an
unresolvable name sets `truncated`. A PE without the directory prints
`no bound-import directory`. The report describes the binder's record; it does
not re-bind or load any module.

### `pe-rich-header <file>`

```bash
open-ida pe-rich-header ./samples/app.exe
```

PE only. Locates the linker's Rich header between the DOS stub and the PE
header, reads the XOR key after the `Rich` signature, validates the `DanS`
marker and decodes up to 64 `(compid, build, count)` entries. Every entry
carries its raw fields; well-known compids also get a best-effort tool name.
An image without a validated Rich header prints `no Rich header`; a run that
is not entry-aligned or exceeds the cap sets `truncated`. The stamp is
linker-written metadata and can be spoofed — nothing is verified against a
real toolchain.

### `dynamic <file>`

```bash
open-ida dynamic ./samples/app.elf
```

ELF only. Prints the `PT_INTERP` interpreter, the `DT_SONAME`, the requested
`DT_NEEDED` libraries, and the `DT_RPATH` / `DT_RUNPATH` search paths split on
`:`. Virtual addresses are mapped to file offsets through the `PT_LOAD`
segments, so the report still works on images whose section headers were
stripped. A static image prints `no PT_DYNAMIC segment (static image)`; non-ELF
answers `binary/unsupported`.

The report reads the recorded dependency names. It does not resolve which copy
of a library the dynamic loader would pick at run time.

### `elf-symbols <file>`

```bash
open-ida elf-symbols ./samples/app.elf
```

ELF only. Walks the section headers to the first `SHT_SYMTAB` and prints one
line per entry: value, size, `type/binding/visibility` and the owning section,
with `SHN_UNDEF`, `SHN_ABS` and `SHN_COMMON` rendered as `UND`, `ABS` and
`COM`. This is the static table, so local and file-scope symbols appear too;
the separate `symbols` command keeps reporting the dynamic one. The listing is
capped at 4,096 entries. An image without `.symtab` prints
`no .symtab section`; non-ELF answers `binary/unsupported`.

### `segments <file>`

```bash
open-ida segments ./samples/app.elf
```

ELF only. Prints one line per program header: index, stable type name (`PT_LOAD`, `PT_DYNAMIC`, `PT_GNU_RELRO`, ...),
file offset, virtual and physical
address, file and memory size, `R/W/X` permissions and alignment. The layout is
chosen from `e_ident` class, so ELF32 and ELF64 both work. A file without program
headers prints `no program header table`; non-ELF answers `binary/unsupported`.

The report describes the table; it does not apply relocations or load the image.

### `notes <file>`

```bash
open-ida notes ./samples/app.elf
```

ELF only. Reads notes from `PT_NOTE` segments, or from `SHT_NOTE` sections when
the program headers are absent, and prints each note's owner, type, description
size and decoded description. `NT_GNU_BUILD_ID` prints as lowercase hex,
`NT_GNU_ABI_TAG` as `<os> <major>.<minor>.<subminor>`, and
`NT_GNU_PROPERTY_TYPE_0` as one line per property with its stable name and hex
payload. Other descriptions are a bounded hex preview. An image without notes
prints `no note segments or sections`; non-ELF answers `binary/unsupported`.

The report decodes the note records; it does not validate build ids against a
symbol server or interpret every architecture-specific property bit.

### `certificates <file>`

```bash
open-ida certificates ./samples/app.exe
```

PE only. Prints one line per `WIN_CERTIFICATE` entry behind data directory 4:
file offset, revision (`1.0`, `2.0` or hex), certificate type (`X509`,
`PKCS_SIGNED_DATA`, ...), payload size and whether the payload starts with a
DER `SEQUENCE`, the usual `PKCS#7` shape. Entries are read on their eight-byte
boundaries. A PE without the table prints `no attribute certificate table`;
non-PE answers `binary/unsupported`.

Headers and payload shape only: the table is not a trust decision, and no
signature, chain or timestamp is verified.

### `tls <file>`

```bash
open-ida tls ./samples/app.exe
```

PE only. Decodes data directory 9 and prints the raw template range, the index
slot, `SizeOfZeroFill`, `Characteristics` and the callback array. Callback
addresses are VAs, so each is mapped back through `ImageBase` to an RVA and a
file offset; an address outside the image keeps its VA and reports `null` for
the mapping. At most 64 callbacks are listed. A PE without a TLS directory
prints `no TLS directory`; non-PE answers `binary/unsupported`.

The report describes the table; it never calls a callback or initialises TLS.

### `load-config <file>`

```bash
open-ida load-config ./samples/app.exe
```

PE only. Decodes data directory 10 in the layout chosen by the optional-header
magic and prints the `/GS` security cookie, the SEH handler table and count, the
CFG check/dispatch/table pointers, the raw `GuardFlags` with their stable names (`CF_INSTRUMENTED`,
`RETPOLINE_PRESENT`, ...) and the `CodeIntegrity` block. A PE
without the directory prints `no load configuration directory`; non-PE answers
`binary/unsupported`. `truncated` is set when `Size` is shorter than the
documented PE32/PE32+ prefix.

The report reads the table; it does not prove that the loader enforced a flag.

### `mitigations <file>`

```bash
open-ida mitigations ./samples/app.exe
```

PE only. Prints `DllCharacteristics` and the derived posture: ASLR, high-entropy
VA, DEP (NX compatibility), CFG (header bit or load-config `GuardFlags`), force
integrity, no-SEH, terminal-server-aware, base relocations present or stripped,
and whether the certificate table is present. Load-config GS cookies report
`present`, `absent` or `no load config`. Sections mapped write+execute are
listed by name.

The certificate table entry means a signature blob exists. OpenIDA does not
verify it, so do not describe a file as "signed by X" from this report.

### `code-signature <file>`

```bash
open-ida code-signature ./samples/app.macho
```

Mach-O only. Finds `LC_CODE_SIGNATURE`, prints the blob offset and size, the
SuperBlob blob types and the first `CodeDirectory`: version, decoded flags,
hash algorithm, page size, code limit, signing identifier, team id and code /
special slot counts. A thin image without the command prints `no embedded code
signature`; fat containers answer `binary/unsupported` and point at
`macho-slices` + `macho-extract`; non-Mach-O answers `binary/unsupported`.

Parsed only: hashes are not recomputed and no certificate chain or requirement
is validated.

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
`binary/unsupported` and is inspected with `macho` directly. Use
`macho-extract` to write a slice before running `macho` or `macho-symbols`.

### `macho-extract <file>`

```bash
open-ida macho-extract ./samples/universal.macho --index 1 --out ./samples/app.arm64.macho
```

Fat/universal Mach-O only. Writes the slice selected by `--index` (default `0`,
matching the `macho-slices` table) to `--out`. The report repeats the index,
architecture, source offset and size. Writing to the source container itself is
refused; any other destination is replaced. The source container is never
modified; `--out` is required.

### `macho-symbols <file>`

```bash
open-ida macho-symbols ./samples/app.macho --limit 200
```

Mach-O only. Walks `LC_SYMTAB`, resolves each `nlist` / `nlist_64` name through
the string table and prints its address, kind (`undefined`, `absolute`,
`section`, `indirect`, `prebound`, `debug`), external/debug flags and section
index. `--limit` defaults to unlimited and reports `truncated` when it cuts the
table. A Mach-O without `LC_SYMTAB` answers `binary/unsupported`.

### `macho-function-starts <file>`

```bash
open-ida macho-function-starts ./samples/app.macho --limit 200
```

Mach-O only. Decodes the `LC_FUNCTION_STARTS` ULEB128 delta table, starting from
the `__TEXT` segment address, and prints each absolute function start address.
`--limit` defaults to unlimited and reports `truncated` when it cuts the table.
A Mach-O without `LC_FUNCTION_STARTS` answers `binary/unsupported`; fat
containers must be sliced first.

### `macho-exports <file>`

```bash
open-ida macho-exports ./samples/app.macho
```

Mach-O only. Walks the dyld export trie behind `LC_DYLD_EXPORTS_TRIE` or the
export fields of `LC_DYLD_INFO(_ONLY)` and prints each symbol with its flags (`WEAK`, `REEXPORT`, `STUB_AND_RESOLVER`),
address or reexport ordinal. At most
512 exports are returned and 8,192 trie nodes are visited. A Mach-O without a
trie prints `no dyld export trie`; bind opcodes are still not decoded.

### `macho-encryption <file>`

```bash
open-ida macho-encryption ./samples/app.macho
```

Mach-O only. Decodes `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64` and prints
the crypt range file offset, its size, the encryption system id and whether the
image is encrypted (`cryptid != 0`). A Mach-O without either command prints
`no LC_ENCRYPTION_INFO command`; fat containers must be sliced first. The
command is metadata only: it never decrypts bytes.

### `macho-chained-fixups <file>`

```bash
open-ida macho-chained-fixups ./samples/app.macho
```

Mach-O only. Decodes `LC_DYLD_CHAINED_FIXUPS`: the chain data range, the
`dyld_chained_fixups_header` fields, the import table (library ordinal, weak
flag, symbol name, addend for the `ADDEND` formats) and the segment count of
`dyld_chained_starts_in_image` with the number of populated segments. At most
512 imports are listed. Symbol names stay empty when the pool is zlib
compressed (`symbolsFormat: 1`). A Mach-O without the command prints
`no LC_DYLD_CHAINED_FIXUPS command`; fat containers must be sliced first.
Chained-pointer chains are not walked; the classic bind opcode streams are
decoded by `macho-bindings`.

### `macho-bindings <file>`

```bash
open-ida macho-bindings ./samples/app.macho
```

Mach-O only. Decodes the classic dyld bind, weak-bind and lazy-bind opcode
streams of `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` and prints each binding's
stream, address, owning segment, symbol, library, bind type, weak flag and
addend. Positive library ordinals resolve through the linked dylib commands in
file order; special ordinals print as `self`, `main-executable`,
`flat-lookup`, `weak-lookup` or `special`. Bindings are capped at 512; a
malformed or unsupported opcode (including the threaded table) truncates its
stream. Nothing is bound at runtime: the image bytes are never written. A
Mach-O without the command prints `no LC_DYLD_INFO bind opcodes`; fat
containers must be sliced first.

### `disasm <file>`

```bash
open-ida disasm ./samples/app.exe --offset 0x1000 --count 20 --syntax intel
```

| Flag                | Default | Meaning                                |
|---------------------|---------|----------------------------------------|
| `--offset <offset>` | `0`     | File offset to start decoding.         |
| `--count <count>`   | `64`    | Maximum instructions; capped at 4,096. |
| `--syntax <syntax>` | `intel` | `intel`, `masm` or `nasm`.             |

Only x86 and x64 are decoded. PE reports virtual addresses derived from the
image base; other architectures answer `binary/unsupported`.

### `entropy <file>`

```bash
open-ida entropy ./samples/app.exe
```

Prints whole-file entropy in bits per byte, per-section entropy for PE, ELF and
Mach-O, and the PE overlay offset and size when one exists.

### `overlay <file>`

```bash
open-ida overlay ./samples/app.exe
```

Describes the bytes after the last PE section payload: absolute offset, size,
share of the file, Shannon entropy, the first 16 bytes as spaced hex and a name
for them. It also scans the overlay for container signatures and reports a
`container` when the evidence names one:

- `nsis` for the `NullsoftInst` first header, including its header-size field;
- `pyinstaller` for the `MEI` cookie, including the Python runtime when the
  archive records one;
- the leading archive kind (`zlib`, `gzip`, `7z`, `zip`, `rar`, `cab`, `xz`,
  `zstd`, `bzip2` or `ar`) when the overlay starts with that signature.

Each entry of `signatures` carries its absolute file offset and kind; the scan
also recognises `SQLite`, PNG, JPEG, GIF and `MZ` images that point at a real
`PE\0\0` header. The list keeps at most eight entries per kind and 64 overall,
so one noisy family cannot hide the distinctive containers, and sets
`truncated` when it dropped entries. Files
without trailing bytes answer `present: false`; non-PE input exits `1` with
`binary/unsupported`.

### `inflate <file>`

```bash
open-ida inflate ./samples/app.exe --offset 0x600 --out ./payload.bin
open-ida inflate ./samples/app.exe --offset 0x600 --format raw --limit 65536
```

| Flag                | Default | Meaning                                                        |
|---------------------|---------|----------------------------------------------------------------|
| `--offset <offset>` | `0`     | File offset of the first compressed byte.                      |
| `--format <format>` | `auto`  | `auto`, `zlib`, `gzip` or `raw` DEFLATE.                       |
| `--limit <bytes>`   | `4 MiB` | Maximum decoded bytes; the engine clamps the value at 64 MiB.  |
| `--out <file>`      | —       | Write the decoded bytes to this file; omit to only report.     |

`auto` picks zlib or gzip from the first bytes and falls back to raw DEFLATE.
The report carries the wrapper used, the decoded length, the `status`
(`complete`, `output-limit`, `input-truncated`, `checksum`, `stalled` or
`invalid`), the spaced hex magic and a printable ASCII head. Nothing is
executed: only bytes are decoded, so the result can be fed to `info`, `strings`
or another `inflate`. A range outside the file exits `1` with `binary/range`; a
range that does not decode cleanly (`invalid`, `stalled` or `checksum`) exits
`1` with `binary/parse` and writes nothing, so a wrong offset cannot leave a
file full of garbage behind.

### `nsis <file>`

```bash
open-ida nsis ./samples/installer.exe
open-ida nsis ./samples/installer.exe --extract-dir ./payload
open-ida nsis ./samples/installer.exe --offset 0x12000 --commands-limit 8192
```

| Flag                       | Default    | Meaning                                                       |
|----------------------------|------------|---------------------------------------------------------------|
| `--offset <offset>`        | scan       | Absolute offset of the NSIS first header.                     |
| `--commands-limit <count>` | `4096`     | Maximum rendered script commands; capped at 65536.            |
| `--strings-limit <count>`  | `8192`     | Maximum rendered strings; capped at 65536.                    |
| `--extract-dir <dir>`      | —          | Extract the `File` payload files into this directory.         |
| `--extract-limit <bytes>`  | `256 MiB`  | Maximum bytes per extracted file; capped at 1 GiB.            |

Decodes one NSIS 2/3 installer container: the 28-byte first header, the
container framing (solid or non-solid, `none`/`deflate`/`lzma`/`bzip2`), the
eight header blocks, the script command stream with every opcode named and its
parameters rendered from the string table, the string table itself and the
`File` extraction manifest. Nothing is executed: only bytes are decoded. A
`--extract-dir` request writes each `File` chunk (raw DEFLATE decoded, stored
bytes copied) under the directory, mirroring the installer output path. Input
without an NSIS header exits `1` with `binary/parse`; solid archives and
`lzma`/`bzip2` framing answer `binary/unsupported` for extraction because only
the DEFLATE and stored paths are decoded.

### `asar <file>`

```bash
open-ida asar ./samples/app.asar
open-ida asar ./samples/app.asar --extract-dir ./source
open-ida asar ./samples/app.asar --offset 0x1000 --entries-limit 8192
```

| Flag                      | Default   | Meaning                                                    |
|---------------------------|-----------|------------------------------------------------------------|
| `--offset <offset>`       | `0`       | Absolute offset of the archive start.                      |
| `--entries-limit <count>` | `4096`    | Maximum listed file entries; capped at 65536.              |
| `--extract-dir <dir>`     | —         | Extract the packed entries into this directory.            |
| `--extract-limit <bytes>` | `256 MiB` | Maximum bytes per extracted entry; capped at 1 GiB.        |

Decodes one Electron `asar` archive statically: the sixteen-byte header (magic,
block size, string-block size, JSON length), the derived data-area offset and
the full file tree with every entry's size, absolute packed offset and
`unpacked` flag. Entries marked `unpacked` are stored loose next to the archive
and carry no packed bytes. A `--extract-dir` request writes each packed entry
under the directory, mirroring its archive path; traversal-safe names only.
Input whose first header word is not `4` exits `1` with `binary/parse`.

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

| Flag               | Default     | Meaning                                            |
|--------------------|-------------|----------------------------------------------------|
| `--mode <mode>`    | `ascii`     | `hex`, `ascii` or `utf16le`.                       |
| `--case-sensitive` | off         | ASCII letters must match case.                     |
| `--whole-word`     | off         | Matches must be surrounded by non-word characters. |
| `--limit <count>`  | `100`       | Maximum hits.                                      |
| `--start <offset>` | `0`         | First byte to scan.                                |
| `--end <offset>`   | end of file | One past the last byte to scan.                    |

Every hit carries the file offset and a preview.

### `find <file>`

```bash
open-ida find ./samples/app.exe --pattern "marker[.-][a-z]" --limit 20
open-ida find ./samples/app.exe --pattern "https?://" --ignore-case --context 120
```

| Flag              | Default | Meaning                                                  |
|-------------------|---------|----------------------------------------------------------|
| `--pattern <regex>` | —     | Regular expression evaluated against the raw bytes. Required. |
| `--skip <count>`  | `0`     | Leading matches dropped before the limit, for paging.    |
| `--limit <count>` | `100`   | Maximum matches; the engine clamps the value at 5,000.   |
| `--context <bytes>` | `80`  | Bytes rendered into each preview; clamped at 512.        |
| `--ignore-case`   | off     | ASCII letters match case-insensitively.                  |

Every match carries its file offset, byte length and a printable preview where
non-printable bytes render as dots. An invalid pattern exits `1` with a
`binary/parse` error.

### `dump <file>`

```bash
open-ida dump ./samples/app.exe --offset 0x1000 --length 64 --output ./smoke_dump.bin
```

| Flag                | Default | Meaning                                                             |
|---------------------|---------|---------------------------------------------------------------------|
| `--offset <offset>` | `0`     | First byte to export, decimal or 0x-prefixed.                       |
| `--length <size>`   | `256`   | Number of bytes to export; the engine clamps the value at 64 MiB.   |
| `--output <path>`   | —       | Destination file the raw bytes are written to. Required.            |

The bytes are stored unchanged, so a range can be fed to a second tool without
a lossy round trip. A range outside the file exits `1` with `binary/range` and
nothing is written; the report carries the applied `length` and the `written`
byte count.

### `carve <file>`

```bash
open-ida carve ./samples/app.exe --marker "synthetic-blob" --min 200 --limit 5
open-ida carve ./samples/app.exe --marker "eval\\(" --out ./carved
```

| Flag                    | Default | Meaning                                                        |
|-------------------------|---------|----------------------------------------------------------------|
| `--marker <regex>`      | —       | Byte regex that marks the regions to carve. Required.          |
| `--min <size>`          | `200`   | Regions shorter than this many bytes are dropped.              |
| `--max <size>`          | `262144`| Right expansion cap per region, in bytes.                      |
| `--expand-left <size>`  | `4096`  | Left expansion cap per region, in bytes.                       |
| `--limit <count>`       | `20`    | Maximum marker matches examined; the engine clamps at 100.     |
| `--out <dir>`           | —       | Write each region to `<dir>/carve_<n>.bin`, creating the directory. |

Every match expands left and right to the printable boundary (printable ASCII
plus tab, newline and carriage return), so a plaintext payload hidden in a
packed or interpreted container is recovered whole. Regions are deduplicated by
start offset, each carries a 120-character preview where non-printable bytes
render as dots, and `truncated` marks a scan the limit stopped early. An
invalid marker exits `1` with a `binary/parse` error.

### `tauri-assets <file>`

```bash
open-ida tauri-assets ./samples/tauri-app.exe
open-ida tauri-assets ./samples/tauri-app.exe --out ./assets --limit 50
```

| Flag              | Default | Meaning                                                          |
|-------------------|---------|------------------------------------------------------------------|
| `--out <dir>`     | —       | Write each decoded asset under `<dir>`, mirroring its key path.  |
| `--limit <count>` | `200`   | Maximum assets returned; the engine clamps at 1000.              |

Tauri v2 compiles its frontend into the executable as a `phf` map whose values
are standalone brotli streams. The command walks the interleaved
`[key_ptr, key_len, blob_ptr, blob_len, ...]` record array, keeps the longest
run of complete `(key, blob)` pairs and decodes every entry, so binary assets
such as `icon.png` survive next to text ones. A PE without such a table answers
an empty report; a non-PE input exits `1` with `binary/parse`. Keys that would
escape the output directory (`..` or a backslash) are refused with
`binary/parse`.

### `patch <file>`

```bash
open-ida patch ./samples/app.exe --offset 0x200 --bytes 90,90 --out ./samples/app-patched.exe
```

| Flag                | Required | Meaning                                                      |
|---------------------|----------|--------------------------------------------------------------|
| `--offset <offset>` | yes      | First byte to replace.                                       |
| `--bytes <hex>`     | yes      | Replacement bytes, such as `90,90` or `0x90 0x90`.           |
| `--out <file>`      | no       | Write a patched copy here instead of overwriting the source. |

The write is atomic and the report carries the whole-file hash before and after.
A range outside the file is `binary/range` and the file is unchanged.

### `gui`

```bash
open-ida gui
```

Opens the Studio window. If the window cannot start, the command exits `1` with
`open-ida.cli.gui-failed`.

## Stable CLI error codes

| Code                                         | Cause                                             |
|----------------------------------------------|---------------------------------------------------|
| `open-ida.cli.file-required`                 | A required file argument is missing.              |
| `open-ida.cli.rva-args`                      | `rva` was called without a file and an address.   |
| `open-ida.cli.offset-args`                   | `offset` was called without a file and an offset. |
| `open-ida.cli.search-args`                   | `search` was called without a file and a pattern. |
| `open-ida.cli.min`                           | `--min` is not a positive integer.                |
| `open-ida.cli.limit`                         | `--limit` is not a positive integer.              |
| `open-ida.cli.offset`                        | An offset is not a non-negative integer.          |
| `open-ida.cli.length`                        | `--length` is not a non-negative integer.         |
| `open-ida.cli.count`                         | `--count` is not a positive integer.              |
| `open-ida.cli.encoding` / `cli.err.encoding` | `--encoding` is not `ascii`, `utf16le` or `both`. |
| `cli.err.pattern`                            | `find` was called without `--pattern`.            |
| `cli.err.outputRequired`                     | `dump` was called without `--output`.             |
| `cli.err.markerRequired`                     | `carve` was called without `--marker`.            |
| `open-ida.cli.mode`                          | `--mode` is not `hex`, `ascii` or `utf16le`.      |
| `open-ida.cli.syntax`                        | `--syntax` is not `intel`, `masm` or `nasm`.      |
| `open-ida.cli.bytes`                         | `--bytes` is missing or empty.                    |
| `open-ida.cli.gui-failed`                    | The Studio window failed to open.                 |
