# OpenIDA architecture

OpenIDA is one product domain on top of shared `boost.rs` owners. The domain
owns the session policy, the workflows and the report assembly; the format
adapters project upstream facts; the binding and the SDK only transport them.
No layer parses a business payload twice.

## Components

| Layer    | Crate or package                                  | Responsibility                                                                                                                                                                                                                                        |
|----------|---------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Domain   | `../projects/crates/ida-domain` (`ida-domain`)     | Session defaults, `OpenIda`, the capability matrix, the stable error surface and the workflows that assemble reports: inspect (strings, find), compare (diff), disassemble, patch and extract (dump, carve, inflate, Tauri assets, container unpack). It owns no format decoder. |
| Adapters | `../projects/crates/ida-format-adapters` (`ida-format-adapters`) | Thin projections over `data-binary-*` facts: `pe`, `elf`, `macho`, `python` and `containers` (asar, nsis, overlay, entropy). Every entry takes an open `BinarySession` and returns one report. The shared `IdaError`/`Result` type is defined here so the domain can depend on the adapters without a cycle. |
| Upstream | `data-binary-inspect`, `data-binary-pe`, `data-binary-mach-o`, `data-binary-container`, `data-binary-x64`, `data-binary-sevenz`, `data-compression`, `data-encoding`, `boost-source` | Container detection, headers, sections, imports, exports, symbols, literal search, hex/base64 transforms, hex dumps, byte diff, printable-text extraction, entropy, address mapping, atomic patching, every PE directory, the ELF program-header/dynamic/note facts, the Mach-O identity/bind/export/fixup/signature/fat facts, the `.pyc`/PyInstaller/NSIS/`asar`/Tauri container facts, x86/x64 decoding (behind the `decode` feature) and bounded DEFLATE/zlib/gzip/Brotli decoding. Pinned at `boost.rs` revision `3e865d5c96ffe4e6d4da2143f63b3d29f12d0dd7`. |
| Codecs   | none (product)                                   | LZMA1/LZMA2, the DEFLATE/zlib/gzip envelopes and Brotli are owned by `data-compression`; x86/x64 decoding is owned by `data-binary-x64::decode`. The former in-repo `ida-inflate`, `ida-brotli` and `ida-x86` crates were deleted in batches 1, 2 and 3. |
| Binding  | `../projects/crates/ida-napi` (`open-ida-napi`)    | JSON-in / JSON-out Node-API exports plus the WebView host. No inspection policy and no message parsing.                                                                                                                                                |
| SDK      | `projects/packages/open-ida/src`                   | `OpenIDA` session, report types, stable error translation, addon discovery.                                                                                                                                                                            |
| CLI      | `projects/packages/open-ida/src/cli.ts`            | Argument parsing and rendering only.                                                                                                                                                                                                                   |
| Studio   | `projects/packages/open-ida-ui`                    | VMZ static shell; empty when no host is connected.                                                                                                                                                                                                     |
| Skill    | `projects/packages/open-ida-skills`                | Agent instructions; no code.                                                                                                                                                                                                                           |

## Dependency direction

```text
open-ida-napi -> ida-domain -> ida-format-adapters -> boost data-* crates
                            \-> data-binary-x64::decode
```

The production graph is acyclic. `ida-format-adapters` takes `ida-domain` only
as a dev-dependency so the projection tests can open fixtures through
`BinaryView`; the library target never sees it.

## Call path

```text
open-ida <command>
  -> src/cli.ts parses flags
  -> new OpenIDA({ path })
  -> src/native.ts requires @wae/open-ida-<platform>-<arch>
  -> open-ida-napi maps JSON onto ida-domain calls
  -> ida-domain workflow -> ida-format-adapters projection -> upstream fact
  -> JSON report
  -> CLI renders text, or the SDK returns typed data
```

The SDK and CLI never read the file themselves. A missing addon is a declarative
state: `capabilities()` and every constructor answer
`capability/not-implemented` instead of returning an empty report.

## Directory constraints

- `ida-domain/src`: `lib.rs` only wires modules and re-exports; `session.rs`
  holds `OpenIdaOptions`, `BinaryView` and `OpenIda`; `capabilities.rs`,
  `report.rs` and `error.rs` are single-purpose. `workflow/` holds
  `inspect.rs`, `compare.rs`, `disassemble.rs`, `patch.rs` and `extract.rs`;
  their private submodules keep one verb per file.
- `ida-format-adapters/src`: `lib.rs`, `error.rs`, one file per format family
  (`pe.rs`, `elf.rs`, `macho.rs`, `python.rs`, `containers.rs`) and one private
  submodule per projection. A file name states the owner it projects.
- `ida-napi/src`: `lib.rs`, `args.rs`, `registry.rs`, `webview.rs` and
  `commands/{binary,elf,macho,pe,scan}.rs`.
- No `misc.rs`, `utils.rs` or `helpers.rs` catch-all. A module that cannot name
  its owner does not get created; the code stays in the closest workflow or
  projection.
- Tests: `ida-domain/tests/contract.rs`, `ida-domain/tests/workflows.rs`,
  `ida-domain/tests/decode.rs`, `ida-domain/tests/brotli.rs` (with the fixed
  vectors in `ida-domain/tests/brotli_fixtures/mod.rs`),
  `ida-format-adapters/tests/projection.rs` and
  `ida-format-adapters/tests/pyc_opcodes.rs`. Fixtures are built per target;
  no shared catch-all fixture module.

## Determinism and bounds

- Every report is a pure function of the opened bytes and the request options.
- Hash values come from one upstream digest implementation; `diff` reuses the
  hashes already reported by `info` instead of growing a second convention.
- Byte observation is delegated: `diff` calls `data-binary-inspect::diff`,
  `strings` calls `text::extract`, `dump` calls `dump::window`, and the entropy
  and overlay projections call `entropy::range`. The product keeps the report
  shape (`differences`, `firstDifference`, `comparedBytes`, `skip`/`limit`,
  four-decimal entropy rounding) and the defaults.
- Listings are bounded by constants in the owning crate:
  string scans default to 100 hits and cap at 10,000, disassembly defaults to 64
  instructions and caps at 4,096, and diff keeps at most 64 differing ranges.
  Reports carry `total` and `truncated` so a caller can tell a complete answer
  from a cut one.
- `diff.comparedBytes` is the shorter of the two file sizes. Two files of
  different lengths are never reported as identical.
- `utf16le` scans ASCII code units with a zero high byte at every byte offset;
  `text::extract` aligns pairs to its window start, so the workflow runs the
  even and odd windows and merges the hits to keep the documented meaning.

## Address model

- A file offset is the byte position inside the file.
- An RVA is a PE image-relative address; a VA is an absolute virtual address.
- `rva <file> <address>` accepts a PE RVA or an ELF virtual address and maps it
  to a file offset.
- `offset <file> <offset>` always reports a VA and additionally reports an RVA
  when the format has one. ELF has no PE RVA, so the CLI reports `rva: null`.

## Patching

`ida-domain/src/workflow/patch.rs` delegates to the upstream session, which
writes atomically and reports the whole-file hash before and after. OpenIDA adds
no second writer:

- A range that does not fit the file is rejected with `binary/range` and the
  file is unchanged.
- `patch(offset, data)` without an output path patches the source in place.
- `patch(offset, data, output)` writes a patched copy and leaves the source
  untouched. The CLI exposes the same choice through `--out`.

## Error contract

One type owns the surface: `ida_format_adapters::error::IdaError`, re-exported
as `ida_domain::{IdaError, Result}`. It carries a stable code and a
human-readable message, keeps `source()` for the caller and never changes the
code when the message is reworded or translated.

| Code                         | Meaning                                                       |
|------------------------------|---------------------------------------------------------------|
| `binary/parse`               | The file is not a decodable container.                        |
| `binary/range`               | An offset or length is outside the file.                      |
| `binary/unsupported`         | The format or architecture is recognised but not implemented. |
| `binary/io`                  | Reading, writing or an unexpected failure.                    |
| `handle/invalid`             | The session handle is closed or unknown.                      |
| `capability/not-implemented` | The addon is absent or the route is declared unsupported.     |

N-API transport: `args::failure` serialises `"{code}: {message}"` into the
Node error string, and the binding never derives, rewrites or normalises a code
from the message. `projects/packages/open-ida/src/errors.ts` splits the
`code: ` prefix for display only and keeps branching on the code. Unknown
messages become `binary/io` with the original value as the cause.

Typed parameters are the target, not the current state: the code is stable but
the adapters still carry the detail in the message. The wiring pass moves the
per-code detail into structured fields (`offset`, `span`, `expected`, `found`)
and projects them as a discriminated N-API/IPC object. Until then no consumer
may parse the message to recover a parameter, and the code + message shape must
stay identical.

## Capability status

The status column distinguishes what is already shared from what is still a
product copy. A capability is only "migrated" when a fixed Boost revision has
both consumers and an independent oracle.

| Capability                                                                 | Owner today                                  | Status                                | Target owner                        |
|----------------------------------------------------------------------------|----------------------------------------------|---------------------------------------|-------------------------------------|
| Headers, sections, imports, exports, symbols, search, hexdump, RVA mapping, atomic patch writer | `data-binary-inspect` / `data-binary-pe` / `data-binary-mach-o` | Migrated, consumed                   | same                                |
| PE version resource, resources, relocations, exception, delay/bound imports, Rich header, certificates, TLS, load config, mitigations | `data-binary-pe::pe` (`read_*`)              | Migrated, consumed (batch 4); report structs are projections | same |
| ELF `PT_DYNAMIC`, program headers, notes                                    | `data-binary-pe::elf` (`read_*`)             | Migrated, consumed (batch 4); report structs are projections | same |
| Mach-O UUID/build versions, function starts, exports, encryption, chained fixups, bind opcodes, fat slices, code signature | `data-binary-mach-o::mach_o` (`read_*`) | Migrated, consumed (batch 4); report structs are projections | same |
| PE debug directory and `RSDS`/`NB10` records                                | `data-binary-pe` (`read_debug_directory`)    | Migrated, consumed (batch 3, unchanged in batch 4) | same                    |
| ELF static symbol table (`.symtab`)                                         | `data-binary-pe::elf` (`read_elf_symbols`)   | Migrated, consumed (batch 3)          | same                                |
| Mach-O `LC_SYMTAB` symbol table                                             | `data-binary-mach-o` (`read_macho_symbols`)  | Migrated, consumed (batch 3)          | same                                |
| CPython `marshal`/`pyc` decode, opcode tables                               | `data-binary-container::pyc`, `pyc_opcodes`  | Migrated, consumed (batch 4)          | same                                |
| PyInstaller `CArchive`/`PYZ` facts                                          | `data-binary-container::pyinstaller`         | Migrated, consumed (batch 4)          | same                                |
| `asar`, `NSIS`, Tauri v2 asset facts                                         | `data-binary-container::{asar,nsis,tauri}`   | Migrated, consumed (batch 4)          | same                                |
| Byte diff, encoded strings, dump range window, entropy range                 | `data-binary-inspect` (`3e865d5c`)           | Migrated, consumed                    | same                                |
| Byte-regex `find`                                                            | `ida-domain/src/workflow/inspect/find.rs`    | Kept local: upstream `find` is a literal matcher and has no context preview | `data-binary-inspect` once it owns byte regex |
| Overlay range and container-signature scan                                   | `ida-format-adapters/src/containers/overlay.rs` | Product/format-owned semantics; range math from `dump::window` | stays product      |
| x86/x64 decoding                                                             | `data-binary-x64` at `3e865d5c` (`decode` feature) through the disassemble workflow | Migrated, consumed: `decode::{Decoder, Instruction, Syntax}` drives `workflow/disassemble.rs`, and the former in-repo `projects/crates/ida-x86` crate was deleted (batch 3). Tests moved to `ida-domain/tests/decode.rs` | same                                |
| DEFLATE/zlib/gzip decoding                                                   | `data-compression` at `3e865d5c`             | Migrated, consumed: `Envelope::{Raw,Zlib,Gzip}::decode` and the per-envelope `Deflate`/`Zlib`/`Gzip::decode_bounded` calls drive the NSIS header block and payload chunks (`containers/nsis.rs`), PyInstaller `CArchive`/`PYZ` entries (`python/pyinstaller.rs`) and the `inflate` workflow (`workflow/extract/inflate.rs`). The former in-repo `projects/crates/ida-inflate` crate and its call sites were deleted | same                                |
| Brotli decoding                                                              | `data-compression` at `3e865d5c` (`brotli` feature) | Migrated, consumed: `Brotli::decode_bounded` drives the Tauri v2 embedded-asset decode (`workflow/extract/tauri.rs`), which rejects a blob that stops early or leaves `trailing_input != 0`. The former in-repo `projects/crates/ida-brotli` crate was deleted (batch 2) and the external `brotli` dev-dependency removed; tests use fixed Node.js 24 vectors | same                                |
| Carve and container unpack routing                                           | `ida-domain/src/workflow/extract`            | Product-local workflow                | stays product                       |
| Tauri v2 asset recovery                                                      | `data-binary-container::tauri`               | Migrated, consumed (batch 4)          | same                                |
| Decompilation, live debugging, Mach-O rebase stream                          | none                                         | Not implemented                       | stays unsupported                   |

The workspace pins every consumed `boost.rs` crate at
`3e865d5c96ffe4e6d4da2143f63b3d29f12d0dd7`. Batch 4 pinned that revision and
consumed the newly exposed `data-binary-pe` (`read_debug_directory` with
`NB10` offset/timestamp, version resources, resources, relocations, exception,
delay/bound imports, Rich header, certificates, TLS, load config, mitigations),
`data-binary-pe::elf` (`read_program_headers`, `read_dynamic`, `read_notes`),
`data-binary-mach-o::mach_o` (`read_fat_slices`, `read_exports`, encryption,
`read_chained_fixups`, `read_function_starts`, `read_code_signature`,
identity/UUID/build version, dylib timestamp and lazy commands, bind types) and
the new `data-binary-container` crate (`pyc`, `pyc_opcodes`, `pyinstaller`,
`nsis`, `asar`, `tauri`). `find` stays local because its product verb is a
regular-expression matcher rather than the upstream literal search, and
`overlay` stays product-owned because the container signature families are
OpenIDA policy. `data-compression` is the unique owner of DEFLATE/zlib/gzip and
Brotli: `ida-inflate` was deleted in batch 1 and `ida-brotli` in batch 2.
`data-binary-x64::decode` is the unique owner of instruction decoding:
`ida-x86` was deleted in batch 3.

`capabilities()` is the only support claim. A format may be classified and still
unsupported, and a suffix is never treated as a support claim. Mach-O is
`partial`: headers, load commands, segments, sections, dylibs, build versions,
the `LC_SYMTAB` symbol table, the `LC_FUNCTION_STARTS` delta table, the dyld
export trie, the `LC_ENCRYPTION_INFO(_64)` crypt range and the
`LC_DYLD_CHAINED_FIXUPS` imports/starts table and the classic dyld bind,
weak-bind and lazy-bind opcode streams (`macho-bindings`) are decoded, but the
rebase stream and chained-pointer decoding are not; fat containers expose their
architecture table through `macho-slices`, and `macho-extract` writes one slice
that the thin-image reports can reopen. Decompilation and debugging are
explicitly `not-implemented`; Mach-O import bindings are `partial` because the
bind opcode streams are decoded while nothing is bound at runtime. ARM and ARM64
disassembly returns `binary/unsupported` instead of decoding with a guessed
mode.

## Format fact ownership

Batch 4 compared every `ida-format-adapters/src/{pe,elf,macho,python,containers}`
field with the public API of the owning `boost.rs` crate at `3e865d5c`. A fact
moved to the owner only when offset, span, truncation and error code mean the
same thing; the product report shape did not change. 29 fact families migrated,
and the adapters now hold no container, `PE`, `ELF` or Mach-O decoder.

### Owner matrix (fact -> owner path)

| Fact family | Owner path |
|-------------|------------|
| PE debug directory, `RSDS`/`NB10` | `data-binary-pe::pe::{read_debug_directory, PeDebugEntry::stable_type_name, PeCodeView::{offset,timestamp}}` |
| PE version resource | `data-binary-pe::pe::read_version_resources` |
| PE resource tree | `data-binary-pe::pe::read_resources` |
| PE base relocations | `data-binary-pe::pe::read_relocations` |
| PE exception/unwind | `data-binary-pe::pe::read_exception_directory` |
| PE delay imports | `data-binary-pe::pe::read_delay_imports` |
| PE bound imports | `data-binary-pe::pe::read_bound_imports` |
| PE Rich header | `data-binary-pe::pe::read_rich_header` |
| PE certificates | `data-binary-pe::pe::read_certificates` |
| PE TLS | `data-binary-pe::pe::read_tls_directory` |
| PE load config | `data-binary-pe::pe::read_load_config` |
| PE mitigations (header/section/load-config facts) | `data-binary-pe::pe::read_mitigations` |
| ELF program headers | `data-binary-pe::elf::read_program_headers` |
| ELF dynamic table | `data-binary-pe::elf::read_dynamic` |
| ELF notes | `data-binary-pe::elf::read_notes` |
| ELF `.symtab` | `data-binary-pe::elf::read_elf_symbols` |
| Mach-O image identity (header/segments/sections/dylibs/UUID/build/entry/encryption) | `data-binary-mach-o::mach_o::{parse_macho, MachOImage}` |
| Mach-O fat slices | `data-binary-mach-o::mach_o::read_fat_slices` |
| Mach-O export trie | `data-binary-mach-o::mach_o::read_exports` |
| Mach-O chained fixups | `data-binary-mach-o::mach_o::read_chained_fixups` |
| Mach-O function starts | `data-binary-mach-o::mach_o::read_function_starts` |
| Mach-O code signature | `data-binary-mach-o::mach_o::read_code_signature` |
| Mach-O classic bind streams | `data-binary-mach-o::mach_o::read_bindings` |
| Mach-O `LC_SYMTAB` | `data-binary-mach-o::mach_o::read_macho_symbols` |
| `.pyc` / `marshal` | `data-binary-container::pyc::{analyze, sniff}` |
| CPython opcode tables | `data-binary-container::pyc_opcodes` |
| PyInstaller `CArchive`/`PYZ` | `data-binary-container::pyinstaller::{analyze_carchive, analyze_pyz, locate_cookie}` |
| NSIS | `data-binary-container::nsis::{analyze, locate}` |
| `asar` | `data-binary-container::asar::analyze` |
| Tauri v2 assets | `data-binary-container::tauri::{analyze, scan_assets}` |

### Deleted local parser modules

| Removed path | Fact it parsed | Replacement |
|--------------|----------------|-------------|
| `python/pyc/marshal.rs` | `marshal` object graph | `data-binary-container::pyc` |
| `python/pyc/render.rs` | `.pyc` report rendering | `data-binary-container::pyc::analyze` |
| `macho/util.rs` | fat-magic probe | `data_binary_mach_o::mach_o::fat_magic` |
| decoder bodies in `pe/{debug,version,resources,relocations,exception,delay_imports,bound_imports,rich_header,certificates,tls,load_config,mitigations}.rs` | byte walks over `IMAGE_*` directories | the `read_*` calls above |
| decoder bodies in `elf/{segments,dynamic,notes}.rs` | `e_phoff` / `PT_DYNAMIC` / `PT_NOTE` walks | `read_program_headers` / `read_dynamic` / `read_notes` |
| decoder bodies in `macho/{image,fat,exports,encryption,chained_fixups,function_starts,code_signature,bindings}.rs` | load-command and trie walks | the `MachOImage` fields and `read_*` calls above |
| decoder bodies in `python/{pyc,pyc_opcodes,pyinstaller}.rs`, `containers/{asar,nsis}.rs`, `workflow/extract/tauri.rs` | container parsers | `data-binary-container` calls |

Only projections remain in those files: each maps owner types into the
published report JSON and aliases different owner names (for example
`PeResourcesReport` -> `ResourcesReport`).

### Remaining gaps (product-local)

| Gap | Local path | Why it stays |
|-----|------------|--------------|
| PE overlay range and signature families | `containers/overlay.rs` | The owner exposes sections and directories, not "the overlay"; which signatures count is OpenIDA policy. |
| `unpack` verb | `workflow/extract/unpack.rs` | A verb: format routing plus the 7z aggregation; the 7z facts are `data-binary-sevenz`. |
| `carve` verb | `workflow/extract/carve.rs` | A product scan-and-write workflow, not a container fact. |
| Byte-regex `find` | `workflow/inspect/find.rs` | Upstream `find` is literal-only and has no context preview. |
| Mach-O binding list bound | `macho/bindings.rs` | `read_bindings` is unbounded; the projection keeps the product 512-entry cap and `total`/`truncated`. |
| PyInstaller cookie window | `python/pyinstaller.rs` | Reads the final 1 KiB through the session and rebases the owner's in-window offset; equivalent to a full-image scan without loading a whole installer. |

Report-shape adaptations: owner report names that differ are aliased, owner
types without serde (ELF dynamic/segments/notes, Mach-O reports) are copied into
the existing JSON structs, and every `ContainerError` / `PeAnalysisError` /
`ElfParseError` / `MachOParseError` is mapped onto `IdaError`, keeping the
existing codes. The PE32+ `DllCharacteristics` fixture now uses the real
optional-header offset 70, because the owner reads it correctly and the former
local `+0x4a` workaround was removed.

## Representation helpers

`data-encoding` at `3e865d5c` owns `Hex`, `Base64`, LEB128 and ZigZag. It was
already in the graph through `data-binary-inspect`; the workspace now declares it
directly, so no new external crate was added. Standard byte-to-hex conversions
route through `representation::Hex::lowercase()`:

- disassembly instruction bytes (`workflow/disassemble.rs`),
- the `read` hex payload (`ida-napi/src/commands/binary.rs`),
- the 7z method-id rendering (`workflow/extract/unpack.rs`),
- the ELF note hex preview (`elf/notes.rs`).

Hex decoding already ran through `data-binary-inspect::parse_hex`. Three local
formatters stay because they are layouts, not conversions: the spaced
`aa bb cc` previews in the inflate workflow and the overlay signature scan, and
the PE `CodeView` GUID / Mach-O `LC_UUID` dash layouts.

## Test strategy

- `ida-domain/tests/contract.rs` pins the public contract: the capability
  matrix, the stable codes and the camelCase wire defaults of every options
  struct.
- `ida-domain/tests/workflows.rs` drives the product verbs end to end: open,
  inspect, strings, hexdump, patch, compare, disassemble, entropy, search, find,
  dump, carve, inflate, Tauri recovery and container unpack.
- `ida-domain/tests/decode.rs` pins the migrated x86/x64 decoder assertions
  against `data_binary_x64::decode`; the bodies are unchanged from the deleted
  `ida-x86` suite.
- `ida-domain/tests/brotli.rs` pins the migrated Brotli assertions against
  `data_compression::Brotli` and the bounded product contract, using fixed
  Node.js 24 `zlib.brotliCompressSync` vectors from
  `ida-domain/tests/brotli_fixtures/mod.rs`; the tests never encode.
- `ida-format-adapters/tests/projection.rs` asserts the format fact shapes
  (PE/ELF/Mach-O/PYC/container). The test target opens fixtures through
  `BinaryView` via the dev-dependency. Batch 4 removed no projection test; the
  only fixture change is the PE32+ `DllCharacteristics` offset (70 instead of
  the former local `+0x4a` workaround).
- `ida-format-adapters/tests/pyc_opcodes.rs` pins the opcode table invariants;
  the tables now come from `data-binary-container::pyc_opcodes`.
- The three unit tests of the deleted in-repo Tauri brotli decoder moved with
  the decoder to `data-binary-container`; the product workflow-level Tauri
  coverage in `workflows.rs` is unchanged, so the workspace total is 207.
- The TypeScript smoke test lives in
  `projects/packages/open-ida/tests/smoke.test.ts`, compiles with
  `tsconfig.test.json` and asserts the error contract plus the absent-addon
  behaviour. No test file is placed under `src`.
- Tests that need a native addon skip themselves when `nativeBinding()` returns
  `undefined`, so CI stays green without a staged `.node` while still proving
  the pure TypeScript contract.