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
| Upstream | `data-binary-inspect`, `data-binary-pe`, `data-binary-mach-o`, `data-binary-x64`, `data-binary-sevenz`, `data-compression`, `data-encoding`, `boost-source` | Container detection, headers, sections, imports, exports, symbols, literal search, hex/base64 transforms, hex dumps, byte diff, printable-text extraction, entropy, address mapping, atomic patching, Mach-O headers/segments/sections, x86/x64 decoding (behind the `decode` feature) and bounded DEFLATE/zlib/gzip/Brotli decoding. Pinned at `boost.rs` revision `f191fdc4134a5be749f289315dfcacc7c4ad9200`. |
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
| PE version resource, resources, relocations, exception, delay/bound imports, Rich header, certificates, TLS, load config, mitigations | `ida-format-adapters/src/pe`                 | Product projection over an upstream gap | `data-binary-pe`                    |
| ELF `PT_DYNAMIC`, program headers, notes                                    | `ida-format-adapters/src/elf`                | Product projection over an upstream gap | `data-binary-pe::elf`               |
| Mach-O UUID/build versions, function starts, exports, encryption, chained fixups, bind opcodes, fat slices, code signature | `ida-format-adapters/src/macho`              | Product projection over an upstream gap | `data-binary-mach-o`                |
| PE debug directory and `RSDS`/`NB10` records                                | `data-binary-pe` (`read_debug_directory`)    | Migrated, consumed (batch 3)          | same                                |
| ELF static symbol table (`.symtab`)                                         | `data-binary-pe::elf` (`read_elf_symbols`)   | Migrated, consumed (batch 3)          | same                                |
| Mach-O `LC_SYMTAB` symbol table                                             | `data-binary-mach-o` (`read_macho_symbols`)  | Migrated, consumed (batch 3)          | same                                |
| CPython `marshal`/`pyc` decode, opcode tables                               | `ida-format-adapters/src/python`             | Product-local decoder                 | format owner candidate              |
| PyInstaller `CArchive`/`PYZ` facts                                          | `ida-format-adapters/src/python`             | Product-local container               | format owner candidate              |
| `asar`, `NSIS` facts                                                         | `ida-format-adapters/src/containers`         | Product-local container               | `data-binary-zip`/archive candidate |
| Byte diff, encoded strings, dump range window, entropy range                 | `data-binary-inspect` (`d440aae8`)           | Migrated, consumed                    | same                                |
| Byte-regex `find`                                                            | `ida-domain/src/workflow/inspect/find.rs`    | Kept local: upstream `find` is a literal matcher and has no context preview | `data-binary-inspect` once it owns byte regex |
| Overlay range and container-signature scan                                   | `ida-format-adapters/src/containers/overlay.rs` | Product/format-owned semantics; range math from `dump::window` | stays product      |
| x86/x64 decoding                                                             | `data-binary-x64` at `f191fdc4` (`decode` feature) through the disassemble workflow | Migrated, consumed: `decode::{Decoder, Instruction, Syntax}` drives `workflow/disassemble.rs`, and the former in-repo `projects/crates/ida-x86` crate was deleted (batch 3). Tests moved to `ida-domain/tests/decode.rs` | same                                |
| DEFLATE/zlib/gzip decoding                                                   | `data-compression` at `d440aae8`             | Migrated, consumed: `Envelope::{Raw,Zlib,Gzip}::decode` and the per-envelope `Deflate`/`Zlib`/`Gzip::decode_bounded` calls drive the NSIS header block and payload chunks (`containers/nsis.rs`), PyInstaller `CArchive`/`PYZ` entries (`python/pyinstaller.rs`) and the `inflate` workflow (`workflow/extract/inflate.rs`). The former in-repo `projects/crates/ida-inflate` crate and its call sites were deleted | same                                |
| Brotli decoding                                                              | `data-compression` at `d440aae8` (`brotli` feature) | Migrated, consumed: `Brotli::decode_bounded` drives the Tauri v2 embedded-asset decode (`workflow/extract/tauri.rs`), which rejects a blob that stops early or leaves `trailing_input != 0`. The former in-repo `projects/crates/ida-brotli` crate was deleted (batch 2) and the external `brotli` dev-dependency removed; tests use fixed Node.js 24 vectors | same                                |
| Carve, Tauri asset recovery, container unpack routing                        | `ida-domain/src/workflow/extract`            | Product-local workflow                | stays product                       |
| Decompilation, live debugging, Mach-O rebase stream                          | none                                         | Not implemented                       | stays unsupported                   |

The workspace pins every consumed `boost.rs` crate at
`f191fdc4134a5be749f289315dfcacc7c4ad9200`. That revision is the
`d440aae8` tree plus the `data-binary-x64` decoder (behind the non-default
`decode` feature), so the byte-observation owners did not move. `diff`, `text`,
`dump`, `entropy`, the bounded DEFLATE envelopes, Brotli and the x86/x64 decoder
are the migrated owners; `find` stays local because its product verb is a
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

Batch 3 compared every `ida-format-adapters/src/{pe,elf,macho}.rs` field with the
public API of the owning `boost.rs` crate at `f191fdc4`. A fact moved to the
owner only when offset, span, truncation and error code mean the same thing;
the product report shape did not change. Three facts migrated (687 lines of
adapter code became 381, so about 300 lines of local parsing left the repo), the
rest stay because the owner has no field for them or returns it with different
semantics.

### Migrated to the format owners

| Fact                                            | Local parser removed            | Owner now used                                                      |
|-------------------------------------------------|---------------------------------|---------------------------------------------------------------------|
| PE debug directory entries and `RSDS`/`NB10`    | `pe/debug.rs` 28-byte entry walk | `data-binary-pe::pe::{read_debug_directory, PeDebugEntry, PeCodeView}` |
| ELF `.symtab` entries and the linked string table | `elf/symbols.rs` section/symbol `Reader` | `data-binary-pe::elf::{parse_elf, read_elf_symbols, ElfSymbol}` |
| Mach-O `LC_SYMTAB` entries and the string table | `macho/symbols.rs` load-command walk | `data-binary-mach-o::{parse_macho, read_macho_symbols, MachSymbol}` |

### Remaining gaps (local parsing kept)

| Fact                                                       | Local path                        | Owner path                                  | Decision                                                                 | Exit condition                                              |
|------------------------------------------------------------|-----------------------------------|---------------------------------------------|--------------------------------------------------------------------------|-------------------------------------------------------------|
| PE `debugType` vocabulary                                  | `pe/debug.rs::debug_type_name`    | `PeDebugEntry::type_name`                   | Kept: the owner spells `reserved10`, `clsid`, `vc_feature`; switching would change wire values | Owner exposes the product vocabulary, or the values may change |
| PE `NB10` record offset and timestamp                      | `pe/debug.rs::code_view`          | `PeCodeView`                                | Kept: the owner drops the legacy pair                                    | `PeCodeView` returns `offset`/`timestamp`                   |
| PE version resource (`VS_VERSIONINFO`)                     | `pe/version.rs`                   | none                                        | Kept: no owner reader                                                    | `data-binary-pe` owns version resources                     |
| PE resource directory tree                                 | `pe/resources.rs`                 | none                                        | Kept                                                                     | `read_resources` upstream                                   |
| PE base relocations                                        | `pe/relocations.rs`               | none                                        | Kept                                                                     | `read_relocations` upstream                                 |
| PE exception runtime functions and x64 unwind              | `pe/exception.rs`                 | none                                        | Kept                                                                     | `read_runtime_functions` upstream                           |
| PE delay imports                                           | `pe/delay_imports.rs`             | none                                        | Kept                                                                     | `read_delay_imports` upstream                               |
| PE bound imports                                           | `pe/bound_imports.rs`             | none                                        | Kept                                                                     | `read_bound_imports` upstream                               |
| PE Rich header                                             | `pe/rich_header.rs`               | none                                        | Kept                                                                     | `read_rich_header` upstream                                 |
| PE attribute certificate table                             | `pe/certificates.rs`              | none                                        | Kept                                                                     | `read_certificates` upstream                                |
| PE TLS directory                                           | `pe/tls.rs`                       | none                                        | Kept                                                                     | `read_tls` upstream                                         |
| PE load configuration (also read by `mitigations`)         | `pe/load_config.rs`, `pe/mitigations.rs` | none                                 | Kept                                                                     | `read_load_config` upstream                                 |
| ELF `PT_DYNAMIC` table                                     | `elf/dynamic.rs`                  | none                                        | Kept                                                                     | dynamic table upstream                                      |
| ELF program headers                                        | `elf/segments.rs`                 | none (`ElfImage` has sections only)         | Kept                                                                     | `ElfImage.segments` upstream                                |
| ELF note segments                                           | `elf/notes.rs`                    | none                                        | Kept                                                                     | `read_elf_notes` upstream                                   |
| Mach-O identity (`LC_UUID`, `LC_BUILD_VERSION`, `LC_VERSION_MIN_*`, dylib timestamp) | `macho/image.rs` | `MachOImage` has dylibs without a timestamp and no UUID/build fields | Kept | Owner exposes those load commands                           |
| Mach-O `LC_FUNCTION_STARTS`                                 | `macho/function_starts.rs`        | none                                        | Kept                                                                     | `read_function_starts` upstream                             |
| Mach-O dyld export trie                                     | `macho/exports.rs`                | `MachDyldInfo` offsets only                 | Kept                                                                     | `read_exports_trie` upstream                                |
| Mach-O `LC_ENCRYPTION_INFO(_64)`                            | `macho/encryption.rs`             | none                                        | Kept                                                                     | crypt range upstream                                        |
| Mach-O `LC_DYLD_CHAINED_FIXUPS`                             | `macho/chained_fixups.rs`         | none                                        | Kept                                                                     | chained fixups upstream                                     |
| Mach-O classic bind opcodes                                 | `macho/bindings.rs`               | `read_bindings`, `MachBind`                 | Kept: `MachBind` has no bind type and names streams `weak_bind`/`lazy_bind`; the product reports `pointer`/`text-abs32` and special ordinals | `MachBind.bind_type` plus the product stream vocabulary |
| Mach-O code signature blob table                            | `macho/code_signature.rs`         | none                                        | Kept                                                                     | code-directory blob upstream                                |
| Mach-O fat/universal header                                 | `macho/fat.rs`                    | `macho_magic` probe only                    | Kept                                                                     | fat header upstream                                         |
| PyInstaller `CArchive`/`PYZ`, PYC, `asar`, `NSIS`           | `python/`, `containers/`          | none                                        | Kept (product container formats)                                         | a format owner appears                                     |

The PE debug directory keeps one upstream bound: `read_debug_directory` caps the
walk at 256 entries, so a corrupt directory that declares more reports the
capped result instead of the declared count.

## Representation helpers

`data-encoding` at `f191fdc4` owns `Hex`, `Base64`, LEB128 and ZigZag. It was
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
  `BinaryView` via the dev-dependency; the assertion bodies are unchanged from
  the kernel suite.
- `ida-format-adapters/tests/pyc_opcodes.rs` pins the opcode table invariants.
- The TypeScript smoke test lives in
  `projects/packages/open-ida/tests/smoke.test.ts`, compiles with
  `tsconfig.test.json` and asserts the error contract plus the absent-addon
  behaviour. No test file is placed under `src`.
- Tests that need a native addon skip themselves when `nativeBinding()` returns
  `undefined`, so CI stays green without a staged `.node` while still proving
  the pure TypeScript contract.
