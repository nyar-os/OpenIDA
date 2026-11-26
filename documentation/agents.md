# OpenIDA agent reference

How an agent discovers capabilities, drives the `open-ida` CLI and interprets
the stable error surface. The CLI is the automation surface; the SDK (`@wae/open-ida`) exposes the same calls with typed
reports.

## Capability discovery

Start every task with the matrix, not with a file extension:

```bash
open-ida capabilities
```

The matrix reports `formats`, `features`, `unsupported` and `architectures`.
`partial` is not full support, and `unsupported` is a truthful answer rather than
a failure. A classified container can still be unsupported: unknown containers
are rejected, and a fat Mach-O is a slice table rather than a thin image.

## Routes

| Route                       | Command                                                             | Evidence                                                                     |
|-----------------------------|---------------------------------------------------------------------|------------------------------------------------------------------------------|
| Identify                    | `open-ida info <file>`                                              | Format, architecture, entry, image base, hash                                |
| Map sections                | `open-ida sections <file>`                                          | Address, file range and r/w/x per section                                    |
| Find text                   | `open-ida strings <file> --encoding both`                           | Offset and length per run                                                    |
| Read bytes                  | `open-ida hexdump <file> --offset <n> --length <n>`                 | Canonical hex dump                                                           |
| Resolve addresses           | `open-ida rva <file> <address>` / `open-ida offset <file> <offset>` | Offset, RVA and VA                                                           |
| Inspect linkage             | `open-ida imports\|exports\|symbols <file>`                         | Module, symbol, ordinal, address                                             |
| Recover PDB path            | `open-ida debug <file>`                                             | CodeView signature, GUID or NB10 record, path                                |
| Read product metadata       | `open-ida version <file>`                                           | File/product version and `StringFileInfo` pairs                              |
| Profile Mach-O              | `open-ida macho <file>`                                             | UUID, platform, min OS/SDK, dylibs, segments, sections, entry                |
| Check PE hardening          | `open-ida mitigations <file>`                                       | ASLR, DEP, CFG, GS, W+X, relocations, certificate presence                   |
| List PE resources           | `open-ida resources <file>`                                         | Type, name, language, RVA and size per leaf                                  |
| List PE relocations         | `open-ida relocations <file>`                                       | Page RVA, entry count and fixup types per block                              |
| List PE runtime functions   | `open-ida exception <file>`                                         | Begin/end RVA, unwind info and decoded x64 unwind header                     |
| List PE delay imports       | `open-ida pe-delay-imports <file>`                                  | Module name, timestamp and per-thunk INT/IAT RVAs with name, hint or ordinal |
| List PE bound imports       | `open-ida pe-bound-imports <file>`                                  | Descriptor timestamp, module name and inline forwarder refs                  |
| Decode PE Rich header       | `open-ida pe-rich-header <file>`                                    | XOR key, DanS/Rich offsets and compid/build/count entries                    |
| Read ELF dependencies       | `open-ida dynamic <file>`                                           | Interpreter, SONAME, needed libraries, rpath/runpath                         |
| List ELF static symbols     | `open-ida elf-symbols <file>`                                       | `.symtab` name, value, size, type, binding, visibility and section           |
| List ELF program headers    | `open-ida segments <file>`                                          | Segment type, offset, addresses, sizes, permissions and alignment            |
| Read ELF notes              | `open-ida notes <file>`                                             | GNU build id, ABI tag, GNU properties                                        |
| List PE certificates        | `open-ida certificates <file>`                                      | Attribute certificate table headers, `PKCS#7` shape (not verified)           |
| Read PE TLS                 | `open-ida tls <file>`                                               | Raw range, index slot, zero fill and mapped callback addresses               |
| Read PE load config         | `open-ida load-config <file>`                                       | Security cookie, SEH table, CFG metadata and decoded guard flags             |
| Read Mach-O code signature  | `open-ida code-signature <file>`                                    | Blob table and CodeDirectory fields (not verified)                           |
| List fat slices             | `open-ida macho-slices <file>`                                      | CPU, architecture, offset, size and alignment per slice                      |
| Extract a fat slice         | `open-ida macho-extract <file> --index <n> --out <file>`            | Writes one slice; the source is never overwritten                            |
| List Mach-O symbols         | `open-ida macho-symbols <file> --limit <n>`                         | Name, address, kind, section and flags per `LC_SYMTAB` entry                 |
| List Mach-O function starts | `open-ida macho-function-starts <file> --limit <n>`                 | Absolute addresses decoded from `LC_FUNCTION_STARTS`                         |
| List Mach-O exports         | `open-ida macho-exports <file>`                                     | Dyld export trie names, flags, addresses and ordinals                        |
| Read Mach-O encryption      | `open-ida macho-encryption <file>`                                  | `LC_ENCRYPTION_INFO` crypt offset, size and cryptid                          |
| Read Mach-O chained fixups  | `open-ida macho-chained-fixups <file>`                              | `LC_DYLD_CHAINED_FIXUPS` imports, header and starts table                    |
| Decode Mach-O bind opcodes  | `open-ida macho-bindings <file>`                                    | Classic dyld bind, weak-bind and lazy-bind opcode streams                    |
| Decode code                 | `open-ida disasm <file> [--format auto\|x86\|pyc]`                    | Address, offset, bytes, mnemonic; bytecode code objects and instructions     |
| Triage packing              | `open-ida entropy <file>`                                           | Whole-file and section entropy, PE overlay                                   |
| Compare builds              | `open-ida diff <left> <right>`                                      | First difference and differing ranges                                        |
| Search patterns             | `open-ida search <file> <pattern> --mode hex\|ascii\|utf16le`       | Offset and preview                                                           |
| Search byte regexes         | `open-ida find <file> --pattern <regex> [--ignore-case]`            | Offset, length and printable preview per match                               |
| Export raw bytes            | `open-ida dump <file> --offset <n> --length <n> --output <path>`    | Applied length and written byte count                                        |
| Extract printable blobs     | `open-ida carve <file> --marker <regex> [--out <dir>]`              | Region offset, length, preview and written file per match                    |
| Recover Tauri assets        | `open-ida tauri-assets <file> [--out <dir>]`                        | Key, blob offset, compressed/decompressed size and written file per asset    |
| Patch                       | `open-ida patch <file> --offset <n> --bytes <hex> --out <copy>`     | Before/after whole-file hashes                                               |

## Limits agents must respect

- `strings` defaults to 100 hits; the engine caps a request at 10,000, or at
  2,000,000 with `--all`. `--skip <n>` drops leading hits before the limit.
- `find` defaults to 100 matches; the engine clamps `--limit` to 5,000 and
  `--context` to 512 bytes. An invalid pattern is `binary/parse`.
- `dump` exports at most 64 MiB per request; a range outside the file is
  `binary/range` and nothing is written.
- `carve` defaults to 20 examined matches; the engine clamps `--limit` to 100.
  Regions shorter than `--min` (200 bytes) are dropped; expansion caps are
  `--expand-left` 4,096 and `--max` 262,144 bytes. An invalid marker is
  `binary/parse`.
- `tauri-assets` defaults to 200 assets; the engine clamps `--limit` to 1,000.
  A PE without an interleaved Tauri asset table answers an empty report; a
  non-PE input is `binary/parse`.
- `disasm` defaults to 64 instructions and caps at 4,096.
- `diff` reports at most 64 differing ranges.
- Every bounded report carries `total` and `truncated`.
- `utf16le` means ASCII characters stored with a zero high byte, not arbitrary
  UTF-16 text.

## Stable codes

| Code                         | What to do                                                                         |
|------------------------------|------------------------------------------------------------------------------------|
| `binary/parse`               | The file is not a decodable container. Stop and report it.                         |
| `binary/range`               | The offset or length is outside the file. Re-check the value.                      |
| `binary/unsupported`         | The format or architecture is not implemented. Do not substitute another analysis. |
| `binary/io`                  | Read/write failure or an unknown engine message. Report the original error.        |
| `handle/invalid`             | The session is closed. Open a new one.                                             |
| `capability/not-implemented` | The addon is absent or the route is declared unsupported. Do not invent a result.  |

Branch on `code`, never on message text. CLI usage failures add
`open-ida.cli.*` codes and exit `2`.

## Hard rules

1. Never claim a section, offset, import or instruction without printing the
   report that contains it.
2. Never describe Mach-O runtime binding, ARM/ARM64 disassembly, decompilation
   or debugging as available. Mach-O load commands, segments, sections, dylibs,
   build versions, the `LC_SYMTAB` symbol table, the fat slice table and the
   classic dyld bind opcode streams (`macho-bindings`) are available; the
   rebase stream is not decoded and nothing is bound at runtime.
3. A fat Mach-O is not a thin image: `macho-slices` lists its architectures and
   `macho-extract` writes one slice, which can then be opened with `macho` or
   `macho-symbols`. Never point `--out` at the source container.
4. Before patching, state the file, the offset and the exact bytes. Prefer
   `--out` so the source stays untouched.
5. Never present a hash as a security verdict. It only proves the bytes changed.
6. Do not overwrite the only copy of a binary. An in-place patch requires the
   user's explicit request.
7. Report `truncated` results as truncated; do not present a partial listing as
   complete.
8. `mitigations` reports header and load-config facts. A present certificate
   table is not a verified signature, and a set CFG bit is not proof that every
   indirect call is checked.

## Code layout and ownership

| Crate                        | Owns                                                                                                         | Must not contain                                                     |
|------------------------------|--------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| `projects/crates/ida-domain` | Session defaults, `OpenIda`/`BinaryView`, capabilities, stable error re-export, workflows (`inspect`, `compare`, `disassemble`, `patch`, `extract`) | Format decoders, byte-observation algorithms that Boost owns, Node-API |
| `projects/crates/ida-format-adapters` | Format projections `pe`, `elf`, `macho`, `python`, `containers`, and the shared `IdaError`/`Result` | Session policy, workflow ordering, Node-API                          |
| `projects/crates/ida-napi`   | JSON-in/JSON-out exports and the WebView host                                                                 | Inspection policy, message parsing, report reshaping                  |

x86/x64 decoding is no longer a product crate: `data-binary-x64` at `boost.rs`
`3e865d5c` owns it behind the non-default `decode` feature, and the in-repo
`projects/crates/ida-x86` crate was deleted in batch 3. Brotli,
DEFLATE/zlib/gzip and LZMA are owned by `data-compression` at the same revision;
`ida-brotli` and `ida-inflate` no longer exist. Batch 4 also moved every PE
directory, the ELF program-header/dynamic/note facts, the Mach-O identity and
extended load-command facts and the `.pyc`/PyInstaller/NSIS/`asar`/Tauri
containers to `data-binary-pe`, `data-binary-mach-o` and the new
`data-binary-container`; only the overlay policy, the `unpack`/`carve` verbs,
byte-regex `find` and the format gaps listed in `architecture.md` stay
product-local.

The production dependency direction is `open-ida-napi -> ida-domain ->
ida-format-adapters -> boost data-* crates`. `ida-format-adapters` lists
`ida-domain` only as a dev-dependency so projection tests can open fixtures
through `BinaryView`; do not make it a normal dependency. Directory constraints
are in `architecture.md`; in short, one file per verb or per format projection
and no `misc.rs`/`utils.rs` catch-all.

## Error transport

An operation fails with `ida_domain::IdaError`, which is
`ida_format_adapters::error::IdaError` re-exported. It carries a stable `code`
and a message. N-API serialises `"{code}: {message}"` and never derives or
rewrites the code from the message; the SDK splits the prefix for display only
and keeps branching on the code. Typed parameters are the target, not the
current state: do not parse the message to recover an offset or a length, and do
not change the code + message shape until the wiring pass introduces the typed
payload.

## Capability status

`open-ida capabilities` is the only support claim. The status of each capability:

- Migrated and consumed: container headers, sections, imports, exports,
  symbols, search, hexdump, RVA mapping, the atomic patch writer, the
  bounded DEFLATE/zlib/gzip envelopes and hex/base64 transforms.
- Migrated to the format owners at `boost.rs` `3e865d5c`: every PE directory
  (`data-binary-pe::pe::read_*`), the ELF program headers, dynamic table, notes
  and `.symtab` (`data-binary-pe::elf::read_*`), the Mach-O image identity,
  fat slices, exports, chained fixups, function starts, code signature, bind
  streams and `LC_SYMTAB` (`data-binary-mach-o::mach_o`), and the
  `.pyc`/PyInstaller/NSIS/`asar`/Tauri facts (`data-binary-container`). Their
  local parsers were deleted; only projection structs remain, and report shapes
  are unchanged.
- Product projection over an upstream gap: none of the format decode paths.
  `architecture.md` lists the remaining product-local items: overlay policy,
  the `unpack`/`carve` verbs, byte-regex `find`, the Mach-O binding-list bound
  and the windowed PyInstaller cookie adapter.
- Migrated to `data-binary-inspect` at `boost.rs` `3e865d5c`: byte diff,
  encoded string extraction, the dump range window, entropy ranges and
  `parse_hex`.
- Migrated to `data-compression` at `boost.rs` `3e865d5c`: DEFLATE/zlib/gzip
  through `Envelope::{Raw,Zlib,Gzip}` and the per-envelope
  `Deflate`/`Zlib`/`Gzip::decode_bounded`, called by the `nsis` container, the
  PyInstaller `CArchive`/`PYZ` decoder and the `inflate` workflow. The in-repo
  `projects/crates/ida-inflate` crate was deleted.
- Migrated to `data-compression` at `boost.rs` `3e865d5c` with the non-default
  `brotli` feature: `Brotli::decode_bounded` drives the Tauri v2 embedded-asset
  decode, now inside `data-binary-container::tauri`, which keeps the 64 MiB
  output cap and rejects a blob that stops early or leaves trailing bytes. The
  in-repo `projects/crates/ida-brotli` crate and the external `brotli`
  dev-dependency were deleted (batch 2); tests use fixed Node.js 24 vectors.
- Migrated to `data-binary-x64` at `boost.rs` `3e865d5c` with the non-default
  `decode` feature: `decode::{Decoder, Instruction, Syntax}` drives
  `workflow/disassemble.rs`, and the former in-repo `projects/crates/ida-x86`
  crate was deleted (batch 3). The decoder suite moved to
  `ida-domain/tests/decode.rs`.
- Kept local with an owner gap: byte-regex `find` (upstream `find` is
  literal-only and has no context preview), the overlay signature scan (product
  policy over `dump::window`), and the items listed in the `architecture.md`
  gap table.
- Product-local: the `unpack` routing and `carve` verbs.
- Still unsupported: decompilation, live debugging, Mach-O rebase stream,
  ARM/ARM64 disassembly.

## Verification

```bash
cargo test --workspace                 # domain contract/workflows/decode + adapter projections
cargo check --workspace --all-targets  # zero warnings
cargo tree -e normal,build,dev -i iced-x86  # must print nothing (no iced-x86 dependency)
cargo fmt -p ida-domain -p ida-format-adapters -p open-ida-napi -- --check
cargo clippy -p ida-domain -p ida-format-adapters -p open-ida-napi --all-targets -- -D warnings
pnpm typecheck                         # when node_modules exists
```

Tests are layered: `ida-domain/tests/contract.rs` pins capabilities, codes and
wire defaults; `ida-domain/tests/workflows.rs` drives product verbs;
`ida-domain/tests/decode.rs` pins the migrated `data_binary_x64::decode`
assertions; `ida-domain/tests/brotli.rs` pins the migrated Brotli assertions and
the bounded product contract over fixed Node.js 24 vectors in
`ida-domain/tests/brotli_fixtures/mod.rs`; `ida-format-adapters/tests/projection.rs`
pins format fact shapes; and `ida-format-adapters/tests/pyc_opcodes.rs` pins the
opcode tables. Do not put a test file under `src`.

## Key files

| Path                                                         | Contents                                 |
|--------------------------------------------------------------|------------------------------------------|
| `projects/crates/ida-domain/src/session.rs`                   | `OpenIdaOptions`, `BinaryView`, `OpenIda`. |
| `projects/crates/ida-domain/src/report.rs`                    | The public report surface.               |
| `projects/crates/ida-domain/src/workflow/`                    | The five workflow modules.               |
| `projects/crates/ida-format-adapters/src/`                    | `pe`, `elf`, `macho`, `python`, `containers`. |
| `projects/packages/open-ida/src/api.ts`                      | `OpenIDA` session and `capabilities()`.  |
| `projects/packages/open-ida/src/types.ts`                    | Every report shape.                      |
| `projects/packages/open-ida/src/errors.ts`                   | Stable codes and `translateNativeError`. |
| `projects/packages/open-ida/src/cli.ts`                      | Command tree and rendering.              |
| `projects/packages/open-ida/src/native.ts`                   | Addon discovery and `OPEN_IDA_NATIVE`.   |
| `projects/packages/open-ida-skills/skills/open-ida/SKILL.md` | The packaged skill.                      |

The implemented surface is exactly what `open-ida capabilities` reports.
