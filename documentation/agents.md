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
a failure. A classified container can still be unsupported: fat Mach-O
containers are rejected, and unknown containers are rejected.

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
| Decode code                 | `open-ida disasm <file> --offset <n> --count <n>`                   | Address, offset, bytes, mnemonic                                             |
| Triage packing              | `open-ida entropy <file>`                                           | Whole-file and section entropy, PE overlay                                   |
| Compare builds              | `open-ida diff <left> <right>`                                      | First difference and differing ranges                                        |
| Search patterns             | `open-ida search <file> <pattern> --mode hex\|ascii\|utf16le`       | Offset and preview                                                           |
| Search byte regexes         | `open-ida find <file> --pattern <regex> [--ignore-case]`            | Offset, length and printable preview per match                               |
| Export raw bytes            | `open-ida dump <file> --offset <n> --length <n> --output <path>`    | Applied length and written byte count                                        |
| Extract printable blobs     | `open-ida carve <file> --marker <regex> [--out <dir>]`              | Region offset, length, preview and written file per match                    |
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

## Key files

| Path                                                         | Contents                                 |
|--------------------------------------------------------------|------------------------------------------|
| `projects/packages/open-ida/src/api.ts`                      | `OpenIDA` session and `capabilities()`.  |
| `projects/packages/open-ida/src/types.ts`                    | Every report shape.                      |
| `projects/packages/open-ida/src/errors.ts`                   | Stable codes and `translateNativeError`. |
| `projects/packages/open-ida/src/cli.ts`                      | Command tree and rendering.              |
| `projects/packages/open-ida/src/native.ts`                   | Addon discovery and `OPEN_IDA_NATIVE`.   |
| `projects/packages/open-ida-skills/skills/open-ida/SKILL.md` | The packaged skill.                      |

The implemented surface is exactly what `open-ida capabilities` reports.
