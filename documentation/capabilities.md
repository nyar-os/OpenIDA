# OpenIDA capabilities

`open-ida capabilities` prints this matrix from the installed engine. The
TypeScript `capabilities()` returns the same object as JSON, including the
`unsupported` block. A flag name, a file suffix or a method name is never a
support claim.

## Format matrix

| Container | State | What is decoded |
| --- | --- | --- |
| PE (`MZ`) | `supported` | Headers, image base, entry RVA, sections, imports, exports, COFF symbols, debug directory, `RSDS` / `NB10` CodeView records, `RT_VERSION`, the resource directory, overlay and the mitigation posture (ASLR/DEP/CFG/GS/W+X). |
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
| `macho-function-starts` | `supported` | `LC_FUNCTION_STARTS` ULEB128 delta table decoded into absolute virtual addresses starting from the `__TEXT` segment address. A Mach-O without the command answers `binary/unsupported`; fat containers must be sliced first. |
| `macho-exports` | `supported` | Dyld export trie behind `LC_DYLD_EXPORTS_TRIE` or `LC_DYLD_INFO(_ONLY)`: symbol name, flags (`WEAK`, `REEXPORT`, `STUB_AND_RESOLVER`), address and reexport ordinal/stub address. A Mach-O without a trie reports `present: false`. |
| `macho-encryption` | `supported` | `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` crypt range file offset, size, cryptid and an `encrypted` flag (`cryptid != 0`). A Mach-O without the command reports `present: false`; fat containers must be sliced first. Metadata only: bytes are never decrypted. |
| `macho-chained-fixups` | `supported` | `LC_DYLD_CHAINED_FIXUPS` chain data range, `dyld_chained_fixups_header` fields, imports (library ordinal, weak flag, symbol name, addend for the `ADDEND` formats) and the `dyld_chained_starts_in_image` segment count with the number of populated segments. Imports are capped at 512; names stay empty for a compressed symbol pool. A Mach-O without the command reports `present: false`; fat containers must be sliced first. Chained-pointer and bind decoding is not performed. |
| `pe-mitigations` | `supported` | PE `DllCharacteristics` (ASLR, high-entropy VA, DEP, CFG, force integrity, no-SEH, terminal-server-aware), load-config GS cookie and `GuardFlags`, base-relocation and certificate-table presence, and W+X sections. Non-PE answers `binary/unsupported`. |
| `pe-resources` | `supported` | PE resource tree leaves with type, name, language, data RVA, size and code page. A PE without a resource directory reports `present: false`; non-PE answers `binary/unsupported`. |
| `pe-relocations` | `supported` | PE `IMAGE_BASE_RELOCATION` blocks with page RVA, block size, entry count and per-type fixup counts, plus whole-image totals. A PE without relocations reports `present: false`; non-PE answers `binary/unsupported`. |
| `pe-exception` | `supported` | PE exception directory (data directory 3): the `COFF` machine, entry layout and size, and each `RUNTIME_FUNCTION` begin/end RVA and unwind info RVA, with the decoded x64 `UNWIND_INFO` header (version, flags, prologue size, code count, frame register/offset). ARM and ARM64 entries mask the packed begin-address flag bits. A PE without the directory reports `present: false`; non-PE answers `binary/unsupported`. |
| `pe-delay-imports` | `supported` | PE delay-import directory (data directory 13): each `IMAGE_DELAYLOAD_DESCRIPTOR` module name, timestamp and handle/IAT/INT/bound-IAT/unload-IAT RVAs, plus per-thunk INT and IAT slot RVAs with the resolved name and hint or the ordinal (bit 31). 128 modules, 256 thunks per module and 1,024 thunks overall; only the v2 RVA-based layout is mapped, v1 virtual addresses are reported raw. A PE without the directory reports `present: false`; non-PE answers `binary/unsupported`. |
| `pe-bound-imports` | `supported` | PE bound-import directory (data directory 11): each `IMAGE_BOUND_IMPORT_DESCRIPTOR` timestamp, name offset and resolved module name, plus its inline `IMAGE_BOUND_FORWARDER_REF` entries. 64 descriptors and 32 forwarders each; a missing terminator, a cap hit or an unresolvable name sets `truncated`. A PE without the directory reports `present: false`; non-PE answers `binary/unsupported`. |
| `pe-rich-header` | `supported` | Rich header between the DOS stub and the PE header: the `Rich` signature and XOR key, the validated `DanS` marker offset and up to 64 `(compid, build, count)` entries, each always carrying its raw fields plus a best-effort tool name for well-known compids. A missing signature or an unvalidated `DanS` marker reports `present: false`; a run that is not entry-aligned or exceeds the cap sets `truncated`. The stamp is linker-written metadata and can be spoofed; nothing is verified against a real toolchain. |
| `elf-dynamic` | `supported` | ELF `PT_INTERP` interpreter and `PT_DYNAMIC` facts: `DT_SONAME`, `DT_NEEDED`, `DT_RPATH` and `DT_RUNPATH`, mapped through `PT_LOAD`. A static image reports `present: false`; non-ELF answers `binary/unsupported`. |
| `elf-static-symbols` | `supported` | ELF static symbols from the first `SHT_SYMTAB` section and its linked string table: name, value, size, `STT_*` type, `STB_*` binding, visibility and owning section, with `SHN_UNDEF`, `SHN_ABS` and `SHN_COMMON` rendered as `UND`, `ABS` and `COM` and real indices resolved through the section header table. 4,096 symbols and 4,096 section headers; the ELF32 and ELF64 layouts are decoded from `e_ident`. This is the static table; the `symbols` view keeps reporting the dynamic one. An image without `.symtab` reports `present: false`; non-ELF answers `binary/unsupported`. |
| `elf-program-headers` | `supported` | ELF program header table: type (`PT_LOAD`, `PT_DYNAMIC`, `PT_GNU_RELRO`, ...), file offset, virtual/physical address, file/memory size, `R/W/X` flags and alignment, in the ELF32 or ELF64 layout. An image without program headers reports `present: false`; non-ELF answers `binary/unsupported`. |
| `elf-notes` | `supported` | ELF notes from `PT_NOTE` segments, falling back to `SHT_NOTE` sections: `NT_GNU_BUILD_ID` hex, `NT_GNU_ABI_TAG` OS/version, `NT_GNU_PROPERTY_TYPE_0` entries and other notes as a bounded hex preview. An image without notes reports `present: false`; non-ELF answers `binary/unsupported`. |
| `pe-certificates` | `supported` | PE attribute certificate table entries with file offset, length, revision, certificate type, payload size and a `PKCS#7` shape flag. Headers only: no signature, chain or timestamp verification. A PE without the table reports `present: false`; non-PE answers `binary/unsupported`. |
| `pe-tls` | `supported` | PE TLS directory fields (raw template range, index slot, zero fill, characteristics) and the callback array mapped from VAs through the image base and sections. Callbacks beyond 64 are cut. A PE without the directory reports `present: false`; non-PE answers `binary/unsupported`. |
| `pe-load-config` | `supported` | PE load configuration prefix: security cookie, SEH handler table/count, CFG check/dispatch/table pointers, decoded `GuardFlags` and the `CodeIntegrity` block, in the PE32 or PE32+ layout. A PE without the directory reports `present: false`; non-PE answers `binary/unsupported`. |
| `macho-slice-extraction` | `supported` | Writes one fat/universal slice to a caller-chosen `--out` path. Refuses to overwrite the source container; a thin image answers `binary/unsupported`. |
| `macho-code-signature` | `supported` | `LC_CODE_SIGNATURE` SuperBlob index (blob types) and the first `CodeDirectory`: version, decoded flags, hash type, page size, code limit, identifier, team id and slot counts. Parsed only: no hash is recomputed and no chain is validated. A thin image without the command reports `present: false`; fat containers answer `binary/unsupported` with a pointer to slice extraction. |
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
| `imports` / `exports` / `symbols` / `macho-symbols` / `macho-function-starts` / `debug --limit` | Unlimited | — | `total` and `truncated` describe the cut. |
| `resources` | 256 leaves, 8,192 tree nodes | — | `total` and `truncated` describe the cut. |
| `relocations` | 128 blocks listed, 4,096 decoded | — | `totalBlocks`, `totalEntries` and `truncated` describe the cut. |
| `dynamic` | 256 needed libraries, 64 paths per list | — | `truncated` is `true` when a limit stopped the listing. |
| `elf-static-symbols` | 4,096 symbols, 4,096 section headers | — | `total` keeps the declared entry count, `truncated` is `true` when a limit or unreadable data cut the listing. |
| `segments` | 128 program headers | — | `total` and `truncated` describe the cut. |
| `notes` | 128 notes, 32 property entries | — | `total` and `truncated` describe the cut. |
| `certificates` | 64 entries | — | `total` and `truncated` describe the cut. |
| `tls` | 64 callbacks | — | `truncated` is `true` when the array was cut or not fully readable. |
| `pe-delay-imports` | 128 modules, 256 thunks per module, 1,024 thunks total | — | `totalModules`, `totalThunks` and `truncated` describe the cut. |
| `pe-bound-imports` | 64 descriptors, 32 forwarders each | — | `totalModules`, `totalForwarders` and `truncated` describe the cut. |
| `pe-rich-header` | 64 entries | — | `total` counts the decoded run; `truncated` marks a cap hit or a non-aligned run. |
| `load-config` | documented prefix only | — | `truncated` is `true` when `Size` is shorter than the PE32/PE32+ prefix. |
| `code-signature` | 32 SuperBlob entries | — | `truncated` is `true` when the blob table or payload was cut. |
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
| Fat/universal Mach-O | `macho-slices` lists the architecture table and `macho-extract` writes one slice. `macho` and `macho-symbols` answer `binary/unsupported` until that extracted slice is opened. |
| Authenticode verification | Not implemented. `pe-mitigations` reports whether the certificate table is present, not whether the signature is valid. |
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
