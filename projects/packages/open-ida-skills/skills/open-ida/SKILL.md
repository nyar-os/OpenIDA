---
name: open-ida
description: Inspect compiled binaries with OpenIDA. Use when a task involves PE, ELF or Mach-O headers, section maps, printable strings, hex dumps, RVA mapping or a verifiable byte patch.
---

# open-ida

## Status

`open-ida info`, `sections`, `strings`, `hexdump`, `rva`, `offset`, `imports`,
`exports`, `symbols`, `debug`, `version`, `macho`, `macho-symbols`,
`macho-function-starts`,
`macho-exports`,
`macho-encryption`,
`macho-chained-fixups`,
`macho-bindings`,
`macho-slices`, `macho-extract`, `mitigations`, `resources`, `relocations`, `dynamic`, `segments`, `notes`,
`certificates`, `tls`, `load-config`, `code-signature`, `disasm`, `entropy`, `diff`,
`search`, `find`, `dump`, `carve`,
`patch` are implemented for the cases listed below. Decompilation,
debugging and signature verification are
**not** implemented and the capability matrix reports them as `unsupported` /
`not-implemented`; Mach-O import bindings are `partial`: the classic bind
opcode streams are decoded by `macho-bindings` and nothing is bound at runtime.

Do not describe an unimplemented route as available, and do not fill the gap with
a second analysis engine. Report the stable code instead.

## Preflight

1. Run `open-ida capabilities` and read the matrix. A flag name is not a support
   claim; check the reported state first.
2. Confirm the file exists and is readable before opening it.
3. For patching, state the target path and the exact offset before writing. Prefer
   `--out` so the source file stays untouched.
4. If the requested analysis needs a feature marked `not-implemented`, stop and
   report it.

## Routes

| Route | Intent | Evidence |
|-------|--------|----------|
| inspect | Identify container, architecture, entry point and image base | `info` report plus hash |
| map | Find sections, their addresses, sizes and access flags | `sections` table |
| discover | Locate printable strings and their offsets | `strings` listing with offsets |
| find | Locate regex matches with printable previews | `find` report with offset, length and preview |
| dump | Export a raw byte range to a new file        | `dump` report with written count              |
| carve | Extract printable regions around a marker   | `carve` report with region files              |
| read | Show bytes around an offset | `hexdump` or `read` output |
| resolve | Turn an RVA or virtual address into a file offset | `rva` mapping |
| link | List imports, exports, symbols or the PDB path | `imports` / `exports` / `symbols` / `debug` report |
| metadata | Read PE file/product version and string table | `version` report |
| macho | Read UUID, platform, dylibs, segments and sections | `macho` report |
| macho-symbols | List `LC_SYMTAB` entries with kind, section and flags | `macho-symbols` report |
| macho-function-starts | List `LC_FUNCTION_STARTS` function addresses | `macho-function-starts` report |
| macho-exports | List dyld export trie symbols, flags and addresses | `macho-exports` report |
| macho-encryption | Read `LC_ENCRYPTION_INFO` crypt offset, size and cryptid | `macho-encryption` report |
| macho-chained-fixups | Read `LC_DYLD_CHAINED_FIXUPS` imports, header and starts table | `macho-chained-fixups` report |
| macho-bindings | Decode classic dyld bind, weak-bind and lazy-bind opcode streams | `macho-bindings` report |
| macho-slices | List the architectures of a fat/universal container | `macho-slices` report |
| macho-extract | Write one fat/universal slice to a new file | `macho-extract` report |
| mitigations | Read the PE hardening posture | `mitigations` report |
| resources | List the PE resource tree | `resources` report |
| relocations | List the PE base relocation blocks and fixup types | `relocations` report |
| exception | List the PE runtime functions and unwind headers | `exception` report |
| pe-delay-imports | List the PE delay-load modules and their INT/IAT thunks | `pe-delay-imports` report |
| pe-bound-imports | List the PE bound-import descriptors and forwarder refs | `pe-bound-imports` report |
| pe-rich-header | Decode the PE Rich header build stamp | `pe-rich-header` report |
| dynamic | Read ELF interpreter, SONAME, needed libraries and search paths | `dynamic` report |
| elf-symbols | List the ELF `.symtab` static symbols with type, binding and section | `elf-symbols` report |
| segments | List ELF program headers with permissions and load ranges | `segments` report |
| notes | Read the ELF build id, ABI tag and GNU properties | `notes` report |
| certificates | List the PE attribute certificate table headers (not verified) | `certificates` report |
| tls | Read the PE TLS directory and callback addresses | `tls` report |
| load-config | Read the PE load configuration and guard flags | `load-config` report |
| code-signature | Read the Mach-O signature blob and CodeDirectory (not verified) | `code-signature` report |
| triage | Spot packing from entropy and the overlay | `entropy` report |
| compare | Find the first difference between two builds | `diff` report |
| patch | Change bytes and prove the change | before/after hash and patched copy |

## Hard rules

- Never claim a section or offset without printing the report that contains it.
- Never patch an offset outside the file; the engine rejects it, and a rejected
  range is not a successful patch.
- Never present a hash as a security verdict. It only proves the bytes changed.
- Mach-O support covers headers, load commands, segments, sections, dylibs,
  build versions, the `LC_SYMTAB` symbol table, the fat architecture table and
  the classic dyld bind opcode streams (`macho-bindings`). Do not claim runtime
  dyld binding, the rebase stream or in-place fat-container modification.
- `mitigations` reports header/load-config facts, not a security verdict, and
  it does not verify Authenticode signatures.
- Big-endian ELF is rejected; do not guess its layout.

## Safety

- Confirm with the user before any command that writes a file, and state the
  source, the output path, the offset and the bytes first.
- Do not overwrite the only copy of a binary. Use `--out` unless the user
  explicitly asks for an in-place change.

## References

The implemented surface is exactly what `open-ida capabilities` reports. No
additional formats, architectures or analysis products are declared.
