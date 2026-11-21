---
name: open-ida
description: Inspect compiled binaries with OpenIDA. Use when a task involves PE, ELF or Mach-O headers, section maps, printable strings, hex dumps, RVA mapping or a verifiable byte patch.
---

# open-ida

## Status

Working minimal kernel. `open-ida info`, `sections`, `strings`, `hexdump`, `rva`
and `patch` are implemented for the cases listed below. Disassembly,
decompilation, debugging and symbol resolution are **not** implemented and the
capability matrix reports them as `unsupported` / `not-implemented`.

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
| read | Show bytes around an offset | `hexdump` or `read` output |
| resolve | Turn an RVA or virtual address into a file offset | `rva` mapping |
| patch | Change bytes and prove the change | before/after hash and patched copy |

## Hard rules

- Never claim a section or offset without printing the report that contains it.
- Never patch an offset outside the file; the engine rejects it, and a rejected
  range is not a successful patch.
- Never present a hash as a security verdict. It only proves the bytes changed.
- Mach-O support is header-only. Do not claim Mach-O sections, symbols or load
  commands.
- Big-endian ELF is rejected; do not guess its layout.

## Safety

- Confirm with the user before any command that writes a file, and state the
  source, the output path, the offset and the bytes first.
- Do not overwrite the only copy of a binary. Use `--out` unless the user
  explicitly asks for an in-place change.

## References

The implemented surface is exactly what `open-ida capabilities` reports. No
additional formats, architectures or analysis products are declared.
