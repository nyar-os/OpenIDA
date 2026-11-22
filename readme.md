# OpenIDA

![Binary formats](https://img.shields.io/badge/formats-PE%20%C2%B7%20ELF%20%C2%B7%20Mach--O-blue)
![Built-in engine](https://img.shields.io/badge/runtime-zero%20system%20dependencies-brightgreen)
![Auditable output](https://img.shields.io/badge/output-bounded%20reports-blueviolet)

## 💡 What is OpenIDA?

OpenIDA answers concrete questions about a compiled binary from one command
line, one TypeScript session and one Studio window: what container and
architecture is this, where does each section live, which strings and imports
does it carry, what do these bytes decode to, how do two builds differ, and did
this patch change only what I intended?

It ships a built-in analysis engine, so it needs no external disassembler
service, SDK or system toolchain at runtime. Results are bounded reports with an
explicit truncation flag, and every failure carries a stable code instead of
prose you have to parse.

OpenIDA is not a decompiler and not a debugger. It does not produce pseudo-code,
attach to a running process or resolve relocations. When a format or
architecture is not implemented it says so instead of guessing.

## 🚀 Getting started

### 1. Agent path (recommended)

```bash
pnpm add @wae/open-ida-skills
```

Point your agent at
`node_modules/@wae/open-ida-skills/skills/open-ida/SKILL.md`. The skill fixes
the preflight checks, the order of inspection and the rules for safe patching,
so the agent does not have to improvise. A realistic prompt:

> Inspect `samples/app.exe`: report its format and architecture, list the
> sections with their permissions, extract both ASCII and UTF-16LE strings, and
> tell me whether anything is imported from `ws2_32.dll`.

### 2. Manual install

OpenIDA has no npm release yet: the application package is private and the
platform addons are unpublished. Until the first release, run from a checkout
built with the repository toolchain; the
[build guide](documentation/README.md#build-and-test) lists the commands. Once
the command is installed, the interface looks like this:

```bash
open-ida capabilities
open-ida info ./samples/app.exe
open-ida sections ./samples/app.exe
open-ida strings ./samples/app.exe --encoding both
open-ida imports ./samples/app.exe
open-ida macho ./samples/app.macho
open-ida macho-slices ./samples/universal.macho
open-ida macho-extract ./samples/universal.macho --index 1 --out ./samples/app.arm64.macho
open-ida mitigations ./samples/app.exe
open-ida resources ./samples/app.exe
open-ida relocations ./samples/app.exe
open-ida exception ./samples/app.exe
open-ida dynamic ./samples/app.elf
open-ida segments ./samples/app.elf
open-ida notes ./samples/app.elf
open-ida certificates ./samples/app.exe
open-ida tls ./samples/app.exe
open-ida load-config ./samples/app.exe
open-ida code-signature ./samples/app.macho
open-ida macho-symbols ./samples/app.macho --limit 200
open-ida macho-function-starts ./samples/app.macho --limit 200
open-ida disasm ./samples/app.exe --offset 0x1000 --count 20
open-ida entropy ./samples/app.exe
open-ida diff build/app.exe build/app-patched.exe
```

Every command prints a human report. The same values are available as JSON from
the TypeScript session, so a script and a person read the same result.

## ✨ Highlights

- **Hardening facts.** ASLR, high-entropy VA, DEP, CFG, GS cookies, W+X
  sections, relocations and certificate-table presence, read from the PE header
  and load config. The PE resource tree is listed by type, name and language.
- **Format-aware facts.** PE and ELF headers, sections, entry points, image
  bases and hashes; Mach-O load commands, segments, sections, dylibs, UUID,
  build versions and the `LC_SYMTAB` symbol table, plus the architecture table
  of fat containers. Mach-O stays partial until dyld bindings are decoded.
- **Strings in both encodings.** ASCII runs by default, plus the
  ASCII-in-UTF-16LE runs that Windows binaries commonly embed.
- **Address mapping both ways.** RVA or virtual address to file offset, and file
  offset back to RVA and VA.
- **Symbols where the format has them.** PE imports, exports, COFF symbols, and
  PE debug directory entries with `RSDS` / `NB10` CodeView records.
- **Product metadata.** PE `RT_VERSION` file and product versions plus the
  `StringFileInfo` pairs, when the resource exists.
- **x86 and x64 disassembly.** Intel, MASM or NASM syntax, with the file offset
  and virtual address of every instruction.
- **Binary diff.** Size and hash for both sides, the first differing offset and
  the differing ranges, or a clear `identical` verdict.
- **Packing triage.** Whole-file and per-section Shannon entropy for PE, ELF and
  Mach-O, plus the PE overlay.
- **Patching you can audit.** Atomic writes with the before and after hash of
  the whole file; pass `--out` to keep the original untouched.
- **Bounded by default.** Every listing has a limit and reports
  `truncated: true` when it cut results, so a huge binary cannot turn into an
  unbounded report.

## 🧭 How it works

One engine answers every surface. The command line, the TypeScript session, the
Studio window and the agent skill read the same handles and the same reports, so
a section shown in the Studio is the section the command line printed. When the
Studio is opened without a connected host it says so and stays empty instead of
drawing sample data.

## 🚧 What this build does not do

- No decompiler: no pseudo-code, control-flow graph or type recovery.
- No debugger: it does not attach, set breakpoints or inspect a running process.
- No non-x86 disassembly: ARM and ARM64 return a stable unsupported error.
- No signature verification: `mitigations` reports whether the certificate
  table is present, not whether the Authenticode signature is valid.
- No Mach-O dyld bindings: load commands, segments, sections, dylibs, build
  versions and the `LC_SYMTAB` symbol table are decoded, but bind opcodes are
  not resolved.
- No fat Mach-O in-place inspection: `macho-slices` lists the architecture
  table and `macho-extract` writes one slice to a new file, which `macho` can
  then inspect. The source container is never modified.
- No big-endian ELF: rejected with a stable code instead of a guessed layout.
- No relocation resolution: import and export tables are parsed, not applied.
- No release artifacts: the packages are private and no installer exists.

## 🧪 Examples

- [Package usage](projects/packages/open-ida/README.md) — the session API, the
  export map and the constraints.
- [Smoke test](projects/packages/open-ida/tests/smoke.test.ts) — runnable
  evidence for the error contract and the declared capability gap.
- [CLI reference](documentation/cli.md) — every command, flag, default and exit
  code.

## 📚 Documentation

- [Capabilities](documentation/capabilities.md) — the support matrix, every
  limit and every unsupported boundary.
- [CLI reference](documentation/cli.md) — all `open-ida` commands.
- [Agent guide](documentation/agents.md) — capability discovery, stable codes
  and guardrails for automation.
- [Package README](projects/packages/open-ida/README.md) — the npm-facing API
  surface.
- [Maintainer guide](documentation/README.md) — layout, build, CI and release
  state.

## 📜 License

[Apache-2.0](License.md)
