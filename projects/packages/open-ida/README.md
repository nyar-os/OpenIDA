# @wae/open-ida

The `OpenIDA` TypeScript session and the `open-ida` command line, both reading
one built-in binary inspection engine. No analysis is re-implemented in
TypeScript, so the SDK and the CLI cannot disagree about a file.

The platform addon is resolved automatically from
`@wae/open-ida-<platform>-<arch>`. Set `OPEN_IDA_NATIVE` to an absolute `.node`
path to use a local build instead.

## Exports

| Import | Contents |
| :--- | :--- |
| `.` | `OpenIDA`, `capabilities`, `errorCodes`, `IdaError`, `NotImplementedError`, `translateNativeError`, `isIdaError`, GUI helpers, `nativeBinding` and every report type |
| `open-ida` (bin) | The command line; see the [CLI reference](../../../documentation/cli.md) |

## Example

```ts
import { OpenIDA, capabilities } from '@wae/open-ida';

const ida = new OpenIDA({ path: 'samples/app.exe' });
const info = ida.info();
console.log(info.format, info.architecture, info.hash);
console.log(ida.sections().sections.length);
console.log(ida.stringsEncoded({ encoding: 'both', limit: 50 }).hits);
console.log(ida.imports(20).entries);
ida.close();

console.log(capabilities().features.disassembly);
```

Patching writes a copy when an output path is given, and the report carries the
whole-file hash before and after:

```ts
const ida = new OpenIDA({ path: 'samples/app.exe' });
const report = ida.patch(0x200, '90,90', 'samples/app-patched.exe');
console.log(report.beforeHash, report.afterHash);
ida.close();
```

## Constraints

- Instances are handles. A closed handle is rejected instead of being reopened
  silently, and every constructor call must be paired with `close()`.
- `resources()` lists the PE resource tree leaves by type, name, language and
  size. It reports `present: false` when the image has no resource directory.
- `relocations()` decodes the PE base relocation blocks, reporting each block's
  page RVA, entry count and fixup types. It reports `present: false` when the
  image has no relocations.
- `exception()` lists the PE exception directory runtime functions with their
  begin/end RVAs, unwind info RVA and, on x64, the decoded unwind header. ARM and
  ARM64 packed entries are unmasked. It reports `present: false` when the image
  has no exception directory.
- `dynamic()` reports the ELF interpreter, SONAME, `NEEDED` libraries and
  rpath/runpath. It reports `present: false` for a static image.
- `segments()` lists the ELF program headers with type, offsets, addresses,
  sizes, permissions and alignment for both ELF32 and ELF64.
- `notes()` decodes ELF `PT_NOTE` / `SHT_NOTE` records: the GNU build id as hex,
  the GNU ABI tag, GNU property entries and a bounded hex preview for other
  notes. It reports `present: false` when the image has no notes.
- `certificates()` lists the PE attribute certificate table entries with their
  revision, type and `PKCS#7` payload shape. It never verifies a signature or a
  chain.
- `tls()` decodes the PE TLS directory and callback array, mapping each callback
  VA back to an RVA and file offset. It never calls a callback.
- `loadConfig()` decodes the PE load configuration: security cookie, SEH table,
  CFG pointers, decoded `GuardFlags` and the `CodeIntegrity` block.
- `codeSignature()` decodes the Mach-O embedded signature SuperBlob and its first
  `CodeDirectory` (identifier, team id, hash type, flags). It never verifies.
- `mitigations()` reads PE header and load-config facts (ASLR, DEP, CFG, GS,
  W+X sections, relocations, certificate-table presence). It does not verify
  Authenticode signatures.
- Mach-O support covers headers, load commands, segments, sections, dylibs,
  build versions, the `LC_SYMTAB` symbol table, the `LC_FUNCTION_STARTS` table,
  the dyld export trie and the fat architecture table; dyld bind opcodes are not
  decoded.
  `extractSlice(index, output)` writes one fat slice to a new file and refuses
  to overwrite the source container.
  Big-endian ELF and unknown containers are rejected with
  `binary/unsupported`, not guessed at.
- Disassembly covers x86 and x64 only; other architectures answer
  `binary/unsupported`.
- `stringsEncoded({ encoding: 'utf16le' })` matches ASCII characters stored with
  a zero high byte. Arbitrary UTF-16 text is not decoded.
- UTF-16LE is encoded as `'utf16le'` in the API. The CLI accepts the same
  spelling.
- Every listing is bounded: string scans default to 100 hits (maximum 10,000),
  disassembly to 64 instructions (maximum 4,096) and diffs to 64 ranges.
  Reports set `truncated` instead of growing without bound.
- `patch()` without an output path writes the source file in place. Prefer an
  explicit output path.
- The package is private and has no npm release yet.

Supported behaviour and every boundary are documented in
[Capabilities](../../../documentation/capabilities.md). For the product overview
start at the [root README](../../../readme.md).
