# OpenIDA architecture

OpenIDA is one inspection kernel with several surfaces. The kernel owns every
fact; the command line, the TypeScript session and the Studio only render what
it returns.

## Components

| Layer | Crate or package | Responsibility |
| --- | --- | --- |
| Engine | `projects/crates/core` (`open-ida-core`) | Opens a file, keeps the session defaults, exposes `OpenIda`, and implements the parts the pinned upstream does not: PE debug/CodeView, x86/x64 disassembly, binary diff, entropy/overlay and encoded string scanning. |
| Upstream | `data-binary-inspect`, `data-binary-pe` | Container detection, headers, sections, imports, exports, symbols, search, hex dumps, address mapping and atomic patching. |
| Binding | `projects/crates/napi` (`open-ida-napi`) | JSON-in / JSON-out Node-API exports plus the WebView host. No inspection policy. |
| SDK | `projects/packages/open-ida/src` | `OpenIDA` session, report types, stable error translation, addon discovery. |
| CLI | `projects/packages/open-ida/src/cli.ts` | Argument parsing and rendering only. |
| Studio | `projects/packages/open-ida-ui` | VMZ static shell; empty when no host is connected. |
| Skill | `projects/packages/open-ida-skills` | Agent instructions; no code. |

## Call path

```text
open-ida <command>
  -> src/cli.ts parses flags
  -> new OpenIDA({ path })
  -> src/native.ts requires @wae/open-ida-<platform>-<arch>
  -> open-ida-napi maps JSON onto open-ida-core / upstream calls
  -> JSON report
  -> CLI renders text, or the SDK returns typed data
```

The SDK and CLI never read the file themselves. A missing addon is a declarative
state: `capabilities()` and every constructor answer
`capability/not-implemented` instead of returning an empty report.

## Determinism and bounds

- Every report is a pure function of the opened bytes and the request options.
- Hash values come from one upstream digest implementation; `diff` reuses the
  hashes already reported by `info` instead of growing a second convention.
- Listings are bounded by constants in the core crate:
  string scans default to 100 hits and cap at 10,000, disassembly defaults to 64
  instructions and caps at 4,096, and diff keeps at most 64 differing ranges.
  Reports carry `total` and `truncated` so a caller can tell a complete answer
  from a cut one.
- `diff.comparedBytes` is the shorter of the two file sizes. Two files of
  different lengths are never reported as identical.

## Address model

- A file offset is the byte position inside the file.
- An RVA is a PE image-relative address; a VA is an absolute virtual address.
- `rva <file> <address>` accepts a PE RVA or an ELF virtual address and maps it
  to a file offset.
- `offset <file> <offset>` always reports a VA and additionally reports an RVA
  when the format has one. ELF has no PE RVA, so the CLI reports `rva: null`.

## Patching

Patching is delegated to the upstream session, which writes atomically and
reports the whole-file hash before and after. OpenIDA adds no second writer:

- A range that does not fit the file is rejected with `binary/range` and the
  file is unchanged.
- `patch(offset, data)` without an output path patches the source in place.
- `patch(offset, data, output)` writes a patched copy and leaves the source
  untouched. The CLI exposes the same choice through `--out`.

## Error contract

`src/errors.ts` defines the complete code set. The engine prefixes messages with
its code; `translateNativeError` splits the prefix, keeps the code and drops it
from the message. Unknown messages become `binary/io` with the original value as
the cause.

| Code | Meaning |
| --- | --- |
| `binary/parse` | The file is not a decodable container. |
| `binary/range` | An offset or length is outside the file. |
| `binary/unsupported` | The format or architecture is recognised but not implemented. |
| `binary/io` | Reading, writing or an unexpected failure. |
| `handle/invalid` | The session handle is closed or unknown. |
| `capability/not-implemented` | The addon is absent or the route is declared unsupported. |

Codes are contract. Callers branch on `code`, never on message text.

## Unsupported policy

`capabilities()` is the only support claim. A format may be classified and still
unsupported, and a suffix is never treated as a support claim. Mach-O is
`partial` (header basics only), and decompilation, debugging and Mach-O import
bindings are explicitly `not-implemented`. ARM and ARM64 disassembly returns
`binary/unsupported` instead of decoding with a guessed mode.

## Test strategy

- Rust integration tests live in `projects/crates/core/tests` and exercise the
  public core surface (kernel, debug, disasm, diff, entropy, encoded strings).
- The TypeScript smoke test lives in
  `projects/packages/open-ida/tests/smoke.test.ts`, compiles with
  `tsconfig.test.json` and asserts the error contract plus the absent-addon
  behaviour. No test file is placed under `src`.
- Tests that need a native addon skip themselves when `nativeBinding()` returns
  `undefined`, so CI stays green without a staged `.node` while still proving
  the pure TypeScript contract.
