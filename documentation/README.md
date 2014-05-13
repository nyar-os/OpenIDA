# OpenIDA maintainer guide

Repository layout, build and test commands, dependency pins, CI, and the actual
state of the npm release path. Reader-facing documentation lives in
[../readme.md](../readme.md) and
[../projects/packages/open-ida/README.md](../projects/packages/open-ida/README.md);
agent-facing documentation lives in [agents.md](agents.md).

## Project layout

| Path | What it is |
| --- | --- |
| `projects/crates/core` | Rust crate `open-ida-core`: session defaults, `OpenIda` API, PE debug/CodeView parsing, disassembly, binary diff, entropy and encoded string scanning, stable errors and the capability matrix. Container decoding, imports, exports, symbols, search, hex dumps and patching come from the pinned `boost.rs` binary crates. |
| `projects/crates/napi` | Rust crate `open-ida-napi`: `cdylib` Node-API exports and the Studio WebView host. It maps JSON in and JSON out; no analysis lives here. |
| `projects/packages/open-ida` | TypeScript package `@wae/open-ida`: `OpenIDA` session (`src/api.ts`), CLI (`src/cli.ts`, bin `open-ida`), GUI helpers, stable errors, types and `locales/en-US/cli.json`. |
| `projects/packages/open-ida/tests` | TypeScript smoke test compiled with `tsconfig.test.json` into `dist-test`. Test files do not live under `src`. |
| `projects/crates/core/tests` | Rust integration tests for the core crate. |
| `projects/packages/open-ida-ui` | `@wae/open-ida-ui`: VMZ static shell for the Studio window. `vmz build . --profile static` emits `dist/static`, staged into `open-ida/dist/gui`. |
| `projects/packages/open-ida-skills` | `@wae/open-ida-skills`: skill document under `skills/`. No runtime library and no analysis. |
| `projects/packages/open-ida-<platform>-<arch>` | Five prebuilt addon packages: `win32-x64`, `darwin-x64`, `darwin-arm64`, `linux-x64`, `linux-arm64`. Each is a thin manifest around a staged `.node` file. |
| `projects/sites/homepage` | `@wae/open-ida-homepage`: VMZ product site. |
| `wae.config.ts` | Build order, native targets, platform package mapping, staging, skills registration, CI job names and window behaviour. |
| `Cargo.toml` | Cargo workspace; members are `projects/crates/*`, default members `core` and `napi`. |
| `pnpm-workspace.yaml` | pnpm workspace covering `projects/packages/*` and `projects/sites/*`. |

The CLI, SDK and Studio all read the same core crate. A behaviour change in
`core` reaches every surface; `capabilities()` is the single disclosure point.

## Build and test

Prerequisites: Node.js 18 or newer, pnpm 10.28.0 (from the root
`package.json`), Rust 1.90 with edition 2024 (from `rust-toolchain.toml` /
`Cargo.toml`).

```bash
pnpm install                  # workspace dependencies
pnpm build:napi               # wae native build (crate open-ida-napi)
pnpm build                    # wae build: native -> ts -> ui -> skills -> staging
pnpm typecheck                # pnpm -r --filter "./projects/packages/*" run typecheck
pnpm test                     # package tests
pnpm test:rust                # cargo test --release
pnpm check:rust               # fmt check + clippy -D warnings + core/napi tests
```

Useful narrower commands:

```bash
cargo test -p open-ida-core
cargo test -p open-ida-core --release
cargo test -p open-ida-napi
pnpm build:ts                 # tsc for @wae/open-ida
pnpm build:ui                 # static Studio shell
pnpm stage:native             # wae native stage into platform package directories
pnpm gui                      # build and launch the Studio window
```

`pnpm test` runs `tsc -p tsconfig.test.json` and then
`node --test dist-test/tests/smoke.test.js`. The smoke test imports the
TypeScript sources through `../src/*.js`; native-dependent assertions skip
themselves when the addon is absent, so a green run without `pnpm build:napi`
proves less than it appears to.

## Dependency pins

Cross-repository dependencies pin a full 40-character revision, not a branch or
tag:

- The workspace `Cargo.toml` pins `data-binary-inspect` and `data-binary-pe` to
  `5ed79ccd125d035b7286c8073b6c9b4ee384dbfb` from `oovm/boost.rs`.
- The workspace `Cargo.toml` pins `wae` to
  `f92f818fde7174154d77a87b55a5e44b367034c9` from `doki-land/wae-framework`.

`open-ida-core` deliberately parses the PE debug directory and CodeView records
itself because the pinned `data-binary-inspect` release does not expose them.
Do not "fix" that by bumping the pin without re-reading the upstream API and
running the core tests.

## Release and publishing

Only the platform packages are publishable today. `@wae/open-ida`,
`@wae/open-ida-skills`, `@wae/open-ida-ui` and the homepage are `private: true`,
and `wae.config.ts` leaves `release` unset.

The intended npm release contract is:

1. Build and stage the native addon so each platform package contains its
   `.node` file.
2. Publish from CI with npm Trusted Publisher / OIDC, triggered by a version
   tag: `permissions: id-token: write` and `environment: NPM_PUBLISH`. No
   long-lived npm token is stored in workflow YAML.
3. Keep local publishing to inspection only: `nifty publish --dry-run`, or
   `nifty publish --placeholder` to claim never-published `0.0.0` names.
4. Keep `.secrets/nifty.json` local. The whole `.secrets/` directory is
   git-ignored.

### Verified state (2026-11-22)

The release path is **not wired**:

- There is no publish workflow. `.github/workflows` contains `check-rust.yml`
  and `check-typescript.yml` only.
- `wae.config.ts` therefore keeps `release` unset and this repository has no
  working automated npm release. Do not claim otherwise in a README or a
  release note.
- `nifty publish` aborts when a native platform package has no staged `.node`,
  so staging is a hard prerequisite for any future publish job.

## CI workflows

| Workflow | Trigger | What it runs |
| --- | --- | --- |
| `check-rust.yml` | Push and pull request to `master` / `dev` | Matrix of Ubuntu, macOS and Windows; installs nightly with `rustfmt` and `clippy`; `cargo build --workspace --release`; `cargo test --workspace --release`. It does not run fmt or clippy checks; `pnpm check:rust` does. |
| `check-typescript.yml` | Push and pull request to `master` / `dev` | Ubuntu; pnpm and Node 22; `pnpm install --no-frozen-lockfile`; `pnpm typecheck`; `pnpm test`. |

## Documentation map

| File | Audience | Owns |
| --- | --- | --- |
| [../readme.md](../readme.md) | readers | Product landing, getting started, highlights and boundaries |
| [../projects/packages/open-ida/README.md](../projects/packages/open-ida/README.md) | npm readers | Exports, usage, constraints |
| [capabilities.md](capabilities.md) | everyone | Support matrix, limits and unsupported boundaries |
| [cli.md](cli.md) | users | Every command, flag, default and exit code |
| [agents.md](agents.md) | agents | Capability discovery, stable codes and guardrails |
| [architecture.md](architecture.md) | maintainers | Modules, call path, determinism and error contract |
| This file | maintainers | Layout, build, CI and release state |

Change the owning file, not a copy. Never put build commands, workspace trees
or CI notes in a reader-facing README.

The project is Apache-2.0; see [../License.md](../License.md).
