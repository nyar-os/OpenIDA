# open-ida-napi

The thin Node-API surface of [OpenIDA](../../../README.md). It exposes the
`open-ida-core` kernel to Node.js as a `cdylib`, and is the only native layer
between JavaScript and the inspection engine.

## Usage

This crate is not consumed directly. Install the npm package instead:

```sh
npm install @wae/open-ida
```

The package resolves the prebuilt platform addon (`@wae/open-ida-<os>-<arch>`)
at load time, so no toolchain is required on the host.

## Build

```sh
cargo build -p open-ida-napi --release
```

The resulting `open_ida_napi.dll` / `.node` is staged into the per-platform
packages by `wae native build`. Keep this layer thin: new capabilities belong
in `open-ida-core` first, then get a one-line binding here.
