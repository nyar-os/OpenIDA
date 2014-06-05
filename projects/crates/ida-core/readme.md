# open-ida-core

The binary inspection kernel behind [OpenIDA](../../../README.md). One engine for
PE, ELF and Mach-O: headers and sections, imports and exports, symbols, strings,
entropy, relocations, resources, TLS, load configuration, code signatures,
chained fixups, disassembly and byte-level diffing.

## Usage

Add it to your `Cargo.toml`:

```toml
[dependencies]
open-ida-core = { path = "projects/crates/ida-core" }
```

```rust
use open_ida_core::OpenIda;

let mut ida = OpenIda::new("path/to/binary")?;
let info = ida.identity()?;
let sections = ida.sections()?;
```

The kernel is read-only and pure Rust. Every answer is a typed, serializable
structure, so the same results power the Node-API surface, the CLI and the GUI.

## Notes

- Parsing leans on the shared `boost.rs` engine so format decoding stays in
  lockstep across the OpenX family.
- This crate is published as part of the OpenIDA workspace; see the repository
  README for the full capability matrix.
