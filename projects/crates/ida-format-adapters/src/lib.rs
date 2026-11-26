//! Format fact projections for OpenIDA.
//!
//! Each module turns one upstream container into the report shape the product
//! exposes. The projections are pure functions of an open
//! [`data_binary_inspect::BinarySession`] and keep the stable error surface in
//! [`error`](crate::error); they hold no session defaults, no workflow policy
//! and no Node-API knowledge.
//!
//! - [`pe`]: `PE` debug/CodeView, version resources, resources, relocations,
//!   exception runtime functions, delay and bound imports, the Rich header,
//!   certificates, TLS, load configuration and the mitigation posture.
//! - [`elf`]: `.symtab` symbols, `PT_INTERP`/`PT_DYNAMIC` dependencies, program
//!   headers and notes.
//! - [`macho`]: load commands, segments, dylibs, symbols, function starts,
//!   exports, encryption, chained fixups, bind opcodes, fat slices and the
//!   embedded code signature.
//! - [`python`]: CPython `marshal`/`pyc` decoding, the opcode tables and the
//!   PyInstaller `CArchive`/`PYZ` container.
//! - [`containers`]: `asar`, `NSIS`, overlay anatomy, entropy and the container
//!   facts consumed by the product `unpack` workflow.
//!
//! Every fact is owned by the pinned `boost.rs` revision
//! (`3e865d5c96ffe4e6d4da2143f63b3d29f12d0dd7`): `data-binary-pe` supplies the
//! `PE` and `ELF` facts, `data-binary-mach-o` the Mach-O facts and
//! `data-binary-container` the Python/installer containers. The modules here
//! hold no parser; they map owner types onto the published report shapes.
//! Product-local policy that the owner cannot express is limited to the `PE`
//! overlay range (see `documentation/architecture.md`).

#![recursion_limit = "256"]
#![warn(missing_docs)]

pub mod containers;
pub mod elf;
pub mod error;
pub mod macho;
pub mod pe;
pub mod python;

pub use error::{IdaError, Result};
