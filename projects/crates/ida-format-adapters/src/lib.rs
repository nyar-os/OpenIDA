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
//! The pinned `boost.rs` release does not expose every field decoded here.
//! Each module documents the gap it fills; the Boost wiring pass replaces the
//! local decoder with the matching owner and keeps these report shapes.

#![recursion_limit = "256"]
#![warn(missing_docs)]

pub mod containers;
pub mod elf;
pub mod error;
pub mod macho;
pub mod pe;
pub mod python;

pub use error::{IdaError, Result};
