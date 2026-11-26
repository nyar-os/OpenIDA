//! CPython opcode tables.
//!
//! The per-version tables and lookups are owned by
//! `data-binary-container::pyc_opcodes`; this module re-exports them for the
//! product tests and downstream consumers.

pub use data_binary_container::pyc_opcodes::*;
