//! CPython bytecode and PyInstaller container projections.
//!
//! `data-binary-container` owns the `marshal` object graph, the `.pyc`
//! container, the 3.11 through 3.13 opcode tables and the PyInstaller
//! `CArchive` / `PYZ` facts. The modules here only adapt a session and keep
//! the product report names.

pub mod pyc;
pub mod pyc_opcodes;
pub mod pyinstaller;
