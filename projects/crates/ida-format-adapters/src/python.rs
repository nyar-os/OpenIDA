//! CPython bytecode and PyInstaller container projections.
//!
//! [`pyc`] decodes the `marshal` object graph and the 3.11 through 3.13
//! bytecode; [`pyc_opcodes`] holds the opcode tables; [`pyinstaller`] reads the
//! `CArchive` and `PYZ` container facts. Nothing is executed.

pub mod pyc;
pub mod pyc_opcodes;
pub mod pyinstaller;
