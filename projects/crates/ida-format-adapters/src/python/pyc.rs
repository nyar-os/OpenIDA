//! CPython `marshal` / `.pyc` projection.
//!
//! The marshal object graph and the 3.11 through 3.13 bytecode decode are
//! owned by `data-binary-container::pyc`. This module keeps the session-facing
//! entry points, the product report names and the error type.

use data_binary_inspect::BinarySession;

use crate::{IdaError, Result};

pub use data_binary_container::pyc::{PycCodeObject, PycConst, PycFormat, PycInstruction, PycOptions, PycReport, sniff};

/// Decodes a `marshal` stream or `.pyc` container of one open session.
pub fn analyze(session: &BinarySession, options: &PycOptions) -> Result<PycReport> {
    let bytes = session.read(0, session.size())?;
    data_binary_container::pyc::analyze(bytes, options).map_err(IdaError::from)
}
