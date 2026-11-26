//! Electron `asar` archive projection.
//!
//! The header, the JSON file tree and the optional extraction are owned by
//! `data-binary-container::asar`. This module keeps the session-facing entry
//! point and the product error type.

use data_binary_inspect::BinarySession;

use crate::{IdaError, Result};

pub use data_binary_container::asar::{AsarEntry, AsarHeader, AsarOptions, AsarReport};

/// Decodes the `asar` archive of one open session.
pub fn analyze(session: &BinarySession, options: &AsarOptions) -> Result<AsarReport> {
    let bytes = session.read(0, session.size())?;
    data_binary_container::asar::analyze(bytes, options).map_err(IdaError::from)
}
