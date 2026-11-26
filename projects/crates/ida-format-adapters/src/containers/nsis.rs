//! `NSIS` installer container projection.
//!
//! The first header, the solid framing, the script command stream and the
//! `File` extraction manifest are owned by `data-binary-container::nsis`. This
//! module keeps the session-facing entry points and the product error type.

use data_binary_inspect::BinarySession;

use crate::{IdaError, Result};

pub use data_binary_container::nsis::{NsisBlock, NsisCommand, NsisFile, NsisHeader, NsisOptions, NsisReport, SIGNATURE};

/// Decodes the `NSIS` container of one open session.
pub fn analyze(session: &BinarySession, options: &NsisOptions) -> Result<NsisReport> {
    let bytes = session.read(0, session.size())?;
    data_binary_container::nsis::analyze(bytes, options).map_err(IdaError::from)
}

/// Finds the first header: `offset` when given, otherwise a signature scan.
pub fn locate(session: &BinarySession, offset: Option<u64>) -> Result<u64> {
    let bytes = session.read(0, session.size())?;
    data_binary_container::nsis::locate(bytes, offset).map_err(IdaError::from)
}
