//! PE TLS directory projection.
//!
//! The `IMAGE_TLS_DIRECTORY` decode and the callback mapping through the image
//! base are owned by `data-binary-pe` (`pe::read_tls_directory`). This module
//! keeps the product report names.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// One TLS callback.
pub type PeTlsCallback = pe::PeTlsCallback;

/// Decoded TLS directory.
pub type PeTlsReport = pe::PeTlsReport;

/// Decodes the TLS directory of one session.
pub fn analyze(session: &BinarySession) -> Result<PeTlsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE TLS data requires a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_tls_directory(&image, bytes).map_err(|error| IdaError::parse(format!("PE TLS directory: {error}")))
}
