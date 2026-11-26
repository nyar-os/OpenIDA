//! PE load configuration projection.
//!
//! The 32/64-bit `IMAGE_LOAD_CONFIG_DIRECTORY` layout and the guard metadata
//! are owned by `data-binary-pe` (`pe::read_load_config`). This module keeps
//! the product report names.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// Code integrity fields of the load configuration.
pub type CodeIntegrityInfo = pe::PeCodeIntegrityInfo;

/// Decoded load configuration.
pub type PeLoadConfigReport = pe::PeLoadConfigReport;

/// Decodes the load configuration of one session.
pub fn analyze(session: &BinarySession) -> Result<PeLoadConfigReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE load configuration requires a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_load_config(&image, bytes).map_err(|error| IdaError::parse(format!("PE load configuration: {error}")))
}
