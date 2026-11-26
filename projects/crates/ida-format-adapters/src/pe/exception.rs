//! PE exception directory projection.
//!
//! The runtime-function walk and the x64/ARM64 unwind decode are owned by
//! `data-binary-pe` (`pe::read_exception_directory`). This module keeps the
//! product report names.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// Decoded x64 `UNWIND_INFO`.
pub type PeUnwindInfo = pe::PeUnwindInfo;

/// One runtime function entry.
pub type PeRuntimeFunction = pe::PeRuntimeFunction;

/// Exception directory summary.
pub type PeExceptionReport = pe::PeExceptionReport;

/// Decodes the exception directory of one session.
pub fn analyze(session: &BinarySession) -> Result<PeExceptionReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE exception data requires a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_exception_directory(&image, bytes).map_err(|error| IdaError::parse(format!("PE exception directory: {error}")))
}
