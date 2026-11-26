//! PE delay-load import projection.
//!
//! The descriptor walk, the `Attributes` flag handling and the thunk decode are
//! owned by `data-binary-pe` (`pe::read_delay_imports`). This module keeps the
//! product report names.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// One delay-load thunk.
pub type PeDelayThunk = pe::PeDelayThunk;

/// One delay-load descriptor.
pub type PeDelayModule = pe::PeDelayModule;

/// Bounded delay-load listing.
pub type PeDelayImportsReport = pe::PeDelayImportsReport;

/// Decodes the delay-load import directory of one session.
pub fn analyze(session: &BinarySession) -> Result<PeDelayImportsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE delay imports require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_delay_imports(&image, bytes).map_err(|error| IdaError::parse(format!("PE delay imports: {error}")))
}
