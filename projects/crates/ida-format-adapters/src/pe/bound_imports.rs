//! PE bound import projection.
//!
//! The descriptor walk and the forwarder table are owned by `data-binary-pe`
//! (`pe::read_bound_imports`). This module keeps the product report names.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// One forwarder reference of a bound module.
pub type PeBoundForwarder = pe::PeBoundForwarder;

/// One bound import descriptor.
pub type PeBoundModule = pe::PeBoundModule;

/// Bounded bound-import listing.
pub type PeBoundImportsReport = pe::PeBoundImportsReport;

/// Decodes the bound import directory of one session.
pub fn analyze(session: &BinarySession) -> Result<PeBoundImportsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE bound imports require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_bound_imports(&image, bytes).map_err(|error| IdaError::parse(format!("PE bound imports: {error}")))
}
