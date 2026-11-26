//! PE resource directory projection.
//!
//! The three-level `IMAGE_RESOURCE_DIRECTORY` walk and the leaf data entries
//! are owned by `data-binary-pe` (`pe::read_resources`). This module keeps the
//! product report name and the stable unsupported answer for non-PE input.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// One leaf data entry of the resource tree.
pub type PeResource = pe::PeResource;

/// Bounded resource directory listing.
pub type ResourcesReport = pe::PeResourcesReport;

/// Decodes the PE resource directory of one session.
pub fn analyze(session: &BinarySession) -> Result<ResourcesReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE resources require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_resources(&image, bytes).map_err(|error| IdaError::parse(format!("PE resources: {error}")))
}
