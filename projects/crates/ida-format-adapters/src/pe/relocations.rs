//! PE base relocation projection.
//!
//! The block walk and the per-kind counts are owned by `data-binary-pe`
//! (`pe::read_relocations`). This module keeps the product report names.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// Count of one relocation kind.
pub type RelocationKindCount = pe::PeRelocationKindCount;

/// One relocation block.
pub type RelocationBlock = pe::PeRelocationBlock;

/// Bounded relocation listing.
pub type RelocationsReport = pe::PeRelocationsReport;

/// Decodes the `.reloc` directory of one session.
pub fn analyze(session: &BinarySession) -> Result<RelocationsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE relocations require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_relocations(&image, bytes).map_err(|error| IdaError::parse(format!("PE relocations: {error}")))
}
