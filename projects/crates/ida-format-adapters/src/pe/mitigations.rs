//! PE mitigation posture projection.
//!
//! The header, section and load-config facts are owned by `data-binary-pe`
//! (`pe::read_mitigations`). This module keeps the product report names and
//! the stable unsupported answer for non-PE input.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// One section mapped with both write and execute permission.
pub type WritableExecutableSection = pe::PeWritableExecutableSection;

/// PE mitigation posture.
pub type MitigationsReport = pe::PeMitigationsReport;

/// Summarises the PE mitigation posture of one session.
pub fn analyze(session: &BinarySession) -> Result<MitigationsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE mitigations require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_mitigations(&image, bytes).map_err(|error| IdaError::parse(format!("PE mitigations: {error}")))
}
