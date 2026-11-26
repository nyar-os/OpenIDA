//! PE Rich header projection.
//!
//! The `DanS` marker search, the XOR key and the entry table are owned by
//! `data-binary-pe` (`pe::read_rich_header`). This module keeps the product
//! report names.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// One Rich header entry.
pub type PeRichEntry = pe::PeRichEntry;

/// Decoded Rich header.
pub type PeRichHeaderReport = pe::PeRichHeaderReport;

/// Decodes the Rich header of one session.
pub fn analyze(session: &BinarySession) -> Result<PeRichHeaderReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("the PE Rich header requires a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_rich_header(&image, bytes).map_err(|error| IdaError::parse(format!("PE Rich header: {error}")))
}
