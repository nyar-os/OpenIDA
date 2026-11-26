//! `PE` version resource (`RT_VERSION`) projection.
//!
//! The three-level resource walk and the `VS_VERSIONINFO` decode are owned by
//! `data-binary-pe` (`pe::read_version_resources`). This module keeps the
//! product report names and the stable unsupported answer for non-PE input.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// Fixed part of a `VS_VERSIONINFO` resource.
pub type FixedFileInfo = pe::PeFixedFileInfo;

/// One `StringFileInfo` key/value pair.
pub type VersionString = pe::PeVersionString;

/// Decoded version resource of one PE file.
pub type VersionReport = pe::PeVersionReport;

/// Decodes the version resource of one open session.
pub fn analyze(session: &BinarySession) -> Result<VersionReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("version resources are only available for PE files"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_version_resources(&image, bytes).map_err(|error| IdaError::parse(format!("PE version resources: {error}")))
}
