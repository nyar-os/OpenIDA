//! PE attribute certificate table projection.
//!
//! The `WIN_CERTIFICATE` walk and the `pkcs7` shape check are owned by
//! `data-binary-pe` (`pe::read_certificates`). This module keeps the product
//! report names.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;

use crate::{IdaError, Result};

/// One attribute certificate entry.
pub type PeCertificate = pe::PeCertificate;

/// Bounded certificate table listing.
pub type CertificatesReport = pe::PeCertificatesReport;

/// Decodes the certificate table of one session.
pub fn analyze(session: &BinarySession) -> Result<CertificatesReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE certificates require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    pe::read_certificates(&image, bytes).map_err(|error| IdaError::parse(format!("PE certificates: {error}")))
}
