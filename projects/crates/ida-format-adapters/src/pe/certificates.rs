//! PE attribute certificate table decoding.
//!
//! The security data directory (index 4) points at a file offset, not an RVA.
//! It holds one or more `WIN_CERTIFICATE` entries, each eight-byte aligned, that
//! carry Authenticode payloads. This module reports the entry headers and
//! whether the payload looks like a DER `PKCS#7` structure; it never verifies a
//! signature, chain or timestamp.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Data directory index of the attribute certificate table.
const DIRECTORY_SECURITY: usize = 4;
/// `WIN_CERTIFICATE` header: length, revision and type.
const CERTIFICATE_HEADER_SIZE: usize = 8;
const MAX_CERTIFICATES: usize = 64;

const WIN_CERT_REVISION_1_0: u16 = 0x0100;
const WIN_CERT_REVISION_2_0: u16 = 0x0200;

const WIN_CERT_TYPE_X509: u16 = 0x0001;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
const WIN_CERT_TYPE_RESERVED_1: u16 = 0x0003;
const WIN_CERT_TYPE_TS_STACK_SIGNED: u16 = 0x0004;

/// One `WIN_CERTIFICATE` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeCertificate {
    /// File offset of the entry header.
    pub offset: u32,
    /// `dwLength`, including the eight-byte header.
    pub length: u32,
    /// `wRevision` as `1.0`, `2.0` or `0x<revision>`.
    pub revision: String,
    /// `wCertificateType` as a stable name.
    pub certificate_type: String,
    /// Payload size, which is `dwLength - 8`.
    pub payload_size: u32,
    /// Whether the payload starts with a DER `SEQUENCE` tag, the usual shape of
    /// a `PKCS#7` `SignedData` blob.
    pub pkcs7: bool,
}

/// Attribute certificate table summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificatesReport {
    /// Whether the security directory is non-empty.
    pub present: bool,
    /// Entries that survived the limit, in table order.
    pub certificates: Vec<PeCertificate>,
    /// Number of entries declared by the table.
    pub total: usize,
    /// Declared size of the security directory.
    pub directory_size: u32,
    /// Whether a limit or a malformed entry cut the listing.
    pub truncated: bool,
}

/// Decodes the PE attribute certificate table of one session.
pub fn analyze(session: &BinarySession) -> Result<CertificatesReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE certificates require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let directory = image.optional.data_directories[DIRECTORY_SECURITY];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(CertificatesReport {
            present: false,
            certificates: Vec::new(),
            total: 0,
            directory_size: 0,
            truncated: false,
        });
    }

    let mut report = CertificatesReport {
        present: true,
        certificates: Vec::new(),
        total: 0,
        directory_size: directory.size,
        truncated: false,
    };
    // Unlike the other directories, this one stores a file offset in `rva`.
    let base = directory.rva as usize;
    let end = base.saturating_add(directory.size as usize).min(bytes.len());
    if base >= bytes.len() {
        report.truncated = true;
        return Ok(report);
    }

    let mut at = base;
    while at.saturating_add(CERTIFICATE_HEADER_SIZE) <= end {
        let length = read_u32(bytes, at)?;
        if length < CERTIFICATE_HEADER_SIZE as u32 {
            report.truncated = true;
            break;
        }
        let entry_end = at.saturating_add(length as usize);
        if entry_end > end {
            report.truncated = true;
            break;
        }
        let revision = read_u16(bytes, at + 4)?;
        let certificate_type = read_u16(bytes, at + 6)?;

        report.total += 1;
        if report.certificates.len() < MAX_CERTIFICATES {
            let payload = &bytes[at + CERTIFICATE_HEADER_SIZE..entry_end];
            report.certificates.push(PeCertificate {
                offset: at as u32,
                length,
                revision: revision_name(revision),
                certificate_type: certificate_type_name(certificate_type),
                payload_size: length - CERTIFICATE_HEADER_SIZE as u32,
                pkcs7: certificate_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA && payload.first() == Some(&0x30),
            });
        }
        else {
            report.truncated = true;
        }

        // Entries start on an eight-byte boundary.
        at = align_u64(entry_end as u64, 8) as usize;
    }
    if at < end {
        report.truncated = true;
    }
    Ok(report)
}

fn revision_name(revision: u16) -> String {
    match revision {
        WIN_CERT_REVISION_1_0 => "1.0".to_string(),
        WIN_CERT_REVISION_2_0 => "2.0".to_string(),
        other => format!("0x{other:04x}"),
    }
}

fn certificate_type_name(certificate_type: u16) -> String {
    match certificate_type {
        WIN_CERT_TYPE_X509 => "X509".to_string(),
        WIN_CERT_TYPE_PKCS_SIGNED_DATA => "PKCS_SIGNED_DATA".to_string(),
        WIN_CERT_TYPE_RESERVED_1 => "RESERVED_1".to_string(),
        WIN_CERT_TYPE_TS_STACK_SIGNED => "TS_STACK_SIGNED".to_string(),
        other => format!("0x{other:04x}"),
    }
}

fn align_u64(value: u64, alignment: u64) -> u64 {
    value.saturating_add(alignment - 1) & !(alignment - 1)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("a certificate header lies outside the file"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("a certificate header lies outside the file"))?;
    Ok(u32::from_le_bytes(raw))
}
