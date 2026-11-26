//! Bounded DEFLATE, zlib and gzip decoding.
//!
//! This crate is a from-scratch implementation of the DEFLATE algorithm
//! (RFC 1951) together with the zlib (RFC 1950) and gzip (RFC 1952) containers.
//! Every entry point decodes exactly one stream from the start of the input and
//! enforces a caller-supplied output limit, so a hostile header cannot make the
//! decoder allocate without bound.
//!
//! Trailing bytes after the end of the stream are ignored. zlib streams are
//! verified against their Adler-32 trailer and gzip streams against their
//! CRC-32 and length trailer.

#![warn(missing_docs)]

mod bits;
mod checksum;
mod deflate;
mod gzip;
mod huffman;

use checksum::{adler32, crc32};

/// Error raised while decoding a compressed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateError {
    /// The stream ended before a complete block was decoded.
    Truncated,
    /// The stream is structurally invalid.
    Corrupt(&'static str),
    /// Decoding would exceed the caller's output limit.
    LimitExceeded,
}

impl core::fmt::Display for InflateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated compressed stream"),
            Self::Corrupt(reason) => write!(f, "corrupt compressed stream: {reason}"),
            Self::LimitExceeded => f.write_str("decoded output exceeds the limit"),
        }
    }
}

impl std::error::Error for InflateError {}

/// Terminal state of a decode that keeps its partial output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateStatus {
    /// The stream decoded completely.
    Complete,
    /// The input ended before the final block was decoded.
    NeedsMoreInput,
    /// The caller's output limit stopped the decode.
    OutputLimit,
    /// A container checksum did not match the decoded bytes.
    Checksum,
    /// The stream is structurally invalid.
    Invalid,
}

/// Decoded bytes together with the terminal status.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// Bytes produced; a prefix of the full output unless `status` is [`InflateStatus::Complete`].
    pub output: Vec<u8>,
    /// Terminal state of the decode.
    pub status: InflateStatus,
}

/// Maps an error to the status reported by the partial-output entry points.
fn status_of(error: InflateError) -> InflateStatus {
    match error {
        InflateError::Truncated => InflateStatus::NeedsMoreInput,
        InflateError::LimitExceeded => InflateStatus::OutputLimit,
        InflateError::Corrupt(_) => InflateStatus::Invalid,
    }
}

/// Decodes a raw DEFLATE stream.
///
/// Bytes after the final block are ignored and `limit` caps the decoded length;
/// a stream that would produce more bytes yields [`InflateError::LimitExceeded`].
pub fn decompress_raw(input: &[u8], limit: usize) -> Result<Vec<u8>, InflateError> {
    let outcome = deflate::inflate(input, limit);
    match outcome.error {
        Some(error) => Err(error),
        None => Ok(outcome.output),
    }
}

/// Decodes a zlib-framed DEFLATE stream.
///
/// The two-byte header is validated, preset dictionaries are rejected and the
/// four-byte big-endian Adler-32 trailer must match the decoded bytes.
pub fn decompress_zlib(input: &[u8], limit: usize) -> Result<Vec<u8>, InflateError> {
    if input.len() < 2 {
        return Err(InflateError::Truncated);
    }
    let (cmf, flg) = (input[0], input[1]);
    if cmf & 0x0f != 8 {
        return Err(InflateError::Corrupt("unsupported zlib compression method"));
    }
    if cmf >> 4 > 7 {
        return Err(InflateError::Corrupt("zlib window size exceeds 32 KiB"));
    }
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Err(InflateError::Corrupt("zlib header check failed"));
    }
    if flg & 0x20 != 0 {
        return Err(InflateError::Corrupt("zlib preset dictionary is not supported"));
    }

    let outcome = deflate::inflate(&input[2..], limit);
    if let Some(error) = outcome.error {
        return Err(error);
    }
    let trailer_at = 2 + outcome.consumed;
    let trailer = input.get(trailer_at..).and_then(|rest| rest.get(..4)).ok_or(InflateError::Truncated)?;
    let expected = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    if adler32(&outcome.output) != expected {
        return Err(InflateError::Corrupt("zlib Adler-32 mismatch"));
    }
    Ok(outcome.output)
}

/// Decodes a gzip-framed DEFLATE stream.
///
/// The optional extra field, file name, comment and header checksum are
/// skipped or verified, and the CRC-32 plus length trailer must match the
/// decoded bytes.
pub fn decompress_gzip(input: &[u8], limit: usize) -> Result<Vec<u8>, InflateError> {
    let header_at = gzip::header_len(input)?;
    let outcome = deflate::inflate(&input[header_at..], limit);
    if let Some(error) = outcome.error {
        return Err(error);
    }
    let trailer_at = header_at + outcome.consumed;
    let trailer = input.get(trailer_at..).and_then(|rest| rest.get(..8)).ok_or(InflateError::Truncated)?;
    let expected_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let expected_size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if crc32(&outcome.output) != expected_crc {
        return Err(InflateError::Corrupt("gzip CRC-32 mismatch"));
    }
    if outcome.output.len() as u32 != expected_size {
        return Err(InflateError::Corrupt("gzip length mismatch"));
    }
    Ok(outcome.output)
}

/// Decodes a raw DEFLATE stream and keeps the bytes produced before a failure.
pub fn decode_raw(input: &[u8], limit: usize) -> Decoded {
    let outcome = deflate::inflate(input, limit);
    match outcome.error {
        Some(error) => Decoded { output: outcome.output, status: status_of(error) },
        None => Decoded { output: outcome.output, status: InflateStatus::Complete },
    }
}

/// Decodes a zlib stream and keeps the bytes produced before a failure.
pub fn decode_zlib(input: &[u8], limit: usize) -> Decoded {
    if input.len() < 2 {
        return Decoded { output: Vec::new(), status: InflateStatus::NeedsMoreInput };
    }
    let (cmf, flg) = (input[0], input[1]);
    if cmf & 0x0f != 8 || cmf >> 4 > 7 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Decoded { output: Vec::new(), status: InflateStatus::Invalid };
    }
    if flg & 0x20 != 0 {
        return Decoded { output: Vec::new(), status: InflateStatus::Invalid };
    }

    let outcome = deflate::inflate(&input[2..], limit);
    if let Some(error) = outcome.error {
        return Decoded { output: outcome.output, status: status_of(error) };
    }
    let Some(trailer) = input.get(2 + outcome.consumed..).and_then(|rest| rest.get(..4)) else {
        return Decoded { output: outcome.output, status: InflateStatus::NeedsMoreInput };
    };
    let expected = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    if adler32(&outcome.output) != expected {
        return Decoded { output: outcome.output, status: InflateStatus::Checksum };
    }
    Decoded { output: outcome.output, status: InflateStatus::Complete }
}

/// Decodes a gzip stream and keeps the bytes produced before a failure.
pub fn decode_gzip(input: &[u8], limit: usize) -> Decoded {
    let header_at = match gzip::header_len(input) {
        Ok(header_at) => header_at,
        Err(error) => return Decoded { output: Vec::new(), status: status_of(error) },
    };
    let outcome = deflate::inflate(&input[header_at..], limit);
    if let Some(error) = outcome.error {
        return Decoded { output: outcome.output, status: status_of(error) };
    }
    let Some(trailer) = input.get(header_at + outcome.consumed..).and_then(|rest| rest.get(..8)) else {
        return Decoded { output: outcome.output, status: InflateStatus::NeedsMoreInput };
    };
    let expected_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let expected_size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if crc32(&outcome.output) != expected_crc || outcome.output.len() as u32 != expected_size {
        return Decoded { output: outcome.output, status: InflateStatus::Checksum };
    }
    Decoded { output: outcome.output, status: InflateStatus::Complete }
}
