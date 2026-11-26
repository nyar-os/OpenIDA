//! Bounded DEFLATE, zlib and gzip decoding of an embedded payload.
//!
//! Packed loaders usually wrap their real payload in a single compressed
//! stream. This module decodes one stream starting at a caller-chosen file
//! offset, keeps the output under a hard cap and reports the decoded head so the
//! next step (`info`, `strings` or another `inflate`) can run on the result.
//! Nothing is executed: only bytes are decoded.

use std::path::Path;

use data_binary_inspect::BinarySession;
use data_compression::{BoundedDecode, CodecLimits, DecodeStatus, Deflate, Gzip, Zlib};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Output cap applied when the caller does not ask for a smaller limit.
const DEFAULT_LIMIT: usize = 4 * 1024 * 1024;

/// Hard cap on the number of decoded bytes one inflate request can produce.
const MAX_LIMIT: usize = 64 * 1024 * 1024;

/// Decoded bytes rendered as magic and as a printable preview.
const HEAD_BYTES: usize = 32;

/// Compression wrapper around a DEFLATE stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum InflateFormat {
    /// Infer zlib, gzip or raw DEFLATE from the first bytes.
    #[default]
    Auto,
    /// zlib (RFC 1950) framing.
    Zlib,
    /// gzip (RFC 1952) framing.
    Gzip,
    /// Raw DEFLATE (RFC 1951) without a wrapper.
    Raw,
}

impl InflateFormat {
    /// Stable lowercase name used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Zlib => "zlib",
            Self::Gzip => "gzip",
            Self::Raw => "raw",
        }
    }
}

/// Inputs of one [`crate::OpenIda::inflate`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InflateOptions {
    /// File offset of the first compressed byte.
    pub offset: u64,
    /// Wrapper to expect; `auto` infers it from the first bytes.
    #[serde(default)]
    pub format: InflateFormat,
    /// Output cap in bytes; requests above 64 MiB are clamped to the cap.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Optional destination file for the decoded bytes.
    #[serde(default)]
    pub output: Option<String>,
}

/// Result of one [`crate::OpenIda::inflate`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InflateReport {
    /// File offset the decode started at.
    pub offset: u64,
    /// Wrapper that was actually used.
    pub format: String,
    /// Bytes available from `offset` to the end of the file.
    pub input_bytes: u64,
    /// Number of decoded bytes.
    pub output_bytes: u64,
    /// Output cap after the 64 MiB clamp.
    pub limit: usize,
    /// Decoder outcome: `complete`, `output-limit`, `input-truncated`,
    /// `checksum` or `invalid`.
    pub status: String,
    /// Whether the output cap stopped the decode.
    pub truncated: bool,
    /// Spaced hex of the first 32 decoded bytes.
    pub magic: String,
    /// Printable rendering of the first 32 decoded bytes; other bytes become dots.
    pub head_ascii: String,
    /// Destination file the decoded bytes were written to, when requested.
    pub output: Option<String>,
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

/// Decodes one compressed stream described by `options`.
pub fn decode(session: &BinarySession, options: &InflateOptions) -> Result<InflateReport> {
    let limit = options.limit.clamp(1, MAX_LIMIT);
    let available = session.size().saturating_sub(options.offset);
    if available == 0 {
        return Err(IdaError::range("the offset is at or past the end of the file"));
    }

    let bytes = session.read(options.offset, available)?;
    let format = resolve_format(options.format, bytes)?;

    let limits = CodecLimits::new().with_max_output_bytes(limit as u64);
    let (output, status) = match format {
        InflateFormat::Zlib => run(Zlib::decode_bounded(bytes, limits)),
        InflateFormat::Gzip => run(Gzip::decode_bounded(bytes, limits)),
        InflateFormat::Raw => run(Deflate::decode_bounded(bytes, limits)),
        InflateFormat::Auto => unreachable!("auto is resolved before decoding"),
    }?;

    if let Some(path) = &options.output {
        std::fs::write(Path::new(path), &output)?;
    }

    Ok(InflateReport {
        offset: options.offset,
        format: format.as_str().to_string(),
        input_bytes: available,
        output_bytes: output.len() as u64,
        limit,
        status: status.to_string(),
        truncated: status == "output-limit",
        magic: spaced_hex(&output[..output.len().min(HEAD_BYTES)]),
        head_ascii: ascii_preview(&output[..output.len().min(HEAD_BYTES)]),
        output: options.output.clone(),
    })
}

/// Resolves `auto` into a concrete wrapper.
fn resolve_format(requested: InflateFormat, bytes: &[u8]) -> Result<InflateFormat> {
    Ok(match requested {
        InflateFormat::Auto if looks_like_zlib(bytes) => InflateFormat::Zlib,
        InflateFormat::Auto if looks_like_gzip(bytes) => InflateFormat::Gzip,
        InflateFormat::Auto => InflateFormat::Raw,
        InflateFormat::Gzip if !looks_like_gzip(bytes) => {
            return Err(IdaError::parse("the range does not start with a gzip header"));
        }
        other => other,
    })
}

/// Turns a decoder result into decoded bytes plus a stable status name.
///
/// Only a complete stream, a stream stopped by the output cap and a stream cut
/// by the end of the file produce output. Anything else is rejected, so a wrong
/// offset never leaves a file full of garbage behind.
fn run(decoded: BoundedDecode) -> Result<(Vec<u8>, &'static str)> {
    let status = status_name(&decoded.status);
    let keeps_prefix = matches!(decoded.status, DecodeStatus::OutputLimit { .. } | DecodeStatus::InputTruncated { .. })
        && !decoded.output.is_empty();
    if decoded.is_complete() || keeps_prefix {
        Ok((decoded.output, status))
    }
    else {
        Err(IdaError::parse(format!("the selected range did not decode cleanly ({status})")))
    }
}

/// Stable names for the decoder outcomes.
fn status_name(status: &DecodeStatus) -> &'static str {
    match status {
        DecodeStatus::Complete => "complete",
        DecodeStatus::OutputLimit { .. } => "output-limit",
        DecodeStatus::InputTruncated { .. } => "input-truncated",
        // A gzip `ISIZE` mismatch used to surface through the checksum path.
        DecodeStatus::ChecksumMismatch { .. } | DecodeStatus::LengthMismatch { .. } => "checksum",
        DecodeStatus::Invalid { .. } => "invalid",
    }
}

/// Whether the bytes carry a zlib header (deflate, valid check bits).
fn looks_like_zlib(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] & 0x0f == 8 && bytes[0] >> 4 <= 7 && u16::from_be_bytes([bytes[0], bytes[1]]) % 31 == 0
}

/// Whether the bytes start with the gzip magic.
fn looks_like_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

/// Renders bytes as lowercase spaced hex.
fn spaced_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
}

/// Renders printable ASCII and replaces every other byte with a dot.
fn ascii_preview(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| if (0x20..0x7f).contains(&byte) { byte as char } else { '.' }).collect()
}
