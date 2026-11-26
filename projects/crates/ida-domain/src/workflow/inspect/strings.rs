//! Encoded string extraction over the opened bytes.
//!
//! The scanning belongs to `data-binary-inspect::text`: this workflow only
//! chooses the encoding, merges the ASCII and UTF-16LE families and applies the
//! product paging policy (`skip`, `limit`, `all`). `utf16le` means ASCII
//! characters stored with a zero high byte, not general Unicode text.

use data_binary_inspect::{
    BinarySession,
    text::{self, TextMode, TextOptions},
};
use serde::{Deserialize, Serialize};

use crate::Result;

/// Minimum run length used when the caller does not ask for one.
const DEFAULT_MIN_LENGTH: usize = 4;
/// Hit limit used when the caller does not ask for one.
const DEFAULT_LIMIT: usize = 100;
/// Hard cap on the number of hits that can be returned.
const MAX_LIMIT: usize = 10_000;
/// Hard cap on the number of hits returned by an uncapped (`all`) scan.
const MAX_ALL_LIMIT: usize = 2_000_000;

/// Byte encoding used to decode string runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StringEncoding {
    /// Contiguous printable ASCII bytes.
    #[default]
    Ascii,
    /// Printable ASCII code units stored with a zero high byte.
    Utf16Le,
    /// Both scanners merged and ordered by file offset.
    Both,
}

impl StringEncoding {
    /// Stable lower-case name used in reports and on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf16Le => "utf16le",
            Self::Both => "both",
        }
    }
}

fn default_min_length() -> usize {
    DEFAULT_MIN_LENGTH
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

/// Inputs of one [`crate::OpenIda::strings_encoded`] call.
///
/// Serialized as JSON with camelCase keys, so `{ "minLength": 4, "encoding": "both" }`
/// is the wire form the addon and the TypeScript client both use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StringsOptions {
    /// Minimum number of characters in a run; values below one are treated as one.
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    /// Maximum number of hits to return; capped at 10 000 unless `all` is set.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Number of leading hits to drop before the limit is applied.
    #[serde(default)]
    pub skip: usize,
    /// Bypass the 10 000 cap and return up to 2 000 000 hits.
    #[serde(default)]
    pub all: bool,
    /// Encoding scanned for.
    #[serde(default)]
    pub encoding: StringEncoding,
}

impl Default for StringsOptions {
    fn default() -> Self {
        Self { min_length: DEFAULT_MIN_LENGTH, limit: DEFAULT_LIMIT, skip: 0, all: false, encoding: StringEncoding::Ascii }
    }
}

/// One decoded string run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedStringHit {
    /// File offset where the run starts.
    pub offset: u64,
    /// Run length in bytes.
    pub length: u64,
    /// Encoding that produced this hit.
    pub encoding: StringEncoding,
    /// Decoded text.
    pub value: String,
}

/// Bounded result of one encoded string scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedStringsReport {
    /// Requested encoding.
    pub encoding: StringEncoding,
    /// Minimum run length that was applied.
    pub min_length: usize,
    /// Hit limit that was applied.
    pub limit: usize,
    /// Number of leading hits that were dropped before the limit.
    pub skip: usize,
    /// Whether the scan ran uncapped up to the `all` hard limit.
    pub all: bool,
    /// Hits that survived the skip and the limit.
    pub hits: Vec<EncodedStringHit>,
    /// Number of hits before the skip and the limit were applied.
    pub total: usize,
    /// Whether the skip or the limit removed hits.
    pub truncated: bool,
}

/// Scans one session with the requested encoding.
pub(crate) fn scan(session: &BinarySession, options: &StringsOptions) -> Result<EncodedStringsReport> {
    let bytes = session.read(0, session.size())?;
    let min_length = options.min_length.max(1);
    let limit = if options.all { MAX_ALL_LIMIT } else { options.limit.min(MAX_LIMIT) };

    let mut hits = match options.encoding {
        StringEncoding::Ascii => ascii_hits(bytes, min_length)?,
        StringEncoding::Utf16Le => utf16le_hits(bytes, min_length)?,
        StringEncoding::Both => {
            let mut hits = ascii_hits(bytes, min_length)?;
            hits.extend(utf16le_hits(bytes, min_length)?);
            hits.sort_by(|left, right| left.offset.cmp(&right.offset).then(left.encoding.cmp(&right.encoding)));
            hits
        }
    };

    let total = hits.len();
    let skip = options.skip.min(total);
    let mut hits = hits.split_off(skip);
    let truncated = skip > 0 || hits.len() > limit;
    hits.truncate(limit);

    Ok(EncodedStringsReport { encoding: options.encoding, min_length, limit, skip, all: options.all, hits, total, truncated })
}

/// Runs the owner's ASCII scanner over the whole buffer.
fn ascii_hits(bytes: &[u8], min_length: usize) -> Result<Vec<EncodedStringHit>> {
    let report =
        text::extract(bytes, &TextOptions { mode: TextMode::Ascii, min_length, limit: None, offset: 0, length: None })?;
    Ok(report
        .hits
        .into_iter()
        .map(|hit| EncodedStringHit {
            offset: hit.offset,
            length: hit.length,
            encoding: StringEncoding::Ascii,
            value: hit.value,
        })
        .collect())
}

/// Runs the owner's UTF-16LE scanner over both pair alignments.
///
/// The product reports an ASCII-in-UTF-16LE run starting at *any* byte offset,
/// while [`text::extract`] aligns pairs to the start of its window. Two windows,
/// one at offset `0` and one at offset `1`, cover the even and odd runs; the
/// merged hits keep the original byte offsets.
fn utf16le_hits(bytes: &[u8], min_length: usize) -> Result<Vec<EncodedStringHit>> {
    let mut hits = text_hits(bytes, min_length, 0, None)?;
    if bytes.len() > 1 {
        hits.extend(text_hits(bytes, min_length, 1, Some(bytes.len() as u64 - 1))?);
    }
    hits.sort_by_key(|hit| hit.offset);
    Ok(hits)
}

/// Extracts one UTF-16LE window and tags the hits with their encoding.
fn text_hits(bytes: &[u8], min_length: usize, offset: u64, length: Option<u64>) -> Result<Vec<EncodedStringHit>> {
    let report = text::extract(bytes, &TextOptions { mode: TextMode::Utf16Le, min_length, limit: None, offset, length })?;
    Ok(report
        .hits
        .into_iter()
        .map(|hit| EncodedStringHit {
            offset: hit.offset,
            length: hit.length,
            encoding: StringEncoding::Utf16Le,
            value: hit.value,
        })
        .collect())
}
