//! Encoded string extraction over the opened bytes.
//!
//! The pinned inspection engine only scans printable ASCII, so this module owns
//! the encoding switch. UTF-16LE support targets ASCII text stored with a zero
//! high byte, which is what Windows binaries commonly embed; it is not a
//! general Unicode decoder. Runs are reported with their file offset and byte
//! length, and both scanners tolerate odd file endings and truncated pairs.

use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Minimum run length used when the caller does not ask for one.
const DEFAULT_MIN_LENGTH: usize = 4;
/// Hit limit used when the caller does not ask for one.
const DEFAULT_LIMIT: usize = 100;
/// Hard cap on the number of hits that can be returned.
const MAX_LIMIT: usize = 10_000;

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
    /// Maximum number of hits to return; capped at 10 000.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Encoding scanned for.
    #[serde(default)]
    pub encoding: StringEncoding,
}

impl Default for StringsOptions {
    fn default() -> Self {
        Self { min_length: DEFAULT_MIN_LENGTH, limit: DEFAULT_LIMIT, encoding: StringEncoding::Ascii }
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
    /// Hits that survived the limit.
    pub hits: Vec<EncodedStringHit>,
    /// Number of hits before the limit was applied.
    pub total: usize,
    /// Whether the limit removed hits.
    pub truncated: bool,
}

/// Scans one session with the requested encoding.
pub(crate) fn scan(session: &BinarySession, options: &StringsOptions) -> Result<EncodedStringsReport> {
    let bytes = session.read(0, session.size())?;
    let min_length = options.min_length.max(1);
    let limit = options.limit.min(MAX_LIMIT);

    let mut hits = match options.encoding {
        StringEncoding::Ascii => ascii_hits(bytes, min_length),
        StringEncoding::Utf16Le => utf16le_hits(bytes, min_length),
        StringEncoding::Both => {
            let mut hits = ascii_hits(bytes, min_length);
            hits.extend(utf16le_hits(bytes, min_length));
            hits.sort_by(|left, right| left.offset.cmp(&right.offset).then(left.encoding.cmp(&right.encoding)));
            hits
        }
    };

    let total = hits.len();
    let truncated = total > limit;
    hits.truncate(limit);

    Ok(EncodedStringsReport { encoding: options.encoding, min_length, limit, hits, total, truncated })
}

fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

fn ascii_hits(bytes: &[u8], min_length: usize) -> Vec<EncodedStringHit> {
    let mut hits = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if printable(bytes[index]) {
            let start = index;
            while index < bytes.len() && printable(bytes[index]) {
                index += 1;
            }
            if index - start >= min_length {
                let value = String::from_utf8_lossy(&bytes[start..index]).into_owned();
                hits.push(EncodedStringHit {
                    offset: start as u64,
                    length: (index - start) as u64,
                    encoding: StringEncoding::Ascii,
                    value,
                });
            }
        }
        else {
            index += 1;
        }
    }
    hits
}

fn utf16le_hits(bytes: &[u8], min_length: usize) -> Vec<EncodedStringHit> {
    let mut hits = Vec::new();
    let mut index = 0;
    // Pairs are read at every byte offset; a truncated trailing byte is skipped.
    while index + 1 < bytes.len() {
        if printable(bytes[index]) && bytes[index + 1] == 0 {
            let start = index;
            let mut value = String::new();
            while index + 1 < bytes.len() && printable(bytes[index]) && bytes[index + 1] == 0 {
                value.push(bytes[index] as char);
                index += 2;
            }
            if value.len() >= min_length {
                hits.push(EncodedStringHit {
                    offset: start as u64,
                    length: (index - start) as u64,
                    encoding: StringEncoding::Utf16Le,
                    value,
                });
            }
        }
        else {
            index += 1;
        }
    }
    hits
}
