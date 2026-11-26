//! Byte-regex search over the opened bytes.
//!
//! Where [`crate::OpenIda::search`] matches one fixed pattern, this module
//! evaluates a regular expression against the whole file with the `regex`
//! crate's byte matcher, so a single pass can describe a family of layouts.
//! Matches are reported with their file offset, byte length and a bounded
//! printable preview; non-printable bytes inside a preview collapse to dots.
//!
//! `data-binary-inspect::find` is a literal matcher with a match preview, not a
//! byte-regex engine, so this verb stays product-local: reusing the owner would
//! change both the accepted patterns and the reported `preview`/`context`.

use data_binary_inspect::BinarySession;
use regex::bytes::RegexBuilder;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Hit limit used when the caller does not ask for one.
const DEFAULT_LIMIT: usize = 100;
/// Preview length used when the caller does not ask for one.
const DEFAULT_CONTEXT: usize = 80;
/// Hard cap on the number of hits that can be returned.
const MAX_LIMIT: usize = 5_000;
/// Hard cap on the preview length rendered per hit.
const MAX_CONTEXT: usize = 512;

fn default_limit() -> Option<usize> {
    Some(DEFAULT_LIMIT)
}

fn default_context() -> usize {
    DEFAULT_CONTEXT
}

/// Inputs of one [`crate::OpenIda::find`] call.
///
/// Serialized as JSON with camelCase keys, so `{ "pattern": "marker-[0-9]",
/// "caseInsensitive": true }` is the wire form the addon and the TypeScript
/// client both use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindOptions {
    /// Regular expression evaluated against the raw file bytes.
    pub pattern: String,
    /// Whether ASCII letters match case-insensitively.
    #[serde(default)]
    pub case_insensitive: bool,
    /// Number of leading matches to drop before the limit is applied.
    #[serde(default)]
    pub skip: usize,
    /// Maximum number of hits; defaults to 100 and is capped at 5 000.
    /// `null` requests every hit up to the cap.
    #[serde(default = "default_limit")]
    pub limit: Option<usize>,
    /// Bytes rendered into each hit preview; defaults to 80 and is capped at 512.
    #[serde(default = "default_context")]
    pub context: usize,
}

impl Default for FindOptions {
    fn default() -> Self {
        Self { pattern: String::new(), case_insensitive: false, skip: 0, limit: default_limit(), context: DEFAULT_CONTEXT }
    }
}

/// One regex match with its position and a printable preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindHit {
    /// File offset where the match starts.
    pub offset: u64,
    /// Length of the matched bytes in the file.
    pub length: usize,
    /// Printable rendering of the bytes at the match; non-printable bytes
    /// become dots and the preview is capped at twice the requested context.
    pub preview: String,
}

/// Bounded result of one [`crate::OpenIda::find`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindReport {
    /// Pattern that was compiled and evaluated.
    pub pattern: String,
    /// Whether the match ran case-insensitively.
    pub case_insensitive: bool,
    /// Number of leading matches that were dropped before the limit.
    pub skip: usize,
    /// Hit limit that was applied.
    pub limit: usize,
    /// Preview length that was applied.
    pub context: usize,
    /// Matches that survived the skip and the limit.
    pub hits: Vec<FindHit>,
    /// Number of matches before the skip and the limit were applied.
    pub total: usize,
    /// Whether the skip or the limit removed matches.
    pub truncated: bool,
}

/// Evaluates `options.pattern` against the whole file and returns the window of
/// matches selected by `skip` and `limit`.
pub fn find(session: &BinarySession, options: &FindOptions) -> Result<FindReport> {
    let bytes = session.read(0, session.size())?;
    let regex = RegexBuilder::new(&options.pattern)
        .case_insensitive(options.case_insensitive)
        .build()
        .map_err(|error| IdaError::parse(format!("invalid pattern: {error}")))?;
    let limit = options.limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT);
    let context = options.context.min(MAX_CONTEXT);

    let mut hits = Vec::new();
    let mut total = 0_usize;
    let mut skipped = 0_usize;
    for matched in regex.find_iter(bytes) {
        total += 1;
        if skipped < options.skip {
            skipped += 1;
            continue;
        }
        if hits.len() >= limit {
            continue;
        }
        let start = matched.start();
        let end = start.saturating_add(context).min(bytes.len());
        hits.push(FindHit {
            offset: start as u64,
            length: matched.end() - start,
            preview: preview(&bytes[start..end], context.saturating_mul(2)),
        });
    }

    Ok(FindReport {
        pattern: options.pattern.clone(),
        case_insensitive: options.case_insensitive,
        skip: skipped,
        limit,
        context,
        total,
        truncated: skipped > 0 || total - skipped > hits.len(),
        hits,
    })
}

/// Renders `bytes` as printable ASCII, mapping every other byte to a dot, and
/// truncates the rendering to `max_chars` characters.
fn preview(bytes: &[u8], max_chars: usize) -> String {
    bytes
        .iter()
        .map(|&byte| if byte.is_ascii_graphic() || byte == b' ' { char::from(byte) } else { '.' })
        .take(max_chars)
        .collect()
}
