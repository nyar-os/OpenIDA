//! Observation workflows over the opened bytes.
//!
//! [`strings`] scans printable ASCII and ASCII-in-UTF-16LE runs, and [`find`]
//! matches a byte regex. Both are bounded and report `total` plus `truncated`.
//! The string scanner is delegated to `data-binary-inspect::text`; [`find`]
//! stays local because the upstream finder is literal-only.

pub(crate) mod find;
pub(crate) mod strings;
