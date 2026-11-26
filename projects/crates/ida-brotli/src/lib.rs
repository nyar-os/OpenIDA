//! Bounded Brotli (RFC 7932) stream decoding, implemented from scratch with
//! `std` only.
//!
//! The decoder reads one complete stream from the start of the input and stops
//! after the final meta-block; trailing bytes are ignored. Decoding supports
//! window sizes 10 to 24, uncompressed and compressed meta-blocks, block
//! switching for literals, commands and distances, all four context modes,
//! distance postfix/direct codes, the full 704-symbol command table, and static
//! dictionary references with their word transforms.

#![warn(missing_docs)]

mod bit;
mod decoder;
mod dictionary;
mod huffman;
mod tables;

pub use dictionary::{apply_transform, word};

/// Error raised while decoding a Brotli stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrotliError {
    /// The stream ended before the final metablock.
    Truncated,
    /// The stream is structurally invalid.
    Corrupt(&'static str),
    /// Decoding would exceed the caller's output limit.
    LimitExceeded,
}

impl core::fmt::Display for BrotliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated brotli stream"),
            Self::Corrupt(reason) => write!(f, "corrupt brotli stream: {reason}"),
            Self::LimitExceeded => f.write_str("decoded output exceeds the limit"),
        }
    }
}

impl std::error::Error for BrotliError {}

/// Decodes one complete Brotli stream.
///
/// Decoding starts at the first byte of `input` and stops after the stream's
/// final meta-block, so any trailing bytes are ignored. If the decoded output
/// would grow larger than `limit` bytes, [`BrotliError::LimitExceeded`] is
/// returned before the limit is exceeded.
pub fn decompress(input: &[u8], limit: usize) -> Result<Vec<u8>, BrotliError> {
    decoder::decompress(input, limit)
}
