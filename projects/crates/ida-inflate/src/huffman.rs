//! Canonical Huffman decoding tables for DEFLATE blocks.
//!
//! A table is built from a list of per-symbol code lengths. Decoding first
//! consults a direct lookup table for codes up to [`FAST_BITS`] bits long and
//! falls back to the classic canonical walk from `puff` for longer codes.

use crate::{InflateError, bits::BitReader};

/// Longest code length allowed by DEFLATE.
const MAX_BITS: usize = 15;

/// Width of the direct lookup table; covers most literal codes.
const FAST_BITS: u32 = 9;

/// A decoding table for one canonical Huffman code.
pub(crate) struct Huffman {
    /// Packed `(length << 12) | symbol` entries for codes up to `fast_bits`.
    fast: Vec<u16>,
    /// Width of the direct lookup table; zero marks an empty code.
    fast_bits: u32,
    /// Number of codes of each length; `count[0]` is always zero.
    count: [u16; MAX_BITS + 1],
    /// Symbols ordered by code length and then by code value.
    symbol: Vec<u16>,
    /// Reason reported when the code has no symbols at all.
    empty_reason: &'static str,
}

impl Huffman {
    /// Builds the code-length alphabet, which must be complete.
    pub(crate) fn for_code_lengths(lengths: &[u8]) -> Result<Self, InflateError> {
        Self::build(lengths, false, false, "empty code length code")
    }

    /// Builds a literal/length alphabet; one uncoded path is tolerated.
    pub(crate) fn for_literal_length(lengths: &[u8]) -> Result<Self, InflateError> {
        Self::build(lengths, true, false, "empty literal/length code")
    }

    /// Builds a distance alphabet; empty and single-symbol codes are allowed.
    ///
    /// RFC 1951 permits a block that never refers back, in which case the
    /// distance alphabet may be empty. Using it later is still an error.
    pub(crate) fn for_distance(lengths: &[u8]) -> Result<Self, InflateError> {
        Self::build(lengths, true, true, "empty distance code")
    }

    /// Validates the lengths and assembles the decode tables.
    fn build(lengths: &[u8], allow_single: bool, allow_empty: bool, empty_reason: &'static str) -> Result<Self, InflateError> {
        let mut count = [0u16; MAX_BITS + 1];
        for &length in lengths {
            let length = usize::from(length);
            if length > MAX_BITS {
                return Err(InflateError::Corrupt("code length exceeds 15 bits"));
            }
            count[length] += 1;
        }
        // Unused symbols are tallied in `count[0]` but never participate in the
        // canonical code assignment.
        count[0] = 0;
        let symbols: u32 = count[1..].iter().map(|&value| u32::from(value)).sum();

        if symbols == 0 {
            if !allow_empty {
                return Err(InflateError::Corrupt(empty_reason));
            }
            return Ok(Self { fast: vec![0], fast_bits: 0, count, symbol: Vec::new(), empty_reason });
        }

        let mut left: i32 = 1;
        for &value in &count[1..] {
            left <<= 1;
            left -= i32::from(value);
            if left < 0 {
                return Err(InflateError::Corrupt("over-subscribed Huffman code"));
            }
        }
        // An incomplete code is only reachable through a decoder that never
        // emits the missing slot, which RFC 1951 allows for a single one-bit
        // code but not for the code-length alphabet.
        if left > 0 && !(allow_single && symbols == 1 && count[1] == 1) {
            return Err(InflateError::Corrupt("incomplete Huffman code"));
        }

        let mut symbol = vec![0u16; symbols as usize];
        let mut offsets = [0u16; MAX_BITS + 1];
        let mut total = 0u16;
        for length in 1..=MAX_BITS {
            offsets[length] = total;
            total += count[length];
        }
        for (value, &length) in lengths.iter().enumerate() {
            if length != 0 {
                let slot = &mut offsets[usize::from(length)];
                symbol[usize::from(*slot)] = value as u16;
                *slot += 1;
            }
        }

        let mut next_code = [0u16; MAX_BITS + 1];
        let mut code: u32 = 0;
        for length in 1..=MAX_BITS {
            code = (code + u32::from(count[length - 1])) << 1;
            next_code[length] = code as u16;
        }

        let max_length = (1..=MAX_BITS).rev().find(|&length| count[length] != 0).unwrap_or(1);
        let fast_bits = (max_length as u32).min(FAST_BITS);
        let mut fast = vec![0u16; 1usize << fast_bits];
        for (value, &length) in lengths.iter().enumerate() {
            let length = usize::from(length);
            if length == 0 {
                continue;
            }
            let current = u32::from(next_code[length]);
            next_code[length] += 1;
            if length as u32 <= fast_bits {
                // DEFLATE codes are stored most significant bit first while the
                // bit stream delivers them least significant bit first, so the
                // table index is the reversed code.
                let entry = ((length as u16) << 12) | value as u16;
                let step = 1usize << length;
                for slot in (reverse_bits(current, length as u32) as usize..fast.len()).step_by(step) {
                    fast[slot] = entry;
                }
            }
        }

        Ok(Self { fast, fast_bits, count, symbol, empty_reason })
    }

    /// Decodes one symbol from the bit stream.
    pub(crate) fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, InflateError> {
        if self.fast_bits == 0 {
            return Err(InflateError::Corrupt(self.empty_reason));
        }

        if reader.can_peek(self.fast_bits) {
            let entry = self.fast[reader.peek(self.fast_bits) as usize];
            if entry != 0 {
                reader.skip(u32::from(entry >> 12));
                return Ok(entry & 0x0fff);
            }
        }

        // Canonical walk: rebuild the code one bit at a time. Only codes longer
        // than `fast_bits`, or codes near a truncated tail, reach this path.
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for length in 1..=MAX_BITS {
            code |= reader.read_bit()? as i32;
            let count = i32::from(self.count[length]);
            if code - first < count {
                let slot = (index + code - first) as usize;
                return self.symbol.get(slot).copied().ok_or(InflateError::Corrupt("invalid Huffman code"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(InflateError::Corrupt("invalid Huffman code"))
    }
}

/// Reverses the low `length` bits of `code`.
fn reverse_bits(code: u32, length: u32) -> u32 {
    let mut reversed = 0;
    for bit in 0..length {
        reversed |= ((code >> bit) & 1) << (length - 1 - bit);
    }
    reversed
}
