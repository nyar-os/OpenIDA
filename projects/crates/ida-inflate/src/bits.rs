//! Least-significant-bit-first bit reader used by the DEFLATE decoder.
//!
//! DEFLATE packs fields starting at the least significant bit of each byte, in
//! the opposite order of most binary formats. The reader keeps a small bit
//! buffer so Huffman lookups can peek several bits without copying the input.

use crate::InflateError;

/// Reads DEFLATE bit fields from a byte slice, least significant bit first.
pub(crate) struct BitReader<'a> {
    /// Bytes the reader consumes from.
    data: &'a [u8],
    /// Index of the next byte that has not been loaded into the buffer.
    position: usize,
    /// Pending bits; the low `count` bits are valid.
    buffer: u64,
    /// Number of pending bits stored in `buffer`.
    count: u32,
}

impl<'a> BitReader<'a> {
    /// Wraps a byte slice without consuming anything.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0, buffer: 0, count: 0 }
    }

    /// Loads bytes until at least `count` bits are buffered.
    ///
    /// Returns `false` when the input ends first; the bits buffered so far stay
    /// valid, which lets callers fall back to slower decoders near the tail.
    fn fill(&mut self, count: u32) -> bool {
        while self.count < count {
            let Some(&byte) = self.data.get(self.position)
            else {
                return false;
            };
            self.buffer |= u64::from(byte) << self.count;
            self.position += 1;
            self.count += 8;
        }
        true
    }

    /// Reads `count` bits, least significant bit first.
    pub(crate) fn read_bits(&mut self, count: u32) -> Result<u32, InflateError> {
        if count == 0 {
            return Ok(0);
        }
        if !self.fill(count) {
            return Err(InflateError::Truncated);
        }
        let value = (self.buffer & ((1u64 << count) - 1)) as u32;
        self.buffer >>= count;
        self.count -= count;
        Ok(value)
    }

    /// Reads a single bit as zero or one.
    pub(crate) fn read_bit(&mut self) -> Result<u32, InflateError> {
        self.read_bits(1)
    }

    /// Returns whether `count` bits can be peeked without consuming them.
    pub(crate) fn can_peek(&mut self, count: u32) -> bool {
        self.fill(count)
    }

    /// Returns the low `count` buffered bits without consuming them.
    ///
    /// Only call this right after [`Self::can_peek`] succeeded for the same
    /// `count`, because the buffer may hold fewer valid bits.
    pub(crate) fn peek(&self, count: u32) -> u32 {
        (self.buffer & ((1u64 << count) - 1)) as u32
    }

    /// Drops `count` bits that were already inspected with [`Self::peek`].
    pub(crate) fn skip(&mut self, count: u32) {
        self.buffer >>= count;
        self.count -= count;
    }

    /// Discards the bits left in the current byte so the next read is aligned.
    pub(crate) fn align_to_byte(&mut self) {
        let remaining = self.count % 8;
        self.skip(remaining);
    }

    /// Returns the index one past the last byte touched by the consumed bits.
    pub(crate) fn consumed_bytes(&self) -> usize {
        (self.position * 8 - self.count as usize).div_ceil(8)
    }

    /// Returns the next `length` whole bytes, bypassing the bit buffer.
    pub(crate) fn read_aligned_slice(&mut self, length: usize) -> Result<&'a [u8], InflateError> {
        // Whole bytes still in the buffer were already read from the input, so
        // move the cursor back before slicing to keep the borrow independent of
        // `self`.
        self.position -= (self.count / 8) as usize;
        self.buffer = 0;
        self.count = 0;
        let end = self.position.checked_add(length).ok_or(InflateError::Truncated)?;
        let slice = self.data.get(self.position..end).ok_or(InflateError::Truncated)?;
        self.position = end;
        Ok(slice)
    }
}
