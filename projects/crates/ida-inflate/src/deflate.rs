//! DEFLATE (RFC 1951) block decoding.
//!
//! The decoder walks the block stream once, keeps every write inside the
//! caller's output limit and reports the number of consumed input bytes so the
//! zlib and gzip wrappers can locate their trailers.

use std::sync::OnceLock;

use crate::{InflateError, bits::BitReader, huffman::Huffman};

/// Base length for the literal/length symbols 257 through 285.
const LENGTH_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];

/// Extra bits for the literal/length symbols 257 through 285.
const LENGTH_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];

/// Base distance for the distance symbols 0 through 29.
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
    12289, 16385, 24577,
];

/// Extra bits for the distance symbols 0 through 29.
const DISTANCE_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// Transmission order of the code-length alphabet lengths.
const CODE_LENGTH_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Initial output reservation; growth beyond this follows the decoded size.
const INITIAL_CAPACITY: usize = 64 * 1024;

/// One raw DEFLATE decode, keeping the bytes produced before a failure.
pub(crate) struct Outcome {
    /// Bytes decoded before the stream completed or stopped.
    pub(crate) output: Vec<u8>,
    /// Number of input bytes consumed.
    pub(crate) consumed: usize,
    /// Why decoding stopped early, if it did.
    pub(crate) error: Option<InflateError>,
}

/// Decodes one raw DEFLATE stream and returns the partial output on failure.
pub(crate) fn inflate(input: &[u8], limit: usize) -> Outcome {
    let mut state = Inflater { reader: BitReader::new(input), output: Vec::with_capacity(limit.min(INITIAL_CAPACITY)), limit };
    let error = state.blocks().err();
    let consumed = state.reader.consumed_bytes();
    Outcome { output: state.output, consumed, error }
}

/// Decoder state shared by all block types.
struct Inflater<'a> {
    /// Bit-level access to the compressed bytes.
    reader: BitReader<'a>,
    /// Decoded output produced so far.
    output: Vec<u8>,
    /// Maximum number of bytes the caller accepts.
    limit: usize,
}

impl Inflater<'_> {
    /// Decodes blocks until the final one is complete.
    fn blocks(&mut self) -> Result<(), InflateError> {
        loop {
            let last = self.reader.read_bits(1)? == 1;
            match self.reader.read_bits(2)? {
                0 => self.stored_block()?,
                1 => {
                    let (literal, distance) = fixed_tables();
                    self.codes(literal, distance)?;
                }
                2 => self.dynamic_block()?,
                _ => return Err(InflateError::Corrupt("reserved block type")),
            }
            if last {
                return Ok(());
            }
        }
    }

    /// Copies the literal bytes of a stored block.
    fn stored_block(&mut self) -> Result<(), InflateError> {
        self.reader.align_to_byte();
        let length = self.reader.read_bits(16)? as usize;
        let complement = self.reader.read_bits(16)?;
        if !(length as u16) != complement as u16 {
            return Err(InflateError::Corrupt("stored block length check failed"));
        }
        let bytes = self.reader.read_aligned_slice(length)?;
        let take = (self.limit - self.output.len()).min(length);
        self.output.extend_from_slice(&bytes[..take]);
        if take < length {
            return Err(InflateError::LimitExceeded);
        }
        Ok(())
    }

    /// Reads the code description of a dynamic block and decodes its payload.
    fn dynamic_block(&mut self) -> Result<(), InflateError> {
        let literal_count = self.reader.read_bits(5)? as usize + 257;
        let distance_count = self.reader.read_bits(5)? as usize + 1;
        let code_count = self.reader.read_bits(4)? as usize + 4;
        if literal_count > 286 {
            return Err(InflateError::Corrupt("too many literal/length codes"));
        }
        if distance_count > 30 {
            return Err(InflateError::Corrupt("too many distance codes"));
        }

        let mut code_lengths = [0u8; 19];
        for &slot in CODE_LENGTH_ORDER.iter().take(code_count) {
            code_lengths[slot] = self.reader.read_bits(3)? as u8;
        }
        let code_tree = Huffman::for_code_lengths(&code_lengths)?;

        let total = literal_count + distance_count;
        let mut lengths = vec![0u8; total];
        let mut index = 0;
        while index < total {
            let symbol = code_tree.decode(&mut self.reader)?;
            match symbol {
                0..=15 => {
                    lengths[index] = symbol as u8;
                    index += 1;
                }
                16 => {
                    let Some(&previous) = index.checked_sub(1).and_then(|last| lengths.get(last))
                    else {
                        return Err(InflateError::Corrupt("repeat code without a previous length"));
                    };
                    let repeat = 3 + self.reader.read_bits(2)? as usize;
                    self.repeat(&mut lengths, index, repeat, previous)?;
                    index += repeat;
                }
                17 => {
                    let repeat = 3 + self.reader.read_bits(3)? as usize;
                    self.repeat(&mut lengths, index, repeat, 0)?;
                    index += repeat;
                }
                18 => {
                    let repeat = 11 + self.reader.read_bits(7)? as usize;
                    self.repeat(&mut lengths, index, repeat, 0)?;
                    index += repeat;
                }
                _ => return Err(InflateError::Corrupt("invalid code length symbol")),
            }
        }

        let (literal_lengths, distance_lengths) = lengths.split_at(literal_count);
        let literal = Huffman::for_literal_length(literal_lengths)?;
        let distance = Huffman::for_distance(distance_lengths)?;
        self.codes(&literal, &distance)
    }

    /// Fills `count` code lengths of the table starting at `index`.
    fn repeat(&self, lengths: &mut [u8], index: usize, count: usize, value: u8) -> Result<(), InflateError> {
        let end = index.checked_add(count).ok_or(InflateError::Corrupt("code length repeat overflows the table"))?;
        let slots = lengths.get_mut(index..end).ok_or(InflateError::Corrupt("code length repeat overflows the table"))?;
        slots.fill(value);
        Ok(())
    }

    /// Decodes literal/length and distance symbols until the end-of-block code.
    fn codes(&mut self, literal: &Huffman, distance: &Huffman) -> Result<(), InflateError> {
        loop {
            let symbol = literal.decode(&mut self.reader)?;
            match symbol {
                0..=255 => {
                    if self.output.len() >= self.limit {
                        return Err(InflateError::LimitExceeded);
                    }
                    self.output.push(symbol as u8);
                }
                256 => return Ok(()),
                257..=285 => {
                    let slot = usize::from(symbol - 257);
                    let length =
                        usize::from(LENGTH_BASE[slot]) + self.reader.read_bits(u32::from(LENGTH_EXTRA[slot]))? as usize;
                    let distance_symbol = distance.decode(&mut self.reader)?;
                    if distance_symbol > 29 {
                        return Err(InflateError::Corrupt("reserved distance symbol"));
                    }
                    let slot = usize::from(distance_symbol);
                    let back =
                        usize::from(DISTANCE_BASE[slot]) + self.reader.read_bits(u32::from(DISTANCE_EXTRA[slot]))? as usize;
                    self.copy_match(back, length)?;
                }
                _ => return Err(InflateError::Corrupt("reserved literal/length symbol")),
            }
        }
    }

    /// Copies `length` bytes starting `back` bytes before the current end.
    ///
    /// The copy advances one byte at a time so overlapping distances repeat the
    /// pattern they point at, as DEFLATE requires.
    fn copy_match(&mut self, back: usize, length: usize) -> Result<(), InflateError> {
        if back == 0 || back > self.output.len() {
            return Err(InflateError::Corrupt("distance beyond the start of the output"));
        }
        let start = self.output.len() - back;
        let take = (self.limit - self.output.len()).min(length);
        for offset in 0..take {
            let byte = self.output[start + offset];
            self.output.push(byte);
        }
        if take < length {
            return Err(InflateError::LimitExceeded);
        }
        Ok(())
    }
}

/// Returns the fixed Huffman tables shared by every fixed block.
fn fixed_tables() -> &'static (Huffman, Huffman) {
    static TABLES: OnceLock<(Huffman, Huffman)> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut literal_lengths = [0u8; 288];
        for (value, length) in literal_lengths.iter_mut().enumerate() {
            *length = match value {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let literal = Huffman::for_literal_length(&literal_lengths).expect("fixed literal/length code is valid");
        let distance = Huffman::for_distance(&[5; 32]).expect("fixed distance code is valid");
        (literal, distance)
    })
}
