//! The RFC 7932 static dictionary and its word transforms.
//!
//! The 122784-byte blob in `resources/dictionary.bin` is the static dictionary
//! defined by RFC 7932. It was extracted verbatim from the MIT-licensed
//! `brotli-decompressor` 5.0.3 sources (`src/dictionary/mod.rs`), where it is
//! stored as a byte array. No code from that crate is used at runtime.

use crate::{
    BrotliError,
    tables::{PREFIX_SUFFIX, TRANSFORMS},
};

/// Raw static dictionary data.
const DICTIONARY: &[u8; 122784] = include_bytes!("../resources/dictionary.bin");

/// Start offset of the words of each length inside [`DICTIONARY`].
const OFFSETS_BY_LENGTH: [u32; 25] = [
    0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864, 104704, 106752, 108928, 113536,
    115968, 118528, 119872, 121280, 122016,
];

/// Number of index bits for the words of each length.
const SIZE_BITS_BY_LENGTH: [u8; 25] = [0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5];

/// Shortest word that can be referenced from the static dictionary.
pub(crate) const MIN_WORD_LENGTH: usize = 4;

/// Longest word that can be referenced from the static dictionary.
pub(crate) const MAX_WORD_LENGTH: usize = 24;

/// Looks up and transforms one dictionary word.
///
/// `word_id` encodes both the word index and the transform; the transform
/// identifier occupies the high bits above the per-length index width. Returns
/// [`BrotliError::Corrupt`] when the length or index is outside the dictionary.
pub fn word(length: usize, word_id: u32) -> Result<Vec<u8>, BrotliError> {
    if !(MIN_WORD_LENGTH..=MAX_WORD_LENGTH).contains(&length) {
        return Err(BrotliError::Corrupt("dictionary reference with bad length"));
    }
    let shift = u32::from(SIZE_BITS_BY_LENGTH[length]);
    let index = (word_id & ((1u32 << shift) - 1)) as usize;
    let transform = (word_id >> shift) as usize;
    if transform >= TRANSFORMS.len() {
        return Err(BrotliError::Corrupt("dictionary transform out of range"));
    }
    let offset = OFFSETS_BY_LENGTH[length] as usize + index * length;
    let end = offset + length;
    if end > DICTIONARY.len() {
        return Err(BrotliError::Corrupt("dictionary index out of range"));
    }
    apply_transform(transform, &DICTIONARY[offset..end])
}

/// Applies the transform `transform_id` to `word`.
///
/// Returns [`BrotliError::Corrupt`] when `transform_id` is not one of the 121
/// transforms defined by RFC 7932.
pub fn apply_transform(transform_id: usize, word: &[u8]) -> Result<Vec<u8>, BrotliError> {
    if transform_id >= TRANSFORMS.len() {
        return Err(BrotliError::Corrupt("dictionary transform out of range"));
    }
    let transform = TRANSFORMS[transform_id];
    let operation = transform.transform;
    let mut out = Vec::with_capacity(word.len() + 8);
    push_prefix_suffix(&mut out, transform.prefix_id);

    // Operations 12..=20 drop the first (operation - 11) bytes.
    let skip = if operation >= 12 { usize::from(operation - 11).min(word.len()) } else { 0 };
    let mut body = &word[skip..];
    // Operations 1..=9 drop that many trailing bytes.
    if operation <= 9 {
        body = &body[..body.len().saturating_sub(usize::from(operation))];
    }
    let start = out.len();
    out.extend_from_slice(body);
    match operation {
        // 10: uppercase the first character only.
        10 => uppercase_first(&mut out[start..]),
        // 11: uppercase every character.
        11 => uppercase_all(&mut out[start..]),
        _ => {}
    }
    push_prefix_suffix(&mut out, transform.suffix_id);
    Ok(out)
}

/// Appends the NUL-terminated prefix or suffix string starting at `offset`.
fn push_prefix_suffix(out: &mut Vec<u8>, offset: u8) {
    let mut index = usize::from(offset);
    while let Some(&byte) = PREFIX_SUFFIX.get(index) {
        if byte == 0 {
            break;
        }
        out.push(byte);
        index += 1;
    }
}

/// Uppercases the first character, using the simplified UTF-8 model of the spec.
fn uppercase_first(data: &mut [u8]) {
    uppercase_step(data);
}

/// Uppercases every character, using the simplified UTF-8 model of the spec.
fn uppercase_all(data: &mut [u8]) {
    let mut offset = 0;
    while offset < data.len() {
        offset += uppercase_step(&mut data[offset..]);
    }
}

/// Uppercases one character and returns its encoded length in bytes.
fn uppercase_step(data: &mut [u8]) -> usize {
    if data.is_empty() {
        return 1;
    }
    let first = data[0];
    if first < 0xc0 {
        if first.is_ascii_lowercase() {
            data[0] ^= 0x20;
        }
        1
    }
    else if first < 0xe0 {
        if let Some(second) = data.get_mut(1) {
            *second ^= 0x20;
        }
        2
    }
    else {
        if let Some(third) = data.get_mut(2) {
            *third ^= 5;
        }
        3
    }
}
