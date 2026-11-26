//! End-to-end decoding tests driven by fixtures produced with Node.js `zlib`.

mod fixtures;

use fixtures::{BINARY, DISTANT, EMPTY, LGWIN10, MIXED, POSTFIXED, REPETITIVE, SHORT_Q0, SHORT_Q5, TEXT, TRUNCATED};
use ida_brotli::{BrotliError, decompress};

const WORDS: [&str; 8] = ["brotli", "static", "dictionary", "compress", "window", "context", "literal", "command"];

const PARAGRAPH: &str = "Brotli is a generic-purpose lossless compression algorithm that compresses data using a combination of a modern variant of the LZ77 algorithm, Huffman coding and second-order context modeling, providing a compression ratio comparable to the best currently available general-purpose compression methods. It is similar in speed with deflate but offers more dense compression. The specification of the Brotli compressed data format does not define the encoder, only the decoder. ";

const VOCABULARY: [&str; 22] = [
    "alpha",
    "beta",
    "gamma",
    "delta",
    "epsilon",
    "zeta",
    "theta",
    "lambda",
    "literal",
    "distance",
    "metablock",
    "huffman",
    "prefix",
    "suffix",
    "window",
    "transform",
    "dictionary",
    "context",
    "command",
    "insert",
    "copy",
    "block",
];

/// Decodes a hex-encoded compressed fixture.
fn compressed(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "odd number of hex digits");
    (0..value.len()).step_by(2).map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex")).collect()
}

fn short_plaintext() -> &'static [u8] {
    b"Hello, Brotli! This is a short ASCII fixture."
}

fn repetitive_plaintext() -> Vec<u8> {
    let mut text = String::new();
    for index in 0..20_000usize {
        text.push_str(WORDS[index % WORDS.len()]);
        text.push(if index % 7 == 0 { '\n' } else { ' ' });
    }
    text.into_bytes()
}

fn binary_plaintext() -> Vec<u8> {
    let mut state: u32 = 0x1234_5678;
    let mut bytes = Vec::with_capacity(5000);
    for _ in 0..5000 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        bytes.push((state >> 24) as u8);
    }
    bytes
}

fn text_plaintext() -> Vec<u8> {
    let mut text = String::new();
    for _ in 0..40 {
        text.push_str(PARAGRAPH);
    }
    text.into_bytes()
}

fn mixed_plaintext() -> Vec<u8> {
    let mut text = String::new();
    let mut seed: u32 = 12_345;
    for index in 0..90_000u32 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        text.push_str(VOCABULARY[(seed % VOCABULARY.len() as u32) as usize]);
        text.push_str(if seed % 11 == 0 { ", " } else { " " });
        if index % 13 == 0 {
            text.push_str(&format!("{}\n", seed % 100_000));
        }
    }
    text.into_bytes()
}

fn distant_plaintext() -> Vec<u8> {
    let mut fragments: Vec<String> = Vec::with_capacity(1200);
    let mut seed: u32 = 999;
    for _ in 0..1200 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        fragments.push(format!(
            "{} {} {} ",
            VOCABULARY[(seed % VOCABULARY.len() as u32) as usize],
            VOCABULARY[((seed >> 8) % VOCABULARY.len() as u32) as usize],
            seed % 99_991
        ));
    }
    let mut text = String::new();
    for index in 0..12_000u32 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        text.push_str(&fragments[(seed % 1200) as usize]);
        if index % 17 == 0 {
            text.push('\n');
        }
    }
    text.into_bytes()
}

fn postfixed_plaintext() -> Vec<u8> {
    let mut buffer = vec![0u8; 400 * 1024];
    let mut seed: u32 = 777;
    for byte in buffer.iter_mut() {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *byte = ((seed >> 16) & 0xff) as u8;
    }
    for block in 1..97usize {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let source = (seed % block as u32) as usize * 4096;
        let start = block * 4096;
        let chunk = buffer[source..source + 4096].to_vec();
        buffer[start..start + 4096].copy_from_slice(&chunk);
    }
    buffer
}

fn windowed_plaintext() -> Vec<u8> {
    let mut text = String::new();
    for index in 0..400usize {
        text.push_str(&format!("line {index}: {} {}\n", WORDS[index % WORDS.len()], index * 7));
    }
    text.into_bytes()
}

#[test]
fn empty_stream_decodes_to_nothing() {
    let output = decompress(&compressed(EMPTY), 0).expect("empty stream");
    assert!(output.is_empty());
}

#[test]
fn missing_input_is_truncated() {
    assert_eq!(decompress(&[], 16), Err(BrotliError::Truncated));
}

#[test]
fn short_ascii_at_quality_zero() {
    let output = decompress(&compressed(SHORT_Q0), 1024).expect("quality 0 stream");
    assert_eq!(output, short_plaintext());
}

#[test]
fn short_ascii_at_quality_five() {
    let output = decompress(&compressed(SHORT_Q5), 1024).expect("quality 5 stream");
    assert_eq!(output, short_plaintext());
}

#[test]
fn repetitive_text_at_quality_eleven() {
    let output = decompress(&compressed(REPETITIVE), 1 << 20).expect("quality 11 stream");
    assert_eq!(output, repetitive_plaintext());
}

#[test]
fn binary_data_at_quality_five() {
    let output = decompress(&compressed(BINARY), 8192).expect("binary stream");
    assert_eq!(output, binary_plaintext());
}

#[test]
fn text_mode_stream_at_quality_eleven() {
    let output = decompress(&compressed(TEXT), 1 << 20).expect("text mode stream");
    assert_eq!(output, text_plaintext());
}

#[test]
fn window_size_ten() {
    let output = decompress(&compressed(LGWIN10), 1 << 20).expect("window 10 stream");
    assert_eq!(output, windowed_plaintext());
}

#[test]
fn mixed_corpus_with_block_switching() {
    let output = decompress(&compressed(MIXED), 4 << 20).expect("mixed corpus");
    assert_eq!(output, mixed_plaintext());
}

#[test]
fn distant_matches_with_large_window() {
    let output = decompress(&compressed(DISTANT), 4 << 20).expect("distant corpus");
    assert_eq!(output, distant_plaintext());
}

#[test]
fn distance_parameter_heavy_stream() {
    let output = decompress(&compressed(POSTFIXED), 4 << 20).expect("postfix corpus");
    assert_eq!(output, postfixed_plaintext());
}

#[test]
fn truncated_stream_reports_truncation() {
    let result = decompress(&compressed(TRUNCATED), 1 << 20);
    assert_eq!(result, Err(BrotliError::Truncated));
}

#[test]
fn corrupt_meta_block_length_is_rejected() {
    // WBITS=16, ISLAST=0, five length nibbles of which the top one is zero.
    let input = [0x04, 0x00, 0x00, 0x00];
    assert_eq!(decompress(&input, 1024), Err(BrotliError::Corrupt("non-canonical meta-block length")));
}

#[test]
fn corrupted_byte_is_rejected() {
    let mut bytes = compressed(REPETITIVE);
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    assert!(decompress(&bytes, 1 << 20).is_err());
}

#[test]
fn limit_smaller_than_output_is_rejected() {
    let expected = short_plaintext();
    let result = decompress(&compressed(SHORT_Q5), expected.len() - 1);
    assert_eq!(result, Err(BrotliError::LimitExceeded));
}

#[test]
fn exact_limit_is_accepted() {
    let expected = short_plaintext();
    let output = decompress(&compressed(SHORT_Q5), expected.len()).expect("exact limit");
    assert_eq!(output, expected);
}

#[test]
fn limit_zero_for_empty_output_is_accepted() {
    assert!(decompress(&compressed(EMPTY), 0).is_ok());
}

#[test]
fn trailing_bytes_are_ignored() {
    let mut bytes = compressed(SHORT_Q5);
    bytes.extend_from_slice(&[0xff; 32]);
    let output = decompress(&bytes, 1024).expect("trailing bytes");
    assert_eq!(output, short_plaintext());
}
