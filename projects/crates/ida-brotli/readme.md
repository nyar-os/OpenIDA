# ida-brotli

Bounded Brotli (RFC 7932) stream decoding, implemented from scratch with `std`
only. One complete stream is read from the start of the input, so trailing
bytes are ignored.

## Usage

```rust
use ida_brotli::decompress;

let plain = decompress(compressed, 8 * 1024 * 1024)?;
```

## API

- `decompress(input: &[u8], limit: usize) -> Result<Vec<u8>, BrotliError>`
- `word(length: usize, word_id: u32) -> Result<Vec<u8>, BrotliError>`
- `apply_transform(transform_id: usize, word: &[u8]) -> Result<Vec<u8>, BrotliError>`
- `BrotliError` reports `Truncated`, `Corrupt` and `LimitExceeded`.

## Coverage

Window sizes 10 to 24, uncompressed and compressed meta-blocks, block switching
for literals, commands and distances, all four context modes, distance
postfix/direct codes, the full 704-symbol command table, and static dictionary
references with their word transforms. Output never exceeds the caller's
`limit`, and a window size outside 10 to 24 is rejected as corrupt.

## License

This crate is licensed under `Apache-2.0`, matching the OpenIDA workspace.
