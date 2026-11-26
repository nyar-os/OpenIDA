# ida-inflate

Bounded DEFLATE, zlib and gzip decoding. The DEFLATE algorithm (RFC 1951) and
both containers (RFC 1950, RFC 1952) are implemented from scratch with `std`.

## Usage

```rust
use ida_inflate::{decode_zlib, decompress_gzip};

let plain = decompress_gzip(pe_resource, 4 * 1024 * 1024)?;
let partial = decode_zlib(truncated, 4096);
```

## API

- `decompress_raw` / `decompress_zlib` / `decompress_gzip(input: &[u8], limit: usize) -> Result<Vec<u8>, InflateError>`
- `decode_raw` / `decode_zlib` / `decode_gzip(input: &[u8], limit: usize) -> Decoded` keeps the bytes produced before a failure.
- `Decoded { output, status }` pairs partial output with an `InflateStatus` of `Complete`, `NeedsMoreInput`, `OutputLimit`, `Checksum` or `Invalid`.

## Coverage

Stored, fixed-Huffman and dynamic-Huffman blocks. zlib headers are validated,
preset dictionaries are rejected and the Adler-32 trailer is checked. gzip
headers skip or verify the optional extra field, name, comment and header CRC,
and the CRC-32 plus length trailer is verified. Every entry point decodes one
stream from the start of the input and ignores trailing bytes, so decoded
output never exceeds the caller-supplied `limit`.

## License

This crate is licensed under `Apache-2.0`, matching the OpenIDA workspace.
