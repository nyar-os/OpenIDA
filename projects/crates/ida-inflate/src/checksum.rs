//! Checksums required by the zlib and gzip wrappers.

/// Polynomial used by the reflected CRC-32 of gzip and PNG.
const CRC32_POLYNOMIAL: u32 = 0xedb8_8320;

/// Largest input block whose Adler-32 partial sums cannot overflow.
const ADLER_CHUNK: usize = 5552;

/// Precomputed CRC-32 lookup table.
const CRC32_TABLE: [u32; 256] = build_crc32_table();

/// Builds the reflected CRC-32 table at compile time.
const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut byte = 0;
    while byte < 256 {
        let mut value = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 { CRC32_POLYNOMIAL ^ (value >> 1) } else { value >> 1 };
            bit += 1;
        }
        table[byte] = value;
        byte += 1;
    }
    table
}

/// Computes the Adler-32 checksum used by zlib (RFC 1950).
pub(crate) fn adler32(data: &[u8]) -> u32 {
    const MODULUS: u32 = 65521;
    let mut low: u32 = 1;
    let mut high: u32 = 0;
    for chunk in data.chunks(ADLER_CHUNK) {
        for &byte in chunk {
            low += u32::from(byte);
            high += low;
        }
        low %= MODULUS;
        high %= MODULUS;
    }
    (high << 16) | low
}

/// Computes the CRC-32 checksum used by gzip (RFC 1952).
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc = CRC32_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}
