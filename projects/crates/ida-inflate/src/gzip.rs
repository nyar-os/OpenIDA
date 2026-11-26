//! gzip (RFC 1952) header parsing.

use crate::{InflateError, checksum::crc32};

/// Fixed gzip header length before the optional fields.
const BASE_HEADER: usize = 10;

/// Flag bit announcing an extra field.
const FLAG_EXTRA: u8 = 0x04;

/// Flag bit announcing a zero-terminated file name.
const FLAG_NAME: u8 = 0x08;

/// Flag bit announcing a zero-terminated comment.
const FLAG_COMMENT: u8 = 0x10;

/// Flag bit announcing a two-byte header checksum.
const FLAG_HEADER_CRC: u8 = 0x02;

/// Parses the header and returns the offset of the DEFLATE payload.
///
/// The optional extra field, file name, comment and header checksum are all
/// validated, so a mismatch is reported before any payload is decoded.
pub(crate) fn header_len(input: &[u8]) -> Result<usize, InflateError> {
    if input.len() < 2 {
        return Err(InflateError::Truncated);
    }
    if input[0] != 0x1f || input[1] != 0x8b {
        return Err(InflateError::Corrupt("not a gzip stream"));
    }
    if input.len() < BASE_HEADER {
        return Err(InflateError::Truncated);
    }
    if input[2] != 8 {
        return Err(InflateError::Corrupt("unsupported gzip compression method"));
    }
    let flags = input[3];
    if flags & 0xe0 != 0 {
        return Err(InflateError::Corrupt("reserved gzip header flags are set"));
    }

    let mut offset = BASE_HEADER;
    if flags & FLAG_EXTRA != 0 {
        let field = input.get(offset..offset + 2).ok_or(InflateError::Truncated)?;
        let extra = usize::from(u16::from_le_bytes([field[0], field[1]]));
        offset = offset.checked_add(2 + extra).ok_or(InflateError::Corrupt("gzip extra field length overflows"))?;
        if offset > input.len() {
            return Err(InflateError::Truncated);
        }
    }
    if flags & FLAG_NAME != 0 {
        offset = skip_c_string(input, offset)?;
    }
    if flags & FLAG_COMMENT != 0 {
        offset = skip_c_string(input, offset)?;
    }
    if flags & FLAG_HEADER_CRC != 0 {
        let field = input.get(offset..offset + 2).ok_or(InflateError::Truncated)?;
        let stored = u16::from_le_bytes([field[0], field[1]]);
        let computed = (crc32(&input[..offset]) & 0xffff) as u16;
        if stored != computed {
            return Err(InflateError::Corrupt("gzip header checksum mismatch"));
        }
        offset += 2;
    }
    Ok(offset)
}

/// Advances past a zero-terminated header string.
fn skip_c_string(input: &[u8], mut offset: usize) -> Result<usize, InflateError> {
    while let Some(&byte) = input.get(offset) {
        if byte == 0 {
            return Ok(offset + 1);
        }
        offset += 1;
    }
    Err(InflateError::Truncated)
}
