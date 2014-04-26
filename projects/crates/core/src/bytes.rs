//! Bounds-checked little-endian reads.
//!
//! Every read reports `binary/parse` instead of panicking, so a truncated or
//! hostile file degrades into a typed failure.

use crate::error::{IdaError, Result};

/// Reads a little-endian `u16` at `offset`.
pub(crate) fn u16_at(bytes: &[u8], offset: u64) -> Result<u16> {
    let span = span(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([span[0], span[1]]))
}

/// Reads a little-endian `u32` at `offset`.
pub(crate) fn u32_at(bytes: &[u8], offset: u64) -> Result<u32> {
    let span = span(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([span[0], span[1], span[2], span[3]]))
}

/// Reads a little-endian `u64` at `offset`.
pub(crate) fn u64_at(bytes: &[u8], offset: u64) -> Result<u64> {
    let span = span(bytes, offset, 8)?;
    Ok(u64::from_le_bytes([span[0], span[1], span[2], span[3], span[4], span[5], span[6], span[7]]))
}

/// Reads a big-endian `u32` at `offset`.
pub(crate) fn u32_be_at(bytes: &[u8], offset: u64) -> Result<u32> {
    let span = span(bytes, offset, 4)?;
    Ok(u32::from_be_bytes([span[0], span[1], span[2], span[3]]))
}

/// Returns `len` bytes at `offset`, or `binary/parse` when the file is shorter.
pub(crate) fn span(bytes: &[u8], offset: u64, len: usize) -> Result<&[u8]> {
    let end = offset.checked_add(len as u64).ok_or_else(|| IdaError::parse("offset overflow"))?;
    if end > bytes.len() as u64 {
        let available = (bytes.len() as u64).saturating_sub(offset.min(bytes.len() as u64));
        return Err(IdaError::parse(format!("truncated read at 0x{offset:x}: need {len} byte(s), file has {available}")));
    }
    Ok(&bytes[offset as usize..end as usize])
}

/// Reads a NUL-terminated name inside a bounded window.
pub(crate) fn name_at(bytes: &[u8], offset: usize, limit: usize) -> String {
    if offset >= limit || offset >= bytes.len() {
        return String::new();
    }
    let end = limit.min(bytes.len());
    let slice = &bytes[offset..end];
    let length = slice.iter().position(|byte| *byte == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..length]).trim().to_string()
}
