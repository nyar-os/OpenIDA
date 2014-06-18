//! Shared byte helpers for the Mach-O decoders: an endian-aware [`Reader`],
//! ULEB/SLEB readers and the fat-header probe used by every submodule.

use data_binary_mach_o::mach_o::MachOEndian;

use super::{
    FAT_MAGIC, FAT_MAGIC_64,
    image::{MachODylib, dylib_kind, render_version},
};
use crate::{IdaError, Result};

pub(super) struct Reader<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) endian: MachOEndian,
}

impl Reader<'_> {
    pub(super) fn slice(&self, offset: u64, length: u64) -> Option<&[u8]> {
        let end = offset.checked_add(length)?;
        self.bytes.get(offset as usize..end as usize)
    }

    pub(super) fn u32(&self, offset: u64) -> Option<u32> {
        let raw: [u8; 4] = self.slice(offset, 4)?.try_into().ok()?;
        Some(match self.endian {
            MachOEndian::Little => u32::from_le_bytes(raw),
            MachOEndian::Big => u32::from_be_bytes(raw),
        })
    }

    pub(super) fn u16(&self, offset: u64) -> Option<u16> {
        let raw: [u8; 2] = self.slice(offset, 2)?.try_into().ok()?;
        Some(match self.endian {
            MachOEndian::Little => u16::from_le_bytes(raw),
            MachOEndian::Big => u16::from_be_bytes(raw),
        })
    }

    pub(super) fn u64(&self, offset: u64) -> Option<u64> {
        let raw: [u8; 8] = self.slice(offset, 8)?.try_into().ok()?;
        Some(match self.endian {
            MachOEndian::Little => u64::from_le_bytes(raw),
            MachOEndian::Big => u64::from_be_bytes(raw),
        })
    }

    pub(super) fn uuid(&self, offset: u64) -> Option<String> {
        let raw = self.slice(offset, 16)?;
        let hex = raw.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        Some(format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32]))
    }

    pub(super) fn dylib(&self, offset: u64, size: u32, command: u32) -> Option<MachODylib> {
        let name_offset = self.u32(offset + 8)?;
        let timestamp = self.u32(offset + 12)?;
        let current = self.u32(offset + 16)?;
        let compatibility = self.u32(offset + 20)?;
        let name_start = offset.checked_add(u64::from(name_offset))?;
        let command_end = offset.checked_add(u64::from(size))?;
        if name_start >= command_end {
            return None;
        }
        let raw = self.slice(name_start, command_end - name_start)?;
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        Some(MachODylib {
            kind: dylib_kind(command).to_string(),
            name: String::from_utf8_lossy(&raw[..end]).into_owned(),
            timestamp,
            current_version: render_version(current),
            compatibility_version: render_version(compatibility),
        })
    }
}

pub(super) fn fat_header(bytes: &[u8]) -> Option<(bool, usize)> {
    let head = bytes.get(0..8)?;
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let is_fat64 = match magic {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        _ => return None,
    };
    Some((is_fat64, u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize))
}

pub(super) fn be_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("the fat architecture table is truncated"))?;
    Ok(u32::from_be_bytes(raw))
}

pub(super) fn be_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("the fat architecture table is truncated"))?;
    Ok(u64::from_be_bytes(raw))
}

pub(super) fn read_uleb(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut cursor = offset;
    loop {
        let byte = *data.get(cursor)?;
        cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, cursor));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

pub(super) fn read_sleb(data: &[u8], offset: usize) -> Option<(i64, usize)> {
    let mut value = 0i64;
    let mut shift = 0u32;
    let mut cursor = offset;
    loop {
        let byte = *data.get(cursor)?;
        cursor += 1;
        if shift >= 64 {
            return None;
        }
        value |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if byte & 0x40 != 0 && shift < 64 {
                value |= -1i64 << shift;
            }
            return Some((value, cursor));
        }
    }
}
