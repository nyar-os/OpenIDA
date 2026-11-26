//! The dyld export trie of a Mach-O image, decoded from `LC_DYLD_INFO` or
//! `LC_DYLD_EXPORTS_TRIE`.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::parse_macho;
use serde::{Deserialize, Serialize};

use super::{
    HEADER32_SIZE, HEADER64_SIZE, LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY,
    util::{Reader, fat_header, read_uleb},
};
use crate::{IdaError, Result};

const MAX_EXPORTS: usize = 512;
const MAX_EXPORT_NODES: usize = 8192;
const MAX_EXPORT_DEPTH: usize = 64;

/// One symbol decoded from the dyld export trie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOExport {
    /// Accumulated symbol name.
    pub name: String,
    /// Raw export flags.
    pub flags: u64,
    /// Flag names: `WEAK`, `REEXPORT`, `STUB_AND_RESOLVER`.
    pub flag_names: Vec<String>,
    /// Symbol address for regular exports.
    pub address: Option<u64>,
    /// Library ordinal for reexports or stub address for stub-and-resolver.
    pub other: Option<u64>,
}

/// Bounded listing of symbols from the dyld export trie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOExportsReport {
    /// Whether the image carries an export trie.
    pub present: bool,
    /// Decoded exports in trie order.
    pub exports: Vec<MachOExport>,
    /// Entries found before the storage limit.
    pub total: usize,
    /// Whether the limit or a malformed node cut the walk.
    pub truncated: bool,
}

/// Decodes the dyld export trie of one session.
pub fn exports(session: &BinarySession) -> Result<MachOExportsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O exports require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut trie = None;
    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4))
        else {
            break;
        };
        if size < 8 {
            break;
        }
        match command {
            LC_DYLD_EXPORTS_TRIE if size >= 16 => {
                trie = match (reader.u32(offset + 8), reader.u32(offset + 12)) {
                    (Some(data_offset), Some(data_size)) => Some((data_offset, data_size)),
                    _ => None,
                };
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY if size >= 48 => {
                trie = match (reader.u32(offset + 40), reader.u32(offset + 44)) {
                    (Some(data_offset), Some(data_size)) if data_size > 0 => Some((data_offset, data_size)),
                    _ => None,
                };
            }
            _ => {}
        }
        if trie.is_some() {
            break;
        }
        offset = offset.saturating_add(u64::from(size));
    }

    if trie.is_none() {
        return Ok(MachOExportsReport { present: false, exports: Vec::new(), total: 0, truncated: false });
    }
    let (data_offset, data_size) = trie.unwrap();
    let data = reader.slice(u64::from(data_offset), u64::from(data_size)).unwrap_or(&[]);

    let mut report = MachOExportsReport { present: true, exports: Vec::new(), total: 0, truncated: false };
    let mut nodes = 0usize;
    let mut stack = vec![(0usize, String::new(), 0usize)];
    while let Some((node, prefix, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_EXPORT_NODES || depth > MAX_EXPORT_DEPTH || report.exports.len() >= MAX_EXPORTS {
            report.truncated = true;
            continue;
        }
        let Some((terminal_size, terminal_start)) = read_uleb(data, node)
        else {
            report.truncated = true;
            continue;
        };
        let child_start = terminal_start.saturating_add(terminal_size as usize);
        if terminal_size > 0 {
            let Some((flags, next)) = read_uleb(data, terminal_start)
            else {
                report.truncated = true;
                continue;
            };
            let mut cursor = next;
            let address = if flags & 0x02 != 0 || flags & 0x04 != 0 {
                None
            }
            else {
                match read_uleb(data, cursor) {
                    Some((address, next)) => {
                        cursor = next;
                        Some(address)
                    }
                    None => {
                        report.truncated = true;
                        continue;
                    }
                }
            };
            let other = if flags & 0x02 != 0 || flags & 0x04 != 0 {
                match read_uleb(data, cursor) {
                    Some((other, _)) => Some(other),
                    None => {
                        report.truncated = true;
                        continue;
                    }
                }
            }
            else {
                None
            };
            report.total += 1;
            if report.exports.len() < MAX_EXPORTS {
                report.exports.push(MachOExport {
                    name: prefix.clone(),
                    flags,
                    flag_names: export_flag_names(flags),
                    address,
                    other,
                });
            }
            else {
                report.truncated = true;
            }
        }
        let Some(children) = data.get(child_start)
        else {
            report.truncated = true;
            continue;
        };
        let mut position = child_start + 1;
        let mut pending = Vec::new();
        for _ in 0..*children {
            let Some(end) = data.get(position..).and_then(|rest| rest.iter().position(|byte| *byte == 0))
            else {
                report.truncated = true;
                break;
            };
            let edge = String::from_utf8_lossy(&data[position..position + end]).into_owned();
            position += end + 1;
            let Some((child, next)) = read_uleb(data, position)
            else {
                report.truncated = true;
                break;
            };
            position = next;
            pending.push((child as usize, format!("{prefix}{edge}"), depth + 1));
        }
        pending.reverse();
        stack.extend(pending);
    }
    report.truncated |= report.total > report.exports.len();
    Ok(report)
}

fn export_flag_names(flags: u64) -> Vec<String> {
    const NAMES: [(u64, &str); 3] = [(0x01, "WEAK"), (0x02, "REEXPORT"), (0x04, "STUB_AND_RESOLVER")];
    NAMES.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, name)| (*name).to_string()).collect()
}
