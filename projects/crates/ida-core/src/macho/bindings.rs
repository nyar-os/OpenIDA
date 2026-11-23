//! The classic dyld bind, weak-bind and lazy-bind opcode streams recorded by
//! `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`. The rebase stream is not decoded.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::parse_macho;
use serde::{Deserialize, Serialize};

use super::{
    HEADER32_SIZE, HEADER64_SIZE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_LAZY_LOAD_DYLIB, LC_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB,
    LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
    util::{Reader, fat_header, read_sleb, read_uleb},
};
use crate::{IdaError, Result};

/// One binding decoded from a classic dyld bind opcode stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOBinding {
    /// Stream the binding came from: `bind`, `weak` or `lazy`.
    pub stream: String,
    /// Virtual address of the bound slot.
    pub address: u64,
    /// Name of the segment covering `address`, empty when no segment does.
    pub segment: String,
    /// Trailing symbol name of the last `SET_SYMBOL_TRAILING_FLAGS_IMM`.
    pub symbol: String,
    /// Install name for positive library ordinals; special ordinals render as
    /// `self`, `main-executable`, `flat-lookup`, `weak-lookup` or `special`.
    pub dylib: String,
    /// Bind type from `SET_TYPE_IMM`: `pointer`, `text-abs32`, `text-pcrel32` or raw `0xNN`.
    pub bind_type: String,
    /// Whether the symbol flags carry `BIND_SYMBOL_FLAGS_WEAK_IMPORT`.
    pub weak: bool,
    /// Addend from the last `SET_ADDEND_SLEB`.
    pub addend: i64,
}

/// Bounded listing of the classic dyld bind opcode streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOBindingsReport {
    /// Whether the image carries an `LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY` command.
    pub present: bool,
    /// Bindings that survived the limit.
    pub bindings: Vec<MachOBinding>,
    /// Bindings found before the walk was cut.
    pub total: usize,
    /// Whether the limit, an unsupported opcode or a malformed stream cut the walk.
    pub truncated: bool,
}

/// Upper bound on parsed bindings, so a corrupt stream cannot force a huge allocation.
const MAX_BINDINGS: usize = 512;

const BIND_OPCODE_DONE: u8 = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
const BIND_OPCODE_DO_BIND: u8 = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xa0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xb0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xc0;

const BIND_TYPE_POINTER: u8 = 1;
const BIND_TYPE_TEXT_ABSOLUTE32: u8 = 2;
const BIND_TYPE_TEXT_PCREL32: u8 = 3;

/// Mutable state of one classic bind opcode stream.
#[derive(Debug, Default)]
struct BindState {
    address: u64,
    ordinal: i64,
    flags: u8,
    bind_type: u8,
    addend: i64,
    symbol: String,
}

/// Decodes the classic dyld bind, weak-bind and lazy-bind opcode streams.
pub(crate) fn bindings(session: &BinarySession) -> Result<MachOBindingsReport> {
    let bytes = session.read(0, session.size())?;
    if fat_header(bytes).is_some() {
        return Err(IdaError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(IdaError::unsupported("Mach-O bindings require a Mach-O container"));
    }
    let image = parse_macho(bytes).map_err(|error| IdaError::parse(format!("Mach-O: {error}")))?;
    let reader = Reader { bytes, endian: image.header.endian };

    let header_size = if image.header.is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
    let mut offset = header_size as u64;
    let mut streams = None;
    let mut dylibs = Vec::new();
    for _ in 0..image.header.command_count {
        let (Some(command), Some(size)) = (reader.u32(offset), reader.u32(offset + 4))
        else {
            break;
        };
        if size < 8 {
            break;
        }
        match command {
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY if size >= 48 => {
                streams = match (
                    reader.u32(offset + 16),
                    reader.u32(offset + 20),
                    reader.u32(offset + 24),
                    reader.u32(offset + 28),
                    reader.u32(offset + 32),
                    reader.u32(offset + 36),
                ) {
                    (
                        Some(bind_offset),
                        Some(bind_size),
                        Some(weak_offset),
                        Some(weak_size),
                        Some(lazy_offset),
                        Some(lazy_size),
                    ) => Some((bind_offset, bind_size, weak_offset, weak_size, lazy_offset, lazy_size)),
                    _ => None,
                };
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB
                if size >= 24 =>
            {
                if let Some(dylib) = reader.dylib(offset, size, command) {
                    dylibs.push(dylib.name);
                }
            }
            _ => {}
        }
        offset = offset.saturating_add(u64::from(size));
    }

    let mut report = MachOBindingsReport { present: false, bindings: Vec::new(), total: 0, truncated: false };
    let Some((bind_offset, bind_size, weak_offset, weak_size, lazy_offset, lazy_size)) = streams
    else {
        return Ok(report);
    };
    report.present = true;

    let ptrsize = if image.header.is_64 { 8 } else { 4 };
    let segments =
        image.segments.iter().map(|segment| (segment.name.clone(), segment.vm_address, segment.vm_size)).collect::<Vec<_>>();
    let streams: [(&str, u32, u32); 3] =
        [("bind", bind_offset, bind_size), ("weak", weak_offset, weak_size), ("lazy", lazy_offset, lazy_size)];
    'streams: for (stream, stream_offset, stream_size) in streams {
        if stream_size == 0 {
            continue;
        }
        let Some(data) = reader.slice(u64::from(stream_offset), u64::from(stream_size))
        else {
            report.truncated = true;
            continue;
        };
        let mut state = BindState::default();
        let mut cursor = 0usize;
        loop {
            let Some(opcode) = data.get(cursor).copied()
            else {
                report.truncated = true;
                break;
            };
            cursor += 1;
            let imm = opcode & 0x0f;
            match opcode & 0xf0 {
                BIND_OPCODE_DONE => break,
                BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => state.ordinal = i64::from(imm),
                BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => match read_uleb(data, cursor) {
                    Some((value, next)) => {
                        state.ordinal = value as i64;
                        cursor = next;
                    }
                    None => {
                        report.truncated = true;
                        break;
                    }
                },
                BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                    state.ordinal = if imm & 0x08 != 0 { i64::from(imm) - 16 } else { i64::from(imm) };
                }
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                    state.flags = imm;
                    let Some(rest) = data.get(cursor..)
                    else {
                        report.truncated = true;
                        break;
                    };
                    let Some(end) = rest.iter().position(|byte| *byte == 0)
                    else {
                        report.truncated = true;
                        break;
                    };
                    state.symbol = String::from_utf8_lossy(&rest[..end]).into_owned();
                    cursor += end + 1;
                }
                BIND_OPCODE_SET_TYPE_IMM => state.bind_type = imm,
                BIND_OPCODE_SET_ADDEND_SLEB => match read_sleb(data, cursor) {
                    Some((value, next)) => {
                        state.addend = value;
                        cursor = next;
                    }
                    None => {
                        report.truncated = true;
                        break;
                    }
                },
                BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    let segment = usize::from(imm);
                    match (read_uleb(data, cursor), segments.get(segment)) {
                        (Some((value, next)), Some((_, start, _))) => {
                            state.address = start.saturating_add(value);
                            cursor = next;
                        }
                        _ => {
                            report.truncated = true;
                            break;
                        }
                    }
                }
                BIND_OPCODE_ADD_ADDR_ULEB => match read_uleb(data, cursor) {
                    Some((value, next)) => {
                        state.address = state.address.saturating_add(value);
                        cursor = next;
                    }
                    None => {
                        report.truncated = true;
                        break;
                    }
                },
                BIND_OPCODE_DO_BIND => {
                    let Some(stride) = emit_binding(&mut report, stream, &state, &segments, &dylibs, ptrsize)
                    else {
                        break 'streams;
                    };
                    state.address = state.address.saturating_add(stride);
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                    let Some(stride) = emit_binding(&mut report, stream, &state, &segments, &dylibs, ptrsize)
                    else {
                        break 'streams;
                    };
                    match read_uleb(data, cursor) {
                        Some((value, next)) => {
                            state.address = state.address.saturating_add(stride).saturating_add(value);
                            cursor = next;
                        }
                        None => {
                            report.truncated = true;
                            break;
                        }
                    }
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                    let Some(stride) = emit_binding(&mut report, stream, &state, &segments, &dylibs, ptrsize)
                    else {
                        break 'streams;
                    };
                    state.address = state.address.saturating_add(stride).saturating_add(u64::from(imm).saturating_mul(ptrsize));
                }
                BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                    let (count, next) = match read_uleb(data, cursor) {
                        Some(entry) => entry,
                        None => {
                            report.truncated = true;
                            break;
                        }
                    };
                    let (skipping, next) = match read_uleb(data, next) {
                        Some(entry) => entry,
                        None => {
                            report.truncated = true;
                            break;
                        }
                    };
                    cursor = next;
                    for _ in 0..count {
                        let Some(stride) = emit_binding(&mut report, stream, &state, &segments, &dylibs, ptrsize)
                        else {
                            break 'streams;
                        };
                        state.address = state.address.saturating_add(stride).saturating_add(skipping);
                    }
                }
                // `BIND_OPCODE_DO_BIND_THREADED_TABLE` (0xd0) and unknown opcodes are unsupported.
                _ => {
                    report.truncated = true;
                    break;
                }
            }
        }
    }
    report.truncated |= report.total > report.bindings.len();
    Ok(report)
}

fn emit_binding(
    report: &mut MachOBindingsReport,
    stream: &'static str,
    state: &BindState,
    segments: &[(String, u64, u64)],
    dylibs: &[String],
    ptrsize: u64,
) -> Option<u64> {
    let dylib = bind_dylib_name(state.ordinal, dylibs)?;
    let stride = if matches!(state.bind_type, BIND_TYPE_TEXT_ABSOLUTE32 | BIND_TYPE_TEXT_PCREL32) { 4 } else { ptrsize };
    report.total += 1;
    if report.bindings.len() < MAX_BINDINGS {
        report.bindings.push(MachOBinding {
            stream: stream.to_string(),
            address: state.address,
            segment: binding_segment_name(segments, state.address),
            symbol: state.symbol.clone(),
            dylib,
            bind_type: bind_type_name(state.bind_type),
            weak: state.flags & 0x01 != 0,
            addend: state.addend,
        });
        return Some(stride);
    }
    report.truncated = true;
    None
}

fn bind_dylib_name(ordinal: i64, dylibs: &[String]) -> Option<String> {
    if ordinal > 0 {
        let name = dylibs.get((ordinal - 1) as usize)?;
        return Some(name.clone());
    }
    Some(
        match ordinal {
            0 => "self",
            -1 => "main-executable",
            -2 => "flat-lookup",
            -3 => "weak-lookup",
            _ => "special",
        }
        .to_string(),
    )
}

fn bind_type_name(bind_type: u8) -> String {
    match bind_type {
        BIND_TYPE_POINTER => "pointer".to_string(),
        BIND_TYPE_TEXT_ABSOLUTE32 => "text-abs32".to_string(),
        BIND_TYPE_TEXT_PCREL32 => "text-pcrel32".to_string(),
        _ => format!("0x{bind_type:02x}"),
    }
}

fn binding_segment_name(segments: &[(String, u64, u64)], address: u64) -> String {
    segments
        .iter()
        .find(|(_, start, size)| *size > 0 && address >= *start && address < start.saturating_add(*size))
        .map_or(String::new(), |(name, _, _)| name.clone())
}
