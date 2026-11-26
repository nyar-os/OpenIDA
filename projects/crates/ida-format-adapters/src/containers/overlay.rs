//! Anatomy of the bytes that follow the last `PE` section payload.
//!
//! Installers, self-extracting archives and packed loaders keep their real
//! payload in the overlay, so its offset, size, entropy and leading signature
//! are the first facts a triage needs. The report also scans the overlay for the
//! container signatures this tool can name (NSIS, PyInstaller, 7z, ZIP, RAR,
//! CAB, XZ, zstd, bzip2, gzip, SQLite, `ar`, PNG/JPEG/GIF and validated PE
//! images) and stops at a fixed cap instead of returning an unbounded list.

use std::collections::HashMap;

use data_binary_inspect::{BinaryFormat, BinarySession, dump::window, entropy};
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Maximum number of container signatures reported for one overlay.
const MAX_SIGNATURES: usize = 64;

/// Per-kind cap, so one noisy family cannot hide the distinctive containers.
const MAX_PER_KIND: usize = 8;

/// Bytes of the overlay rendered as leading magic.
const MAGIC_BYTES: usize = 16;

/// The PyInstaller `CArchive` cookie that closes a one-file executable.
const PYINSTALLER_COOKIE: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";

/// One container or archive signature found inside the overlay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlaySignature {
    /// Absolute file offset of the signature.
    pub offset: u64,
    /// Short stable kind, such as `nsis`, `pyinstaller`, `zlib` or `zip`.
    pub kind: String,
    /// Optional decoded evidence, such as the Python runtime of a PyInstaller PKG.
    pub detail: Option<String>,
}

/// Anatomy of the bytes that follow the last `PE` section payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlayReport {
    /// Whether the file carries any bytes after the last section payload.
    pub present: bool,
    /// Absolute file offset where the overlay starts.
    pub offset: u64,
    /// Overlay length in bytes.
    pub size: u64,
    /// Overlay size divided by the whole file size, between 0 and 1.
    pub ratio: f64,
    /// Shannon entropy of the overlay in bits per byte.
    pub entropy: f64,
    /// Spaced hex of the first 16 overlay bytes; empty when absent.
    pub leading_magic: String,
    /// Best-effort name of the leading bytes, `none` when absent or `unknown`.
    pub leading_kind: String,
    /// Container named by the overlay evidence, when one was recognised.
    pub container: Option<String>,
    /// Human-readable evidence for `container`.
    pub detail: Option<String>,
    /// Container signatures found inside the overlay, in file-offset order.
    pub signatures: Vec<OverlaySignature>,
    /// Whether the signature scan stopped at the 64-entry cap.
    pub truncated: bool,
}

/// Reports the overlay anatomy of one open `PE` session.
pub fn analyze(session: &BinarySession) -> Result<OverlayReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("the overlay report is implemented for PE files only"));
    }

    let file_size = session.size();
    let end = session
        .sections()?
        .iter()
        .map(|section| section.raw_pointer.saturating_add(section.raw_size))
        .max()
        .unwrap_or(0)
        .min(file_size);

    if end >= file_size {
        return Ok(OverlayReport {
            present: false,
            offset: end,
            size: 0,
            ratio: 0.0,
            entropy: 0.0,
            leading_magic: String::new(),
            leading_kind: "none".to_string(),
            container: None,
            detail: None,
            signatures: Vec::new(),
            truncated: false,
        });
    }

    let all = session.read(0, file_size)?;
    let bytes = window(all, end, Some(file_size - end))?;
    let size = bytes.len() as u64;
    let (leading_kind, leading_detail) = classify_leading(bytes);
    let (signatures, truncated) = scan(bytes, end);

    let container = if let Some(signature) = signatures.iter().find(|entry| entry.kind == "pyinstaller") {
        let detail = signature.detail.clone().unwrap_or_else(|| "PyInstaller PKG cookie".to_string());
        Some(("pyinstaller".to_string(), detail))
    }
    else if let Some(signature) = signatures.iter().find(|entry| entry.kind == "nsis") {
        let detail = signature.detail.clone().unwrap_or_else(|| "NullsoftInst header".to_string());
        Some(("nsis".to_string(), detail))
    }
    else if is_archive(leading_kind) {
        Some((leading_kind.to_string(), format!("{leading_kind} stream at the overlay start")))
    }
    else {
        None
    };

    let (container, detail) = match container {
        Some((name, detail)) => (Some(name), Some(detail)),
        None => (None, leading_detail),
    };

    let ratio = ((size as f64 / file_size as f64) * 1_000_000.0).round() / 1_000_000.0;

    Ok(OverlayReport {
        present: true,
        offset: end,
        size,
        ratio,
        entropy: crate::containers::entropy::reported(entropy::range(bytes, 0, None)?),
        leading_magic: spaced_hex(&bytes[..bytes.len().min(MAGIC_BYTES)]),
        leading_kind: leading_kind.to_string(),
        container,
        detail,
        signatures,
        truncated,
    })
}

/// Names the bytes at the start of the overlay.
fn classify_leading(bytes: &[u8]) -> (&'static str, Option<String>) {
    if is_nsis_first_header(bytes) {
        return ("nsis", nsis_detail(bytes, 8));
    }
    if let Some((kind, _, detail)) = signature_match(bytes, 0) {
        return (kind, detail);
    }
    if looks_like_zlib(bytes) {
        return ("zlib", None);
    }
    ("unknown", None)
}

/// Whether `kind` is an archive that can stand alone as an overlay payload.
fn is_archive(kind: &str) -> bool {
    matches!(kind, "zlib" | "gzip" | "7z" | "zip" | "rar" | "cab" | "xz" | "zstd" | "bzip2" | "ar")
}

/// The `NSIS` first header: four zero flags, `0xDEADBEEF`, then `NullsoftInst`.
fn is_nsis_first_header(bytes: &[u8]) -> bool {
    bytes.len() >= 20
        && bytes[..4] == [0, 0, 0, 0]
        && bytes[4..8] == [0xef, 0xbe, 0xad, 0xde]
        && &bytes[8..20] == b"NullsoftInst"
}

/// Matches one known signature starting at `index`.
fn signature_match(bytes: &[u8], index: usize) -> Option<(&'static str, usize, Option<String>)> {
    let rest = bytes.get(index..)?;
    if rest.starts_with(PYINSTALLER_COOKIE) {
        return Some(("pyinstaller", PYINSTALLER_COOKIE.len(), pyinstaller_detail(bytes, index)));
    }
    if rest.starts_with(b"NullsoftInst") {
        return Some(("nsis", 12, nsis_detail(bytes, index)));
    }
    if rest.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some(("7z", 6, None));
    }
    if rest.starts_with(b"PK\x03\x04") {
        return Some(("zip", 4, None));
    }
    if rest.starts_with(b"PK\x05\x06") {
        return Some(("zip-end", 4, None));
    }
    if rest.starts_with(b"Rar!\x1a\x07") {
        return Some(("rar", 6, None));
    }
    if rest.starts_with(b"MSCF") {
        return Some(("cab", 4, None));
    }
    if rest.starts_with(b"\xfd7zXZ\x00") {
        return Some(("xz", 6, None));
    }
    if rest.starts_with(b"\x28\xb5\x2f\xfd") {
        return Some(("zstd", 4, None));
    }
    if rest.len() >= 4 && rest.starts_with(b"BZh") && (b'1'..=b'9').contains(&rest[3]) {
        return Some(("bzip2", 4, None));
    }
    if rest.starts_with(b"\x1f\x8b\x08") {
        return Some(("gzip", 3, None));
    }
    if rest.starts_with(b"SQLite format 3\x00") {
        return Some(("sqlite", 16, None));
    }
    if rest.starts_with(b"!<arch>\n") {
        return Some(("ar", 8, None));
    }
    if rest.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(("png", 8, None));
    }
    if rest.starts_with(b"GIF87a") || rest.starts_with(b"GIF89a") {
        return Some(("gif", 6, None));
    }
    if rest.starts_with(b"\xff\xd8\xff\xe0") || rest.starts_with(b"\xff\xd8\xff\xe1") {
        return Some(("jpeg", 4, None));
    }
    if rest.starts_with(b"MZ") && has_pe_header(bytes, index) {
        return Some(("pe-image", 2, None));
    }
    None
}

/// Scans the whole overlay once, skipping bytes that cannot start a signature.
fn scan(bytes: &[u8], base: u64) -> (Vec<OverlaySignature>, bool) {
    let mut signatures = Vec::new();
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    let mut index = 0usize;
    let mut truncated = false;

    while index < bytes.len() {
        if !may_start(bytes[index]) {
            index += 1;
            continue;
        }
        match signature_match(bytes, index) {
            Some((kind, length, detail)) => {
                let count = counts.entry(kind).or_insert(0);
                if *count >= MAX_PER_KIND {
                    truncated = true;
                    index += length.max(1);
                    continue;
                }
                if signatures.len() == MAX_SIGNATURES {
                    truncated = true;
                    break;
                }
                *count += 1;
                signatures.push(OverlaySignature { offset: base + index as u64, kind: kind.to_string(), detail });
                index += length.max(1);
            }
            None => index += 1,
        }
    }

    (signatures, truncated)
}

/// First bytes of every known signature, used to keep the scan single-pass.
fn may_start(byte: u8) -> bool {
    matches!(byte, b'M' | b'N' | b'7' | b'P' | b'R' | b'B' | b'S' | b'!' | b'G' | 0xfd | 0x28 | 0x1f | 0x89 | 0xff)
}

/// Whether `MZ` at `index` points at a real `PE\0\0` header.
fn has_pe_header(bytes: &[u8], index: usize) -> bool {
    let Some(header) = bytes.get(index + 0x3c..index + 0x40)
    else {
        return false;
    };
    let offset = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if offset < 0x40 {
        return false;
    }
    bytes.get(index + offset..index + offset + 4).is_some_and(|signature| signature == b"PE\0\0")
}

/// Decodes the NSIS header size field that follows a `NullsoftInst` signature.
fn nsis_detail(bytes: &[u8], signature_start: usize) -> Option<String> {
    let field = bytes.get(signature_start + 12..signature_start + 16)?;
    let size = u32::from_le_bytes([field[0], field[1], field[2], field[3]]);
    Some(format!("NullsoftInst header, header size field {size:#x}"))
}

/// Names the Python runtime recorded after a PyInstaller cookie.
fn pyinstaller_detail(bytes: &[u8], cookie: usize) -> Option<String> {
    let window = bytes.get(cookie..(cookie + 256).min(bytes.len()))?;
    let mut index = 0usize;
    while index + 8 <= window.len() {
        if window[index..].starts_with(b"python3") {
            let mut end = index + 7;
            while end < window.len() && window[end].is_ascii_digit() {
                end += 1;
            }
            if end > index + 7 && window[end..].starts_with(b".dll") {
                let name = String::from_utf8_lossy(&window[index..end + 4]);
                return Some(format!("PyInstaller PKG cookie, runtime {name}"));
            }
        }
        index += 1;
    }
    Some("PyInstaller PKG cookie".to_string())
}

/// Whether the bytes carry a zlib header (deflate, valid check bits).
fn looks_like_zlib(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] & 0x0f == 8 && bytes[0] >> 4 <= 7 && u16::from_be_bytes([bytes[0], bytes[1]]) % 31 == 0
}

/// Renders bytes as lowercase spaced hex.
fn spaced_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
}
