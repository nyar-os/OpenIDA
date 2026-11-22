//! Shannon entropy per section and for the whole file, plus the `PE` overlay.
//!
//! Entropy is computed from exact byte counts and only rounded when it is
//! reported. The overlay starts after the highest section raw end; a file with
//! no trailing bytes reports no overlay at all.

use data_binary_inspect::{BinaryFormat, BinarySession};
use serde::{Deserialize, Serialize};

use crate::Result;

/// Decimal places kept in reported entropy values.
const ENTROPY_SCALE: f64 = 10_000.0;

/// Entropy of one section payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionEntropy {
    /// Section name as stored in the container.
    pub name: String,
    /// Raw file offset of the section payload.
    pub offset: u64,
    /// Declared raw size in bytes.
    pub size: u64,
    /// Shannon entropy in bits per byte.
    pub entropy: f64,
}

/// Bytes that follow the last section payload of a `PE` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlayInfo {
    /// File offset where the overlay starts.
    pub offset: u64,
    /// Overlay length in bytes.
    pub size: u64,
}

/// Entropy summary of one binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntropyReport {
    /// File size in bytes.
    pub file_size: u64,
    /// Shannon entropy of the whole file in bits per byte.
    pub file_entropy: f64,
    /// Per-section entropy; empty when sections are unavailable.
    pub sections: Vec<SectionEntropy>,
    /// `PE` overlay, or `None` when there are no trailing bytes.
    pub overlay: Option<OverlayInfo>,
}

/// Summarizes one open session.
pub(crate) fn analyze(session: &BinarySession) -> Result<EntropyReport> {
    let file_size = session.size();
    let bytes = session.read(0, file_size)?;

    let sections = match session.format() {
        BinaryFormat::Pe | BinaryFormat::Elf => {
            let mut sections = Vec::new();
            for section in session.sections()? {
                let start = section.raw_pointer.min(file_size) as usize;
                let end = section.raw_pointer.saturating_add(section.raw_size).min(file_size) as usize;
                sections.push(SectionEntropy {
                    name: section.name,
                    offset: section.raw_pointer,
                    size: section.raw_size,
                    entropy: shannon(&bytes[start..end]),
                });
            }
            sections
        }
        _ => Vec::new(),
    };

    let overlay = if session.format() == BinaryFormat::Pe {
        sections
            .iter()
            .map(|section| section.offset.saturating_add(section.size))
            .max()
            .and_then(|end| (file_size > end).then_some(OverlayInfo { offset: end, size: file_size - end }))
    }
    else {
        None
    };

    Ok(EntropyReport { file_size, file_entropy: shannon(bytes), sections, overlay })
}

fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    let entropy = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total;
            -probability * probability.log2()
        })
        .sum::<f64>();
    (entropy * ENTROPY_SCALE).round() / ENTROPY_SCALE
}
