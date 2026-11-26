//! ELF note projection.
//!
//! GNU build ids, ABI tags and GNU properties live in `PT_NOTE` segments, or in
//! `SHT_NOTE` sections when the program headers were stripped. The walk is
//! owned by `data-binary-pe::elf` (`read_notes`); this module keeps the product
//! JSON shape.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::elf;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Decoded `NT_GNU_ABI_TAG` description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfAbiTag {
    /// Target operating system recorded by the tag.
    pub os: String,
    /// Major kernel version.
    pub major: u32,
    /// Minor kernel version.
    pub minor: u32,
    /// Sub-minor kernel version.
    pub subminor: u32,
}

/// One entry of a `NT_GNU_PROPERTY_TYPE_0` note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfGnuProperty {
    /// Stable property name, or `0x<type>` for an unknown value.
    pub property_type: String,
    /// Declared size of this property's data.
    pub data_size: u32,
    /// Property data as lowercase hex, bounded by the preview limit.
    pub data: String,
}

/// One note record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfNote {
    /// Note owner without its NUL terminator, such as `GNU`.
    pub owner: String,
    /// Stable note type name, or `type <n>` for an unknown value.
    pub note_type: String,
    /// Declared description size in bytes.
    pub description_size: u32,
    /// Decoded description: build id hex, ABI tag version, property count or a
    /// bounded hex preview.
    pub description: String,
}

/// ELF note facts of one image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfNotesReport {
    /// Whether at least one note region exists.
    pub present: bool,
    /// Where the notes were read from: `segments` or `sections`.
    pub source: Option<String>,
    /// `NT_GNU_BUILD_ID` as lowercase hex, when present.
    pub build_id: Option<String>,
    /// Decoded `NT_GNU_ABI_TAG`, when present.
    pub abi_tag: Option<ElfAbiTag>,
    /// Entries of the first `NT_GNU_PROPERTY_TYPE_0` note.
    pub properties: Vec<ElfGnuProperty>,
    /// Notes that survived the listing limit, in file order.
    pub notes: Vec<ElfNote>,
    /// Number of notes read before the limit was applied.
    pub total: usize,
    /// Whether a limit or a malformed record cut the listing.
    pub truncated: bool,
}

/// Decodes the ELF notes of one session.
pub fn analyze(session: &BinarySession) -> Result<ElfNotesReport> {
    if session.format() != BinaryFormat::Elf {
        return Err(IdaError::unsupported("ELF notes require an ELF container"));
    }
    let bytes = session.read(0, session.size())?;
    let notes = elf::read_notes(bytes).map_err(|error| IdaError::parse(format!("ELF: {error}")))?;

    Ok(ElfNotesReport {
        present: notes.present,
        source: notes.source.map(|source| source.as_str().to_string()),
        build_id: notes.build_id,
        abi_tag: notes.abi_tag.map(|tag| ElfAbiTag { os: tag.os, major: tag.major, minor: tag.minor, subminor: tag.subminor }),
        properties: notes
            .properties
            .into_iter()
            .map(|property| ElfGnuProperty {
                property_type: property.property_type,
                data_size: property.data_size,
                data: property.data,
            })
            .collect(),
        notes: notes
            .notes
            .into_iter()
            .map(|note| ElfNote {
                owner: note.owner,
                note_type: note.note_type,
                description_size: note.description_size,
                description: note.description,
            })
            .collect(),
        total: notes.total,
        truncated: notes.truncated,
    })
}
