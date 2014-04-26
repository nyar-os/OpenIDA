//! One section entry, shared by every container.

use serde::Serialize;

/// A section or segment described by a container header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    /// Section name as stored in the header.
    pub name: String,
    /// Virtual address (RVA for PE, virtual address for ELF).
    pub virtual_address: u64,
    /// Resident size in memory.
    pub virtual_size: u64,
    /// File offset of the section data.
    pub raw_pointer: u64,
    /// Size of the section data on disk.
    pub raw_size: u64,
    /// Container-specific characteristic or flag word.
    pub characteristics: u64,
    /// Whether the flag word grants read access.
    pub readable: bool,
    /// Whether the flag word grants write access.
    pub writable: bool,
    /// Whether the flag word grants execute access.
    pub executable: bool,
}
