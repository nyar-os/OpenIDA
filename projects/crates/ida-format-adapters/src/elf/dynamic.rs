//! ELF dynamic dependency projection.
//!
//! `PT_INTERP`, `DT_NEEDED`, `DT_SONAME`, `DT_RPATH` / `DT_RUNPATH` and the
//! string-table mapping are owned by `data-binary-pe::elf` (`read_dynamic`).
//! This module maps the owner type into the product JSON shape.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::elf;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Dynamic linking facts of one ELF image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfDynamicReport {
    /// Whether a `PT_DYNAMIC` segment exists.
    pub present: bool,
    /// `PT_INTERP` program interpreter, when the segment exists.
    pub interpreter: Option<String>,
    /// `DT_SONAME` of the image, when set.
    pub soname: Option<String>,
    /// `DT_NEEDED` library names, in dynamic entry order.
    pub needed: Vec<String>,
    /// Entries of `DT_RPATH`, split on `:`.
    pub rpath: Vec<String>,
    /// Entries of `DT_RUNPATH`, split on `:`.
    pub runpath: Vec<String>,
    /// `DT_*` entries read before `DT_NULL`.
    pub dynamic_entries: usize,
    /// Whether a limit cut the listing.
    pub truncated: bool,
}

/// Decodes the ELF dynamic dependencies of one session.
pub fn analyze(session: &BinarySession) -> Result<ElfDynamicReport> {
    if session.format() != BinaryFormat::Elf {
        return Err(IdaError::unsupported("ELF dynamic dependencies require an ELF container"));
    }
    let bytes = session.read(0, session.size())?;
    let dynamic = elf::read_dynamic(bytes).map_err(|error| IdaError::parse(format!("ELF: {error}")))?;

    Ok(ElfDynamicReport {
        present: dynamic.present,
        interpreter: dynamic.interpreter,
        soname: dynamic.soname,
        needed: dynamic.needed,
        rpath: dynamic.rpath,
        runpath: dynamic.runpath,
        dynamic_entries: dynamic.dynamic_entries,
        truncated: dynamic.truncated,
    })
}
