//! PyInstaller `CArchive` / `PYZ` projection.
//!
//! The cookie, the TOC and the nested `PYZ` module table are owned by
//! `data-binary-container::pyinstaller`. This module keeps the session-facing
//! entry points, the product report names and the error type.

use data_binary_inspect::BinarySession;

use crate::{IdaError, Result};

pub use data_binary_container::pyinstaller::{
    PyInstallerEntry, PyInstallerModule, PyInstallerOptions, PyInstallerReport, looks_like_pyz,
};

/// Size of the trailing window that the cookie scan reads.
const COOKIE_WINDOW: u64 = 1024;

/// Locates the PyInstaller cookie in the final kilobyte of an open session.
pub fn locate_cookie(session: &BinarySession) -> Result<Option<u64>> {
    let size = session.size();
    if size < 28 {
        return Ok(None);
    }
    let start = size.saturating_sub(COOKIE_WINDOW);
    let bytes = session.read(start, size - start)?;
    Ok(data_binary_container::pyinstaller::locate_cookie(bytes).map(|offset| start + offset))
}

/// Decodes the PyInstaller `CArchive` whose cookie ends the file.
pub fn analyze_carchive(session: &BinarySession, options: &PyInstallerOptions) -> Result<PyInstallerReport> {
    let bytes = session.read(0, session.size())?;
    data_binary_container::pyinstaller::analyze_carchive(bytes, options).map_err(IdaError::from)
}

/// Decodes a standalone PyInstaller `PYZ` archive.
pub fn analyze_pyz(session: &BinarySession, options: &PyInstallerOptions) -> Result<PyInstallerReport> {
    let bytes = session.read(0, session.size())?;
    data_binary_container::pyinstaller::analyze_pyz(bytes, options).map_err(IdaError::from)
}
