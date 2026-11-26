//! Tauri v2 embedded-asset extraction.
//!
//! Tauri v2 compiles its frontend into the executable as an `EmbeddedAssets`
//! map whose values are standalone brotli streams. The interleaved
//! `(key, blob)` walk, the brotli validation and the extraction are owned by
//! `data-binary-container::tauri`. This workflow keeps the PE container check
//! and the product report names.

use data_binary_inspect::{BinaryFormat, BinarySession};

use crate::{IdaError, Result};

pub use data_binary_container::tauri::{TauriAsset, TauriAssetsOptions, TauriAssetsReport};

/// Finds the longest interleaved `(key, blob)` run and decodes its assets.
pub fn scan_assets(
    data: &[u8],
    resolve_va: &dyn Fn(u64) -> Option<usize>,
    options: &TauriAssetsOptions,
) -> Result<TauriAssetsReport> {
    data_binary_container::tauri::scan_assets(data, resolve_va, options).map_err(IdaError::from)
}

/// Extracts the embedded assets of a Tauri v2 PE container.
pub fn tauri_assets(session: &BinarySession, options: &TauriAssetsOptions) -> Result<TauriAssetsReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::parse("Tauri assets require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    data_binary_container::tauri::analyze(bytes, options).map_err(IdaError::from)
}
