//! Extraction workflows.
//!
//! [`dump`] exports one byte range, [`carve`] extracts the printable region
//! around markers, [`inflate`] decodes one compressed stream, [`tauri`]
//! recovers the embedded assets of a Tauri v2 container and [`unpack`] routes
//! one container verb across `7z`, `asar`, `NSIS` and PyInstaller. Each one
//! writes only to caller-chosen paths and reuses the adapter facts.

pub(crate) mod carve;
pub(crate) mod dump;
pub(crate) mod inflate;
pub(crate) mod tauri;
pub(crate) mod unpack;
