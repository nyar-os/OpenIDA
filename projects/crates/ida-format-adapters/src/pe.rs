//! `PE` format projections.
//!
//! Every module is a thin projection over the `data-binary-pe` header and
//! section facts. The debug directory is owned upstream
//! (`pe::read_debug_directory`); version resources, resources, relocations,
//! exception runtime functions, delay/bound imports, the Rich header, the
//! attribute certificate table, TLS and the load configuration are still
//! decoded from the same image here.

pub mod bound_imports;
pub mod certificates;
pub mod debug;
pub mod delay_imports;
pub mod exception;
pub mod load_config;
pub mod mitigations;
pub mod relocations;
pub mod resources;
pub mod rich_header;
pub mod tls;
pub mod version;
