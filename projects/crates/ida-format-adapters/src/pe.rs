//! `PE` format projections.
//!
//! Every module is a thin projection over the `data-binary-pe` facts: the
//! header and section tables plus `read_debug_directory`,
//! `read_version_resources`, `read_resources`, `read_relocations`,
//! `read_exception_directory`, `read_delay_imports`, `read_bound_imports`,
//! `read_rich_header`, `read_certificates`, `read_tls_directory`,
//! `read_load_config` and `read_mitigations`. No PE decoder is kept here.

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
