//! Operation bodies behind the exported Node-API entry points, grouped by
//! domain. Each function owns one orthogonal operation and keeps the JSON
//! contract the TypeScript layer expects.

pub(crate) mod binary;
pub(crate) mod elf;
pub(crate) mod macho;
pub(crate) mod pe;
pub(crate) mod scan;
