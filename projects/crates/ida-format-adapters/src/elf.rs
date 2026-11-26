//! `ELF` format projections.
//!
//! `data-binary-pe::elf` owns the header, the section table and the static
//! symbol table (`read_elf_symbols`). The dynamic table, the program headers
//! and the note segments are decoded here because the pinned release does not
//! expose them.

pub mod dynamic;
pub mod notes;
pub mod segments;
pub mod symbols;
