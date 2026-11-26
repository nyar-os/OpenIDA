//! `ELF` format projections.
//!
//! `data-binary-pe::elf` owns the header, the section table, the static symbol
//! table (`read_elf_symbols`), the program headers (`read_program_headers`),
//! the dynamic table (`read_dynamic`) and the note segments (`read_notes`).
//! Every module here maps those owner types onto the product JSON reports.

pub mod dynamic;
pub mod notes;
pub mod segments;
pub mod symbols;
