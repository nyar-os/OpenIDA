//! Kernel acceptance tests.
//!
//! Every fixture is built in memory and written to a unique file under the
//! system temporary directory, then removed when the guard drops.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use open_ida_core::{BinaryView, IdaError, OpenIda, OpenIdaOptions};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let name = format!("open-ida-{}-{id}-{label}.bin", std::process::id());
        Self(std::env::temp_dir().join(name))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, bytes: &[u8]) {
        fs::write(&self.0, bytes).expect("write fixture");
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        fs::remove_file(&self.0).ok();
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn put_section(
    bytes: &mut [u8],
    offset: usize,
    name: &[u8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
) {
    let name_length = name.len().min(8);
    bytes[offset..offset + name_length].copy_from_slice(&name[..name_length]);
    put_u32(bytes, offset + 8, virtual_size);
    put_u32(bytes, offset + 12, virtual_address);
    put_u32(bytes, offset + 16, raw_size);
    put_u32(bytes, offset + 20, raw_pointer);
    put_u32(bytes, offset + 36, characteristics);
}

/// A two-section PE32+ image with a header at 0x80 and sections at 0x200/0x400.
fn pe_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x600];
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 2);
    put_u16(&mut bytes, 0x94, 0xf0);
    put_u16(&mut bytes, 0x98, 0x20b);
    put_u32(&mut bytes, 0x98 + 16, 0x1000);
    put_u64(&mut bytes, 0x98 + 24, 0x1_4000_0000);
    put_u32(&mut bytes, 0x98 + 60, 0x200);
    put_section(&mut bytes, 0x188, b".text", 0x100, 0x1000, 0x200, 0x200, 0x6000_0020);
    put_section(&mut bytes, 0x1b0, b".data", 0x100, 0x2000, 0x200, 0x400, 0xc000_0040);
    bytes
}

/// A three-section ELF64 little-endian image with a name table at 0x300.
fn elf64_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x400];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, 0x401000);
    put_u64(&mut bytes, 40, 0x100);
    put_u16(&mut bytes, 58, 64);
    put_u16(&mut bytes, 60, 3);
    put_u16(&mut bytes, 62, 2);

    let names = b"\0.text\0.shstrtab\0";
    bytes[0x300..0x300 + names.len()].copy_from_slice(names);

    put_u32(&mut bytes, 0x140, 1);
    put_u32(&mut bytes, 0x144, 1);
    put_u64(&mut bytes, 0x148, 6);
    put_u64(&mut bytes, 0x150, 0x401000);
    put_u64(&mut bytes, 0x158, 0x200);
    put_u64(&mut bytes, 0x160, 0x10);

    put_u32(&mut bytes, 0x180, 7);
    put_u32(&mut bytes, 0x184, 3);
    put_u64(&mut bytes, 0x198, 0x300);
    put_u64(&mut bytes, 0x1a0, names.len() as u64);
    bytes
}

/// A two-section ELF32 little-endian image with a name table at 0x100.
fn elf32_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x300];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 3);
    put_u32(&mut bytes, 20, 1);
    put_u32(&mut bytes, 24, 0x8048000);
    put_u32(&mut bytes, 32, 0x80);
    put_u16(&mut bytes, 46, 40);
    put_u16(&mut bytes, 48, 3);
    put_u16(&mut bytes, 50, 2);

    let names = b"\0.text\0.shstrtab\0";
    bytes[0x100..0x100 + names.len()].copy_from_slice(names);

    put_u32(&mut bytes, 0xa8, 1);
    put_u32(&mut bytes, 0xac, 1);
    put_u32(&mut bytes, 0xb0, 6);
    put_u32(&mut bytes, 0xb4, 0x8048000);
    put_u32(&mut bytes, 0xb8, 0x200);
    put_u32(&mut bytes, 0xbc, 0x10);

    put_u32(&mut bytes, 0xd0, 7);
    put_u32(&mut bytes, 0xd4, 3);
    put_u32(&mut bytes, 0xe0, 0x100);
    put_u32(&mut bytes, 0xe4, names.len() as u32);
    bytes
}

#[test]
fn pe_header_sections_and_rva_mapping() {
    let file = TempFile::new("pe");
    file.write(&pe_bytes());
    let view = BinaryView::open(file.path()).expect("open PE");

    assert_eq!(view.format(), open_ida_core::BinaryFormat::Pe);
    assert_eq!(view.architecture(), open_ida_core::Architecture::X64);
    assert_eq!(view.size(), 0x600);

    let info = view.info().expect("PE info");
    assert_eq!(info.format, "pe");
    assert_eq!(info.architecture, "x64");
    assert_eq!(info.magic.as_deref(), Some("PE32+"));
    assert_eq!(info.entry_rva, Some(0x1000));
    assert_eq!(info.image_base, Some(0x1_4000_0000));
    assert_eq!(info.entry, Some(0x1_4000_1000));
    assert_eq!(info.section_count, 2);
    assert_eq!(info.hash.len(), 16);

    let sections = view.sections().expect("PE sections");
    assert_eq!(sections.len(), 2);
    assert_eq!(sections[0].name, ".text");
    assert_eq!(sections[0].virtual_address, 0x1000);
    assert_eq!(sections[0].raw_pointer, 0x200);
    assert!(sections[0].readable && sections[0].executable && !sections[0].writable);
    assert_eq!(sections[1].name, ".data");
    assert!(sections[1].readable && sections[1].writable && !sections[1].executable);

    assert_eq!(view.rva_to_offset(0x10).unwrap(), 0x10);
    assert_eq!(view.rva_to_offset(0x1000).unwrap(), 0x200);
    assert_eq!(view.rva_to_offset(0x2010).unwrap(), 0x410);
    let error = view.rva_to_offset(0x9000).unwrap_err();
    assert_eq!(error.code(), "binary/range");
}

#[test]
fn elf64_header_names_and_rva_mapping() {
    let file = TempFile::new("elf64");
    file.write(&elf64_bytes());
    let view = BinaryView::open(file.path()).expect("open ELF64");

    assert_eq!(view.format(), open_ida_core::BinaryFormat::Elf);
    assert_eq!(view.architecture(), open_ida_core::Architecture::X64);

    let info = view.info().expect("ELF info");
    assert_eq!(info.magic.as_deref(), Some("ELF64"));
    assert_eq!(info.entry, Some(0x401000));
    assert_eq!(info.section_count, 3);

    let sections = view.sections().expect("ELF sections");
    assert_eq!(sections[1].name, ".text");
    assert_eq!(sections[1].virtual_address, 0x401000);
    assert_eq!(sections[1].raw_pointer, 0x200);
    assert!(sections[1].executable);
    assert_eq!(sections[2].name, ".shstrtab");

    assert_eq!(view.rva_to_offset(0x401004).unwrap(), 0x204);
    assert_eq!(view.rva_to_offset(0x1234).unwrap_err().code(), "binary/range");
}

#[test]
fn elf32_header_detection() {
    let file = TempFile::new("elf32");
    file.write(&elf32_bytes());
    let view = BinaryView::open(file.path()).expect("open ELF32");

    assert_eq!(view.architecture(), open_ida_core::Architecture::X86);
    let sections = view.sections().expect("ELF32 sections");
    assert_eq!(sections.len(), 3);
    assert_eq!(sections[1].name, ".text");
    assert_eq!(view.rva_to_offset(0x8048008).unwrap(), 0x208);
}

#[test]
fn malformed_big_endian_elf_is_rejected() {
    let mut bytes = elf64_bytes();
    bytes[5] = 2;
    let view = BinaryView::from_bytes("big-endian.elf", bytes);
    let error = view.info().unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

#[test]
fn macho_header_basics_only() {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32(&mut bytes, 4, 0x0100_000c);
    put_u32(&mut bytes, 12, 2);
    put_u32(&mut bytes, 16, 3);
    let view = BinaryView::from_bytes("sample.macho", bytes);

    assert_eq!(view.format(), open_ida_core::BinaryFormat::MachO);
    assert_eq!(view.architecture(), open_ida_core::Architecture::Arm64);
    let info = view.info().expect("Mach-O info");
    assert_eq!(info.magic.as_deref(), Some("Mach-O 64"));
    assert_eq!(info.cpu_type, Some(0x0100_000c));
    assert_eq!(info.file_type, Some(2));
    assert_eq!(info.command_count, Some(3));
    assert_eq!(view.sections().unwrap_err().code(), "binary/parse");
}

#[test]
fn unknown_file_reports_unknown_and_refuses_mapping() {
    let view = BinaryView::from_bytes("note.txt", b"just some text".to_vec());
    let info = view.info().expect("unknown info");
    assert_eq!(info.format, "unknown");
    assert_eq!(info.architecture, "unknown");
    assert_eq!(info.section_count, 0);
    assert!(info.magic.is_none());
    assert_eq!(view.sections().unwrap_err().code(), "binary/unsupported");
    assert_eq!(view.rva_to_offset(0).unwrap_err().code(), "binary/unsupported");
}

#[test]
fn strings_report_offsets_and_honour_minimum_length() {
    let view = BinaryView::from_bytes("strings.bin", b"\x00hello\x00ab\x00world!\x00".to_vec());
    let hits = view.strings(2);
    assert_eq!(hits.len(), 3);
    assert_eq!(hits[0].value, "hello");
    assert_eq!(hits[0].offset, 1);
    assert_eq!(hits[1].value, "ab");
    assert_eq!(hits[1].offset, 7);
    assert_eq!(hits[2].value, "world!");
    assert_eq!(hits[2].offset, 10);

    let long = view.strings(3);
    assert_eq!(long.len(), 2);
    assert_eq!(long[0].value, "hello");
    assert_eq!(long[1].value, "world!");
}

#[test]
fn hexdump_uses_the_canonical_layout() {
    let view = BinaryView::from_bytes("hello.bin", b"Hello, world!".to_vec());
    let dump = view.hexdump(0, 13).expect("hexdump");
    let expected = concat!("00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 ", "         ", " |Hello, world!|\n");
    assert_eq!(dump, expected);

    let empty = view.hexdump(0, 0).expect("empty dump");
    assert_eq!(empty, "");
    assert_eq!(view.hexdump(10, 4).unwrap_err().code(), "binary/range");
}

#[test]
fn patch_is_atomic_and_reports_hashes() {
    let file = TempFile::new("patch");
    file.write(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let mut view = BinaryView::open(file.path()).expect("open patch target");

    let report = view.patch(2, &[0xaa, 0xbb]).expect("patch");
    assert_eq!(fs::read(file.path()).unwrap(), vec![0, 1, 0xaa, 0xbb, 4, 5, 6, 7]);
    assert_eq!(report.offset, 2);
    assert_eq!(report.length, 2);
    assert_eq!(report.before_hash.len(), 16);
    assert_ne!(report.before_hash, report.after_hash);
    assert_eq!(view.size(), 8);

    let error = view.patch(7, &[0, 0]).unwrap_err();
    assert_eq!(error.code(), "binary/range");
    assert_eq!(fs::read(file.path()).unwrap(), vec![0, 1, 0xaa, 0xbb, 4, 5, 6, 7]);
}

#[test]
fn patch_to_a_copy_leaves_the_source_untouched() {
    let source = TempFile::new("patch-source");
    source.write(&[1, 2, 3, 4]);
    let target = TempFile::new("patch-target");
    let mut view = BinaryView::open(source.path()).expect("open source");

    let report = view.patch_to(0, &[0xff], Some(target.path())).expect("patch copy");
    assert_eq!(fs::read(source.path()).unwrap(), vec![1, 2, 3, 4]);
    assert_eq!(fs::read(target.path()).unwrap(), vec![0xff, 2, 3, 4]);
    assert_eq!(report.path, target.path().display().to_string());
}

#[test]
fn engine_options_carry_the_defaults_used_by_operations() {
    let file = TempFile::new("engine");
    file.write(b"\x00alpha\x00beta\x00gamma\x00");
    let engine = OpenIda::new(OpenIdaOptions { strings_limit: Some(2), min_string_len: 3, ..OpenIdaOptions::new(file.path()) })
        .expect("open engine");

    assert_eq!(engine.options().strings_limit, Some(2));
    assert_eq!(engine.info().expect("engine info").format, "unknown");

    let report = engine.strings(None, None);
    assert_eq!(report.total, 3);
    assert_eq!(report.hits.len(), 2);
    assert!(report.truncated);
    assert_eq!(report.hits[0].value, "alpha");

    let override_report = engine.strings(Some(5), Some(1));
    assert_eq!(override_report.total, 2);
    assert_eq!(override_report.hits.len(), 1);
    assert_eq!(override_report.hits[0].value, "alpha");

    let unlimited = OpenIda::new(OpenIdaOptions { strings_limit: None, ..OpenIdaOptions::new(file.path()) })
        .expect("open unlimited engine");
    assert_eq!(unlimited.strings(None, None).hits.len(), 3);
}

#[test]
fn engine_hexdump_uses_its_configured_length() {
    let file = TempFile::new("engine-hexdump");
    file.write(b"abcdefgh");
    let engine = OpenIda::new(OpenIdaOptions { hexdump_length: 4, ..OpenIdaOptions::new(file.path()) }).expect("open engine");

    let dump = engine.hexdump(None, None).expect("default dump");
    assert!(dump.contains("61 62 63 64"));
    assert!(!dump.contains("65 66"));
    assert_eq!(engine.read(0, 2).unwrap(), b"ab");
    assert_eq!(engine.read(6, 4).unwrap_err().code(), "binary/range");
}

#[test]
fn engine_options_round_trip_through_json() {
    let file = TempFile::new("engine-json");
    file.write(b"\x00engine\x00");
    let raw = serde_json::json!({ "path": file.path(), "minStringLen": 2 }).to_string();
    let engine = OpenIda::from_options_json(&raw).expect("engine from json");
    assert_eq!(engine.options().min_string_len, 2);
    assert_eq!(engine.options().strings_limit, Some(100));
    assert_eq!(engine.options().hexdump_length, 256);
    assert_eq!(engine.strings(None, None).hits[0].value, "engine");

    let error = OpenIda::from_options_json("{}").unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

#[test]
fn capabilities_declare_what_is_not_implemented() {
    let matrix = open_ida_core::capabilities();
    assert_eq!(matrix["formats"]["pe"], "supported");
    assert_eq!(matrix["formats"]["macho"], "partial");
    assert_eq!(matrix["unsupported"]["disassembly"], "not-implemented");
    assert_eq!(matrix["unsupported"]["debugger"], "not-implemented");
    assert_eq!(matrix["unsupported"]["symbols"], "not-implemented");
}

#[test]
fn hex_parser_accepts_common_separators() {
    assert_eq!(open_ida_core::parse_hex("90,90").unwrap(), vec![0x90, 0x90]);
    assert_eq!(open_ida_core::parse_hex("0x90 0x0d").unwrap(), vec![0x90, 0x0d]);
    assert_eq!(open_ida_core::parse_hex("9090").unwrap(), vec![0x90, 0x90]);
    let error: IdaError = open_ida_core::parse_hex("9").unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}
