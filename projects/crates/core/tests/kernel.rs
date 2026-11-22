//! Kernel acceptance tests.
//!
//! Every fixture is built in memory and written to a unique file under the
//! system temporary directory, then removed when the guard drops.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use open_ida_core::{
    BinaryView, DisassembleOptions, DisassemblySyntax, IdaError, OpenIda, OpenIdaOptions, SearchMode, SearchOptions,
};

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

/// A one-section PE64 whose `.text` payload is exactly `code`.
fn pe_code_bytes(code: &[u8]) -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u16(&mut bytes, 0x86, 1);
    put_u32(&mut bytes, 0x188 + 8, 0x10);
    put_u32(&mut bytes, 0x188 + 16, code.len() as u32);
    bytes.truncate(0x200);
    bytes.extend_from_slice(code);
    bytes
}

/// `pe_bytes()` plus one `CodeView` debug directory entry at RVA 0x2000.
fn pe_debug_bytes() -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u32(&mut bytes, 0x98 + 112 + 6 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 6 * 8 + 4, 28);

    let entry = 0x400;
    put_u32(&mut bytes, entry + 4, 0x1122_3344);
    put_u16(&mut bytes, entry + 8, 1);
    put_u16(&mut bytes, entry + 10, 2);
    put_u32(&mut bytes, entry + 12, 2);
    put_u32(&mut bytes, entry + 16, 44);
    put_u32(&mut bytes, entry + 20, 0x2040);
    put_u32(&mut bytes, entry + 24, 0x440);

    let record = 0x440;
    bytes[record..record + 4].copy_from_slice(b"RSDS");
    bytes[record + 4..record + 8].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    bytes[record + 8..record + 10].copy_from_slice(&0x5566u16.to_le_bytes());
    bytes[record + 10..record + 12].copy_from_slice(&0x7788u16.to_le_bytes());
    bytes[record + 12..record + 20].copy_from_slice(&[0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00]);
    put_u32(&mut bytes, record + 20, 7);
    bytes[record + 24..record + 44].copy_from_slice(b"C:\\build\\sample.pdb\0");
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
    assert_eq!(matrix["features"]["imports"], "supported");
    assert_eq!(matrix["features"]["symbols"], "supported");
    assert_eq!(matrix["features"]["search"], "supported");
    assert_eq!(matrix["features"]["disassembly"], "supported");
    assert_eq!(matrix["unsupported"]["debugger"], "not-implemented");
}

#[test]
fn hex_parser_accepts_common_separators() {
    assert_eq!(open_ida_core::parse_hex("90,90").unwrap(), vec![0x90, 0x90]);
    assert_eq!(open_ida_core::parse_hex("0x90 0x0d").unwrap(), vec![0x90, 0x0d]);
    assert_eq!(open_ida_core::parse_hex("9090").unwrap(), vec![0x90, 0x90]);
    let error: IdaError = open_ida_core::parse_hex("9").unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

/// 单节 `PE32+`：`.rdata` 覆盖文件 0x200..0x800，内含导入、导出与一个 `COFF` 符号。
fn pe_analysis_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x800];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 1);
    put_u32(&mut bytes, 0x8c, 0x600);
    put_u32(&mut bytes, 0x90, 1);
    put_u16(&mut bytes, 0x94, 0xf0);
    put_u16(&mut bytes, 0x98, 0x20b);
    put_u64(&mut bytes, 0x98 + 24, 0x1_4000_0000);
    put_u32(&mut bytes, 0x98 + 56, 0x2000);
    put_u32(&mut bytes, 0x98 + 60, 0x200);
    put_u32(&mut bytes, 0x98 + 112, 0x1100);
    put_u32(&mut bytes, 0x98 + 116, 0x28);
    put_u32(&mut bytes, 0x98 + 120, 0x1000);
    put_u32(&mut bytes, 0x98 + 124, 0x28);

    let section = 0x188;
    bytes[section..section + 6].copy_from_slice(b".rdata");
    put_u32(&mut bytes, section + 8, 0x600);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x600);
    put_u32(&mut bytes, section + 20, 0x200);
    put_u32(&mut bytes, section + 36, 0x4000_0040);

    put_u32(&mut bytes, 0x200, 0x1040);
    put_u32(&mut bytes, 0x20c, 0x1030);
    put_u32(&mut bytes, 0x210, 0x1060);
    bytes[0x230..0x23d].copy_from_slice(b"KERNEL32.dll\0");
    put_u64(&mut bytes, 0x240, 0x1080);
    put_u64(&mut bytes, 0x248, 0x8000_0000_0000_0001);
    put_u64(&mut bytes, 0x260, 0x1080);
    put_u64(&mut bytes, 0x268, 0x8000_0000_0000_0001);
    bytes[0x282..0x28e].copy_from_slice(b"ExitProcess\0");

    put_u32(&mut bytes, 0x300 + 12, 0x1130);
    put_u32(&mut bytes, 0x300 + 16, 1);
    put_u32(&mut bytes, 0x300 + 20, 2);
    put_u32(&mut bytes, 0x300 + 24, 1);
    put_u32(&mut bytes, 0x300 + 28, 0x1140);
    put_u32(&mut bytes, 0x300 + 32, 0x1148);
    put_u32(&mut bytes, 0x300 + 36, 0x114c);
    bytes[0x330..0x33b].copy_from_slice(b"sample.dll\0");
    put_u32(&mut bytes, 0x340, 0x1000);
    put_u32(&mut bytes, 0x348, 0x1150);
    put_u16(&mut bytes, 0x34c, 0);
    bytes[0x350..0x356].copy_from_slice(b"Start\0");

    bytes[0x600..0x606].copy_from_slice(b"native");
    put_u32(&mut bytes, 0x608, 0x1000);
    put_u16(&mut bytes, 0x60c, 1);
    put_u16(&mut bytes, 0x60e, 0x20);
    bytes[0x610] = 2;
    put_u32(&mut bytes, 0x612, 4);
    bytes
}

#[test]
fn pe_imports_exports_and_symbols_flow_through_the_engine() {
    let file = TempFile::new("pe-analysis");
    file.write(&pe_analysis_bytes());
    let view = BinaryView::open(file.path()).expect("open PE");

    let imports = view.imports(None).expect("imports");
    assert_eq!(imports.total, 2);
    assert_eq!(imports.entries[0].module, "KERNEL32.dll");
    assert_eq!(imports.entries[0].name.as_deref(), Some("ExitProcess"));
    assert_eq!(imports.entries[0].address, Some(0x1_4000_1060));
    assert_eq!(imports.entries[1].ordinal, Some(1));
    assert_eq!(imports.entries[1].address, Some(0x1_4000_1068));
    assert!(!imports.truncated);

    let limited = view.imports(Some(1)).expect("bounded imports");
    assert_eq!(limited.entries.len(), 1);
    assert_eq!(limited.total, 2);
    assert!(limited.truncated);

    let exports = view.exports(None).expect("exports");
    assert_eq!(exports.entries.len(), 1);
    assert_eq!(exports.entries[0].name.as_deref(), Some("Start"));
    assert_eq!(exports.entries[0].ordinal, Some(1));
    assert_eq!(exports.entries[0].address, Some(0x1_4000_1000));

    let symbols = view.symbols(None).expect("symbols");
    assert_eq!(symbols.entries.len(), 1);
    assert_eq!(symbols.entries[0].name, "native");
    assert_eq!(symbols.entries[0].kind, "function");
    assert_eq!(symbols.entries[0].binding, "global");
    assert_eq!(symbols.entries[0].section.as_deref(), Some(".rdata"));
    assert_eq!(symbols.entries[0].address, 0x1_4000_1000);
}

#[test]
fn pe_debug_directory_reports_codeview_records() {
    let file = TempFile::new("pe-debug");
    file.write(&pe_debug_bytes());
    let view = BinaryView::open(file.path()).expect("open PE");

    let report = view.debug(None).expect("debug");
    assert_eq!(report.total, 1);
    assert!(!report.truncated);
    let entry = &report.entries[0];
    assert_eq!(entry.debug_type, "codeview");
    assert_eq!(entry.timestamp, 0x1122_3344);
    assert_eq!(entry.major_version, 1);
    assert_eq!(entry.minor_version, 2);
    assert_eq!(entry.size_of_data, 44);
    assert_eq!(entry.address_of_raw_data, 0x2040);
    assert_eq!(entry.pointer_to_raw_data, 0x440);

    let code_view = entry.code_view.as_ref().expect("RSDS record");
    assert_eq!(code_view.signature, "RSDS");
    assert_eq!(code_view.guid.as_deref(), Some("11223344-5566-7788-99aa-bbccddeeff00"));
    assert_eq!(code_view.age, 7);
    assert_eq!(code_view.offset, None);
    assert_eq!(code_view.timestamp, None);
    assert_eq!(code_view.path, "C:\\build\\sample.pdb");

    let limited = view.debug(Some(0)).expect("bounded debug");
    assert_eq!(limited.entries.len(), 0);
    assert_eq!(limited.total, 1);
    assert!(limited.truncated);
}

#[test]
fn pe_without_a_debug_directory_reports_no_entries() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    let report = view.debug(None).expect("debug");
    assert_eq!(report.total, 0);
    assert!(report.entries.is_empty());
    assert!(!report.truncated);
}

#[test]
fn debug_directory_is_unsupported_outside_pe() {
    let view = BinaryView::from_bytes("note.txt", b"not a PE file".to_vec());
    assert_eq!(view.debug(None).unwrap_err().code(), "binary/unsupported");
}

#[test]
fn x64_disassembly_decodes_mov_sub_ret() {
    let bytes = pe_code_bytes(&[0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xc3]);
    let view = BinaryView::from_bytes("code.exe", bytes);

    let report = view.disasm(&DisassembleOptions::new(0x200)).expect("x64 disasm");
    assert_eq!(report.architecture, "x64");
    assert_eq!(report.bitness, 64);
    assert_eq!(report.start_offset, 0x200);
    assert_eq!(report.start_address, 0x1_4000_1000);
    assert_eq!(report.syntax, "intel");
    assert!(!report.truncated);
    assert_eq!(report.instructions.len(), 3);

    assert_eq!(report.instructions[0].address, 0x1_4000_1000);
    assert_eq!(report.instructions[0].offset, 0x200);
    assert_eq!(report.instructions[0].length, 3);
    assert_eq!(report.instructions[0].bytes, "4889e5");
    assert_eq!(report.instructions[0].text, "mov rbp,rsp");
    assert_eq!(report.instructions[1].text, "sub rsp,0x20");
    assert_eq!(report.instructions[2].text, "ret");
    assert_eq!(report.instructions[2].offset, 0x207);
}

#[test]
fn x86_disassembly_uses_the_detected_bitness() {
    let mut bytes = elf32_bytes();
    bytes[0x200..0x204].copy_from_slice(&[0x55, 0x89, 0xe5, 0xc3]);
    put_u32(&mut bytes, 0xbc, 4);
    bytes.truncate(0x204);
    let view = BinaryView::from_bytes("code.elf", bytes);

    let report = view.disasm(&DisassembleOptions::new(0x200)).expect("x86 disasm");
    assert_eq!(report.architecture, "x86");
    assert_eq!(report.bitness, 32);
    assert_eq!(report.start_address, 0x200);
    assert_eq!(report.instructions.len(), 3);
    assert_eq!(report.instructions[0].text, "push ebp");
    assert_eq!(report.instructions[1].text, "mov ebp,esp");
    assert_eq!(report.instructions[2].text, "ret");
}

#[test]
fn disassembly_honours_the_count_and_syntax_options() {
    let bytes = pe_code_bytes(&[0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xc3]);
    let view = BinaryView::from_bytes("code.exe", bytes);

    let mut options = DisassembleOptions::new(0x200);
    options.count = 2;
    options.syntax = DisassemblySyntax::Nasm;
    let report = view.disasm(&options).expect("bounded disasm");
    assert_eq!(report.syntax, "nasm");
    assert_eq!(report.instructions.len(), 2);
    assert!(report.truncated);
}

#[test]
fn disassembly_is_unsupported_outside_x86_and_x64() {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32(&mut bytes, 4, 0x0100_000c);
    put_u32(&mut bytes, 12, 2);
    put_u32(&mut bytes, 16, 3);
    let view = BinaryView::from_bytes("sample.macho", bytes);

    let error = view.disasm(&DisassembleOptions::new(0)).unwrap_err();
    assert_eq!(error.code(), "binary/unsupported");
}

fn open_engine(file: &TempFile) -> OpenIda {
    OpenIda::new(OpenIdaOptions::new(file.path())).expect("open engine")
}

#[test]
fn diff_reports_identical_files() {
    let left_file = TempFile::new("diff-left");
    left_file.write(&[1, 2, 3, 4]);
    let right_file = TempFile::new("diff-right");
    right_file.write(&[1, 2, 3, 4]);
    let left = open_engine(&left_file);
    let right = open_engine(&right_file);

    let report = left.diff(&right).expect("diff");
    assert!(report.identical);
    assert_eq!(report.left_size, 4);
    assert_eq!(report.right_size, 4);
    assert_eq!(report.compared_bytes, 4);
    assert_eq!(report.left_hash, report.right_hash);
    assert_eq!(report.first_difference, None);
    assert!(report.differences.is_empty());
    assert_eq!(report.total, 0);
    assert!(!report.truncated);
}

#[test]
fn diff_reports_the_first_divergence_and_range() {
    let left_file = TempFile::new("diff-prefix-left");
    left_file.write(&[1, 2, 3, 4, 5]);
    let right_file = TempFile::new("diff-prefix-right");
    right_file.write(&[1, 2, 9, 4, 5]);
    let left = open_engine(&left_file);
    let right = open_engine(&right_file);

    let report = left.diff(&right).expect("diff");
    assert!(!report.identical);
    assert_eq!(report.compared_bytes, 5);
    assert_eq!(report.first_difference, Some(2));
    assert_ne!(report.left_hash, report.right_hash);
    assert_eq!(report.differences, vec![open_ida_core::DiffRange { offset: 2, length: 1 }]);
    assert_eq!(report.total, 1);
    assert!(!report.truncated);
}

#[test]
fn diff_handles_different_lengths() {
    let left_file = TempFile::new("diff-length-left");
    left_file.write(&[1, 2, 3]);
    let right_file = TempFile::new("diff-length-right");
    right_file.write(&[1, 2, 3, 4, 5]);
    let left = open_engine(&left_file);
    let right = open_engine(&right_file);

    let report = left.diff(&right).expect("diff");
    assert!(!report.identical);
    assert_eq!(report.left_size, 3);
    assert_eq!(report.right_size, 5);
    assert_eq!(report.compared_bytes, 3);
    assert_eq!(report.first_difference, Some(3));
    assert_eq!(report.differences, vec![open_ida_core::DiffRange { offset: 3, length: 2 }]);
}

#[test]
fn diff_caps_the_number_of_ranges() {
    let mut left_bytes = vec![0u8; 200];
    let mut right_bytes = vec![0u8; 200];
    for index in 0..100 {
        left_bytes[index * 2] = 1;
        right_bytes[index * 2] = 2;
    }
    let left_file = TempFile::new("diff-cap-left");
    left_file.write(&left_bytes);
    let right_file = TempFile::new("diff-cap-right");
    right_file.write(&right_bytes);
    let left = open_engine(&left_file);
    let right = open_engine(&right_file);

    let report = left.diff(&right).expect("diff");
    assert_eq!(report.total, 100);
    assert_eq!(report.differences.len(), 64);
    assert!(report.truncated);
    assert_eq!(report.first_difference, Some(0));
    assert_eq!(report.differences[0].offset, 0);
    assert_eq!(report.differences[63].offset, 126);
}

#[test]
fn search_and_reverse_mapping_are_exposed() {
    let file = TempFile::new("pe-search");
    file.write(&pe_analysis_bytes());
    let view = BinaryView::open(file.path()).expect("open PE");

    let text = view.search(&SearchOptions::new(SearchMode::Ascii, "kernel32")).expect("ascii search");
    assert_eq!(text.mode, "ascii");
    assert_eq!(text.total, 1);
    assert_eq!(text.hits[0].offset, 0x230);
    assert_eq!(text.hits[0].preview, "KERNEL32");

    let hex = view.search(&SearchOptions::new(SearchMode::Hex, "45 78 69 74")).expect("hex search");
    assert_eq!(hex.hits[0].offset, 0x282);

    let wide = view.search(&SearchOptions::new(SearchMode::Utf16Le, "Exit")).expect("utf16 search");
    assert_eq!(wide.total, 0);

    assert_eq!(view.offset_to_rva(0x230).unwrap(), 0x1030);
    assert_eq!(view.offset_to_va(0x230).unwrap(), 0x1_4000_1030);
    assert_eq!(view.offset_to_rva(0x10).unwrap(), 0x10);
    assert_eq!(view.offset_to_va(0x800).unwrap_err().code(), "binary/range");
}
