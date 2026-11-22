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
    StringEncoding, StringsOptions,
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
fn encoded_strings_match_the_ascii_scanner() {
    let view = BinaryView::from_bytes("encoded.bin", b"\x00hello\x00ab\x00world!\x00".to_vec());
    let report = view
        .strings_encoded(&StringsOptions { min_length: 2, encoding: StringEncoding::Ascii, ..StringsOptions::default() })
        .expect("ascii encoded strings");

    assert_eq!(report.encoding, StringEncoding::Ascii);
    assert_eq!(report.min_length, 2);
    assert_eq!(report.total, 3);
    assert!(!report.truncated);
    let values: Vec<&str> = report.hits.iter().map(|hit| hit.value.as_str()).collect();
    assert_eq!(values, vec!["hello", "ab", "world!"]);
    let legacy_hits = view.strings(2);
    let legacy: Vec<&str> = legacy_hits.iter().map(|hit| hit.value.as_str()).collect();
    assert_eq!(values, legacy);
    assert!(report.hits.iter().all(|hit| hit.encoding == StringEncoding::Ascii));
    assert_eq!(report.hits[0].offset, 1);
    assert_eq!(report.hits[0].length, 5);
}

#[test]
fn utf16le_strings_report_byte_offsets_and_lengths() {
    let view = BinaryView::from_bytes("wide.bin", b"\xff\x00H\x00e\x00l\x00l\x00o\x00\xff".to_vec());
    let options = StringsOptions { encoding: StringEncoding::Utf16Le, ..StringsOptions::default() };
    let report = view.strings_encoded(&options).expect("utf16 strings");

    assert_eq!(report.total, 1);
    let hit = &report.hits[0];
    assert_eq!(hit.value, "Hello");
    assert_eq!(hit.offset, 2);
    assert_eq!(hit.length, 10);
    assert_eq!(hit.encoding, StringEncoding::Utf16Le);

    let ascii_only = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Ascii, ..StringsOptions::default() })
        .expect("ascii only");
    assert_eq!(ascii_only.total, 0);
}

#[test]
fn both_encodings_merge_in_offset_order() {
    let mut bytes = b"abcde\x00\xff".to_vec();
    bytes.extend_from_slice(b"H\x00e\x00l\x00l\x00o\x00");
    let view = BinaryView::from_bytes("mixed.bin", bytes);
    let report = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Both, ..StringsOptions::default() })
        .expect("merged strings");

    assert_eq!(report.encoding, StringEncoding::Both);
    assert_eq!(report.total, 2);
    assert_eq!(report.hits[0].offset, 0);
    assert_eq!(report.hits[0].encoding, StringEncoding::Ascii);
    assert_eq!(report.hits[0].value, "abcde");
    assert_eq!(report.hits[1].offset, 7);
    assert_eq!(report.hits[1].encoding, StringEncoding::Utf16Le);
    assert_eq!(report.hits[1].value, "Hello");
}

#[test]
fn encoded_strings_honour_the_minimum_length() {
    let view = BinaryView::from_bytes("short-wide.bin", b"H\x00e\x00y\x00\x00\x00".to_vec());
    let filtered = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Utf16Le, min_length: 4, ..StringsOptions::default() })
        .expect("filtered utf16");
    assert_eq!(filtered.total, 0);

    let kept = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Utf16Le, min_length: 3, ..StringsOptions::default() })
        .expect("kept utf16");
    assert_eq!(kept.total, 1);
    assert_eq!(kept.hits[0].value, "Hey");

    let zero = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Utf16Le, min_length: 0, ..StringsOptions::default() })
        .expect("zero minimum");
    assert_eq!(zero.min_length, 1);
    assert_eq!(zero.total, 1);
}

#[test]
fn encoded_strings_apply_the_limit_once() {
    let file = TempFile::new("encoded-limit");
    file.write(b"\x00alpha\x00beta\x00gamma\x00");
    let engine = open_engine(&file);
    let report = engine
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Both, min_length: 3, limit: 2 })
        .expect("bounded strings");

    assert_eq!(report.total, 3);
    assert_eq!(report.hits.len(), 2);
    assert!(report.truncated);
    assert_eq!(report.limit, 2);
    assert_eq!(report.hits[0].value, "alpha");
    assert_eq!(report.hits[1].value, "beta");
}

#[test]
fn encoded_strings_tolerate_odd_endings_and_truncated_pairs() {
    let view = BinaryView::from_bytes("odd.bin", b"\x00H\x00i\x00J".to_vec());
    let report = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Both, min_length: 2, ..StringsOptions::default() })
        .expect("odd ending");
    assert_eq!(report.total, 1);
    assert_eq!(report.hits[0].value, "Hi");
    assert_eq!(report.hits[0].offset, 1);
    assert_eq!(report.hits[0].length, 4);

    let lone = BinaryView::from_bytes("lone.bin", b"\x00H".to_vec());
    assert_eq!(
        lone.strings_encoded(&StringsOptions { encoding: StringEncoding::Utf16Le, ..StringsOptions::default() })
            .expect("truncated pair")
            .total,
        0
    );
}

#[test]
fn strings_options_use_camel_case_defaults() {
    let defaults = serde_json::from_str::<StringsOptions>("{}").expect("default options");
    assert_eq!(defaults, StringsOptions::default());
    assert_eq!(defaults.min_length, 4);
    assert_eq!(defaults.limit, 100);
    assert_eq!(defaults.encoding, StringEncoding::Ascii);

    let parsed = serde_json::from_str::<StringsOptions>(r#"{"minLength": 2, "limit": 5, "encoding": "both"}"#)
        .expect("camelCase options");
    assert_eq!(parsed.min_length, 2);
    assert_eq!(parsed.limit, 5);
    assert_eq!(parsed.encoding, StringEncoding::Both);

    let report = BinaryView::from_bytes("json.bin", b"text".to_vec()).strings_encoded(&parsed).expect("json strings");
    let value = serde_json::to_value(&report).expect("report json");
    assert_eq!(value["minLength"], 2);
    assert_eq!(value["limit"], 5);
    assert_eq!(value["encoding"], "both");
    assert_eq!(value["hits"][0]["encoding"], "ascii");
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
    assert_eq!(matrix["features"]["version"], "supported");
    assert_eq!(matrix["features"]["macho-dylibs"], "supported");
    assert_eq!(matrix["features"]["macho-sections"], "supported");
    assert_eq!(matrix["features"]["macho-symbols"], "supported");
    assert_eq!(matrix["features"]["macho-fat-slices"], "supported");
    assert_eq!(matrix["features"]["pe-mitigations"], "supported");
    assert_eq!(matrix["features"]["pe-resources"], "supported");
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

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(|unit| unit.to_le_bytes()).collect()
}

fn version_block(key: &str, value_length: u16, value_type: u16, value: &[u8], children: &[u8]) -> Vec<u8> {
    let mut block = vec![0u8, 0];
    block.extend_from_slice(&value_length.to_le_bytes());
    block.extend_from_slice(&value_type.to_le_bytes());
    block.extend_from_slice(&utf16z(key));
    while block.len() % 4 != 0 {
        block.push(0);
    }
    block.extend_from_slice(value);
    while block.len() % 4 != 0 {
        block.push(0);
    }
    block.extend_from_slice(children);
    while block.len() % 4 != 0 {
        block.push(0);
    }
    let length = block.len() as u16;
    block[0..2].copy_from_slice(&length.to_le_bytes());
    block
}

/// A `VS_VERSIONINFO` payload with fixed info 1.2.3.4 / 5.6.7.8 and two strings.
fn version_payload() -> Vec<u8> {
    let mut fixed = vec![0u8; 52];
    put_u32(&mut fixed, 0, 0xFEEF_04BD);
    put_u32(&mut fixed, 4, 0x0001_0000);
    put_u32(&mut fixed, 8, 0x0001_0002);
    put_u32(&mut fixed, 12, 0x0003_0004);
    put_u32(&mut fixed, 16, 0x0005_0006);
    put_u32(&mut fixed, 20, 0x0007_0008);
    put_u32(&mut fixed, 24, 0x3f);
    put_u32(&mut fixed, 32, 0x4);
    put_u32(&mut fixed, 36, 0x1);

    let company = version_block("CompanyName", 8, 1, &utf16z("OpenIDA"), &[]);
    let description = version_block("FileDescription", 7, 1, &utf16z("Sample"), &[]);
    let mut table_children = company;
    table_children.extend_from_slice(&description);
    let table = version_block("040904B0", 0, 1, &[], &table_children);
    let string_file_info = version_block("StringFileInfo", 0, 1, &[], &table);
    version_block("VS_VERSION_INFO", 52, 0, &fixed, &string_file_info)
}

/// A PE32+ image whose `.rsrc` section carries one `RT_VERSION` resource.
fn pe_version_bytes() -> Vec<u8> {
    let payload = version_payload();
    let mut bytes = vec![0u8; 0x600];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 1);
    put_u16(&mut bytes, 0x94, 0xf0);
    put_u16(&mut bytes, 0x98, 0x20b);
    put_u32(&mut bytes, 0x98 + 16, 0x1000);
    put_u64(&mut bytes, 0x98 + 24, 0x1_4000_0000);
    put_u32(&mut bytes, 0x98 + 56, 0x2000);
    put_u32(&mut bytes, 0x98 + 60, 0x200);
    put_u32(&mut bytes, 0x98 + 112 + 2 * 8, 0x1000);
    put_u32(&mut bytes, 0x98 + 112 + 2 * 8 + 4, 0x400);
    put_section(&mut bytes, 0x188, b".rsrc", 0x400, 0x1000, 0x400, 0x200, 0x4000_0040);

    // Root -> type (16) -> name (1) -> language (0x0409) -> data entry.
    put_u16(&mut bytes, 0x200 + 12, 0);
    put_u16(&mut bytes, 0x200 + 14, 1);
    put_u32(&mut bytes, 0x210, 16);
    put_u32(&mut bytes, 0x210 + 4, 0x8000_0020);
    put_u16(&mut bytes, 0x220 + 12, 0);
    put_u16(&mut bytes, 0x220 + 14, 1);
    put_u32(&mut bytes, 0x230, 1);
    put_u32(&mut bytes, 0x230 + 4, 0x8000_0060);
    put_u16(&mut bytes, 0x260 + 12, 0);
    put_u16(&mut bytes, 0x260 + 14, 1);
    put_u32(&mut bytes, 0x270, 0x0409);
    put_u32(&mut bytes, 0x270 + 4, 0x80);
    put_u32(&mut bytes, 0x280, 0x1090);
    put_u32(&mut bytes, 0x280 + 4, payload.len() as u32);
    put_u32(&mut bytes, 0x280 + 8, 0x04b0);
    bytes[0x290..0x290 + payload.len()].copy_from_slice(&payload);
    bytes
}

#[test]
fn pe_version_resource_reports_fixed_info_and_strings() {
    let view = BinaryView::from_bytes("version.exe", pe_version_bytes());
    let report = view.version().expect("version report");

    assert!(report.present);
    let fixed = report.fixed.expect("fixed file info");
    assert_eq!(fixed.file_version, "1.2.3.4");
    assert_eq!(fixed.product_version, "5.6.7.8");
    assert_eq!(fixed.file_flags_mask, 0x3f);
    assert_eq!(fixed.file_os, 0x4);
    assert_eq!(fixed.file_type, 0x1);

    assert_eq!(report.total, 2);
    assert!(!report.truncated);
    let company = report.strings.iter().find(|entry| entry.key == "CompanyName").expect("CompanyName");
    assert_eq!(company.value, "OpenIDA");
    assert_eq!(company.language_id, 0x0409);
    assert_eq!(company.codepage, 0x04b0);
    let description = report.strings.iter().find(|entry| entry.key == "FileDescription").expect("FileDescription");
    assert_eq!(description.value, "Sample");
}

#[test]
fn pe_without_version_resource_reports_absence() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    let report = view.version().expect("version report");
    assert!(!report.present);
    assert!(report.fixed.is_none());
    assert!(report.strings.is_empty());
    assert!(report.note.is_none());
}

#[test]
fn version_resource_is_unsupported_outside_pe() {
    let view = BinaryView::from_bytes("note.txt", b"not a PE file".to_vec());
    assert_eq!(view.version().unwrap_err().code(), "binary/unsupported");
}

fn put_name16(bytes: &mut [u8], offset: usize, name: &[u8]) {
    let length = name.len().min(16);
    bytes[offset..offset + length].copy_from_slice(&name[..length]);
}

/// A thin arm64 Mach-O with `__TEXT,__text`, `LC_MAIN`, `LC_UUID`, one dylib
/// and `LC_BUILD_VERSION`. The code payload starts at file offset 0x200.
fn macho64_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x210];
    bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32(&mut bytes, 4, 0x0100_000c);
    put_u32(&mut bytes, 8, 0);
    put_u32(&mut bytes, 12, 2);
    put_u32(&mut bytes, 16, 5);
    put_u32(&mut bytes, 20, 280);
    put_u32(&mut bytes, 24, 0x0020_0085);

    let segment = 32;
    put_u32(&mut bytes, segment, 0x19);
    put_u32(&mut bytes, segment + 4, 152);
    put_name16(&mut bytes, segment + 8, b"__TEXT");
    put_u64(&mut bytes, segment + 24, 0x1000);
    put_u64(&mut bytes, segment + 32, 0x200);
    put_u64(&mut bytes, segment + 40, 0x200);
    put_u64(&mut bytes, segment + 48, 0x10);
    put_u32(&mut bytes, segment + 56, 5);
    put_u32(&mut bytes, segment + 60, 5);
    put_u32(&mut bytes, segment + 64, 1);

    let section = segment + 72;
    put_name16(&mut bytes, section, b"__text");
    put_name16(&mut bytes, section + 16, b"__TEXT");
    put_u64(&mut bytes, section + 32, 0x1000);
    put_u64(&mut bytes, section + 40, 0x10);
    put_u32(&mut bytes, section + 48, 0x200);
    put_u32(&mut bytes, section + 52, 2);
    put_u32(&mut bytes, section + 64, 0x8000_0400);

    let main = segment + 152;
    put_u32(&mut bytes, main, 0x8000_0028);
    put_u32(&mut bytes, main + 4, 24);
    put_u64(&mut bytes, main + 8, 0x200);

    let uuid = main + 24;
    put_u32(&mut bytes, uuid, 0x1b);
    put_u32(&mut bytes, uuid + 4, 24);
    bytes[uuid + 8..uuid + 24]
        .copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    let dylib = uuid + 24;
    put_u32(&mut bytes, dylib, 0x0c);
    put_u32(&mut bytes, dylib + 4, 56);
    put_u32(&mut bytes, dylib + 8, 24);
    put_u32(&mut bytes, dylib + 12, 2);
    put_u32(&mut bytes, dylib + 16, 0x0001_0203);
    put_u32(&mut bytes, dylib + 20, 0x0001_0000);
    bytes[dylib + 24..dylib + 51].copy_from_slice(b"/usr/lib/libSystem.B.dylib\0");

    let build = dylib + 56;
    put_u32(&mut bytes, build, 0x32);
    put_u32(&mut bytes, build + 4, 24);
    put_u32(&mut bytes, build + 8, 1);
    put_u32(&mut bytes, build + 12, 0x000d_0100);
    put_u32(&mut bytes, build + 16, 0x000e_0000);

    bytes[0x200..0x210].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    bytes
}

#[test]
fn macho_load_commands_report_identity_dylibs_and_entry() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    let report = view.macho().expect("Mach-O report");

    assert!(report.is_64);
    assert_eq!(report.endian, "little");
    assert_eq!(report.architecture, "arm64");
    assert_eq!(report.kind, "executable");
    assert_eq!(report.file_type, 2);
    assert_eq!(report.command_count, 5);
    assert_eq!(report.uuid.as_deref(), Some("00112233-4455-6677-8899-aabbccddeeff"));
    assert_eq!(report.platform.as_deref(), Some("macos"));
    assert_eq!(report.min_os.as_deref(), Some("13.1.0"));
    assert_eq!(report.sdk.as_deref(), Some("14.0.0"));
    assert_eq!(report.entry_offset, Some(0x200));
    assert_eq!(report.entry_address, Some(0x1000));

    assert_eq!(report.dylibs.len(), 1);
    assert_eq!(report.dylibs[0].kind, "load");
    assert_eq!(report.dylibs[0].name, "/usr/lib/libSystem.B.dylib");
    assert_eq!(report.dylibs[0].current_version, "1.2.3");
    assert_eq!(report.dylibs[0].compatibility_version, "1.0.0");

    assert_eq!(report.segments.len(), 1);
    assert_eq!(report.segments[0].name, "__TEXT");
    assert!(report.segments[0].readable && report.segments[0].executable && !report.segments[0].writable);

    assert_eq!(report.sections.len(), 1);
    assert_eq!(report.sections[0].segment, "__TEXT");
    assert_eq!(report.sections[0].name, "__text");
    assert_eq!(report.sections[0].address, 0x1000);
    assert_eq!(report.sections[0].file_offset, 0x200);
    assert!(report.sections[0].executable);
}

#[test]
fn macho_sections_and_entropy_come_from_the_section_table() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    let sections = view.sections().expect("Mach-O sections");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].name, "__TEXT,__text");
    assert_eq!(sections[0].raw_pointer, 0x200);

    let entropy = view.entropy().expect("Mach-O entropy");
    assert_eq!(entropy.sections.len(), 1);
    assert_eq!(entropy.sections[0].name, "__TEXT,__text");
    assert_eq!(entropy.sections[0].size, 0x10);
    assert_eq!(entropy.overlay, None);
}

#[test]
fn macho_report_is_unsupported_outside_macho() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    assert_eq!(view.macho().unwrap_err().code(), "binary/unsupported");
}

/// `macho64_bytes()` plus an `LC_SYMTAB` command, three `nlist_64` entries at
/// 0x300 and a string table at 0x340.
fn macho64_symbols_bytes() -> Vec<u8> {
    let mut bytes = macho64_bytes();
    bytes.resize(0x400, 0);
    put_u32(&mut bytes, 16, 6);
    put_u32(&mut bytes, 20, 304);

    let symtab = 32 + 280;
    put_u32(&mut bytes, symtab, 0x2);
    put_u32(&mut bytes, symtab + 4, 24);
    put_u32(&mut bytes, symtab + 8, 0x300);
    put_u32(&mut bytes, symtab + 12, 3);
    put_u32(&mut bytes, symtab + 16, 0x340);
    put_u32(&mut bytes, symtab + 20, 0x40);

    let strings = b"\0_main\0_printf\0Llabel\0";
    bytes[0x340..0x340 + strings.len()].copy_from_slice(strings);

    let main = 0x300;
    put_u32(&mut bytes, main, 1);
    bytes[main + 4] = 0x0f;
    bytes[main + 5] = 1;
    put_u16(&mut bytes, main + 6, 0);
    put_u64(&mut bytes, main + 8, 0x1000);

    let printf = main + 16;
    put_u32(&mut bytes, printf, 7);
    bytes[printf + 4] = 0x01;
    bytes[printf + 5] = 0;
    put_u16(&mut bytes, printf + 6, 0x0200);
    put_u64(&mut bytes, printf + 8, 0);

    let label = main + 32;
    put_u32(&mut bytes, label, 15);
    bytes[label + 4] = 0x0e;
    bytes[label + 5] = 1;
    put_u16(&mut bytes, label + 6, 0);
    put_u64(&mut bytes, label + 8, 0x1004);
    bytes
}

#[test]
fn macho_symbols_decode_the_symtab() {
    let view = BinaryView::from_bytes("symbols.macho", macho64_symbols_bytes());
    let report = view.macho_symbols(None).expect("Mach-O symbols");

    assert_eq!(report.total, 3);
    assert!(!report.truncated);
    assert_eq!(report.string_table_size, 0x40);
    assert_eq!(report.symbols.len(), 3);

    assert_eq!(report.symbols[0].name, "_main");
    assert_eq!(report.symbols[0].kind, "section");
    assert_eq!(report.symbols[0].address, 0x1000);
    assert_eq!(report.symbols[0].section, Some(1));
    assert!(report.symbols[0].external);
    assert!(!report.symbols[0].debug);

    assert_eq!(report.symbols[1].name, "_printf");
    assert_eq!(report.symbols[1].kind, "undefined");
    assert_eq!(report.symbols[1].section, None);
    assert_eq!(report.symbols[1].descriptor, 0x0200);

    assert_eq!(report.symbols[2].name, "Llabel");
    assert_eq!(report.symbols[2].kind, "section");
    assert!(!report.symbols[2].external);
}

#[test]
fn macho_symbols_honour_the_limit() {
    let view = BinaryView::from_bytes("symbols.macho", macho64_symbols_bytes());
    let report = view.macho_symbols(Some(2)).expect("bounded Mach-O symbols");

    assert_eq!(report.total, 3);
    assert!(report.truncated);
    assert_eq!(report.symbols.len(), 2);
    assert_eq!(report.symbols[1].name, "_printf");
}

#[test]
fn macho_symbols_require_a_symtab() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    assert_eq!(view.macho_symbols(None).unwrap_err().code(), "binary/unsupported");

    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    assert_eq!(view.macho_symbols(None).unwrap_err().code(), "binary/unsupported");
}

fn put_be_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_be_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

/// A `fat_arch` container with an x86_64 and an arm64 slice.
fn fat32_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x2400];
    put_be_u32(&mut bytes, 0, 0xcafe_babe);
    put_be_u32(&mut bytes, 4, 2);

    put_be_u32(&mut bytes, 8, 0x0100_0007);
    put_be_u32(&mut bytes, 12, 3);
    put_be_u32(&mut bytes, 16, 0x1000);
    put_be_u32(&mut bytes, 20, 0x200);
    put_be_u32(&mut bytes, 24, 12);

    put_be_u32(&mut bytes, 28, 0x0100_000c);
    put_be_u32(&mut bytes, 32, 0);
    put_be_u32(&mut bytes, 36, 0x2000);
    put_be_u32(&mut bytes, 40, 0x300);
    put_be_u32(&mut bytes, 44, 14);

    bytes[0x1000..0x1004].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    bytes[0x2000..0x2004].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    bytes
}

#[test]
fn macho_fat_slices_report_architectures_and_ranges() {
    let view = BinaryView::from_bytes("universal.macho", fat32_bytes());
    let report = view.macho_slices().expect("fat slices");

    assert!(!report.is_fat64);
    assert_eq!(report.slices.len(), 2);

    assert_eq!(report.slices[0].index, 0);
    assert_eq!(report.slices[0].architecture, "x64");
    assert_eq!(report.slices[0].cpu_type, 0x0100_0007);
    assert_eq!(report.slices[0].offset, 0x1000);
    assert_eq!(report.slices[0].size, 0x200);
    assert_eq!(report.slices[0].alignment, 12);
    assert_eq!(report.slices[0].bits, Some(64));

    assert_eq!(report.slices[1].architecture, "arm64");
    assert_eq!(report.slices[1].offset, 0x2000);
    assert_eq!(report.slices[1].size, 0x300);

    let message = view.macho().unwrap_err().message().to_string();
    assert!(message.contains("macho-slices"), "unexpected message: {message}");
}

/// A `fat_arch_64` container with one arm64 slice and 64-bit ranges.
fn fat64_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1200];
    put_be_u32(&mut bytes, 0, 0xcafe_babf);
    put_be_u32(&mut bytes, 4, 1);
    put_be_u32(&mut bytes, 8, 0x0100_000c);
    put_be_u32(&mut bytes, 12, 2);
    put_be_u64(&mut bytes, 16, 0x1000);
    put_be_u64(&mut bytes, 24, 0x100);
    put_be_u32(&mut bytes, 32, 12);
    put_be_u32(&mut bytes, 36, 0);
    bytes[0x1000..0x1004].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    bytes
}

#[test]
fn macho_fat64_slices_use_64_bit_ranges() {
    let view = BinaryView::from_bytes("universal.macho", fat64_bytes());
    let report = view.macho_slices().expect("fat64 slices");

    assert!(report.is_fat64);
    assert_eq!(report.slices.len(), 1);
    assert_eq!(report.slices[0].architecture, "arm64");
    assert_eq!(report.slices[0].offset, 0x1000);
    assert_eq!(report.slices[0].size, 0x100);
    assert_eq!(report.slices[0].bits, Some(64));
}

#[test]
fn macho_fat_slice_outside_the_file_is_a_parse_error() {
    let mut bytes = fat32_bytes();
    put_be_u32(&mut bytes, 20, 0x4000);
    let view = BinaryView::from_bytes("truncated.macho", bytes);
    assert_eq!(view.macho_slices().unwrap_err().code(), "binary/parse");
}

#[test]
fn macho_slices_require_a_fat_container() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    assert_eq!(view.macho_slices().unwrap_err().code(), "binary/unsupported");

    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    assert_eq!(view.macho_slices().unwrap_err().code(), "binary/unsupported");
}

#[test]
fn macho_slice_extraction_writes_only_the_selected_slice() {
    let source = TempFile::new("universal");
    source.write(&fat32_bytes());
    let view = BinaryView::open(source.path()).expect("open fat container");
    let output = std::env::temp_dir().join(format!("open-ida-{}-extracted-slice.bin", std::process::id()));

    let report = view.extract_slice(1, &output).expect("extract slice");
    assert_eq!(report.index, 1);
    assert_eq!(report.architecture, "arm64");
    assert_eq!(report.offset, 0x2000);
    assert_eq!(report.size, 0x300);
    assert_eq!(report.output, output.display().to_string());

    let written = fs::read(&output).expect("read extracted slice");
    assert_eq!(written.len(), 0x300);
    assert_eq!(&written[..4], &[0xcf, 0xfa, 0xed, 0xfe]);
    assert_eq!(fs::read(source.path()).expect("read source").len(), 0x2400);
    fs::remove_file(&output).ok();

    assert_eq!(view.extract_slice(2, &output).unwrap_err().code(), "binary/range");
    assert_eq!(view.extract_slice(0, source.path()).unwrap_err().code(), "binary/io");

    let thin = BinaryView::from_bytes("thin.macho", macho64_bytes());
    assert_eq!(thin.extract_slice(0, &output).unwrap_err().code(), "binary/unsupported");
}

#[test]
fn pe_resources_walk_the_directory_tree() {
    let mut bytes = pe_bytes();
    put_u32(&mut bytes, 0x98 + 112 + 2 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 2 * 8 + 4, 0x100);

    let base = 0x400;
    put_u16(&mut bytes, base + 12, 1);
    put_u16(&mut bytes, base + 14, 1);
    put_u32(&mut bytes, base + 0x10, 0x8000_00c0);
    put_u32(&mut bytes, base + 0x14, 0x8000_0020);
    put_u32(&mut bytes, base + 0x18, 16);
    put_u32(&mut bytes, base + 0x1c, 0x8000_0070);

    put_u16(&mut bytes, base + 0x2c, 1);
    put_u32(&mut bytes, base + 0x30, 1);
    put_u32(&mut bytes, base + 0x34, 0x8000_0040);
    put_u16(&mut bytes, base + 0x4c, 1);
    put_u32(&mut bytes, base + 0x50, 0x409);
    put_u32(&mut bytes, base + 0x54, 0x60);
    put_u32(&mut bytes, base + 0x60, 0x1000);
    put_u32(&mut bytes, base + 0x64, 0x10);
    put_u32(&mut bytes, base + 0x68, 0);

    put_u16(&mut bytes, base + 0x7c, 1);
    put_u32(&mut bytes, base + 0x80, 1);
    put_u32(&mut bytes, base + 0x84, 0x8000_0090);
    put_u16(&mut bytes, base + 0x9c, 1);
    put_u32(&mut bytes, base + 0xa0, 0x409);
    put_u32(&mut bytes, base + 0xa4, 0xb0);
    put_u32(&mut bytes, base + 0xb0, 0x1000);
    put_u32(&mut bytes, base + 0xb4, 0x20);
    put_u32(&mut bytes, base + 0xb8, 1200);

    put_u16(&mut bytes, base + 0xc0, 4);
    for (index, unit) in "TEST".encode_utf16().enumerate() {
        put_u16(&mut bytes, base + 0xc2 + index * 2, unit);
    }

    let view = BinaryView::from_bytes("resources.exe", bytes);
    let report = view.resources().expect("PE resources");

    assert!(report.present);
    assert_eq!(report.total, 2);
    assert!(!report.truncated);
    assert_eq!(report.resources.len(), 2);

    assert_eq!(report.resources[0].resource_type, "TEST");
    assert_eq!(report.resources[0].name, "#1");
    assert_eq!(report.resources[0].language, 0x409);
    assert_eq!(report.resources[0].data_rva, 0x1000);
    assert_eq!(report.resources[0].size, 0x10);
    assert_eq!(report.resources[0].code_page, 0);

    assert_eq!(report.resources[1].resource_type, "VERSION");
    assert_eq!(report.resources[1].language, 0x409);
    assert_eq!(report.resources[1].size, 0x20);
    assert_eq!(report.resources[1].code_page, 1200);
}

#[test]
fn pe_resources_report_absence_and_reject_non_pe() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    let report = view.resources().expect("PE resources");
    assert!(!report.present);
    assert_eq!(report.total, 0);
    assert!(report.resources.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.resources().unwrap_err().code(), "binary/unsupported");
}

/// `pe_bytes()` plus two base relocation blocks behind data directory 5.
fn pe_relocations_bytes() -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u32(&mut bytes, 0x98 + 112 + 5 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 5 * 8 + 4, 24);

    let first = 0x400;
    put_u32(&mut bytes, first, 0x1000);
    put_u32(&mut bytes, first + 4, 16);
    put_u16(&mut bytes, first + 8, 0x3010);
    put_u16(&mut bytes, first + 10, 0x0000);
    put_u16(&mut bytes, first + 12, 0xa000);
    put_u16(&mut bytes, first + 14, 0x3018);

    let second = 0x410;
    put_u32(&mut bytes, second, 0x2000);
    put_u32(&mut bytes, second + 4, 8);
    bytes
}

#[test]
fn pe_relocations_decode_blocks_and_fixup_types() {
    let view = BinaryView::from_bytes("reloc.exe", pe_relocations_bytes());
    let report = view.relocations().expect("PE relocations");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.total_blocks, 2);
    assert_eq!(report.total_entries, 4);
    assert_eq!(report.blocks.len(), 2);

    assert_eq!(report.blocks[0].page_rva, 0x1000);
    assert_eq!(report.blocks[0].block_size, 16);
    assert_eq!(report.blocks[0].entries, 4);
    assert_eq!(report.blocks[0].kinds.len(), 3);
    assert_eq!(report.blocks[0].kinds[0].kind, "ABSOLUTE");
    assert_eq!(report.blocks[0].kinds[0].count, 1);
    assert_eq!(report.blocks[0].kinds[1].kind, "HIGHLOW");
    assert_eq!(report.blocks[0].kinds[1].count, 2);
    assert_eq!(report.blocks[0].kinds[2].kind, "DIR64");

    assert_eq!(report.blocks[1].page_rva, 0x2000);
    assert_eq!(report.blocks[1].entries, 0);
    assert!(report.blocks[1].kinds.is_empty());

    assert_eq!(report.kinds.len(), 3);
    assert_eq!(report.kinds[0].kind, "ABSOLUTE");
    assert_eq!(report.kinds[1].count, 2);
    assert_eq!(report.kinds[2].kind, "DIR64");
}

#[test]
fn pe_relocations_report_absence_and_reject_non_pe() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    let report = view.relocations().expect("PE relocations");
    assert!(!report.present);
    assert_eq!(report.total_blocks, 0);
    assert_eq!(report.total_entries, 0);
    assert!(report.blocks.is_empty());
    assert!(report.kinds.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.relocations().unwrap_err().code(), "binary/unsupported");
}

/// ELF64 with `PT_LOAD`, `PT_INTERP` and `PT_DYNAMIC` program headers.
fn elf_dynamic_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x500];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, 0x401000);
    put_u64(&mut bytes, 32, 0x40);
    put_u16(&mut bytes, 54, 56);
    put_u16(&mut bytes, 56, 3);

    put_u32(&mut bytes, 0x40, 1);
    put_u32(&mut bytes, 0x44, 4);
    put_u64(&mut bytes, 0x48, 0);
    put_u64(&mut bytes, 0x50, 0x400000);
    put_u64(&mut bytes, 0x60, 0x500);
    put_u64(&mut bytes, 0x68, 0x500);
    put_u64(&mut bytes, 0x70, 0x1000);

    put_u32(&mut bytes, 0x78, 3);
    put_u32(&mut bytes, 0x7c, 4);
    put_u64(&mut bytes, 0x80, 0x200);
    put_u64(&mut bytes, 0x88, 0x400200);
    put_u64(&mut bytes, 0x98, 28);
    put_u64(&mut bytes, 0xa0, 28);
    put_u64(&mut bytes, 0xa8, 1);

    put_u32(&mut bytes, 0xb0, 2);
    put_u32(&mut bytes, 0xb4, 6);
    put_u64(&mut bytes, 0xb8, 0x300);
    put_u64(&mut bytes, 0xc0, 0x400300);
    put_u64(&mut bytes, 0xd0, 128);
    put_u64(&mut bytes, 0xd8, 128);
    put_u64(&mut bytes, 0xe0, 8);

    let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
    bytes[0x200..0x200 + interpreter.len()].copy_from_slice(interpreter);

    let dynstr = b"\0libc.so.6\0libm.so.6\0libsample.so\0/opt/lib:/usr/lib\0/usr/local/lib\0";
    bytes[0x240..0x240 + dynstr.len()].copy_from_slice(dynstr);

    let entries = [
        (1u64, 1u64),
        (1, 11),
        (14, 21),
        (15, 34),
        (29, 52),
        (5, 0x400240),
        (10, dynstr.len() as u64),
        (0, 0),
    ];
    for (index, (tag, value)) in entries.iter().enumerate() {
        let base = 0x300 + index * 16;
        put_u64(&mut bytes, base, *tag);
        put_u64(&mut bytes, base + 8, *value);
    }
    bytes
}

#[test]
fn elf_dynamic_reports_interpreter_needed_and_search_paths() {
    let view = BinaryView::from_bytes("app.elf", elf_dynamic_bytes());
    let report = view.dynamic().expect("ELF dynamic report");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.interpreter.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
    assert_eq!(report.soname.as_deref(), Some("libsample.so"));
    assert_eq!(report.needed, ["libc.so.6", "libm.so.6"]);
    assert_eq!(report.rpath, ["/opt/lib", "/usr/lib"]);
    assert_eq!(report.runpath, ["/usr/local/lib"]);
    assert_eq!(report.dynamic_entries, 7);
}

#[test]
fn elf_dynamic_reports_static_images_and_rejects_other_containers() {
    let view = BinaryView::from_bytes("static.elf", elf64_bytes());
    let report = view.dynamic().expect("ELF dynamic report");
    assert!(!report.present);
    assert_eq!(report.interpreter, None);
    assert!(report.needed.is_empty());
    assert!(report.rpath.is_empty());

    let pe = BinaryView::from_bytes("app.exe", pe_bytes());
    assert_eq!(pe.dynamic().unwrap_err().code(), "binary/unsupported");
}

#[test]
fn pe_certificates_decode_entries_and_pkcs7_shape() {
    let mut bytes = pe_bytes();
    let (offset, size) = (0x500u32, 0x18u32);
    let directory = 0x98 + 112 + 4 * 8;
    put_u32(&mut bytes, directory, offset);
    put_u32(&mut bytes, directory + 4, size);

    put_u32(&mut bytes, 0x500, 12);
    put_u16(&mut bytes, 0x504, 0x0200);
    put_u16(&mut bytes, 0x506, 2);
    bytes[0x508..0x50c].copy_from_slice(&[0x30, 0x82, 0x00, 0x10]);

    put_u32(&mut bytes, 0x510, 8);
    put_u16(&mut bytes, 0x514, 0x0100);
    put_u16(&mut bytes, 0x516, 1);

    let view = BinaryView::from_bytes("signed.exe", bytes);
    let report = view.certificates().expect("PE certificates");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.total, 2);
    assert_eq!(report.directory_size, 0x18);
    assert_eq!(report.certificates.len(), 2);

    assert_eq!(report.certificates[0].offset, 0x500);
    assert_eq!(report.certificates[0].length, 12);
    assert_eq!(report.certificates[0].revision, "2.0");
    assert_eq!(report.certificates[0].certificate_type, "PKCS_SIGNED_DATA");
    assert_eq!(report.certificates[0].payload_size, 4);
    assert!(report.certificates[0].pkcs7);

    assert_eq!(report.certificates[1].offset, 0x510);
    assert_eq!(report.certificates[1].revision, "1.0");
    assert_eq!(report.certificates[1].certificate_type, "X509");
    assert_eq!(report.certificates[1].payload_size, 0);
    assert!(!report.certificates[1].pkcs7);
}

#[test]
fn pe_certificates_report_absence_and_reject_non_pe() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    let report = view.certificates().expect("PE certificates");
    assert!(!report.present);
    assert_eq!(report.total, 0);
    assert!(report.certificates.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.certificates().unwrap_err().code(), "binary/unsupported");
}

#[test]
fn pe_tls_decodes_callbacks_and_maps_them_through_the_image_base() {
    let view = BinaryView::from_bytes("tls.exe", pe_tls_bytes());
    let report = view.tls().expect("PE TLS");

    assert!(report.present);
    assert!(report.is64);
    assert!(!report.truncated);
    assert_eq!(report.directory_rva, 0x2000);
    assert_eq!(report.directory_size, 40);
    assert_eq!(report.raw_data_start, 0x1_4000_2010);
    assert_eq!(report.raw_data_end, 0x1_4000_2020);
    assert_eq!(report.index_address, 0x1_4000_2030);
    assert_eq!(report.callbacks_address, 0x1_4000_2040);
    assert_eq!(report.callbacks_rva, Some(0x2040));
    assert_eq!(report.size_of_zero_fill, 0x10);
    assert_eq!(report.characteristics, 0x0030_0000);

    assert_eq!(report.callbacks.len(), 2);
    assert_eq!(report.callbacks[0].address, 0x1_4000_1010);
    assert_eq!(report.callbacks[0].rva, Some(0x1010));
    assert_eq!(report.callbacks[0].offset, Some(0x210));
    assert_eq!(report.callbacks[1].rva, Some(0x1020));
    assert_eq!(report.callbacks[1].offset, Some(0x220));
}

#[test]
fn pe_tls_reports_absence_and_rejects_non_pe() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    let report = view.tls().expect("PE TLS");
    assert!(!report.present);
    assert!(report.callbacks.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.tls().unwrap_err().code(), "binary/unsupported");
}

/// `pe_bytes()` plus a PE32+ TLS directory at RVA 0x2000 and two callbacks.
fn pe_tls_bytes() -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u32(&mut bytes, 0x98 + 112 + 9 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 9 * 8 + 4, 40);

    let base = 0x400;
    let image_base = 0x1_4000_0000u64;
    put_u64(&mut bytes, base, image_base + 0x2010);
    put_u64(&mut bytes, base + 8, image_base + 0x2020);
    put_u64(&mut bytes, base + 16, image_base + 0x2030);
    put_u64(&mut bytes, base + 24, image_base + 0x2040);
    put_u32(&mut bytes, base + 32, 0x10);
    put_u32(&mut bytes, base + 36, 0x0030_0000);

    put_u64(&mut bytes, 0x440, image_base + 0x1010);
    put_u64(&mut bytes, 0x448, image_base + 0x1020);
    put_u64(&mut bytes, 0x450, 0);
    bytes
}

#[test]
fn pe_load_config_decodes_guard_metadata() {
    let view = BinaryView::from_bytes("config.exe", pe_load_config_bytes());
    let report = view.load_config().expect("PE load configuration");

    assert!(report.present);
    assert!(report.is64);
    assert!(!report.truncated);
    assert_eq!(report.size, 0xa0);
    assert_eq!(report.timestamp, 0x0102_0304);
    assert_eq!(report.global_flags_clear, 1);
    assert_eq!(report.global_flags_set, 2);
    assert_eq!(report.critical_section_default_timeout, 1000);
    assert_eq!(report.security_cookie, 0x1_4000_2010);
    assert_eq!(report.se_handler_table, 0x1_4000_2020);
    assert_eq!(report.se_handler_count, 2);
    assert_eq!(report.guard_cf_function_table, 0x1_4000_2040);
    assert_eq!(report.guard_cf_function_count, 4);
    assert_eq!(report.guard_flags, 0x0010_0500);
    assert_eq!(
        report.guard_flags_text,
        vec!["CF_INSTRUMENTED", "CF_FUNCTION_TABLE_PRESENT", "RETPOLINE_PRESENT"]
    );
    assert_eq!(report.code_integrity.flags, 1);
    assert_eq!(report.code_integrity.catalog, 0x1234);
    assert_eq!(report.code_integrity.catalog_offset, 0x800);
}

#[test]
fn pe_load_config_reports_absence_and_rejects_non_pe() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    let report = view.load_config().expect("PE load configuration");
    assert!(!report.present);
    assert!(report.guard_flags_text.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.load_config().unwrap_err().code(), "binary/unsupported");
}

/// `pe_bytes()` plus a PE32+ load configuration table at RVA 0x2000.
fn pe_load_config_bytes() -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u32(&mut bytes, 0x98 + 112 + 10 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 10 * 8 + 4, 0xa0);

    let base = 0x400;
    let image_base = 0x1_4000_0000u64;
    put_u32(&mut bytes, base, 0xa0);
    put_u32(&mut bytes, base + 4, 0x0102_0304);
    put_u16(&mut bytes, base + 8, 1);
    put_u32(&mut bytes, base + 0x0c, 1);
    put_u32(&mut bytes, base + 0x10, 2);
    put_u32(&mut bytes, base + 0x14, 1000);
    put_u64(&mut bytes, base + 0x18, 0x1000);
    put_u64(&mut bytes, base + 0x20, 0x1_0000);
    put_u64(&mut bytes, base + 0x28, image_base + 0x1010);
    put_u64(&mut bytes, base + 0x30, 0x10_0000);
    put_u64(&mut bytes, base + 0x38, 0x20_0000);
    put_u64(&mut bytes, base + 0x40, 3);
    put_u32(&mut bytes, base + 0x48, 2);
    put_u64(&mut bytes, base + 0x58, image_base + 0x2010);
    put_u64(&mut bytes, base + 0x60, image_base + 0x2020);
    put_u64(&mut bytes, base + 0x68, 2);
    put_u64(&mut bytes, base + 0x70, image_base + 0x1030);
    put_u64(&mut bytes, base + 0x80, image_base + 0x2040);
    put_u64(&mut bytes, base + 0x88, 4);
    put_u32(&mut bytes, base + 0x90, 0x0010_0500);
    put_u16(&mut bytes, base + 0x94, 1);
    put_u16(&mut bytes, base + 0x96, 0x1234);
    put_u32(&mut bytes, base + 0x98, 0x800);
    bytes
}

#[test]
fn macho_code_signature_decodes_the_code_directory() {
    let view = BinaryView::from_bytes("signed", macho_signature_bytes());
    let report = view.code_signature().expect("Mach-O code signature");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.data_offset, 0x200);
    assert_eq!(report.data_size, 0x100);
    assert_eq!(report.magic.as_deref(), Some("embedded-signature"));
    assert_eq!(report.blob_count, Some(1));
    assert_eq!(report.blob_types, vec!["CodeDirectory"]);

    let code = report.code_directory.as_ref().expect("CodeDirectory");
    assert_eq!(code.version, 0x20200);
    assert_eq!(code.flags, 2);
    assert_eq!(code.flag_text, vec!["HARD"]);
    assert_eq!(code.hash_type, "SHA256");
    assert_eq!(code.hash_size, 32);
    assert_eq!(code.page_size, 4096);
    assert_eq!(code.code_limit, 0x1000);
    assert_eq!(code.identifier, "com.example.app");
    assert_eq!(code.team_id.as_deref(), Some("TEAM"));
    assert_eq!(code.code_slots, 2);
    assert_eq!(code.special_slots, 0);
}

#[test]
fn macho_code_signature_reports_absence_and_rejects_non_macho() {
    let mut unsigned = macho_signature_bytes();
    put_u32(&mut unsigned, 16, 0);
    let view = BinaryView::from_bytes("unsigned", unsigned);
    let report = view.code_signature().expect("Mach-O code signature");
    assert!(!report.present);
    assert!(report.code_directory.is_none());

    let pe = BinaryView::from_bytes("app.exe", pe_bytes());
    assert_eq!(pe.code_signature().unwrap_err().code(), "binary/unsupported");
}

/// Mach-O64 with one `LC_CODE_SIGNATURE` and an embedded SuperBlob.
fn macho_signature_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x400];
    bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32(&mut bytes, 4, 0x0100_0007);
    put_u32(&mut bytes, 8, 3);
    put_u32(&mut bytes, 12, 2);
    put_u32(&mut bytes, 16, 1);
    put_u32(&mut bytes, 20, 16);
    put_u32(&mut bytes, 32, 0x1d);
    put_u32(&mut bytes, 36, 16);
    put_u32(&mut bytes, 40, 0x200);
    put_u32(&mut bytes, 44, 0x100);

    put_be_u32(&mut bytes, 0x200, 0xfade_0cc0);
    put_be_u32(&mut bytes, 0x204, 0x100);
    put_be_u32(&mut bytes, 0x208, 1);
    put_be_u32(&mut bytes, 0x20c, 0);
    put_be_u32(&mut bytes, 0x210, 0x20);

    let blob = 0x220;
    put_be_u32(&mut bytes, blob, 0xfade_0c02);
    put_be_u32(&mut bytes, blob + 4, 0x60);
    put_be_u32(&mut bytes, blob + 8, 0x20200);
    put_be_u32(&mut bytes, blob + 12, 2);
    put_be_u32(&mut bytes, blob + 20, 0x40);
    put_be_u32(&mut bytes, blob + 28, 2);
    put_be_u32(&mut bytes, blob + 32, 0x1000);
    bytes[blob + 36] = 32;
    bytes[blob + 37] = 2;
    bytes[blob + 39] = 12;
    put_be_u32(&mut bytes, blob + 48, 0x58);
    bytes[blob + 0x40..blob + 0x4f].copy_from_slice(b"com.example.app");
    bytes[blob + 0x4f] = 0;
    bytes[blob + 0x58..blob + 0x5d].copy_from_slice(b"TEAM\0");
    bytes
}

#[test]
fn elf_segments_decode_the_program_header_table() {
    let view = BinaryView::from_bytes("notes.elf", elf_notes_bytes());
    let report = view.segments().expect("ELF segments");

    assert!(report.present);
    assert!(report.is64);
    assert!(!report.truncated);
    assert_eq!(report.total, 1);
    assert_eq!(report.segments.len(), 1);
    let segment = &report.segments[0];
    assert_eq!(segment.index, 0);
    assert_eq!(segment.segment_type, "PT_NOTE");
    assert_eq!(segment.type_value, 4);
    assert_eq!(segment.offset, 0x200);
    assert_eq!(segment.virtual_address, 0x400200);
    assert_eq!(segment.file_size, 0x80);
    assert_eq!(segment.memory_size, 0x80);
    assert_eq!(segment.flags, 4);
    assert_eq!(segment.flag_text, "R");
    assert_eq!(segment.alignment, 4);
}

#[test]
fn elf_segments_report_absence_and_reject_non_elf() {
    let view = BinaryView::from_bytes("static.elf", elf64_bytes());
    let report = view.segments().expect("ELF segments");
    assert!(!report.present);
    assert_eq!(report.total, 0);
    assert!(report.segments.is_empty());

    let pe = BinaryView::from_bytes("app.exe", pe_bytes());
    assert_eq!(pe.segments().unwrap_err().code(), "binary/unsupported");
}

#[test]
fn elf_notes_decode_build_id_abi_tag_and_properties() {
    let view = BinaryView::from_bytes("notes.elf", elf_notes_bytes());
    let report = view.notes().expect("ELF notes");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.source.as_deref(), Some("segments"));
    assert_eq!(report.total, 3);
    assert_eq!(report.notes.len(), 3);
    assert_eq!(report.build_id.as_deref(), Some("0102030405060708090a0b0c0d0e0f1011121314"));

    let abi = report.abi_tag.as_ref().expect("GNU ABI tag");
    assert_eq!(abi.os, "Linux");
    assert_eq!((abi.major, abi.minor, abi.subminor), (6, 8, 0));

    assert_eq!(report.notes[0].owner, "GNU");
    assert_eq!(report.notes[0].note_type, "NT_GNU_BUILD_ID");
    assert_eq!(report.notes[1].note_type, "NT_GNU_ABI_TAG");
    assert_eq!(report.notes[1].description, "Linux 6.8.0");
    assert_eq!(report.notes[2].note_type, "NT_GNU_PROPERTY_TYPE_0");

    assert_eq!(report.properties.len(), 1);
    assert_eq!(report.properties[0].property_type, "X86_FEATURE_1_AND");
    assert_eq!(report.properties[0].data_size, 4);
    assert_eq!(report.properties[0].data, "03000000");
}

#[test]
fn elf_notes_report_absence_and_reject_non_elf() {
    let view = BinaryView::from_bytes("static.elf", elf64_bytes());
    let report = view.notes().expect("ELF notes");
    assert!(!report.present);
    assert_eq!(report.source, None);
    assert_eq!(report.build_id, None);
    assert!(report.notes.is_empty());

    let pe = BinaryView::from_bytes("app.exe", pe_bytes());
    assert_eq!(pe.notes().unwrap_err().code(), "binary/unsupported");
}

/// ELF64 with one `PT_NOTE` segment holding build-id, ABI-tag and property notes.
fn elf_notes_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x300];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, 0x401000);
    put_u64(&mut bytes, 32, 0x40);
    put_u16(&mut bytes, 52, 64);
    put_u16(&mut bytes, 54, 56);
    put_u16(&mut bytes, 56, 1);

    put_u32(&mut bytes, 0x40, 4);
    put_u32(&mut bytes, 0x44, 4);
    put_u64(&mut bytes, 0x48, 0x200);
    put_u64(&mut bytes, 0x50, 0x400200);
    put_u64(&mut bytes, 0x60, 0x80);
    put_u64(&mut bytes, 0x68, 0x80);
    put_u64(&mut bytes, 0x70, 4);

    // GNU build id: 20-byte description.
    put_u32(&mut bytes, 0x200, 4);
    put_u32(&mut bytes, 0x204, 20);
    put_u32(&mut bytes, 0x208, 3);
    bytes[0x20c..0x210].copy_from_slice(b"GNU\0");
    for index in 0..20 {
        bytes[0x210 + index] = (index + 1) as u8;
    }

    // GNU ABI tag: os, major, minor, subminor.
    put_u32(&mut bytes, 0x224, 4);
    put_u32(&mut bytes, 0x228, 16);
    put_u32(&mut bytes, 0x22c, 1);
    bytes[0x230..0x234].copy_from_slice(b"GNU\0");
    put_u32(&mut bytes, 0x234, 0);
    put_u32(&mut bytes, 0x238, 6);
    put_u32(&mut bytes, 0x23c, 8);
    put_u32(&mut bytes, 0x240, 0);

    // GNU property: one X86_FEATURE_1_AND entry with IBT + SHSTK.
    put_u32(&mut bytes, 0x244, 4);
    put_u32(&mut bytes, 0x248, 16);
    put_u32(&mut bytes, 0x24c, 5);
    bytes[0x250..0x254].copy_from_slice(b"GNU\0");
    put_u32(&mut bytes, 0x254, 0xc000_0002);
    put_u32(&mut bytes, 0x258, 4);
    put_u32(&mut bytes, 0x25c, 3);
    bytes
}

#[test]
fn pe_mitigations_read_the_optional_header() {
    let mut bytes = pe_bytes();
    put_u16(&mut bytes, 0x98 + 0x4a, 0x0160);

    let view = BinaryView::from_bytes("hardened.exe", bytes);
    let report = view.mitigations().expect("PE mitigations");

    assert_eq!(report.dll_characteristics, 0x0160);
    assert!(report.aslr);
    assert!(report.dep);
    assert!(report.high_entropy_va);
    assert!(!report.cfg);
    assert!(!report.force_integrity);
    assert!(!report.no_seh);
    assert!(!report.relocations_present);
    assert!(!report.signed);
    assert!(report.writable_executable_sections.is_empty());
    assert_eq!(report.security_cookie, None);
    assert_eq!(report.guard_flags, None);

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.mitigations().unwrap_err().code(), "binary/unsupported");
}

#[test]
fn pe_mitigations_detect_wx_relocations_and_load_config() {
    let mut bytes = pe_bytes();
    bytes.resize(0x800, 0);
    put_u16(&mut bytes, 0x98 + 0x4a, 0x0000);
    put_u32(&mut bytes, 0x188 + 36, 0xe000_0020);

    put_u32(&mut bytes, 0x98 + 112 + 5 * 8, 0x1000);
    put_u32(&mut bytes, 0x98 + 112 + 5 * 8 + 4, 12);
    put_u32(&mut bytes, 0x98 + 112 + 4 * 8, 0x700);
    put_u32(&mut bytes, 0x98 + 112 + 4 * 8 + 4, 8);
    put_u32(&mut bytes, 0x98 + 112 + 10 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 10 * 8 + 4, 0x94);

    put_u32(&mut bytes, 0x400, 0x94);
    put_u64(&mut bytes, 0x400 + 0x58, 0x1_4000_1000);
    put_u32(&mut bytes, 0x400 + 0x90, 0x100);

    let view = BinaryView::from_bytes("loose.exe", bytes);
    let report = view.mitigations().expect("PE mitigations");

    assert!(!report.aslr);
    assert!(!report.dep);
    assert!(report.cfg);
    assert!(report.relocations_present);
    assert!(report.signed);
    assert_eq!(report.writable_executable_sections.len(), 1);
    assert_eq!(report.writable_executable_sections[0].name, ".text");
    assert_eq!(report.security_cookie, Some(true));
    assert_eq!(report.guard_flags, Some(0x100));
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
fn entropy_of_uniform_and_high_entropy_data() {
    let uniform = BinaryView::from_bytes("zeros.bin", vec![0u8; 256]);
    let report = uniform.entropy().expect("uniform entropy");
    assert_eq!(report.file_size, 256);
    assert_eq!(report.file_entropy, 0.0);
    assert!(report.sections.is_empty());
    assert_eq!(report.overlay, None);

    let spread: Vec<u8> = (0..=255u8).collect();
    let high = BinaryView::from_bytes("spread.bin", spread);
    let report = high.entropy().expect("high entropy");
    assert_eq!(report.file_entropy, 8.0);
}

#[test]
fn entropy_reports_sections_and_the_pe_overlay() {
    let mut bytes = pe_bytes();
    for (index, byte) in bytes[0x200..0x400].iter_mut().enumerate() {
        *byte = index as u8;
    }
    bytes.extend_from_slice(&[0xaa; 16]);
    let view = BinaryView::from_bytes("overlay.exe", bytes);

    let report = view.entropy().expect("entropy");
    assert_eq!(report.file_size, 0x610);
    assert_eq!(report.sections.len(), 2);

    let text = report.sections.iter().find(|section| section.name == ".text").expect("text section");
    assert_eq!(text.offset, 0x200);
    assert_eq!(text.size, 0x200);
    assert_eq!(text.entropy, 8.0);

    let data = report.sections.iter().find(|section| section.name == ".data").expect("data section");
    assert_eq!(data.entropy, 0.0);

    let overlay = report.overlay.expect("overlay");
    assert_eq!(overlay.offset, 0x600);
    assert_eq!(overlay.size, 16);
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
