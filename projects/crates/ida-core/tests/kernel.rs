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
    BinaryView, CarveOptions, DisassembleOptions, DisassemblySyntax, DumpOptions, FindOptions, IdaError,
    InflateFormat, InflateOptions, OpenIda, OpenIdaOptions, PycFormat, PycOptions, SearchMode,
    SearchOptions, StringEncoding, StringsOptions, TauriAssetsOptions, UnpackFormat, UnpackOptions, UnpackReport, scan_assets,
    sniff_pyc,
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
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Both, min_length: 3, limit: 2, ..StringsOptions::default() })
        .expect("bounded strings");

    assert_eq!(report.total, 3);
    assert_eq!(report.hits.len(), 2);
    assert!(report.truncated);
    assert_eq!(report.limit, 2);
    assert_eq!(report.hits[0].value, "alpha");
    assert_eq!(report.hits[1].value, "beta");
}

#[test]
fn encoded_strings_page_with_skip_and_uncap_with_all() {
    let view = BinaryView::from_bytes("paged.bin", b"\x00alpha\x00beta\x00gamma\x00delta\x00".to_vec());
    let paged = view
        .strings_encoded(&StringsOptions {
            encoding: StringEncoding::Ascii,
            min_length: 3,
            limit: 2,
            skip: 2,
            ..StringsOptions::default()
        })
        .expect("paged strings");

    assert_eq!(paged.total, 4);
    assert_eq!(paged.skip, 2);
    assert!(!paged.all);
    assert!(paged.truncated);
    let values: Vec<&str> = paged.hits.iter().map(|hit| hit.value.as_str()).collect();
    assert_eq!(values, vec!["gamma", "delta"]);

    let tail = view
        .strings_encoded(&StringsOptions {
            encoding: StringEncoding::Ascii,
            min_length: 3,
            limit: 100,
            skip: 9,
            ..StringsOptions::default()
        })
        .expect("skip past the end");
    assert_eq!(tail.skip, 4);
    assert!(tail.hits.is_empty());
    assert!(tail.truncated);

    let uncapped = view
        .strings_encoded(&StringsOptions {
            encoding: StringEncoding::Ascii,
            min_length: 3,
            limit: 1,
            all: true,
            ..StringsOptions::default()
        })
        .expect("uncapped strings");
    assert!(uncapped.all);
    assert_eq!(uncapped.limit, 2_000_000);
    assert_eq!(uncapped.hits.len(), 4);
    assert!(!uncapped.truncated);

    let parsed: StringsOptions = serde_json::from_str(r#"{"skip": 3, "all": true}"#).expect("paged wire options");
    assert_eq!(parsed.skip, 3);
    assert!(parsed.all);
    let defaults: StringsOptions = serde_json::from_str("{}").expect("default wire options");
    assert_eq!(defaults.skip, 0);
    assert!(!defaults.all);
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

#[test]
fn macho_function_starts_decode_uleb128_deltas() {
    let view = BinaryView::from_bytes("starts.macho", macho64_function_starts_bytes());
    let report = view.macho_function_starts(None).expect("Mach-O function starts");

    assert_eq!(report.image_base, 0x1000);
    assert_eq!(report.total, 3);
    assert!(!report.truncated);
    assert_eq!(report.addresses, vec![0x1100, 0x1120, 0x1160]);

    let bounded = BinaryView::from_bytes("starts.macho", macho64_function_starts_bytes())
        .macho_function_starts(Some(2))
        .expect("bounded function starts");
    assert_eq!(bounded.total, 3);
    assert!(bounded.truncated);
    assert_eq!(bounded.addresses, vec![0x1100, 0x1120]);
}

#[test]
fn macho_function_starts_require_the_command() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    assert_eq!(view.macho_function_starts(None).unwrap_err().code(), "binary/unsupported");

    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    assert_eq!(view.macho_function_starts(None).unwrap_err().code(), "binary/unsupported");
}

/// `macho64_bytes()` plus `LC_FUNCTION_STARTS` at 0x300 holding the deltas
/// 0x100, 0x20, 0x40 and a terminal zero.
fn macho64_function_starts_bytes() -> Vec<u8> {
    let mut bytes = macho64_bytes();
    bytes.resize(0x320, 0);
    put_u32(&mut bytes, 16, 6);
    put_u32(&mut bytes, 20, 304);

    let command = 32 + 280;
    put_u32(&mut bytes, command, 0x26);
    put_u32(&mut bytes, command + 4, 16);
    put_u32(&mut bytes, command + 8, 0x300);
    put_u32(&mut bytes, command + 12, 8);

    bytes[0x300] = 0x80;
    bytes[0x301] = 0x02;
    bytes[0x302] = 0x20;
    bytes[0x303] = 0x40;
    bytes[0x304] = 0x00;
    bytes
}

#[test]
fn macho_exports_walk_the_dyld_trie() {
    let view = BinaryView::from_bytes("exports.macho", macho64_exports_bytes());
    let report = view.macho_exports().expect("Mach-O exports");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.total, 2);
    assert_eq!(report.exports.len(), 2);

    let first = &report.exports[0];
    assert_eq!(first.name, "_foo");
    assert_eq!(first.flags, 0);
    assert!(first.flag_names.is_empty());
    assert_eq!(first.address, Some(0x1000));
    assert_eq!(first.other, None);

    let second = &report.exports[1];
    assert_eq!(second.name, "_bar");
    assert_eq!(second.flags, 1);
    assert_eq!(second.flag_names, vec!["WEAK"]);
    assert_eq!(second.address, Some(0x1040));
}

#[test]
fn macho_exports_report_absence_and_reject_non_macho() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    assert!(!view.macho_exports().expect("empty export trie").present);

    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    assert_eq!(view.macho_exports().unwrap_err().code(), "binary/unsupported");
}

#[test]
fn macho_encryption_reports_the_crypt_range() {
    let view = BinaryView::from_bytes("encrypted.macho", macho64_encryption_bytes());
    let report = view.macho_encryption().expect("Mach-O encryption");

    assert!(report.present);
    assert!(report.is_64);
    assert_eq!(report.crypt_offset, 0x2000);
    assert_eq!(report.crypt_size, 0x1000);
    assert_eq!(report.crypt_id, 1);
    assert!(report.encrypted);
}

#[test]
fn macho_encryption_reports_absence_and_rejects_non_macho() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    let report = view.macho_encryption().expect("no encryption command");
    assert!(!report.present);
    assert!(!report.encrypted);

    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    assert_eq!(view.macho_encryption().unwrap_err().code(), "binary/unsupported");
}

/// `macho64_bytes()` plus `LC_ENCRYPTION_INFO_64` describing a 0x1000-byte
/// crypt range at file offset 0x2000 with cryptid 1.
fn macho64_encryption_bytes() -> Vec<u8> {
    let mut bytes = macho64_bytes();
    put_u32(&mut bytes, 16, 6);
    put_u32(&mut bytes, 20, 304);

    let command = 32 + 280;
    put_u32(&mut bytes, command, 0x2c);
    put_u32(&mut bytes, command + 4, 24);
    put_u32(&mut bytes, command + 8, 0x2000);
    put_u32(&mut bytes, command + 12, 0x1000);
    put_u32(&mut bytes, command + 16, 1);
    put_u32(&mut bytes, command + 20, 0);
    bytes
}

#[test]
fn macho_chained_fixups_report_imports_and_starts() {
    let view = BinaryView::from_bytes("chained.macho", macho64_chained_fixups_bytes());
    let report = view.macho_chained_fixups().expect("Mach-O chained fixups");

    assert!(report.present);
    assert_eq!(report.data_offset, 0x300);
    assert_eq!(report.data_size, 0x80);
    let header = report.header.expect("fixups header");
    assert_eq!(header.fixups_version, 0);
    assert_eq!(header.starts_offset, 0x30);
    assert_eq!(header.imports_offset, 0x1c);
    assert_eq!(header.symbols_offset, 0x24);
    assert_eq!(header.imports_count, 2);
    assert_eq!(header.imports_format, 1);
    assert_eq!(header.symbols_format, 0);

    assert_eq!(report.imports.len(), 2);
    assert_eq!(report.imports[0].lib_ordinal, 1);
    assert!(!report.imports[0].weak_import);
    assert_eq!(report.imports[0].name, "puts");
    assert_eq!(report.imports[0].addend, None);
    assert_eq!(report.imports[1].lib_ordinal, 2);
    assert!(report.imports[1].weak_import);
    assert_eq!(report.imports[1].name, "malloc");
    assert!(!report.truncated);

    assert_eq!(report.starts_in_image, Some(2));
    assert_eq!(report.starts_in_segment_count, 2);
}

#[test]
fn macho_chained_fixups_report_absence_and_reject_non_macho() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    let report = view.macho_chained_fixups().expect("no chained fixups command");
    assert!(!report.present);
    assert!(report.imports.is_empty());

    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    assert_eq!(view.macho_chained_fixups().unwrap_err().code(), "binary/unsupported");
}

/// `macho64_bytes()` plus `LC_DYLD_CHAINED_FIXUPS` pointing at `0x300`, with a
/// header (2 imports, uncompressed symbols), imports `puts` / `malloc` and a
/// two-segment starts table.
fn macho64_chained_fixups_bytes() -> Vec<u8> {
    let mut bytes = macho64_bytes();
    bytes.resize(0x400, 0);
    put_u32(&mut bytes, 16, 6);
    put_u32(&mut bytes, 20, 304);

    let command = 32 + 280;
    put_u32(&mut bytes, command, 0x8000_0034);
    put_u32(&mut bytes, command + 4, 16);
    put_u32(&mut bytes, command + 8, 0x300);
    put_u32(&mut bytes, command + 12, 0x80);

    put_u32(&mut bytes, 0x300, 0);
    put_u32(&mut bytes, 0x304, 0x30);
    put_u32(&mut bytes, 0x308, 0x1c);
    put_u32(&mut bytes, 0x30c, 0x24);
    put_u32(&mut bytes, 0x310, 2);
    put_u32(&mut bytes, 0x314, 1);
    put_u32(&mut bytes, 0x318, 0);

    put_u32(&mut bytes, 0x31c, 1);
    put_u32(&mut bytes, 0x320, 2 | (1 << 8) | (5 << 9));

    bytes[0x324..0x324 + 5].copy_from_slice(b"puts\0");
    bytes[0x329..0x329 + 7].copy_from_slice(b"malloc\0");

    put_u32(&mut bytes, 0x330, 2);
    put_u32(&mut bytes, 0x334, 0x0c);
    put_u32(&mut bytes, 0x338, 0x18);
    bytes
}

#[test]
fn macho_bindings_decode_classic_bind_opcodes() {
    let view = BinaryView::from_bytes("bindings.macho", macho64_bindings_bytes());
    let report = view.macho_bindings().expect("Mach-O dyld bind opcodes");

    assert!(report.present);
    assert_eq!(report.total, 6);
    assert!(!report.truncated);
    assert_eq!(report.bindings.len(), 6);

    let first = &report.bindings[0];
    assert_eq!(first.stream, "bind");
    assert_eq!(first.address, 0x1020);
    assert_eq!(first.segment, "__TEXT");
    assert_eq!(first.symbol, "___stack_chk_fail");
    assert_eq!(first.dylib, "/usr/lib/libSystem.B.dylib");
    assert_eq!(first.bind_type, "pointer");
    assert!(!first.weak);
    assert_eq!(first.addend, 0);

    let second = &report.bindings[1];
    assert_eq!(second.address, 0x1040);
    assert_eq!(second.symbol, "_bar");
    assert!(second.weak);
    assert_eq!(second.addend, 2);

    let third = &report.bindings[2];
    assert_eq!(third.stream, "weak");
    assert_eq!(third.address, 0x1000);
    assert_eq!(third.bind_type, "text-abs32");
    assert_eq!(third.dylib, "/usr/lib/libSystem.B.dylib");

    let fourth = &report.bindings[3];
    assert_eq!(fourth.stream, "lazy");
    assert_eq!(fourth.address, 0);
    assert_eq!(fourth.segment, "");
    assert_eq!(fourth.dylib, "/usr/lib/libz.1.dylib");

    assert_eq!(report.bindings[4].address, 8);
    assert_eq!(report.bindings[4].segment, "");

    let last = &report.bindings[5];
    assert_eq!(last.stream, "lazy");
    assert_eq!(last.address, 17);
    assert_eq!(last.symbol, "_lazy_a");
    assert_eq!(last.dylib, "/usr/lib/libz.1.dylib");
    assert_eq!(last.bind_type, "pointer");
    assert!(!last.weak);
}

#[test]
fn macho_bindings_report_absence_and_reject_non_macho() {
    let view = BinaryView::from_bytes("sample.macho", macho64_bytes());
    let report = view.macho_bindings().expect("no dyld info command");
    assert!(!report.present);
    assert!(report.bindings.is_empty());
    assert!(!report.truncated);

    let view = BinaryView::from_bytes("fat.macho", fat32_bytes());
    assert_eq!(view.macho_bindings().unwrap_err().code(), "binary/unsupported");

    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    assert_eq!(view.macho_bindings().unwrap_err().code(), "binary/unsupported");
}

/// `macho64_bytes()` plus a second `LC_LOAD_DYLIB` (`libz.1.dylib`), an
/// `LC_DYLD_INFO_ONLY` at 0x170 and bind, weak-bind and lazy-bind opcode
/// streams at 0x400, 0x480 and 0x4c0 with six bindings in total.
fn macho64_bindings_bytes() -> Vec<u8> {
    let mut bytes = macho64_bytes();
    bytes.resize(0x600, 0);
    put_u32(&mut bytes, 16, 7);
    put_u32(&mut bytes, 20, 384);

    let dylib = 32 + 280;
    put_u32(&mut bytes, dylib, 0x0c);
    put_u32(&mut bytes, dylib + 4, 56);
    put_u32(&mut bytes, dylib + 8, 24);
    put_u32(&mut bytes, dylib + 12, 2);
    put_u32(&mut bytes, dylib + 16, 0x0001_0203);
    put_u32(&mut bytes, dylib + 20, 0x0001_0000);
    bytes[dylib + 24..dylib + 46].copy_from_slice(b"/usr/lib/libz.1.dylib\0");

    let info = dylib + 56;
    put_u32(&mut bytes, info, 0x8000_0022);
    put_u32(&mut bytes, info + 4, 48);
    put_u32(&mut bytes, info + 8, 0);
    put_u32(&mut bytes, info + 12, 0);
    put_u32(&mut bytes, info + 16, 0x400);
    put_u32(&mut bytes, info + 20, 37);
    put_u32(&mut bytes, info + 24, 0x480);
    put_u32(&mut bytes, info + 28, 15);
    put_u32(&mut bytes, info + 32, 0x4c0);
    put_u32(&mut bytes, info + 36, 17);
    put_u32(&mut bytes, info + 40, 0);
    put_u32(&mut bytes, info + 44, 0);

    bytes[0x400] = 0x11;
    bytes[0x401] = 0x51;
    bytes[0x402] = 0x70;
    bytes[0x403] = 0x20;
    bytes[0x404] = 0x40;
    bytes[0x405..0x417].copy_from_slice(b"___stack_chk_fail\0");
    bytes[0x417] = 0x90;
    bytes[0x418] = 0x80;
    bytes[0x419] = 0x18;
    bytes[0x41a] = 0x62;
    bytes[0x41b] = 0x02;
    bytes[0x41c] = 0x41;
    bytes[0x41d..0x422].copy_from_slice(b"_bar\0");
    bytes[0x422] = 0xa0;
    bytes[0x423] = 0x08;
    bytes[0x424] = 0x00;

    bytes[0x480] = 0x11;
    bytes[0x481] = 0x52;
    bytes[0x482] = 0x70;
    bytes[0x483] = 0x00;
    bytes[0x484] = 0x42;
    bytes[0x485..0x48c].copy_from_slice(b"_wmain\0");
    bytes[0x48c] = 0x90;
    bytes[0x48d] = 0x00;

    bytes[0x4c0] = 0x20;
    bytes[0x4c1] = 0x02;
    bytes[0x4c2] = 0x51;
    bytes[0x4c3] = 0x40;
    bytes[0x4c4..0x4cc].copy_from_slice(b"_lazy_a\0");
    bytes[0x4cc] = 0xb0;
    bytes[0x4cd] = 0xc0;
    bytes[0x4ce] = 0x02;
    bytes[0x4cf] = 0x01;
    bytes[0x4d0] = 0x00;

    bytes
}

/// `macho64_bytes()` plus `LC_DYLD_EXPORTS_TRIE` at 0x300 exporting `_foo`
/// (address 0x1000) and the weak `_bar` (address 0x1040).
fn macho64_exports_bytes() -> Vec<u8> {
    let mut bytes = macho64_bytes();
    bytes.resize(0x320, 0);
    put_u32(&mut bytes, 16, 6);
    put_u32(&mut bytes, 20, 304);

    let command = 32 + 280;
    put_u32(&mut bytes, command, 0x8000_0033);
    put_u32(&mut bytes, command + 4, 16);
    put_u32(&mut bytes, command + 8, 0x300);
    put_u32(&mut bytes, command + 12, 24);

    let trie: [u8; 24] = [
        0x00, 0x02, b'_', b'f', b'o', b'o', 0x00, 0x0e, b'_', b'b', b'a', b'r', 0x00, 0x13, 0x03, 0x00, 0x80, 0x20,
        0x00, 0x03, 0x01, 0xc0, 0x20, 0x00,
    ];
    bytes[0x300..0x300 + trie.len()].copy_from_slice(&trie);
    bytes
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

/// `pe_bytes()` plus two x64 runtime functions behind data directory 3.
fn pe_exception_bytes() -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u32(&mut bytes, 0x98 + 112 + 3 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 3 * 8 + 4, 24);

    put_u32(&mut bytes, 0x400, 0x1010);
    put_u32(&mut bytes, 0x404, 0x1040);
    put_u32(&mut bytes, 0x408, 0x2060);
    put_u32(&mut bytes, 0x40c, 0x1050);
    put_u32(&mut bytes, 0x410, 0x1080);
    put_u32(&mut bytes, 0x414, 0x2070);

    let handler = 0x460;
    bytes[handler] = 0x01 | (0x01 << 3);
    bytes[handler + 1] = 0x10;
    bytes[handler + 2] = 5;
    bytes[handler + 3] = (2 << 4) | 3;

    let chained = 0x470;
    bytes[chained] = 0x02 | (0x04 << 3);
    bytes
}

#[test]
fn pe_exception_decodes_x64_runtime_functions() {
    let view = BinaryView::from_bytes("guarded.exe", pe_exception_bytes());
    let report = view.exception().expect("PE exception directory");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.machine, 0x8664);
    assert_eq!(report.machine_name, "amd64");
    assert_eq!(report.entry_format, "x64");
    assert_eq!(report.entry_size, Some(12));
    assert_eq!(report.total, 2);
    assert_eq!(report.functions.len(), 2);

    let first = &report.functions[0];
    assert_eq!(first.begin_address, 0x1010);
    assert_eq!(first.end_address, 0x1040);
    assert_eq!(first.unwind_info, 0x2060);
    assert_eq!(first.unwind_offset, Some(0x460));
    let unwind = first.unwind.as_ref().expect("unwind header");
    assert_eq!(unwind.version, 1);
    assert_eq!(unwind.flags, 1);
    assert_eq!(unwind.flag_names, vec!["EHANDLER"]);
    assert_eq!(unwind.prolog_size, 0x10);
    assert_eq!(unwind.code_count, 5);
    assert_eq!(unwind.frame_register, 3);
    assert_eq!(unwind.frame_offset, 2);
    assert!(!unwind.chained);

    let second = &report.functions[1];
    assert_eq!(second.begin_address, 0x1050);
    assert_eq!(second.unwind_info, 0x2070);
    let unwind = second.unwind.as_ref().expect("chained unwind header");
    assert_eq!(unwind.version, 2);
    assert_eq!(unwind.flag_names, vec!["CHAININFO"]);
    assert!(unwind.chained);
}

#[test]
fn pe_exception_masks_arm64_packed_entries() {
    let mut bytes = pe_exception_bytes();
    put_u16(&mut bytes, 0x84, 0xaa64);
    put_u32(&mut bytes, 0x98 + 112 + 3 * 8 + 4, 8);
    put_u32(&mut bytes, 0x400, 0x1012);
    put_u32(&mut bytes, 0x404, 0x2060);

    let report = BinaryView::from_bytes("arm64.exe", bytes).exception().expect("ARM64 exception directory");
    assert!(report.present);
    assert_eq!(report.machine_name, "arm64");
    assert_eq!(report.entry_format, "arm64");
    assert_eq!(report.entry_size, Some(8));
    assert_eq!(report.total, 1);
    assert_eq!(report.functions.len(), 1);
    assert_eq!(report.functions[0].begin_address, 0x1010);
    assert_eq!(report.functions[0].end_address, 0);
    assert_eq!(report.functions[0].unwind_info, 0x2060);
    assert!(report.functions[0].unwind.is_none());
}

#[test]
fn pe_exception_reports_absence_and_rejects_non_pe() {
    let report = BinaryView::from_bytes("plain.exe", pe_bytes()).exception().expect("PE exception directory");
    assert!(!report.present);
    assert_eq!(report.total, 0);
    assert!(report.functions.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.exception().unwrap_err().code(), "binary/unsupported");
}

/// `pe_bytes()` plus two delay-load descriptors behind data directory 13.
fn pe_delay_bytes() -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u32(&mut bytes, 0x98 + 112 + 13 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 13 * 8 + 4, 96);

    put_u32(&mut bytes, 0x400 + 4, 0x20a0);
    put_u32(&mut bytes, 0x400 + 8, 0x2008);
    put_u32(&mut bytes, 0x400 + 12, 0x2070);
    put_u32(&mut bytes, 0x400 + 16, 0x2060);
    put_u32(&mut bytes, 0x400 + 28, 0x1122_3344);

    put_u32(&mut bytes, 0x420 + 4, 0x20b0);
    put_u32(&mut bytes, 0x420 + 8, 0x2010);
    put_u32(&mut bytes, 0x420 + 12, 0x2090);
    put_u32(&mut bytes, 0x420 + 16, 0x2080);
    // 0x440 stays the all-zero terminator.

    put_u32(&mut bytes, 0x460, 0x20c0);
    put_u32(&mut bytes, 0x464, 0x8000_0005);
    put_u32(&mut bytes, 0x470, 0x1000);
    put_u32(&mut bytes, 0x474, 0x2000);
    put_u32(&mut bytes, 0x480, 0x20d0);
    put_u32(&mut bytes, 0x490, 0x3000);

    bytes[0x4a0..0x4aa].copy_from_slice(b"FIRST.DLL\0");
    bytes[0x4b0..0x4bb].copy_from_slice(b"SECOND.DLL\0");
    put_u16(&mut bytes, 0x4c0, 7);
    bytes[0x4c2..0x4ca].copy_from_slice(b"FuncOne\0");
    bytes[0x4d2..0x4d6].copy_from_slice(b"One\0");
    bytes
}

#[test]
fn pe_delay_imports_walk_descriptors_and_thunks() {
    let view = BinaryView::from_bytes("delayed.exe", pe_delay_bytes());
    let report = view.delay_imports().expect("PE delay-import directory");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.directory_rva, 0x2000);
    assert_eq!(report.total_modules, 2);
    assert_eq!(report.modules.len(), 2);
    assert_eq!(report.total_thunks, 3);

    let first = &report.modules[0];
    assert_eq!(first.name, "FIRST.DLL");
    assert_eq!(first.timestamp, 0x1122_3344);
    assert_eq!(first.module_handle_rva, 0x2008);
    assert_eq!(first.iat_rva, 0x2070);
    assert_eq!(first.int_rva, 0x2060);
    assert_eq!(first.thunks.len(), 2);
    let by_name = &first.thunks[0];
    assert_eq!(by_name.int_rva, 0x2060);
    assert_eq!(by_name.iat_rva, Some(0x2070));
    assert_eq!(by_name.name.as_deref(), Some("FuncOne"));
    assert_eq!(by_name.hint, Some(7));
    assert_eq!(by_name.ordinal, None);
    let by_ordinal = &first.thunks[1];
    assert_eq!(by_ordinal.int_rva, 0x2064);
    assert_eq!(by_ordinal.iat_rva, Some(0x2074));
    assert_eq!(by_ordinal.name, None);
    assert_eq!(by_ordinal.ordinal, Some(5));

    let second = &report.modules[1];
    assert_eq!(second.name, "SECOND.DLL");
    assert_eq!(second.timestamp, 0);
    assert_eq!(second.thunks.len(), 1);
    assert_eq!(second.thunks[0].name.as_deref(), Some("One"));
    assert_eq!(second.thunks[0].hint, Some(0));
    assert_eq!(second.thunks[0].iat_rva, Some(0x2090));
}

#[test]
fn pe_delay_imports_flag_unreadable_int_tables() {
    let mut bytes = pe_delay_bytes();
    put_u32(&mut bytes, 0x400 + 16, 0x9000);

    let report =
        BinaryView::from_bytes("broken.exe", bytes).delay_imports().expect("PE delay-import directory");
    assert!(report.present);
    assert!(report.truncated);
    assert_eq!(report.modules.len(), 2);
    assert!(report.modules[0].thunks.is_empty());
    assert_eq!(report.modules[0].int_rva, 0x9000);
}

#[test]
fn pe_delay_imports_report_absence_and_reject_non_pe() {
    let report =
        BinaryView::from_bytes("plain.exe", pe_bytes()).delay_imports().expect("PE delay-import directory");
    assert!(!report.present);
    assert_eq!(report.total_modules, 0);
    assert!(report.modules.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.delay_imports().unwrap_err().code(), "binary/unsupported");
}

/// `pe_bytes()` plus two bound-import descriptors behind data directory 11.
fn pe_bound_bytes() -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u32(&mut bytes, 0x98 + 112 + 11 * 8, 0x2000);
    put_u32(&mut bytes, 0x98 + 112 + 11 * 8 + 4, 48);

    put_u32(&mut bytes, 0x400, 0x1122_3344);
    put_u16(&mut bytes, 0x404, 0x40);
    put_u16(&mut bytes, 0x406, 2);
    put_u32(&mut bytes, 0x408, 0x5566_7788);
    put_u16(&mut bytes, 0x40c, 0x50);
    put_u32(&mut bytes, 0x410, 0);
    put_u16(&mut bytes, 0x414, 0x60);
    put_u32(&mut bytes, 0x418, 0x99aa_bbcc);
    put_u16(&mut bytes, 0x41c, 0x70);
    // 0x420 stays the all-zero terminator.

    bytes[0x440..0x44a].copy_from_slice(b"BOUND.DLL\0");
    bytes[0x450..0x459].copy_from_slice(b"REF1.DLL\0");
    bytes[0x460..0x469].copy_from_slice(b"REF2.DLL\0");
    bytes[0x470..0x47b].copy_from_slice(b"SECOND.DLL\0");
    bytes
}

#[test]
fn pe_bound_imports_walk_descriptors_and_forwarders() {
    let view = BinaryView::from_bytes("bound.exe", pe_bound_bytes());
    let report = view.bound_imports().expect("PE bound-import directory");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.directory_rva, 0x2000);
    assert_eq!(report.total_modules, 2);
    assert_eq!(report.modules.len(), 2);
    assert_eq!(report.total_forwarders, 2);

    let first = &report.modules[0];
    assert_eq!(first.timestamp, 0x1122_3344);
    assert_eq!(first.offset_module_name, 0x40);
    assert_eq!(first.name, "BOUND.DLL");
    assert_eq!(first.forwarders.len(), 2);
    assert_eq!(first.forwarders[0].timestamp, 0x5566_7788);
    assert_eq!(first.forwarders[0].offset_module_name, 0x50);
    assert_eq!(first.forwarders[0].name, "REF1.DLL");
    assert_eq!(first.forwarders[1].timestamp, 0);
    assert_eq!(first.forwarders[1].name, "REF2.DLL");

    let second = &report.modules[1];
    assert_eq!(second.timestamp, 0x99aa_bbcc);
    assert_eq!(second.offset_module_name, 0x70);
    assert_eq!(second.name, "SECOND.DLL");
    assert!(second.forwarders.is_empty());
}

#[test]
fn pe_bound_imports_flag_unresolvable_names() {
    let mut bytes = pe_bound_bytes();
    put_u16(&mut bytes, 0x404, 0xffff);

    let report =
        BinaryView::from_bytes("broken.exe", bytes).bound_imports().expect("PE bound-import directory");
    assert!(report.present);
    assert!(report.truncated);
    assert_eq!(report.modules.len(), 2);
    assert_eq!(report.modules[0].name, "");
    assert_eq!(report.modules[1].name, "SECOND.DLL");
}

#[test]
fn pe_bound_imports_report_absence_and_reject_non_pe() {
    let report =
        BinaryView::from_bytes("plain.exe", pe_bytes()).bound_imports().expect("PE bound-import directory");
    assert!(!report.present);
    assert_eq!(report.total_modules, 0);
    assert!(report.modules.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.bound_imports().unwrap_err().code(), "binary/unsupported");
}

/// `pe_bytes()` plus a two-entry Rich header inside the DOS stub region.
fn pe_rich_bytes() -> Vec<u8> {
    let mut bytes = pe_bytes();
    let key = 0x7788_99AAu32;
    put_u32(&mut bytes, 0x40, 0x536e_6144 ^ key);
    put_u32(&mut bytes, 0x50, ((30729u32 << 16) | 155) ^ key);
    put_u32(&mut bytes, 0x54, 3 ^ key);
    put_u32(&mut bytes, 0x58, ((1u32 << 16) | 216) ^ key);
    put_u32(&mut bytes, 0x5c, 2 ^ key);
    bytes[0x60..0x64].copy_from_slice(b"Rich");
    put_u32(&mut bytes, 0x64, key);
    bytes
}

#[test]
fn pe_rich_header_decodes_xor_entries() {
    let view = BinaryView::from_bytes("rich.exe", pe_rich_bytes());
    let report = view.rich_header().expect("PE Rich header");

    assert!(report.present);
    assert!(!report.truncated);
    assert_eq!(report.key, 0x7788_99AA);
    assert_eq!(report.dans_offset, 0x40);
    assert_eq!(report.rich_offset, 0x60);
    assert_eq!(report.total, 2);
    assert_eq!(report.entries.len(), 2);

    let first = &report.entries[0];
    assert_eq!(first.comp_id, 155);
    assert_eq!(first.build, 30729);
    assert_eq!(first.count, 3);
    assert_eq!(first.name.as_deref(), Some("Microsoft Visual C++ 14.x (VS2017-2022)"));

    let second = &report.entries[1];
    assert_eq!(second.comp_id, 216);
    assert_eq!(second.build, 1);
    assert_eq!(second.count, 2);
    assert_eq!(second.name.as_deref(), Some("Microsoft C/C++ linker or CRT (VS2017-2022 era)"));
}

#[test]
fn pe_rich_header_flags_malformed_runs() {
    let mut bytes = pe_rich_bytes();
    bytes.copy_within(0x60..0x68, 0x64);
    bytes[0x60] = 0;
    let report = BinaryView::from_bytes("odd.exe", bytes).rich_header().expect("PE Rich header");
    assert!(report.present);
    assert!(report.truncated);
    assert_eq!(report.total, 2);
    assert_eq!(report.entries.len(), 2);

    let mut bytes = pe_rich_bytes();
    put_u32(&mut bytes, 0x40, 0);
    let report = BinaryView::from_bytes("sans.exe", bytes).rich_header().expect("PE Rich header");
    assert!(!report.present);
}

#[test]
fn pe_rich_header_reports_absence_and_rejects_non_pe() {
    let report = BinaryView::from_bytes("plain.exe", pe_bytes()).rich_header().expect("PE Rich header");
    assert!(!report.present);
    assert_eq!(report.total, 0);
    assert!(report.entries.is_empty());

    let elf = BinaryView::from_bytes("sample.elf", elf64_bytes());
    assert_eq!(elf.rich_header().unwrap_err().code(), "binary/unsupported");
}

/// ELF64 with a `.symtab`, `.strtab` and `.shstrtab` behind five sections.
fn elf64_symtab_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x2400];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 0x3e);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, 0x1050);
    put_u64(&mut bytes, 40, 0x40);
    put_u16(&mut bytes, 58, 64);
    put_u16(&mut bytes, 60, 5);
    put_u16(&mut bytes, 62, 4);

    // .text
    put_u32(&mut bytes, 0x80, 1);
    put_u32(&mut bytes, 0x84, 1);
    put_u64(&mut bytes, 0x98, 0x200);
    put_u64(&mut bytes, 0xa0, 0x100);
    // .symtab
    put_u32(&mut bytes, 0xc0, 7);
    put_u32(&mut bytes, 0xc4, 2);
    put_u64(&mut bytes, 0xd8, 0x2000);
    put_u64(&mut bytes, 0xe0, 72);
    put_u32(&mut bytes, 0xe8, 3);
    put_u32(&mut bytes, 0xec, 1);
    put_u64(&mut bytes, 0xf8, 24);
    // .strtab
    put_u32(&mut bytes, 0x100, 15);
    put_u32(&mut bytes, 0x104, 3);
    put_u64(&mut bytes, 0x118, 0x2100);
    put_u64(&mut bytes, 0x120, 0x40);
    // .shstrtab
    put_u32(&mut bytes, 0x140, 23);
    put_u32(&mut bytes, 0x144, 3);
    put_u64(&mut bytes, 0x158, 0x2200);
    put_u64(&mut bytes, 0x160, 0x40);

    bytes[0x2201..0x2207].copy_from_slice(b".text\0");
    bytes[0x2207..0x220f].copy_from_slice(b".symtab\0");
    bytes[0x220f..0x2217].copy_from_slice(b".strtab\0");
    bytes[0x2217..0x2221].copy_from_slice(b".shstrtab\0");

    bytes[0x2100..0x2106].copy_from_slice(b"\0main\0");
    bytes[0x2106..0x210d].copy_from_slice(b"buffer\0");

    // sym1: GLOBAL/FUNC in .text
    put_u32(&mut bytes, 0x2018, 1);
    bytes[0x201c] = 0x12;
    put_u16(&mut bytes, 0x201e, 1);
    put_u64(&mut bytes, 0x2020, 0x1050);
    put_u64(&mut bytes, 0x2028, 42);
    // sym2: WEAK/HIDDEN OBJECT in COMMON
    put_u32(&mut bytes, 0x2030, 6);
    bytes[0x2034] = 0x21;
    bytes[0x2035] = 2;
    put_u16(&mut bytes, 0x2036, 0xfff2);
    put_u64(&mut bytes, 0x2040, 8);
    bytes
}

#[test]
fn elf_static_symbols_list_symtab_entries() {
    let view = BinaryView::from_bytes("symtab.elf", elf64_symtab_bytes());
    let report = view.static_symbols().expect("ELF .symtab");

    assert!(report.present);
    assert!(report.is64);
    assert!(!report.truncated);
    assert_eq!(report.total, 3);
    assert_eq!(report.symbols.len(), 3);

    assert_eq!(report.symbols[0].name, "");
    assert_eq!(report.symbols[0].section, "UND");

    let main = &report.symbols[1];
    assert_eq!(main.name, "main");
    assert_eq!(main.value, 0x1050);
    assert_eq!(main.size, 42);
    assert_eq!(main.symbol_type, "FUNC");
    assert_eq!(main.binding, "GLOBAL");
    assert_eq!(main.visibility, "DEFAULT");
    assert_eq!(main.section, ".text");

    let buffer = &report.symbols[2];
    assert_eq!(buffer.name, "buffer");
    assert_eq!(buffer.size, 8);
    assert_eq!(buffer.symbol_type, "OBJECT");
    assert_eq!(buffer.binding, "WEAK");
    assert_eq!(buffer.visibility, "HIDDEN");
    assert_eq!(buffer.section, "COM");
}

/// ELF32 with the same `.symtab` content in 32-bit layouts.
fn elf32_symtab_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x2400];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 3);
    put_u32(&mut bytes, 20, 1);
    put_u32(&mut bytes, 24, 0x1050);
    put_u32(&mut bytes, 32, 0x34);
    put_u16(&mut bytes, 46, 40);
    put_u16(&mut bytes, 48, 5);
    put_u16(&mut bytes, 50, 4);

    // .text
    put_u32(&mut bytes, 0x5c, 1);
    put_u32(&mut bytes, 0x60, 1);
    put_u32(&mut bytes, 0x6c, 0x200);
    put_u32(&mut bytes, 0x70, 0x100);
    // .symtab
    put_u32(&mut bytes, 0x84, 7);
    put_u32(&mut bytes, 0x88, 2);
    put_u32(&mut bytes, 0x94, 0x2000);
    put_u32(&mut bytes, 0x98, 48);
    put_u32(&mut bytes, 0x9c, 3);
    put_u32(&mut bytes, 0xa0, 1);
    put_u32(&mut bytes, 0xa8, 16);
    // .strtab
    put_u32(&mut bytes, 0xac, 15);
    put_u32(&mut bytes, 0xb0, 3);
    put_u32(&mut bytes, 0xbc, 0x2100);
    put_u32(&mut bytes, 0xc0, 0x40);
    // .shstrtab
    put_u32(&mut bytes, 0xd4, 23);
    put_u32(&mut bytes, 0xd8, 3);
    put_u32(&mut bytes, 0xe4, 0x2200);
    put_u32(&mut bytes, 0xe8, 0x40);

    bytes[0x2201..0x2207].copy_from_slice(b".text\0");
    bytes[0x2207..0x220f].copy_from_slice(b".symtab\0");
    bytes[0x220f..0x2217].copy_from_slice(b".strtab\0");
    bytes[0x2217..0x2221].copy_from_slice(b".shstrtab\0");

    bytes[0x2100..0x2106].copy_from_slice(b"\0main\0");
    bytes[0x2106..0x210d].copy_from_slice(b"buffer\0");

    // sym1: GLOBAL/FUNC in .text
    put_u32(&mut bytes, 0x2010, 1);
    put_u32(&mut bytes, 0x2014, 0x1050);
    put_u32(&mut bytes, 0x2018, 42);
    bytes[0x201c] = 0x12;
    put_u16(&mut bytes, 0x201e, 1);
    // sym2: WEAK/HIDDEN OBJECT in COMMON
    put_u32(&mut bytes, 0x2020, 6);
    put_u32(&mut bytes, 0x2028, 8);
    bytes[0x202c] = 0x21;
    bytes[0x202d] = 2;
    put_u16(&mut bytes, 0x202e, 0xfff2);
    bytes
}

#[test]
fn elf32_static_symbols_list_symtab_entries() {
    let view = BinaryView::from_bytes("symtab32.elf", elf32_symtab_bytes());
    let report = view.static_symbols().expect("ELF32 .symtab");

    assert!(report.present);
    assert!(!report.is64);
    assert_eq!(report.total, 3);
    let main = &report.symbols[1];
    assert_eq!(main.name, "main");
    assert_eq!(main.value, 0x1050);
    assert_eq!(main.symbol_type, "FUNC");
    assert_eq!(main.section, ".text");
    assert_eq!(report.symbols[2].section, "COM");
}

#[test]
fn elf_static_symbols_report_absence_and_reject_non_pe() {
    let report = BinaryView::from_bytes("stripped.elf", elf64_bytes()).static_symbols().expect("ELF .symtab");
    assert!(!report.present);
    assert_eq!(report.total, 0);
    assert!(report.symbols.is_empty());

    let pe = BinaryView::from_bytes("sample.exe", pe_bytes());
    assert_eq!(pe.static_symbols().unwrap_err().code(), "binary/unsupported");
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

/// An `NSIS` first header followed by two fake archive entries.
fn nsis_overlay() -> Vec<u8> {
    let mut overlay = vec![0u8; 0x20];
    overlay[4..8].copy_from_slice(&[0xef, 0xbe, 0xad, 0xde]);
    overlay[8..20].copy_from_slice(b"NullsoftInst");
    put_u32(&mut overlay, 20, 0x31416);
    overlay.extend_from_slice(b"PK\x03\x04");
    overlay.extend_from_slice(&[0u8; 8]);
    overlay
}

#[test]
fn overlay_reports_an_nsis_installer() {
    let overlay = nsis_overlay();
    let mut bytes = pe_bytes();
    bytes.extend_from_slice(&overlay);

    let report = BinaryView::from_bytes("setup.exe", bytes).overlay().expect("overlay");
    assert!(report.present);
    assert_eq!(report.offset, 0x600);
    assert_eq!(report.size, overlay.len() as u64);
    assert_eq!(report.leading_kind, "nsis");
    assert_eq!(report.container.as_deref(), Some("nsis"));
    assert!(report.ratio > 0.0 && report.ratio < 1.0);
    assert!(report.detail.as_deref().unwrap_or_default().contains("0x31416"));
    assert!(report.signatures.iter().any(|entry| entry.kind == "nsis" && entry.offset == 0x608));
    assert!(report.signatures.iter().any(|entry| entry.kind == "zip" && entry.offset == 0x620));
}

#[test]
fn overlay_names_a_pyinstaller_package() {
    let mut overlay = vec![0x78, 0xda, 0, 0, 0, 0, 0, 0];
    overlay.extend_from_slice(b"PK\x03\x04");
    overlay.extend_from_slice(b"MEI\x0c\x0b\x0a\x0b\x0e");
    overlay.extend_from_slice(b"\0\0\0\0python311.dll\0");

    let mut bytes = pe_bytes();
    bytes.extend_from_slice(&overlay);

    let report = BinaryView::from_bytes("onefile.exe", bytes).overlay().expect("overlay");
    assert_eq!(report.leading_kind, "zlib");
    assert_eq!(report.container.as_deref(), Some("pyinstaller"));
    assert!(report.detail.as_deref().unwrap_or_default().contains("python311.dll"));
    assert!(report.signatures.iter().any(|entry| entry.kind == "zip" && entry.offset == 0x608));
    assert!(report.signatures.iter().any(|entry| entry.kind == "pyinstaller" && entry.offset == 0x60c));
}

#[test]
fn overlay_caps_one_signature_family() {
    let mut overlay = Vec::new();
    for _ in 0..10 {
        overlay.extend_from_slice(&[0x1f, 0x8b, 0x08]);
        overlay.extend_from_slice(&[0u8; 5]);
    }
    overlay.extend_from_slice(b"PK\x03\x04");

    let mut bytes = pe_bytes();
    bytes.extend_from_slice(&overlay);

    let report = BinaryView::from_bytes("noisy.exe", bytes).overlay().expect("overlay");
    assert_eq!(report.signatures.iter().filter(|entry| entry.kind == "gzip").count(), 8);
    assert!(report.signatures.iter().any(|entry| entry.kind == "zip"));
    assert!(report.truncated);
}

#[test]
fn overlay_is_absent_without_trailing_bytes() {
    let report = BinaryView::from_bytes("plain.exe", pe_bytes()).overlay().expect("overlay");
    assert!(!report.present);
    assert_eq!(report.leading_kind, "none");
    assert!(report.signatures.is_empty());
    assert!(!report.truncated);
}

#[test]
fn overlay_rejects_non_pe_input() {
    let error = BinaryView::from_bytes("image.elf", elf64_bytes()).overlay().expect_err("unsupported");
    assert_eq!(error.code(), "binary/unsupported");
}

/// Builds a synthetic uncompressed `NSIS` header block with two `File` commands.
fn nsis_block() -> Vec<u8> {
    let mut block = vec![0u8; 139];
    put_u32(&mut block, 0, 0);
    // block table: pages, sections, entries, strings, langtables, ctlcolors, font, data
    put_u32(&mut block, 20, 68); // entries.offset
    put_u32(&mut block, 24, 2); // entries.num
    put_u32(&mut block, 28, 124); // strings.offset
    put_u32(&mut block, 36, 139); // langtables.offset (ends the string table)
    // command 0: File, output = string char 1
    put_u32(&mut block, 68, 20);
    put_u32(&mut block, 68 + 4, 0);
    put_u32(&mut block, 68 + 8, 1);
    put_u32(&mut block, 68 + 12, u32::MAX);
    // command 1: File, output = string char 9
    put_u32(&mut block, 96, 20);
    put_u32(&mut block, 96 + 8, 9);
    put_u32(&mut block, 96 + 12, u32::MAX);
    // string table (latin-1): "", "app.exe", "hello"
    block[124] = 0x00;
    block[125..132].copy_from_slice(b"app.exe");
    block[132] = 0x00;
    block[133..138].copy_from_slice(b"hello");
    block[138] = 0x00;
    block
}

#[test]
fn nsis_decodes_an_uncompressed_container() {
    let block = nsis_block();
    let header_size = block.len() as u32;

    // 28-byte first header, then the framing word, then the header block.
    let mut container = vec![0u8; 32];
    container[4..8].copy_from_slice(&[0xef, 0xbe, 0xad, 0xde]);
    container[8..20].copy_from_slice(b"NullsoftInst");
    put_u32(&mut container, 20, header_size);
    // framing word equal to the header size selects the uncompressed path
    put_u32(&mut container, 28, header_size);
    container.extend_from_slice(&block);

    let mut bytes = pe_bytes();
    let start = bytes.len();
    bytes.extend_from_slice(&container);

    let view = BinaryView::from_bytes("setup.exe", bytes);
    let sniffed = view.unpack(&UnpackOptions::default()).expect("sniff the NSIS container");
    assert!(matches!(sniffed, UnpackReport::Nsis(_)));
    let report = view
        .unpack(&UnpackOptions { format: UnpackFormat::Nsis, ..UnpackOptions::default() })
        .expect("nsis");
    let UnpackReport::Nsis(report) = report else {
        panic!("the explicit nsis route must answer with an NSIS report");
    };
    assert_eq!(report.header.start_offset as usize, start);
    assert_eq!(report.header.method, "none");
    assert!(!report.header.solid);
    assert!(!report.unicode);
    assert_eq!(report.string_chars, 15);
    assert_eq!(report.strings, vec!["app.exe".to_string(), "hello".to_string()]);
    assert_eq!(report.command_count, 2);
    assert_eq!(report.commands[0].name, "File");
    assert_eq!(report.commands[0].rendered[1], "app.exe");
    assert_eq!(report.files.len(), 2);
    assert_eq!(report.files[0].output, "app.exe");
    assert_eq!(report.files[1].output, "hello");
    assert!(report.files.iter().all(|file| file.data_offset.is_none()));
}

#[test]
fn unpack_rejects_input_without_any_container_signature() {
    let view = BinaryView::from_bytes("plain.exe", pe_bytes());
    let error = view
        .unpack(&UnpackOptions { format: UnpackFormat::Nsis, ..UnpackOptions::default() })
        .expect_err("the PE must not contain an NSIS first header");
    assert_eq!(error.code(), "binary/parse");
    let sniffed = view.unpack(&UnpackOptions::default()).expect_err("the PE must not sniff as a container");
    assert_eq!(sniffed.code(), "binary/parse");
}

#[test]
fn inflate_decodes_a_zlib_stream() {
    let payload = b"open-ida inflate smoke test payload";
    let stream = miniz_oxide::deflate::compress_to_vec_zlib(payload, 6);

    let mut bytes = vec![0u8; 0x10];
    bytes.extend_from_slice(&stream);
    let view = BinaryView::from_bytes("zlib.bin", bytes);

    let report = view
        .inflate(&InflateOptions { offset: 0x10, format: InflateFormat::Auto, limit: 1024, output: None })
        .expect("inflate");
    assert_eq!(report.format, "zlib");
    assert_eq!(report.output_bytes, payload.len() as u64);
    assert_eq!(report.status, "complete");
    assert!(!report.truncated);
    assert!(report.head_ascii.starts_with("open-ida inflate smoke test"));
    assert!(report.magic.starts_with("6f 70 65 6e"));

    let capped = view
        .inflate(&InflateOptions { offset: 0x10, format: InflateFormat::Zlib, limit: 8, output: None })
        .expect("capped inflate");
    assert!(capped.truncated);
    assert_eq!(capped.status, "output-limit");
    assert!(capped.output_bytes > 0 && capped.output_bytes <= 8);
}

#[test]
fn inflate_decodes_a_gzip_stream_and_writes_the_output() {
    let payload = b"gzip payload";
    let mut stream = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0x03];
    stream.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
    stream.extend_from_slice(&[0u8; 8]);

    let view = BinaryView::from_bytes("gzip.bin", stream);
    let output = TempFile::new("inflate-gzip");
    let report = view
        .inflate(&InflateOptions {
            offset: 0,
            format: InflateFormat::Auto,
            limit: 1024,
            output: Some(output.path().to_string_lossy().into_owned()),
        })
        .expect("inflate");

    assert_eq!(report.format, "gzip");
    assert_eq!(report.status, "complete");
    assert_eq!(fs::read(output.path()).expect("read output"), payload);
    assert!(report.output.is_some());
}

#[test]
fn inflate_rejects_a_stream_that_does_not_decode() {
    let view = BinaryView::from_bytes("noise.bin", vec![0x78, 0x9c, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00]);
    let output = TempFile::new("inflate-noise");
    let error = view
        .inflate(&InflateOptions {
            offset: 0,
            format: InflateFormat::Zlib,
            limit: 1024,
            output: Some(output.path().to_string_lossy().into_owned()),
        })
        .expect_err("invalid");
    assert_eq!(error.code(), "binary/parse");
    assert!(!output.path().exists());
}

#[test]
fn inflate_rejects_an_empty_range() {
    let view = BinaryView::from_bytes("tiny.bin", vec![0u8; 4]);
    let error = view
        .inflate(&InflateOptions { offset: 4, format: InflateFormat::Auto, limit: 64, output: None })
        .expect_err("range");
    assert_eq!(error.code(), "binary/range");
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

#[test]
fn find_reports_regex_hits_with_previews() {
    let view = BinaryView::from_bytes("find.bin", b"junk\x00marker-1\x00tail marker-2\x00".to_vec());
    let report = view
        .find(&FindOptions { pattern: "marker-[0-9]".into(), ..FindOptions::default() })
        .expect("regex hits");

    assert_eq!(report.pattern, "marker-[0-9]");
    assert!(!report.case_insensitive);
    assert_eq!(report.total, 2);
    assert_eq!(report.hits.len(), 2);
    assert!(!report.truncated);
    assert_eq!(report.hits[0].offset, 5);
    assert_eq!(report.hits[0].length, 8);
    assert!(report.hits[0].preview.starts_with("marker-1"));
    assert_eq!(report.hits[1].offset, 19);
    assert_eq!(report.context, 80);
    assert_eq!(report.limit, 100);
}

#[test]
fn find_honours_case_insensitive() {
    let view = BinaryView::from_bytes("find-case.bin", b"Marker here marker there".to_vec());
    let sensitive =
        view.find(&FindOptions { pattern: "marker".into(), ..FindOptions::default() }).expect("sensitive");
    assert_eq!(sensitive.total, 1);
    assert_eq!(sensitive.hits[0].offset, 12);

    let insensitive = view
        .find(&FindOptions { pattern: "marker".into(), case_insensitive: true, ..FindOptions::default() })
        .expect("insensitive");
    assert_eq!(insensitive.total, 2);
    assert!(insensitive.case_insensitive);
    assert_eq!(insensitive.hits[0].offset, 0);
}

#[test]
fn find_pages_with_skip_and_clamps_limit_and_context() {
    let view = BinaryView::from_bytes("find-page.bin", b"a1 b2 c3 d4 e5".to_vec());
    let paged = view
        .find(&FindOptions { pattern: "[a-z][0-9]".into(), skip: 2, limit: Some(2), ..FindOptions::default() })
        .expect("paged matches");
    assert_eq!(paged.total, 5);
    assert_eq!(paged.skip, 2);
    assert_eq!(paged.hits.len(), 2);
    assert!(paged.truncated);
    assert_eq!(paged.hits[0].offset, 6);
    assert_eq!(paged.hits[0].preview, "c3 d4 e5");

    let clamped = view
        .find(&FindOptions { pattern: "[a-z][0-9]".into(), limit: Some(9_999), context: 4_096, ..FindOptions::default() })
        .expect("clamped options");
    assert_eq!(clamped.limit, 5_000);
    assert_eq!(clamped.context, 512);
}

#[test]
fn find_rejects_invalid_patterns_and_reports_empty_results() {
    let view = BinaryView::from_bytes("find-bad.bin", b"abc".to_vec());
    let error: IdaError = view.find(&FindOptions { pattern: "(unclosed".into(), ..FindOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");

    let empty = view.find(&FindOptions { pattern: "zzz".into(), ..FindOptions::default() }).expect("no match");
    assert!(empty.hits.is_empty());
    assert_eq!(empty.total, 0);
    assert!(!empty.truncated);
}

#[test]
fn find_options_use_camel_case_defaults() {
    let defaults: FindOptions = serde_json::from_str(r#"{ "pattern": "ab" }"#).expect("minimal wire options");
    assert!(!defaults.case_insensitive);
    assert_eq!(defaults.skip, 0);
    assert_eq!(defaults.limit, Some(100));
    assert_eq!(defaults.context, 80);

    let wire = serde_json::to_value(FindOptions::default()).expect("serialize options");
    assert!(wire.get("caseInsensitive").is_some());
    assert!(serde_json::from_str::<FindOptions>("{}").is_err(), "the pattern is required");

    let view = BinaryView::from_bytes("find-wire.bin", b"ab\x00cd".to_vec());
    let report = view.find(&defaults).expect("wire find");
    let value = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(value["caseInsensitive"], false);
    assert_eq!(value["hits"][0]["offset"], 0);
    assert_eq!(value["hits"][0]["length"], 2);
    assert_eq!(value["hits"][0]["preview"], "ab.cd");
}

#[test]
fn dump_writes_a_byte_range_to_the_output_file() {
    let view = BinaryView::from_bytes("dump.bin", b"0123456789abcdef".to_vec());
    let output = TempFile::new("dump-out");
    let report = view
        .dump(&DumpOptions { offset: 4, length: 8, output: output.path().display().to_string() })
        .expect("dump range");

    assert_eq!(report.offset, 4);
    assert_eq!(report.length, 8);
    assert_eq!(report.written, 8);
    assert_eq!(fs::read(output.path()).expect("read output"), b"456789ab");

    let value = serde_json::to_value(&report).expect("serialize dump report");
    assert_eq!(value["written"], 8);
    assert!(value.get("output").is_some());
}

#[test]
fn dump_clamps_the_length_and_rejects_ranges_outside_the_file() {
    const CAP: usize = 64 * 1024 * 1024;
    let view = BinaryView::from_bytes("dump-big.bin", vec![0x41_u8; CAP]);
    let output = TempFile::new("dump-big-out");
    let report = view
        .dump(&DumpOptions { offset: 0, length: CAP + 1024, output: output.path().display().to_string() })
        .expect("clamped dump");
    assert_eq!(report.length, CAP);
    assert_eq!(report.written, CAP);
    assert_eq!(fs::metadata(output.path()).expect("output metadata").len(), CAP as u64);

    let outside = view.dump(&DumpOptions { offset: CAP as u64 + 1, length: 16, output: output.path().display().to_string() });
    assert_eq!(outside.unwrap_err().code(), "binary/range");
}

/// Builds a container of zero padding around one printable JavaScript-style
/// run that mentions the `synthetic-blob` marker twice.
fn carve_fixture() -> (Vec<u8>, usize, usize, usize) {
    let mut js: Vec<u8> = Vec::new();
    js.extend_from_slice(b"(function(){var mode=\"synthetic-blob\";document.addEventListener(\"click\",function(){\n");
    while js.len() < 300 {
        js.extend_from_slice(b"console.log(mode); ");
    }
    js.extend_from_slice(b"var rearm=\"synthetic-blob\"})})();");
    let js_len = js.len();

    let mut bytes = vec![0_u8; 2048];
    let start = bytes.len();
    bytes.extend_from_slice(&js);
    let marker = start + js.windows(14).position(|window| window == b"synthetic-blob").expect("marker");
    bytes.extend_from_slice(&vec![0_u8; 512]);
    (bytes, start, marker, js_len)
}

#[test]
fn carve_expands_the_printable_run_around_every_marker() {
    let (bytes, start, marker, js_len) = carve_fixture();
    let view = BinaryView::from_bytes("carve.bin", bytes);
    let report = view
        .carve(&CarveOptions { marker: "synthetic-blob".into(), ..CarveOptions::default() })
        .expect("carve regions");

    assert_eq!(report.marker, "synthetic-blob");
    assert_eq!(report.min_region, 200);
    assert_eq!(report.max_region, 262_144);
    assert_eq!(report.expand_left, 4_096);
    assert_eq!(report.limit, 20);
    assert!(report.output_dir.is_none());
    assert_eq!(report.total, 2);
    assert!(!report.truncated);
    assert_eq!(report.regions.len(), 1, "both matches share one printable region");

    let region = &report.regions[0];
    assert_eq!(region.marker_offset, marker as u64);
    assert_eq!(region.region_offset, start as u64);
    assert_eq!(region.region_length, js_len);
    assert!(region.preview.starts_with("(function(){var mode=\"synthetic-blob\";"));
    assert_eq!(region.preview.chars().count(), 120);
    assert!(region.preview.contains('.'), "the embedded newline renders as a dot");
    assert!(region.file.is_none());
}

#[test]
fn carve_writes_each_region_to_the_output_directory() {
    let (bytes, start, _marker, js_len) = carve_fixture();
    let view = BinaryView::from_bytes("carve-out.bin", bytes.clone());
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("open-ida-{}-{id}-carve", std::process::id()));
    let report = view
        .carve(&CarveOptions { marker: "synthetic-blob".into(), output_dir: Some(dir.display().to_string()), ..CarveOptions::default() })
        .expect("carve with output");

    let file = report.regions[0].file.as_ref().expect("region file");
    assert!(file.ends_with("carve_0.bin"));
    assert_eq!(fs::read(file).expect("read region file"), &bytes[start..start + js_len]);
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn carve_filters_short_regions_and_clamps_the_limit() {
    let view = BinaryView::from_bytes("carve-small.bin", b"needle \x00 and more".to_vec());
    let short = view.carve(&CarveOptions { marker: "needle".into(), ..CarveOptions::default() }).expect("short run");
    assert_eq!(short.total, 1);
    assert!(short.regions.is_empty(), "the printable run is shorter than min_region");
    assert!(!short.truncated);

    let clamped = view.carve(&CarveOptions { marker: "more".into(), limit: 9_999, ..CarveOptions::default() }).expect("clamped");
    assert_eq!(clamped.limit, 100);

    let (bytes, _start, _marker, _js_len) = carve_fixture();
    let big = BinaryView::from_bytes("carve-cut.bin", bytes);
    let cut = big.carve(&CarveOptions { marker: "synthetic-blob".into(), limit: 1, ..CarveOptions::default() }).expect("cut scan");
    assert_eq!(cut.limit, 1);
    assert_eq!(cut.total, 1);
    assert!(cut.truncated);
    assert_eq!(cut.regions.len(), 1);

    let error: IdaError =
        big.carve(&CarveOptions { marker: "(unclosed".into(), ..CarveOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

#[test]
fn carve_options_use_camel_case_defaults() {
    let defaults: CarveOptions = serde_json::from_str(r#"{ "marker": "ab" }"#).expect("minimal wire options");
    assert_eq!(defaults.min_region, 200);
    assert_eq!(defaults.max_region, 262_144);
    assert_eq!(defaults.expand_left, 4_096);
    assert_eq!(defaults.limit, 20);
    assert_eq!(defaults.output_dir, None);
    assert!(serde_json::from_str::<CarveOptions>("{}").is_err(), "the marker is required");

    let view = BinaryView::from_bytes("carve-wire.bin", b"ab".to_vec());
    let report = view.carve(&defaults).expect("wire carve");
    let value = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(value["minRegion"], 200);
    assert_eq!(value["expandLeft"], 4_096);
    assert_eq!(value["outputDir"], serde_json::Value::Null);
}

/// Compresses one payload into the standalone brotli stream Tauri embeds.
fn brotli_stream(bytes: &[u8]) -> Vec<u8> {
    let mut input = bytes;
    let mut out = Vec::new();
    brotli::BrotliCompress(&mut input, &mut out, &brotli::enc::BrotliEncoderParams::default()).expect("brotli compress");
    assert!(input.is_empty());
    out
}

/// Builds a 1:1 virtual-address container holding one interleaved
/// `[key_ptr, key_len, blob_ptr, blob_len, ...]` table in noise.
fn tauri_container(payloads: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut data = vec![0_u8; 512];
    let mut records: Vec<(u64, u64, u64, u64)> = Vec::new();
    for (key, content) in payloads {
        let key_offset = data.len() as u64;
        data.extend_from_slice(key.as_bytes());
        while data.len() % 8 != 0 {
            data.push(0);
        }
        let blob = brotli_stream(content);
        let blob_offset = data.len() as u64;
        data.extend_from_slice(&blob);
        records.push((key_offset, key.len() as u64, blob_offset, blob.len() as u64));
    }
    while data.len() % 32 != 0 {
        data.push(0);
    }
    for (key_pointer, key_length, blob_pointer, blob_length) in records {
        data.extend_from_slice(&key_pointer.to_le_bytes());
        data.extend_from_slice(&key_length.to_le_bytes());
        data.extend_from_slice(&blob_pointer.to_le_bytes());
        data.extend_from_slice(&blob_length.to_le_bytes());
    }
    data.extend_from_slice(&[0x41_u8; 64]);
    data
}

fn tauri_payloads() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("/index.html", b"<!doctype html><html><body>hello</body></html>".to_vec()),
        ("/assets/app.js", b"console.log(\"tauri\");".to_vec()),
        ("/icon.png", vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
    ]
}

/// Identity virtual-address map: the recorded address is the file offset.
fn identity_resolver(data: &[u8]) -> impl Fn(u64) -> Option<usize> + '_ {
    move |address| usize::try_from(address).ok().filter(|offset| *offset < data.len())
}

#[test]
fn tauri_assets_recovers_the_interleaved_table() {
    let payloads = tauri_payloads();
    let data = tauri_container(&payloads);
    let resolve = identity_resolver(&data);
    let report = scan_assets(&data, &resolve, &TauriAssetsOptions::default()).expect("scan");

    assert_eq!(report.total, payloads.len());
    assert!(!report.truncated);
    assert!(report.output_dir.is_none());
    let keys: Vec<&str> = report.assets.iter().map(|asset| asset.key.as_str()).collect();
    assert_eq!(keys, vec!["/index.html", "/assets/app.js", "/icon.png"]);
    for (asset, (_, content)) in report.assets.iter().zip(&payloads) {
        assert_eq!(asset.decompressed_len, content.len());
    }
    assert!(report.assets[0].preview.contains("<html>"));
    assert!(report.assets[2].preview.is_empty(), "binary payloads keep an empty preview");
}

#[test]
fn tauri_assets_writes_files_and_cuts_at_the_limit() {
    let payloads = tauri_payloads();
    let data = tauri_container(&payloads);
    let resolve = identity_resolver(&data);
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("open-ida-{}-{id}-tauri", std::process::id()));
    let report = scan_assets(
        &data,
        &resolve,
        &TauriAssetsOptions { output_dir: Some(dir.display().to_string()), ..TauriAssetsOptions::default() },
    )
    .expect("scan with output");

    let written = report.assets[1].file.as_ref().expect("asset file").replace('\\', "/");
    assert!(written.ends_with("/assets/app.js"), "the key path is mirrored: {written}");
    assert_eq!(fs::read(&written).expect("read asset file"), payloads[1].1);
    fs::remove_dir_all(&dir).expect("cleanup");

    let cut = scan_assets(&data, &resolve, &TauriAssetsOptions { limit: Some(1), ..TauriAssetsOptions::default() })
        .expect("cut scan");
    assert_eq!(cut.assets.len(), 1);
    assert_eq!(cut.total, 3);
    assert!(cut.truncated);

    let clamped =
        scan_assets(&data, &resolve, &TauriAssetsOptions { limit: Some(9_999), ..TauriAssetsOptions::default() })
            .expect("clamped scan");
    assert_eq!(clamped.assets.len(), 3);
    assert!(!clamped.truncated);
}

#[test]
fn tauri_assets_finds_no_table_in_flat_data() {
    let data: Vec<u8> = (0..4096_u32).map(|index| (index % 251) as u8).collect();
    let resolve = identity_resolver(&data);
    let report = scan_assets(&data, &resolve, &TauriAssetsOptions::default()).expect("noise scan");
    assert!(report.assets.is_empty());
    assert_eq!(report.total, 0);
    assert!(!report.truncated);
}

#[test]
fn tauri_assets_refuses_unsafe_asset_keys() {
    let payloads: Vec<(&str, Vec<u8>)> =
        vec![("/index.html", b"<!doctype html><p>hello</p>".to_vec()), ("/../evil.txt", b"traversal payload".to_vec())];
    let data = tauri_container(&payloads);
    let resolve = identity_resolver(&data);
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("open-ida-{}-{id}-tauri-bad", std::process::id()));
    let error: IdaError = scan_assets(
        &data,
        &resolve,
        &TauriAssetsOptions { output_dir: Some(dir.display().to_string()), ..TauriAssetsOptions::default() },
    )
    .expect_err("a traversal key must be refused");
    assert_eq!(error.code(), "binary/parse");
    let _ = fs::remove_dir_all(&dir);
}

/// The JSON header of the synthetic asar fixture.
const ASAR_JSON: &str = concat!(
    r#"{"files":{"a.txt":{"size":"13","offset":"0"},"dir":{"files":{"b.txt":"#,
    r#"{"size":"4","offset":"13"}}},"loose.txt":{"size":"7","offset":"0","unpacked":true}}}"#
);

/// The packed data blob referenced by [`ASAR_JSON`].
const ASAR_DATA: &[u8] = b"alpha-payloadbeta";

/// Assembles a minimal asar archive: four header words, the JSON, the data blob.
fn asar_bytes() -> Vec<u8> {
    let json = ASAR_JSON.as_bytes();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&((8 + json.len()) as u32).to_le_bytes());
    bytes.extend_from_slice(&((json.len() + 4) as u32).to_le_bytes());
    bytes.extend_from_slice(&(json.len() as u32).to_le_bytes());
    bytes.extend_from_slice(json);
    bytes.extend_from_slice(ASAR_DATA);
    bytes
}

#[test]
fn asar_lists_the_header_tree() {
    let file = TempFile::new("asar");
    file.write(&asar_bytes());
    let view = BinaryView::open(file.path()).expect("open asar");
    let sniffed = view.unpack(&UnpackOptions::default()).expect("sniff the asar archive");
    assert!(matches!(sniffed, UnpackReport::Asar(_)));
    let report = view
        .unpack(&UnpackOptions { format: UnpackFormat::Asar, ..UnpackOptions::default() })
        .expect("decode asar");
    let UnpackReport::Asar(report) = report else {
        panic!("the explicit asar route must answer with an asar report");
    };

    let json_len = ASAR_JSON.len() as u64;
    assert_eq!(report.header.start_offset, 0);
    assert_eq!(report.header.data_start, 16 + json_len);
    assert_eq!(report.entry_count, 3);
    assert_eq!(report.directory_count, 1);
    assert_eq!(report.packed_bytes, 17);
    assert!(!report.truncated);

    let paths: Vec<&str> = report.entries.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(paths, vec!["a.txt", "dir/b.txt", "loose.txt"]);
    assert_eq!(report.entries[0].offset, Some(16 + json_len));
    assert_eq!(report.entries[1].offset, Some(16 + json_len + 13));
    assert!(report.entries[2].unpacked);
    assert_eq!(report.entries[2].offset, None, "unpacked entries carry no packed bytes");

    let packed = view.read_bytes(16 + json_len, 13).expect("read packed bytes");
    assert_eq!(packed, b"alpha-payload".as_slice());

    let cut = view
        .unpack(&UnpackOptions { format: UnpackFormat::Asar, entries_limit: 1, ..UnpackOptions::default() })
        .expect("cut listing");
    let UnpackReport::Asar(cut) = cut else {
        panic!("the explicit asar route must answer with an asar report");
    };
    assert_eq!(cut.entries.len(), 1);
    assert!(cut.truncated);
}

#[test]
fn asar_extracts_packed_entries() {
    let file = TempFile::new("asar-extract");
    file.write(&asar_bytes());
    let view = BinaryView::open(file.path()).expect("open asar");
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("open-ida-{}-{id}-asar", std::process::id()));

    let report = view
        .unpack(&UnpackOptions {
            format: UnpackFormat::Asar,
            extract_dir: Some(dir.display().to_string()),
            ..UnpackOptions::default()
        })
        .expect("decode with extraction");
    let UnpackReport::Asar(report) = report else {
        panic!("the explicit asar route must answer with an asar report");
    };

    let written = report.entries[1].extracted.as_ref().expect("nested entry").replace('\\', "/");
    assert!(written.ends_with("/dir/b.txt"), "the archive path is mirrored: {written}");
    assert_eq!(fs::read(&written).expect("read entry"), b"beta");
    assert!(report.entries[2].extracted.is_none(), "unpacked entries are not written");
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn asar_rejects_a_non_asar_input() {
    let file = TempFile::new("asar-bad");
    file.write(&pe_bytes());
    let view = BinaryView::open(file.path()).expect("open PE");
    let error = view
        .unpack(&UnpackOptions { format: UnpackFormat::Asar, ..UnpackOptions::default() })
        .unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

/// Assembles a minimal valid empty 7z container: signature, version 0.4 and a
/// start header that announces a zero-length next header.
fn sevenz_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    bytes[6] = 0x00;
    bytes[7] = 0x04;
    bytes
}

#[test]
fn unpack_indexes_a_sevenz_container() {
    let file = TempFile::new("sevenz");
    file.write(&sevenz_bytes());
    let view = BinaryView::open(file.path()).expect("open 7z");
    let sniffed = view.unpack(&UnpackOptions::default()).expect("sniff the 7z container");
    let UnpackReport::SevenZ(report) = sniffed else {
        panic!("the 7z signature must win the auto sniff");
    };
    assert_eq!(report.start_offset, 0);
    assert_eq!(report.version, "0.4");
    assert_eq!(report.entry_count, 0);
    assert_eq!(report.folder_count, 0);
    assert_eq!(report.total_unpack_size, 0);
    assert!(report.methods.is_empty());
    assert!(!report.truncated);

    let explicit = view
        .unpack(&UnpackOptions { format: UnpackFormat::SevenZ, ..UnpackOptions::default() })
        .expect("explicit 7z route");
    let UnpackReport::SevenZ(explicit) = explicit else {
        panic!("the explicit 7z route must answer with a 7z report");
    };
    assert_eq!(explicit.entry_count, 0);
}

#[test]
fn unpack_rejects_a_non_sevenz_input_on_the_explicit_route() {
    let file = TempFile::new("sevenz-bad");
    file.write(&pe_bytes());
    let view = BinaryView::open(file.path()).expect("open PE");
    let error = view
        .unpack(&UnpackOptions { format: UnpackFormat::SevenZ, ..UnpackOptions::default() })
        .unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

/// Writes one raw little-endian word of a code object header field.
fn marshal_word(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Writes a `marshal` small int object.
fn marshal_small_int(out: &mut Vec<u8>, value: i8) {
    out.push(b'b');
    out.push(value as u8);
}

/// Writes a `marshal` none object.
fn marshal_none(out: &mut Vec<u8>) {
    out.push(b'N');
}

/// Writes an interned short ASCII string; the parser records it as a ref.
fn marshal_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'Z');
    out.push(text.len() as u8);
    out.extend_from_slice(text.as_bytes());
}

/// Writes a `marshal` string reference to an earlier interned object.
fn marshal_ref(out: &mut Vec<u8>, index: i32) {
    out.push(b'r');
    out.extend_from_slice(&index.to_le_bytes());
}

/// Writes a `marshal` bytes object.
fn marshal_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b's');
    out.extend_from_slice(&(bytes.len() as i32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Writes a `marshal` tuple of exactly `count` items from encoded `bytes`.
fn marshal_tuple(out: &mut Vec<u8>, count: usize, bytes: &[u8]) {
    out.push(b'(');
    out.extend_from_slice(&(count as i32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Writes the empty 3.11+ `localsplus` pair for the locals tables.
fn marshal_localsplus(out: &mut Vec<u8>) {
    out.push(b')');
    out.push(0);
    marshal_bytes(out, &[]);
}

/// Field values of one synthetic 3.11 code object.
struct CodeSpec<'a> {
    stacksize: i32,
    flags: i32,
    code: &'a [u8],
    consts_count: usize,
    consts: &'a [u8],
    names_count: usize,
    names: &'a [u8],
    filename: &'a str,
    name: &'a str,
    qualname: &'a [u8],
    firstlineno: i32,
}

/// Writes one 3.11 code object with the fixed field order.
fn marshal_code(out: &mut Vec<u8>, spec: &CodeSpec<'_>) {
    out.push(0xE3);
    marshal_word(out, 0);
    marshal_word(out, 0);
    marshal_word(out, 0);
    marshal_word(out, spec.stacksize);
    marshal_word(out, spec.flags);
    marshal_bytes(out, spec.code);
    marshal_tuple(out, spec.consts_count, spec.consts);
    marshal_tuple(out, spec.names_count, spec.names);
    marshal_localsplus(out);
    marshal_string(out, spec.filename);
    marshal_string(out, spec.name);
    out.extend_from_slice(spec.qualname);
    marshal_word(out, spec.firstlineno);
    marshal_bytes(out, &[]);
    marshal_bytes(out, &[]);
}

/// Builds a synthetic module holding one nested function, as `marshal` v4.
fn pyc_fixture() -> Vec<u8> {
    let mut helper = Vec::new();
    let mut helper_consts = Vec::new();
    marshal_small_int(&mut helper_consts, 42);
    let mut helper_qualname = Vec::new();
    marshal_ref(&mut helper_qualname, 3);
    marshal_code(
        &mut helper,
        &CodeSpec {
            stacksize: 1,
            flags: 65,
            code: &[0x97, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x53, 0x00],
            consts_count: 1,
            consts: &helper_consts,
            names_count: 0,
            names: &[],
            filename: "fixture.py",
            name: "helper",
            qualname: &helper_qualname,
            firstlineno: 2,
        },
    );
    let mut module = Vec::new();
    let mut module_consts = Vec::new();
    marshal_none(&mut module_consts);
    module_consts.extend_from_slice(&helper);
    let mut module_names = Vec::new();
    marshal_string(&mut module_names, "helper");
    let mut module_qualname = Vec::new();
    marshal_string(&mut module_qualname, "<module>");
    marshal_code(
        &mut module,
        &CodeSpec {
            stacksize: 2,
            flags: 64,
            code: &[0x97, 0x00, 0x64, 0x01, 0x84, 0x00, 0x5A, 0x00, 0x64, 0x00, 0x53, 0x00],
            consts_count: 2,
            consts: &module_consts,
            names_count: 1,
            names: &module_names,
            filename: "fixture.py",
            name: "<module>",
            qualname: &module_qualname,
            firstlineno: 1,
        },
    );
    let mut out = Vec::new();
    out.extend_from_slice(&module);
    out
}

#[test]
fn pyc_disassembles_a_synthetic_marshal_graph() {
    let view = BinaryView::from_bytes("pyc-graph", pyc_fixture());
    let report = view.pyc(&PycOptions::default()).expect("decode marshal");

    assert_eq!(report.source_format, "marshal");
    assert_eq!(report.marshal_version, None);
    assert_eq!(report.code_count, 2);
    assert_eq!(report.instruction_count, 9);
    assert!(!report.truncated);

    let helper = &report.codes[0];
    assert_eq!(helper.qualname, "helper", "the qualname resolves through the string ref");
    assert_eq!(helper.flags_text, "OPTIMIZED, NOFREE");
    assert_eq!(helper.consts[0].kind, "int");
    assert_eq!(helper.consts[0].repr, "42");
    assert_eq!(helper.instructions[0].name, "RESUME");
    assert_eq!(helper.instructions[0].caches, 4, "the zero opcode slots attach to RESUME");
    assert_eq!(helper.instructions[1].name, "LOAD_CONST");
    assert_eq!(helper.instructions[1].resolved.as_deref(), Some("42"));

    let module = &report.codes[1];
    assert_eq!(module.qualname, "<module>");
    assert_eq!(module.flags_text, "NOFREE");
    assert_eq!(module.names, vec!["helper".to_string()]);
    assert_eq!(module.consts[1].kind, "code");
    assert_eq!(module.consts[1].code_index, Some(0));
    assert_eq!(module.consts[1].repr, "<code helper>");
    assert_eq!(module.instructions[1].name, "LOAD_CONST");
    assert_eq!(module.instructions[1].resolved.as_deref(), Some("<code helper>"));
    assert_eq!(module.instructions[3].name, "STORE_NAME");
    assert_eq!(module.instructions[3].resolved.as_deref(), Some("helper"));
    assert_eq!(module.instructions[5].name, "RETURN_VALUE");
    assert_eq!(module.instructions[5].arg, None);
}

#[test]
fn pyc_reads_a_pyc_container_and_filters_by_qualname() {
    let mut bytes = vec![0xa7, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x64, 0, 0, 0];
    bytes.extend(pyc_fixture());
    let view = BinaryView::from_bytes("pyc-container", bytes);

    let report = view.pyc(&PycOptions::default()).expect("decode pyc");
    assert_eq!(report.source_format, "pyc");
    assert_eq!(report.pyc_magic, Some(0x0a0d_0da7));
    assert_eq!(report.python.as_deref(), Some("CPython 3.11"));
    assert_eq!(report.code_count, 2);

    let filtered = view.pyc(&PycOptions { code: Some("helper".into()), ..PycOptions::default() }).expect("filter");
    assert_eq!(filtered.codes.len(), 1);
    assert_eq!(filtered.codes[0].qualname, "helper");
    assert_eq!(filtered.code_count, 2, "the count stays the decoded total");

    let missing: IdaError =
        view.pyc(&PycOptions { code: Some("absent".into()), ..PycOptions::default() }).unwrap_err();
    assert_eq!(missing.code(), "binary/parse");

    let forced = view.pyc(&PycOptions { format: PycFormat::Marshal, ..PycOptions::default() });
    assert!(forced.is_err(), "the pyc header is not a marshal stream");
}

#[test]
fn sniff_accepts_every_assigned_pyc_magic() {
    // Every assigned CPython magic is odd, so the signature must not depend on parity.
    for magic in [3413u16, 3425, 3439, 3495, 3531, 3571] {
        let header = [magic as u8, (magic >> 8) as u8, 0x0d, 0x0a, 0, 0, 0, 0];
        assert!(sniff_pyc(&header), "magic {magic} must sniff as bytecode");
    }
    assert!(sniff_pyc(&[0xE3, 0, 0, 0, 0]), "a raw code object sniffs as bytecode");
    assert!(sniff_pyc(&[4, 0, 0, 0, 0]), "a marshal version prefix sniffs as bytecode");
    assert!(!sniff_pyc(b"MZ\x90\x00\x03\x00\x00\x00"), "a PE header is not bytecode");
    assert!(!sniff_pyc(b"\x7fELF\x02\x01\x01\x00"), "an ELF header is not bytecode");
    assert!(!sniff_pyc(&[0x01, 0x01, 0x0d, 0x0a, 0, 0, 0, 0]), "a magic outside the assigned range is not bytecode");
}

#[test]
fn pyc_rejects_a_non_marshal_input() {
    let view = BinaryView::from_bytes("pyc-bad", pe_bytes());
    let error = view.pyc(&PycOptions::default()).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

#[test]
fn pyc_options_use_camel_case_defaults() {
    let defaults: PycOptions = serde_json::from_str("{}").expect("empty wire options");
    assert_eq!(defaults.format, PycFormat::Auto);
    assert_eq!(defaults.code_limit, 1024);
    assert_eq!(defaults.instruction_limit, 65_536);

    let view = BinaryView::from_bytes("pyc-wire", pyc_fixture());
    let report = view.pyc(&defaults).expect("wire decode");
    let value = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(value["sourceFormat"], "marshal");
    assert_eq!(value["codeCount"], 2);
    assert_eq!(value["codes"][0]["qualname"], "helper");
    assert_eq!(value["codes"][0]["instructions"][0]["caches"], 4);
    assert_eq!(value["codes"][0]["consts"][0]["repr"], "42");
}
