//! Product workflow acceptance tests.
//!
//! Every fixture is built in memory and written to a unique file under the
//! system temporary directory, then removed when the guard drops. These tests
//! cover the product verbs end to end: open, inspect, search, patch, compare,
//! disassemble, extract and unpack.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use ida_domain::{
    BinaryView, CarveOptions, DisassembleOptions, DisassemblySyntax, DumpOptions, FindOptions, IdaError, InflateFormat,
    InflateOptions, OpenIda, OpenIdaOptions, SearchMode, SearchOptions, StringEncoding, StringsOptions, TauriAssetsOptions,
    UnpackFormat, UnpackOptions, UnpackReport, scan_assets,
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

/// Fixed DEFLATE, zlib and gzip vectors produced once with Node.js 24.18.0
/// from the built-in `node:zlib` module. No test encodes, so a decoder bug
/// cannot hide behind a matching bug in a local encoder. Each constant records
/// the plaintext SHA-256 and the envelope checksum of the decoded bytes.
///
/// - `RAW_HELLO`, `ZLIB_HELLO`, `GZIP_HELLO`: `deflateRawSync`, `deflateSync`
///   and `gzipSync` of `b"Hello, DEFLATE!"` at level 9. Plaintext is 15 bytes,
///   SHA-256 `28d54d6f992f913965998453b2004df7340e8af4759af23c57482ed59f6a0026`,
///   Adler-32 `633603159` (`0x25c40457`), CRC-32 `32427180` (`0x01eeccac`),
///   ISIZE `15`.
/// - `RAW_BIG`: `deflateRawSync` at level 6 of `b"0123456789abcdef"` repeated
///   8192 times (131072 bytes across three blocks, 288 stored bytes). Plaintext
///   SHA-256 `a2706a20394e48179a86c71e82c360c2960d3652340f9b9fdb355a42e3ac7691`,
///   Adler-32 `2490189877`, CRC-32 `3671360`, ISIZE `131072`.
/// - `ZLIB_INFLATE_PAYLOAD`: `deflateSync` at level 6 of
///   `b"open-ida inflate smoke test payload"` (35 bytes, SHA-256
///   `075ba49c8ad311059c78a0f0be89f04c4fce64f1db46a7b2c4f24e9a809708d8`,
///   Adler-32 `3953986874`, CRC-32 `2393800574`).
/// - `GZIP_PAYLOAD`: `gzipSync` at level 6 of `b"gzip payload"` (12 bytes,
///   SHA-256 `c41d7dd86af0a21741408d75bb6a96a3892f03de479054ae13443cb8628fce64`,
///   Adler-32 `519963845`, CRC-32 `3237311181`, ISIZE `12`).
/// - `ZLIB_MODULE_ONE`: `deflateSync` at level 6 of
///   `b"\xe3\x00\x00\x00\x00first module marshal"` (25 bytes, SHA-256
///   `d32ea28378521c333c08faea9784773eeda7daee7ab82a63ba5ac0a58c0579d6`,
///   Adler-32 `1754269882`).
/// - `ZLIB_MODULE_TWO`: `deflateSync` at level 6 of
///   `b"\xe3\x00\x00\x00\x00second module marshal"` (26 bytes, SHA-256
///   `ae950ee72dc3be8e433d5bbdd1664dd9b68f05d0fd99c7261cdca8a0b986dcfd`,
///   Adler-32 `1892813070`).
/// - `ZLIB_COMPRESSIBLE`: `deflateSync` at level 6 of
///   `b"compressible compressible compressible data"` (43 bytes, SHA-256
///   `23ba6d67a46d5824daebedcb2190752c2ea54c1773d8125598b116ce5dde6b1f`,
///   Adler-32 `2102923539`).
/// - `ZLIB_PYZ`: `deflateSync` at level 6 of the 135-byte PYZ image that
///   `pyz_image()` rebuilds from `ZLIB_MODULE_ONE`/`ZLIB_MODULE_TWO`. Plaintext
///   SHA-256 `1e8d1608a49f7ec28e3c43c57bab6aa9d49c25ffb0c1d852cf26318d0ab69c38`,
///   Adler-32 `4160892971`.
/// - `RAW_NSIS_BLOCK`: `deflateRawSync` at level 6 of the 139-byte
///   uncompressed NSIS header block `nsis_block()` builds. Plaintext SHA-256
///   `1a986458ab720b809010dd3c3373dac8acd86ea505726bcceeea55c5e7b2c345`,
///   Adler-32 `430378557`, 52 stored bytes.
const RAW_HELLO: &str = "f348cdc9c9d751707175f3710c71550400";
const ZLIB_HELLO: &str = "78daf348cdc9c9d751707175f3710c7155040025c40457";
const GZIP_HELLO: &str = "1f8b080000000000020af348cdc9c9d751707175f3710c71550400acccee010f000000";
const RAW_BIG: &str = "edc7c901c0100000b09594bac641d97f840e22f9253c31bdb9d4d6c75cdf3ec1ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddaffd0f";
const ZLIB_INFLATE_PAYLOAD: &str = "789ccb2f48cdd3cd4c4954c8cc4bcb492c495528cecdcf4e5528492d2e512848acccc94f4c0100ebad0d3a";
const GZIP_PAYLOAD: &str = "1f8b080000000000000a4bafca2c502848acccc94f4c0100cd72f5c00c000000";
const ZLIB_MODULE_ONE: &str = "789c7bccc0c0c0909659545ca2909b9f529a93aa909b58549c91980300689008ba";
const ZLIB_MODULE_TWO: &str = "789c7bccc0c0c0509c9a9c9f97a2909b9f529a93aa909b58549c9198030070d2090e";
const ZLIB_COMPRESSIBLE: &str = "789c4bcecf2d284a2d2ece4cca495548c6c949492c4904007d581113";
const ZLIB_PYZ: &str = "789c0b888c6238cdcbcbc5c0c0e05f31a7facc810307264c8b0c89593461f6fca05993574d981d113267e20c66868c091cbba00a02e6cc9a337f3a868a824b9c7cd551dc4989c5a9f1b9f929a539a91acc0c0c0c6e993c0c0c0c998a0c0c0c51ec05d9e97ab9f9296089904c5d9084120303830100f802302b";
const RAW_NSIS_BLOCK: &str =
    "6360c0042e0c0c0c4c0c0c0c35507e371635c840044a33323030fcffffff3f36394e2c720c8905057aa915a90c19a93939f90c00";

/// Decodes a hex literal into bytes.
fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "hex literal has an odd length");
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digit")).collect()
}

/// Plaintext of the big multi-block raw vector.
fn big_payload() -> Vec<u8> {
    b"0123456789abcdef".repeat(8192)
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

fn pe_code_bytes(code: &[u8]) -> Vec<u8> {
    let mut bytes = pe_bytes();
    put_u16(&mut bytes, 0x86, 1);
    put_u32(&mut bytes, 0x188 + 8, 0x10);
    put_u32(&mut bytes, 0x188 + 16, code.len() as u32);
    bytes.truncate(0x200);
    bytes.extend_from_slice(code);
    bytes
}

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

    assert_eq!(view.format(), ida_domain::BinaryFormat::Pe);
    assert_eq!(view.architecture(), ida_domain::Architecture::X64);
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

    assert_eq!(view.format(), ida_domain::BinaryFormat::Elf);
    assert_eq!(view.architecture(), ida_domain::Architecture::X64);

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

    assert_eq!(view.architecture(), ida_domain::Architecture::X86);
    let sections = view.sections().expect("ELF32 sections");
    assert_eq!(sections.len(), 3);
    assert_eq!(sections[1].name, ".text");
    assert_eq!(view.rva_to_offset(0x8048008).unwrap(), 0x208);
}

#[test]
fn macho_header_basics_only() {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32(&mut bytes, 4, 0x0100_000c);
    put_u32(&mut bytes, 12, 2);
    put_u32(&mut bytes, 16, 3);
    let view = BinaryView::from_bytes("sample.macho", bytes);

    assert_eq!(view.format(), ida_domain::BinaryFormat::MachO);
    assert_eq!(view.architecture(), ida_domain::Architecture::Arm64);
    let info = view.info().expect("Mach-O info");
    assert_eq!(info.magic.as_deref(), Some("Mach-O 64"));
    assert_eq!(info.cpu_type, Some(0x0100_000c));
    assert_eq!(info.file_type, Some(2));
    assert_eq!(info.command_count, Some(3));
    assert_eq!(view.sections().unwrap_err().code(), "binary/parse");
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
        .strings_encoded(&StringsOptions {
            encoding: StringEncoding::Both,
            min_length: 3,
            limit: 2,
            ..StringsOptions::default()
        })
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
    assert_eq!(report.differences, vec![ida_domain::DiffRange { offset: 2, length: 1 }]);
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
    assert_eq!(report.differences, vec![ida_domain::DiffRange { offset: 3, length: 2 }]);
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
    let report = view.unpack(&UnpackOptions { format: UnpackFormat::Nsis, ..UnpackOptions::default() }).expect("nsis");
    let UnpackReport::Nsis(report) = report
    else {
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
fn nsis_decodes_a_deflate_container_from_a_fixed_vector() {
    let block = nsis_block();
    let header_size = block.len() as u32;
    let stream = unhex(RAW_NSIS_BLOCK);
    assert_eq!(stream.len(), 52, "the fixed raw DEFLATE vector has 52 stored bytes");

    // 28-byte first header, then a non-solid framing word (bit 31 set) whose
    // low 31 bits hold the compressed length, then the raw DEFLATE stream.
    let mut container = vec![0u8; 32];
    container[4..8].copy_from_slice(&[0xef, 0xbe, 0xad, 0xde]);
    container[8..20].copy_from_slice(b"NullsoftInst");
    put_u32(&mut container, 20, header_size);
    put_u32(&mut container, 28, 0x8000_0000 | stream.len() as u32);
    container.extend_from_slice(&stream);

    let mut bytes = pe_bytes();
    let start = bytes.len();
    bytes.extend_from_slice(&container);

    let view = BinaryView::from_bytes("setup-deflate.exe", bytes);
    let report = view.unpack(&UnpackOptions { format: UnpackFormat::Nsis, ..UnpackOptions::default() }).expect("nsis");
    let UnpackReport::Nsis(report) = report
    else {
        panic!("the explicit nsis route must answer with an NSIS report");
    };
    assert_eq!(report.header.start_offset as usize, start);
    assert_eq!(report.header.method, "deflate");
    assert!(!report.header.solid);
    assert_eq!(report.header.compressed_header_size, stream.len() as u32);
    // The decoded header block is exactly the plaintext `nsis_block()` builds.
    assert_eq!(report.string_chars, 15);
    assert_eq!(report.strings, vec!["app.exe".to_string(), "hello".to_string()]);
    assert_eq!(report.command_count, 2);
    assert_eq!(report.commands[0].name, "File");
    assert_eq!(report.commands[0].rendered[1], "app.exe");
    assert_eq!(report.files.len(), 2);
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
    let stream = unhex(ZLIB_INFLATE_PAYLOAD);
    assert_eq!(stream.len(), 43, "the fixed zlib vector has 43 stored bytes");

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
    let stream = unhex(GZIP_PAYLOAD);

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
fn inflate_decodes_a_fixed_vector_in_every_envelope() {
    let plaintext = b"Hello, DEFLATE!";
    for (label, format, vector) in [
        ("raw", InflateFormat::Raw, RAW_HELLO),
        ("zlib", InflateFormat::Zlib, ZLIB_HELLO),
        ("gzip", InflateFormat::Gzip, GZIP_HELLO),
    ] {
        let output = TempFile::new(label);
        let view = BinaryView::from_bytes("vector.bin", unhex(vector));
        let report = view
            .inflate(&InflateOptions {
                offset: 0,
                format,
                limit: 4096,
                output: Some(output.path().to_string_lossy().into_owned()),
            })
            .expect("fixed vector");
        assert_eq!(report.status, "complete", "{label}");
        assert_eq!(report.output_bytes, plaintext.len() as u64, "{label}");
        assert_eq!(fs::read(output.path()).expect("read output"), plaintext, "{label}");
    }
}

#[test]
fn inflate_reports_input_truncation_in_every_envelope() {
    // A raw stream cut inside a later block keeps the prefix decoded so far.
    let payload = big_payload();
    let raw = unhex(RAW_BIG);
    let view = BinaryView::from_bytes("raw-truncated.bin", raw[..100].to_vec());
    let report = view
        .inflate(&InflateOptions { offset: 0, format: InflateFormat::Raw, limit: 1 << 20, output: None })
        .expect("truncated raw");
    assert_eq!(report.status, "input-truncated");
    assert!(!report.truncated, "only the output cap marks `truncated`");
    let produced = report.output_bytes as usize;
    assert!(produced > 0 && produced < payload.len(), "prefix length {produced}");
    assert_eq!(report.head_ascii, payload[..produced.min(32)].iter().map(|&b| b as char).collect::<String>());

    // A zlib member missing its Adler-32 trailer still yields the plaintext.
    let zlib = unhex(ZLIB_HELLO);
    let view = BinaryView::from_bytes("zlib-truncated.bin", zlib[..zlib.len() - 2].to_vec());
    let report = view
        .inflate(&InflateOptions { offset: 0, format: InflateFormat::Zlib, limit: 4096, output: None })
        .expect("truncated zlib");
    assert_eq!(report.status, "input-truncated");
    assert_eq!(report.output_bytes, 15);

    // A gzip member missing its CRC-32/ISIZE trailer behaves the same way.
    let gzip = unhex(GZIP_HELLO);
    let view = BinaryView::from_bytes("gzip-truncated.bin", gzip[..gzip.len() - 4].to_vec());
    let report = view
        .inflate(&InflateOptions { offset: 0, format: InflateFormat::Gzip, limit: 4096, output: None })
        .expect("truncated gzip");
    assert_eq!(report.status, "input-truncated");
    assert_eq!(report.output_bytes, 15);
}

#[test]
fn inflate_reports_the_output_limit_in_every_envelope() {
    // The raw back-reference that crosses the cap is refused whole, so the
    // prefix stops at 791 of the 1000 requested bytes.
    let payload = big_payload();
    let output = TempFile::new("raw-capped");
    let view = BinaryView::from_bytes("raw-capped.bin", unhex(RAW_BIG));
    let report = view
        .inflate(&InflateOptions {
            offset: 0,
            format: InflateFormat::Raw,
            limit: 1000,
            output: Some(output.path().to_string_lossy().into_owned()),
        })
        .expect("capped raw");
    assert_eq!(report.status, "output-limit");
    assert!(report.truncated);
    assert_eq!(report.output_bytes, 791);
    assert_eq!(fs::read(output.path()).expect("read output"), payload[..791]);

    for (label, format, vector) in [("zlib", InflateFormat::Zlib, ZLIB_HELLO), ("gzip", InflateFormat::Gzip, GZIP_HELLO)] {
        let output = TempFile::new(label);
        let view = BinaryView::from_bytes("capped.bin", unhex(vector));
        let report = view
            .inflate(&InflateOptions {
                offset: 0,
                format,
                limit: 1,
                output: Some(output.path().to_string_lossy().into_owned()),
            })
            .expect("capped envelope");
        assert_eq!(report.status, "output-limit", "{label}");
        assert_eq!(report.output_bytes, 1, "{label}");
        assert_eq!(fs::read(output.path()).expect("read output"), b"H", "{label}");
    }
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
    let error =
        view.inflate(&InflateOptions { offset: 4, format: InflateFormat::Auto, limit: 64, output: None }).expect_err("range");
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
    let report = view.find(&FindOptions { pattern: "marker-[0-9]".into(), ..FindOptions::default() }).expect("regex hits");

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
    let sensitive = view.find(&FindOptions { pattern: "marker".into(), ..FindOptions::default() }).expect("sensitive");
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
fn dump_writes_a_byte_range_to_the_output_file() {
    let view = BinaryView::from_bytes("dump.bin", b"0123456789abcdef".to_vec());
    let output = TempFile::new("dump-out");
    let report =
        view.dump(&DumpOptions { offset: 4, length: 8, output: output.path().display().to_string() }).expect("dump range");

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
    let report =
        view.carve(&CarveOptions { marker: "synthetic-blob".into(), ..CarveOptions::default() }).expect("carve regions");

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
        .carve(&CarveOptions {
            marker: "synthetic-blob".into(),
            output_dir: Some(dir.display().to_string()),
            ..CarveOptions::default()
        })
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

    let clamped =
        view.carve(&CarveOptions { marker: "more".into(), limit: 9_999, ..CarveOptions::default() }).expect("clamped");
    assert_eq!(clamped.limit, 100);

    let (bytes, _start, _marker, _js_len) = carve_fixture();
    let big = BinaryView::from_bytes("carve-cut.bin", bytes);
    let cut =
        big.carve(&CarveOptions { marker: "synthetic-blob".into(), limit: 1, ..CarveOptions::default() }).expect("cut scan");
    assert_eq!(cut.limit, 1);
    assert_eq!(cut.total, 1);
    assert!(cut.truncated);
    assert_eq!(cut.regions.len(), 1);

    let error: IdaError = big.carve(&CarveOptions { marker: "(unclosed".into(), ..CarveOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

/// One fixed Tauri asset: key, expected plaintext, compressed hex.
struct AssetVector {
    key: &'static str,
    plaintext: &'static [u8],
    compressed: &'static str,
}

/// Decodes a hex-encoded compressed fixture.
fn compressed(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "odd number of hex digits");
    (0..value.len()).step_by(2).map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex")).collect()
}

/// Embedded assets produced once with Node.js 24 `zlib.brotliCompressSync`
/// (quality 9, default 22-bit window), the settings Tauri v2 codegen uses for
/// every asset. `INDEX_HTML` is 46 bytes (SHA-256
/// `9a042df3871c5fb2ecf58ab0e13cd9ef5ada81304bc782ed49827fd5707258ce`).
const INDEX_HTML: &str = "1b2d0000a45e7860030e1cd22ca4878db1295fbcfd9e983dbc65eee51501";

/// `/assets/app.js`, 21 bytes (SHA-256
/// `f4b457f23429ca4f1afb44665306b56e6fa9deb620fc3eed01619fe328f65100`).
const APP_JS: &str = "0b0a80636f6e736f6c652e6c6f672822746175726922293b03";

/// `/icon.png`, 14 bytes (SHA-256
/// `84b15eaf2db8997aa5ba96d6ca7e29a6d30cb44e5a802d80033b122928b185c2`).
const ICON_PNG: &str = "8b068089504e470d0a1a0a00010203040503";

/// `/index.html` for the unsafe-key case, 27 bytes (SHA-256
/// `74262fd91e8cd47ae659a23a3856472937d0fd35dc6f4627e30d3f38b6040a8b`).
const SAFE_INDEX_HTML: &str = "1b1a0000a45f787ce0e426a208539377e02d4f0e";

/// `/../evil.txt` for the unsafe-key case, 17 bytes (SHA-256
/// `48d57bc3fcbd608b890753e317c6ede778a0fa0e4d8e933f601e8adf38a8f853`).
const EVIL_TRAVERSAL: &str = "0b088074726176657273616c207061796c6f616403";

/// Builds a 1:1 virtual-address container holding one interleaved
/// `[key_ptr, key_len, blob_ptr, blob_len, ...]` table in noise.
fn tauri_container(payloads: &[AssetVector]) -> Vec<u8> {
    let mut data = vec![0_u8; 512];
    let mut records: Vec<(u64, u64, u64, u64)> = Vec::new();
    for vector in payloads {
        let key_offset = data.len() as u64;
        data.extend_from_slice(vector.key.as_bytes());
        while data.len() % 8 != 0 {
            data.push(0);
        }
        let blob = compressed(vector.compressed);
        let blob_offset = data.len() as u64;
        data.extend_from_slice(&blob);
        records.push((key_offset, vector.key.len() as u64, blob_offset, blob.len() as u64));
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

fn tauri_payloads() -> Vec<AssetVector> {
    vec![
        AssetVector {
            key: "/index.html",
            plaintext: b"<!doctype html><html><body>hello</body></html>",
            compressed: INDEX_HTML,
        },
        AssetVector { key: "/assets/app.js", plaintext: b"console.log(\"tauri\");", compressed: APP_JS },
        AssetVector {
            key: "/icon.png",
            plaintext: &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            compressed: ICON_PNG,
        },
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
    for (asset, vector) in report.assets.iter().zip(&payloads) {
        assert_eq!(asset.decompressed_len, vector.plaintext.len());
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
    assert_eq!(fs::read(&written).expect("read asset file"), payloads[1].plaintext);
    fs::remove_dir_all(&dir).expect("cleanup");

    let cut = scan_assets(&data, &resolve, &TauriAssetsOptions { limit: Some(1), ..TauriAssetsOptions::default() })
        .expect("cut scan");
    assert_eq!(cut.assets.len(), 1);
    assert_eq!(cut.total, 3);
    assert!(cut.truncated);

    let clamped = scan_assets(&data, &resolve, &TauriAssetsOptions { limit: Some(9_999), ..TauriAssetsOptions::default() })
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
    let payloads = vec![
        AssetVector { key: "/index.html", plaintext: b"<!doctype html><p>hello</p>", compressed: SAFE_INDEX_HTML },
        AssetVector { key: "/../evil.txt", plaintext: b"traversal payload", compressed: EVIL_TRAVERSAL },
    ];
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
    let report = view.unpack(&UnpackOptions { format: UnpackFormat::Asar, ..UnpackOptions::default() }).expect("decode asar");
    let UnpackReport::Asar(report) = report
    else {
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
    let UnpackReport::Asar(cut) = cut
    else {
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
    let UnpackReport::Asar(report) = report
    else {
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
    let error = view.unpack(&UnpackOptions { format: UnpackFormat::Asar, ..UnpackOptions::default() }).unwrap_err();
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
    let UnpackReport::SevenZ(report) = sniffed
    else {
        panic!("the 7z signature must win the auto sniff");
    };
    assert_eq!(report.start_offset, 0);
    assert_eq!(report.version, "0.4");
    assert_eq!(report.entry_count, 0);
    assert_eq!(report.folder_count, 0);
    assert_eq!(report.total_unpack_size, 0);
    assert!(report.methods.is_empty());
    assert!(!report.truncated);

    let explicit =
        view.unpack(&UnpackOptions { format: UnpackFormat::SevenZ, ..UnpackOptions::default() }).expect("explicit 7z route");
    let UnpackReport::SevenZ(explicit) = explicit
    else {
        panic!("the explicit 7z route must answer with a 7z report");
    };
    assert_eq!(explicit.entry_count, 0);
}

#[test]
fn unpack_rejects_a_non_sevenz_input_on_the_explicit_route() {
    let file = TempFile::new("sevenz-bad");
    file.write(&pe_bytes());
    let view = BinaryView::open(file.path()).expect("open PE");
    let error = view.unpack(&UnpackOptions { format: UnpackFormat::SevenZ, ..UnpackOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

/// Appends one big-endian word, as PyInstaller stores cookie and TOC words.

fn pyi_be32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Appends one `CArchive` TOC entry header plus its NUL-terminated name.
/// The fixed header is 18 bytes; the declared entry size counts the name
/// field, so the NUL padding is `19 - name length` bytes.
fn pyi_toc_entry(out: &mut Vec<u8>, offset: u32, length: u32, compress_length: u32, flags: u8, typecode: u8, name: &str) {
    pyi_be32(out, (18 + name.len() + 1) as u32);
    pyi_be32(out, offset);
    pyi_be32(out, length);
    pyi_be32(out, compress_length);
    out.push(flags);
    out.push(typecode);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
}

/// Writes one `marshal` short-ASCII string and one small int.
fn pyi_marshal_str(out: &mut Vec<u8>, text: &str) {
    out.push(b'Z');
    out.push(text.len() as u8);
    out.extend_from_slice(text.as_bytes());
}

fn pyi_marshal_int(out: &mut Vec<u8>, value: i32) {
    out.push(b'i');
    out.extend_from_slice(&value.to_le_bytes());
}

/// Writes the PYZ module dictionary: names mapped to triples.
fn pyi_pyz_toc(out: &mut Vec<u8>, modules: &[(&str, bool, u32, u32)]) {
    out.push(b'{');
    for (name, is_package, offset, length) in modules {
        pyi_marshal_str(out, name);
        out.push(b'(');
        out.extend_from_slice(&3i32.to_le_bytes());
        out.push(if *is_package { b'T' } else { b'F' });
        pyi_marshal_int(out, *offset as i32);
        pyi_marshal_int(out, *length as i32);
    }
    out.push(b'0');
}

/// The PYZ image: header, two fixed zlib-stored modules and the marshal
/// dictionary. The streams come from the fixed Node.js vectors, so the image
/// bytes are stable and `ZLIB_PYZ` is the matching compressed member.
fn pyz_image() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let module_one = b"\xe3\x00\x00\x00\x00first module marshal".to_vec();
    let module_two = b"\xe3\x00\x00\x00\x00second module marshal".to_vec();
    let stream_one = unhex(ZLIB_MODULE_ONE);
    let stream_two = unhex(ZLIB_MODULE_TWO);
    let mut pyz = b"PYZ\x00".to_vec();
    pyz.extend_from_slice(&[0xcb, 0x0d, 0x0d, 0x0a]);
    pyi_be32(&mut pyz, 12 + stream_one.len() as u32 + stream_two.len() as u32);
    pyz.extend_from_slice(&stream_one);
    pyz.extend_from_slice(&stream_two);
    let offset_one = 12;
    let offset_two = 12 + stream_one.len() as u32;
    pyi_pyz_toc(
        &mut pyz,
        &[("base_module", false, offset_one, stream_one.len() as u32), ("pkg.mod", true, offset_two, stream_two.len() as u32)],
    );
    (pyz, module_one, module_two)
}

/// A fake bootloader prefix with a complete `CArchive` appended: a raw script,
/// one zlib data entry and one zlib-compressed PYZ.
fn pyinstaller_bytes() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (pyz, module_one, module_two) = pyz_image();
    let mut exe = b"MZ\x90\x00 fake bootloader prefix".to_vec();
    let mut package: Vec<u8> = Vec::new();
    let script = b"\xe3\x00\x00\x00\x00main script marshal".to_vec();
    let script_offset = package.len() as u32;
    package.extend_from_slice(&script);
    let payload = b"compressible compressible compressible data".to_vec();
    let stream = unhex(ZLIB_COMPRESSIBLE);
    let data_offset = package.len() as u32;
    package.extend_from_slice(&stream);
    let pyz_stream = unhex(ZLIB_PYZ);
    let pyz_offset = package.len() as u32;
    package.extend_from_slice(&pyz_stream);
    let toc_offset = package.len() as u32;
    let mut toc = Vec::new();
    pyi_toc_entry(&mut toc, script_offset, script.len() as u32, script.len() as u32, 0, b's', "main.py");
    pyi_toc_entry(&mut toc, data_offset, payload.len() as u32, stream.len() as u32, 1, b'd', "payload.bin");
    pyi_toc_entry(&mut toc, pyz_offset, pyz.len() as u32, pyz_stream.len() as u32, 1, b'z', "PYZ-00.pyz");
    let toc_length = toc.len() as u32;
    package.extend_from_slice(&toc);
    exe.extend_from_slice(&package);
    exe.extend_from_slice(b"MEI\x0c\x0b\x0a\x0b\x0e");
    pyi_be32(&mut exe, (package.len() + 24) as u32);
    pyi_be32(&mut exe, toc_offset);
    pyi_be32(&mut exe, toc_length);
    pyi_be32(&mut exe, 312);
    (exe, module_one, module_two)
}

#[test]
fn unpack_indexes_a_pyinstaller_carchive_and_its_pyz() {
    let (bytes, _, _) = pyinstaller_bytes();
    let file = TempFile::new("pyi");
    file.write(&bytes);
    let view = BinaryView::open(file.path()).expect("open the bundle");

    let sniffed = view.unpack(&UnpackOptions::default()).expect("sniff the CArchive");
    let UnpackReport::Pyinstaller(report) = sniffed
    else {
        panic!("the sniff must resolve to PyInstaller");
    };
    assert_eq!(report.archive_kind, "carchive");
    assert_eq!(report.version.as_deref(), Some("3.12"));
    assert_eq!(report.entry_count, 3);
    assert_eq!(report.entries.len(), 3);
    assert_eq!(report.entries[0].kind, "script");
    assert_eq!(report.entries[0].name, "main.py");
    assert!(!report.entries[0].compressed);
    assert_eq!(report.entries[1].kind, "data");
    assert!(report.entries[1].compressed);
    assert_eq!(report.entries[2].typecode, "z");
    assert_eq!(report.entries[2].module_count, Some(2));
    assert_eq!(report.entries[2].modules[0].name, "base_module");
    assert!(!report.entries[2].modules[0].is_package);
    assert_eq!(report.entries[2].modules[1].name, "pkg.mod");
    assert!(report.entries[2].modules[1].is_package);
    assert!(!report.truncated);

    let explicit = view
        .unpack(&UnpackOptions { format: UnpackFormat::Pyinstaller, entries_limit: 2, ..UnpackOptions::default() })
        .expect("explicit CArchive route");
    let UnpackReport::Pyinstaller(report) = explicit
    else {
        panic!("the explicit route must answer with a PyInstaller report");
    };
    assert_eq!(report.entries.len(), 2);
    assert!(report.truncated);
}

#[test]
fn unpack_indexes_a_standalone_pyz_archive() {
    let (pyz, _, _) = pyz_image();
    let file = TempFile::new("pyz");
    file.write(&pyz);
    let view = BinaryView::open(file.path()).expect("open the PYZ");

    let sniffed = view.unpack(&UnpackOptions::default()).expect("sniff the PYZ");
    let UnpackReport::Pyinstaller(report) = sniffed
    else {
        panic!("the sniff must resolve to PyInstaller");
    };
    assert_eq!(report.archive_kind, "pyz");
    assert_eq!(report.python.as_deref(), Some("CPython 3.12"));
    assert_eq!(report.entry_count, 2);
    assert_eq!(report.modules[0].name, "base_module");
    assert_eq!(report.modules[1].name, "pkg.mod");
}

#[test]
fn pyinstaller_extracts_entries_and_pyz_modules() {
    let (bytes, module_one, module_two) = pyinstaller_bytes();
    let file = TempFile::new("pyi-extract");
    file.write(&bytes);
    let view = BinaryView::open(file.path()).expect("open the bundle");
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("open-ida-{id}-pyi"));

    let report = view
        .unpack(&UnpackOptions {
            format: UnpackFormat::Pyinstaller,
            extract_dir: Some(dir.display().to_string()),
            ..UnpackOptions::default()
        })
        .expect("decode with extraction");
    let UnpackReport::Pyinstaller(report) = report
    else {
        panic!("the explicit route must answer with a PyInstaller report");
    };

    let script = report.entries[0].extracted.as_ref().expect("script entry").replace('\\', "/");
    assert!(script.ends_with("/main.py"), "the entry name is mirrored: {script}");
    assert_eq!(fs::read(&script).expect("read script"), b"\xe3\x00\x00\x00\x00main script marshal");
    let payload = report.entries[1].extracted.as_ref().expect("data entry").replace('\\', "/");
    assert_eq!(fs::read(&payload).expect("read payload"), b"compressible compressible compressible data");
    assert!(report.entries[2].extracted.is_none(), "the PYZ blob itself is not written");
    let modules = &report.entries[2].modules;
    let first = modules[0].extracted.as_ref().expect("module one").replace('\\', "/");
    assert!(first.ends_with("/PYZ-00.pyz/base_module.pyc"), "modules land under the PYZ name: {first}");
    assert_eq!(fs::read(&first).expect("read module one"), module_one);
    let second = modules[1].extracted.as_ref().expect("module two").replace('\\', "/");
    assert_eq!(fs::read(&second).expect("read module two"), module_two);
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn unpack_rejects_a_broken_pyinstaller_cookie() {
    let (mut bytes, _, _) = pyinstaller_bytes();
    // Claim a package longer than the file.
    let cookie = bytes.len() - 16;
    bytes[cookie..cookie + 4].copy_from_slice(&(u32::MAX).to_be_bytes());
    let file = TempFile::new("pyi-bad");
    file.write(&bytes);
    let view = BinaryView::open(file.path()).expect("open the bundle");
    let error = view.unpack(&UnpackOptions { format: UnpackFormat::Pyinstaller, ..UnpackOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
    assert!(error.message().contains("package length"), "the message names the field: {}", error.message());

    let plain = TempFile::new("pyi-none");
    plain.write(&pe_bytes());
    let view = BinaryView::open(plain.path()).expect("open the PE");
    let error = view.unpack(&UnpackOptions { format: UnpackFormat::Pyinstaller, ..UnpackOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
    assert!(error.message().contains("cookie"), "the message names the cookie: {}", error.message());
}
