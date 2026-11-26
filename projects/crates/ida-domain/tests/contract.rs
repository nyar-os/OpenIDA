//! Product contract tests.
//!
//! Capabilities, the stable error codes and the wire defaults every report
//! option carries. These assertions are the published contract; changing a
//! code or a serde name must fail here first.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use ida_domain::{BinaryView, CarveOptions, FindOptions, IdaError, OpenIda, StringEncoding, StringsOptions};

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

#[test]
fn malformed_big_endian_elf_is_rejected() {
    let mut bytes = elf64_bytes();
    bytes[5] = 2;
    let view = BinaryView::from_bytes("big-endian.elf", bytes);
    let error = view.info().unwrap_err();
    assert_eq!(error.code(), "binary/parse");
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
    let matrix = ida_domain::capabilities();
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
    assert_eq!(ida_domain::parse_hex("90,90").unwrap(), vec![0x90, 0x90]);
    assert_eq!(ida_domain::parse_hex("0x90 0x0d").unwrap(), vec![0x90, 0x0d]);
    assert_eq!(ida_domain::parse_hex("9090").unwrap(), vec![0x90, 0x90]);
    let error: IdaError = ida_domain::parse_hex("9").unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

/// 单节 `PE32+`：`.rdata` 覆盖文件 0x200..0x800，内含导入、导出与一个 `COFF` 符号。

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
