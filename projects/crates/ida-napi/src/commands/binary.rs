//! Core binary session operations: open, headers, sections, strings, raw
//! bytes, patches, address mapping and comparison.

use std::path::Path;

use open_ida_core::{IdaError, OpenIdaOptions, StringsOptions};
use serde_json::{Value, json};
use wae::{CallContext, Error, JsValue, Result};

use crate::{
    args::{encoded, failure, handle, limit_value, number, optional_number, optional_text, respond, text},
    registry::{close_engine, lock, missing, open_engine, with_engine, with_engine_mut},
};

pub(crate) fn section_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| Ok(json!({ "sections": encoded(&engine.sections()?)? })))
}

pub(crate) fn strings_report(handle: u64, min_len: Option<u64>, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| {
        let min_len =
            min_len.map(|value| usize::try_from(value).map_err(|_| IdaError::range("`minLen` is too large"))).transpose()?;
        let limit = limit.map(|value| usize::try_from(value).unwrap_or(usize::MAX));
        encoded(&engine.strings(min_len, limit))
    })
}

fn strings_encoded_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<StringsOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid StringsOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.strings_encoded(&options)?))
}

pub(crate) fn hexdump_report(handle: u64, offset: Option<u64>, length: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| {
        let resolved_offset = offset.unwrap_or(0);
        let resolved_length = length.unwrap_or(engine.options().hexdump_length);
        let text = engine.hexdump(Some(resolved_offset), Some(resolved_length))?;
        Ok(json!({ "offset": resolved_offset, "length": resolved_length, "text": text }))
    })
}

pub(crate) fn read_report(handle: u64, offset: u64, length: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| {
        let bytes = engine.read(offset, length)?;
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        Ok(json!({ "offset": offset, "length": length, "hex": hex }))
    })
}

pub(crate) fn patch_report(
    handle: u64,
    offset: u64,
    hex_bytes: &str,
    output: Option<&Path>,
) -> std::result::Result<Value, IdaError> {
    let bytes = open_ida_core::parse_hex(hex_bytes)?;
    with_engine_mut(handle, |engine| encoded(&engine.patch(offset, &bytes, output)?))
}

pub(crate) fn rva_report(handle: u64, rva: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| Ok(json!({ "rva": rva, "offset": engine.rva(rva)? })))
}

pub(crate) fn imports_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.imports(limit_value(limit))?))
}

pub(crate) fn exports_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.exports(limit_value(limit))?))
}

pub(crate) fn symbols_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.symbols(limit_value(limit))?))
}

pub(crate) fn entropy_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.entropy()?))
}

pub(crate) fn diff_report(left: u64, right: u64) -> std::result::Result<Value, IdaError> {
    let registry = lock()?;
    let left_engine = registry.engines.get(&left).ok_or_else(|| missing(left))?;
    let right_engine = registry.engines.get(&right).ok_or_else(|| missing(right))?;
    encoded(&left_engine.diff(right_engine)?)
}

pub(crate) fn offset_to_va_report(handle: u64, offset: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| Ok(json!({ "offset": offset, "va": engine.offset_to_va(offset)? })))
}

pub(crate) fn offset_to_rva_report(handle: u64, offset: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| Ok(json!({ "offset": offset, "rva": engine.offset_to_rva(offset)? })))
}

pub(crate) fn binary_open(ctx: CallContext) -> Result<JsValue> {
    let raw = text(&ctx, 0)?;
    let options = serde_json::from_str::<OpenIdaOptions>(&raw)
        .map_err(|error| Error::new(format!("binary/parse: invalid options: {error}")))?;
    match open_engine(options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_info(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match with_engine(handle, |engine| encoded(&engine.info()?)) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_sections(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match section_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_strings(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let min_len = optional_number(&ctx, 1)?;
    let limit = optional_number(&ctx, 2)?;
    match strings_report(handle, min_len, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_strings_encoded(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match strings_encoded_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_hexdump(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = optional_number(&ctx, 1)?;
    let length = optional_number(&ctx, 2)?;
    match hexdump_report(handle, offset, length) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_read(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    let length = number(&ctx, 2)?;
    match read_report(handle, offset, length) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_patch(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    let hex_bytes = text(&ctx, 2)?;
    let output = optional_text(&ctx, 3)?;
    let path = output.as_deref().map(Path::new);
    match patch_report(handle, offset, &hex_bytes, path) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_rva(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let rva = number(&ctx, 1)?;
    match rva_report(handle, rva) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_imports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match imports_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_exports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match exports_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_symbols(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match symbols_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_entropy(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match entropy_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_diff(ctx: CallContext) -> Result<JsValue> {
    let left = handle(&ctx, 0)?;
    let right = handle(&ctx, 1)?;
    match diff_report(left, right) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_offset_to_va(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    match offset_to_va_report(handle, offset) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_offset_to_rva(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    match offset_to_rva_report(handle, offset) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_close(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match close_engine(handle) {
        Ok(()) => ctx.env().boolean(true),
        Err(error) => Err(failure(error)),
    }
}
