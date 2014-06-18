//! Mach-O reports: load commands, symbol tables, dyld structures, fat
//! containers and the embedded code signature.

use std::path::Path;

use open_ida_core::IdaError;
use serde_json::Value;
use wae::{CallContext, Error, JsValue, Result};

use crate::{
    args::{encoded, failure, handle, limit_value, number, optional_number, respond, text},
    registry::with_engine,
};

fn macho_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho()?))
}

fn macho_symbols_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_symbols(limit_value(limit))?))
}

fn macho_slices_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_slices()?))
}

fn macho_function_starts_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_function_starts(limit_value(limit))?))
}

fn macho_exports_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_exports()?))
}

fn macho_encryption_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_encryption()?))
}

fn macho_chained_fixups_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_chained_fixups()?))
}

fn macho_bindings_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_bindings()?))
}

fn macho_extract_report(handle: u64, index: usize, output: &Path) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.extract_slice(index, output)?))
}

fn code_signature_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.code_signature()?))
}

pub(crate) fn binary_macho(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_symbols(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match macho_symbols_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_exports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_exports_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_encryption(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_encryption_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_chained_fixups(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_chained_fixups_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_bindings(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_bindings_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_function_starts(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match macho_function_starts_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_slices(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_slices_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_extract(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let index = number(&ctx, 1)?;
    let index = usize::try_from(index).map_err(|_| Error::new("binary/range: the slice index is too large"))?;
    let output = text(&ctx, 2)?;
    match macho_extract_report(handle, index, Path::new(&output)) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_code_signature(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match code_signature_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
