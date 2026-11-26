//! ELF reports: static symbol table, dynamic dependencies, notes and the
//! program header table.

use ida_domain::IdaError;
use serde_json::Value;
use wae::{CallContext, JsValue, Result};

use crate::{
    args::{encoded, failure, handle, respond},
    registry::with_engine,
};

fn static_symbols_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.static_symbols()?))
}

fn dynamic_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.dynamic()?))
}

fn notes_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.notes()?))
}

fn segments_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.segments()?))
}

pub(crate) fn binary_static_symbols(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match static_symbols_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_dynamic(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match dynamic_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_notes(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match notes_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_segments(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match segments_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
