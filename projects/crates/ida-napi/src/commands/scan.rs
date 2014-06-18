//! Scanning operations: disassembly, pattern search, byte find, raw dump,
//! carving and Tauri asset extraction, each driven by an options JSON.

use open_ida_core::{CarveOptions, DisassembleOptions, DumpOptions, FindOptions, IdaError, SearchOptions, TauriAssetsOptions};
use serde_json::Value;
use wae::{CallContext, JsValue, Result};

use crate::{
    args::{encoded, failure, handle, respond, text},
    registry::with_engine,
};

pub(crate) fn disasm_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<DisassembleOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid DisassembleOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.disasm(&options)?))
}

pub(crate) fn search_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<SearchOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid SearchOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.search(&options)?))
}

fn find_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<FindOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid FindOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.find(&options)?))
}

fn dump_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<DumpOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid DumpOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.dump(&options)?))
}

fn carve_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<CarveOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid CarveOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.carve(&options)?))
}

fn tauri_assets_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<TauriAssetsOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid TauriAssetsOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.tauri_assets(&options)?))
}

pub(crate) fn binary_disasm(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match disasm_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_search(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match search_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_find(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match find_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_dump(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match dump_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_carve(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match carve_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_tauri_assets(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match tauri_assets_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
