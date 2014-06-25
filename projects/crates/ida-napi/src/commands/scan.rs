//! Scanning operations: disassembly, pattern search, byte find, raw dump,
//! carving and Tauri asset extraction, each driven by an options JSON.

use open_ida_core::{
    AsarOptions, CarveOptions, DisassembleOptions, DisassemblySyntax, DumpOptions, FindOptions, IdaError, InflateOptions,
    NsisOptions, PycFormat, PycOptions, SearchOptions, TauriAssetsOptions, sniff_pyc,
};
use serde::Deserialize;
use serde_json::Value;
use wae::{CallContext, JsValue, Result};

use crate::{
    args::{encoded, failure, handle, respond, text},
    registry::with_engine,
};

/// Combined inputs of the unified disassembly route: `format` picks the
/// machine path (`x86`), the bytecode path (`pyc`) or a sniff of the bytes
/// at `offset` (`auto`). Fields irrelevant to the chosen path are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DisasmInput {
    offset: Option<u64>,
    count: Option<usize>,
    syntax: Option<DisassemblySyntax>,
    format: Option<String>,
    code: Option<String>,
    code_limit: Option<usize>,
    instruction_limit: Option<usize>,
}

pub(crate) fn disasm_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let input = serde_json::from_str::<DisasmInput>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid DisassembleOptions: {error}")))?;
    with_engine(handle, |engine| {
        let bytecode = match input.format.as_deref().unwrap_or("auto") {
            "x86" => false,
            "pyc" => true,
            "auto" => {
                let size = engine.session().size();
                let length = 8u64.min(size.saturating_sub(input.offset.unwrap_or(0)));
                length > 0 && sniff_pyc(engine.session().read(input.offset.unwrap_or(0), length)?)
            }
            other => {
                return Err(IdaError::parse(format!(
                    "unknown disassembly format `{other}`; expected auto, x86 or pyc"
                )));
            }
        };
        if bytecode {
            let defaults = PycOptions::default();
            let options = PycOptions {
                offset: input.offset,
                format: PycFormat::Auto,
                code: input.code,
                code_limit: input.code_limit.unwrap_or(defaults.code_limit),
                instruction_limit: input.instruction_limit.unwrap_or(defaults.instruction_limit),
            };
            encoded(&engine.pyc(&options)?)
        } else {
            let defaults = DisassembleOptions::default();
            let options = DisassembleOptions {
                offset: input.offset.unwrap_or(defaults.offset),
                count: input.count.unwrap_or(defaults.count),
                syntax: input.syntax.unwrap_or(defaults.syntax),
            };
            encoded(&engine.disasm(&options)?)
        }
    })
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

fn inflate_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<InflateOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid InflateOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.inflate(&options)?))
}

fn nsis_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<NsisOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid NsisOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.nsis(&options)?))
}

fn asar_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<AsarOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid AsarOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.asar(&options)?))
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

pub(crate) fn binary_inflate(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match inflate_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_nsis(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match nsis_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_asar(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match asar_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
