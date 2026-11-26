//! PE-specific directory reports: debug, version, resources, mitigations,
//! exceptions, imports, relocations, certificates, TLS and load config.

use ida_domain::IdaError;
use serde_json::Value;
use wae::{CallContext, JsValue, Result};

use crate::{
    args::{encoded, failure, handle, limit_value, optional_number, respond},
    registry::with_engine,
};

pub(crate) fn debug_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.debug(limit_value(limit))?))
}

fn version_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.version()?))
}

fn mitigations_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.mitigations()?))
}

fn overlay_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.overlay()?))
}

fn resources_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.resources()?))
}

fn relocations_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.relocations()?))
}

fn exception_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.exception()?))
}

fn delay_imports_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.delay_imports()?))
}

fn bound_imports_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.bound_imports()?))
}

fn rich_header_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.rich_header()?))
}

fn certificates_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.certificates()?))
}

fn tls_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.tls()?))
}

fn load_config_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.load_config()?))
}

pub(crate) fn binary_debug(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match debug_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_version(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match version_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_mitigations(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match mitigations_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_overlay(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match overlay_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_resources(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match resources_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_relocations(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match relocations_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_exception(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match exception_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_delay_imports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match delay_imports_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_bound_imports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match bound_imports_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_rich_header(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match rich_header_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_certificates(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match certificates_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_tls(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match tls_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_load_config(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match load_config_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
