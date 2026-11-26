//! Argument extraction and JSON response helpers shared by every export.

use ida_domain::IdaError;
use serde::Serialize;
use serde_json::Value;
use wae::{CallContext, Error, JsValue, Result};

pub(crate) fn failure(error: IdaError) -> Error {
    Error::new(format!("{}: {}", error.code(), error.message()))
}

pub(crate) fn argument(ctx: &CallContext, index: usize) -> Result<JsValue> {
    ctx.args().get(index).copied().ok_or_else(|| Error::new("binary/range: a required argument is missing"))
}

pub(crate) fn handle(ctx: &CallContext, index: usize) -> Result<u64> {
    number(ctx, index)
}

pub(crate) fn number(ctx: &CallContext, index: usize) -> Result<u64> {
    let raw = argument(ctx, index)?.as_i64()?;
    u64::try_from(raw).map_err(|_| Error::new("binary/range: the argument must be a non-negative integer"))
}

pub(crate) fn text(ctx: &CallContext, index: usize) -> Result<String> {
    argument(ctx, index)?.as_string()
}

pub(crate) fn optional_number(ctx: &CallContext, index: usize) -> Result<Option<u64>> {
    match ctx.args().get(index).copied() {
        Some(value) if !value.is_undefined()? => {
            let raw = value.as_i64()?;
            u64::try_from(raw).map(Some).map_err(|_| Error::new("binary/range: the argument must be a non-negative integer"))
        }
        _ => Ok(None),
    }
}

pub(crate) fn optional_text(ctx: &CallContext, index: usize) -> Result<Option<String>> {
    match ctx.args().get(index).copied() {
        Some(value) if !value.is_undefined()? => Ok(Some(value.as_string()?)),
        _ => Ok(None),
    }
}

pub(crate) fn respond<T: Serialize>(ctx: &CallContext, value: &T) -> Result<JsValue> {
    let encoded = serde_json::to_string(value).map_err(|error| Error::new(format!("binary/parse: {error}")))?;
    ctx.env().string(&encoded)
}

pub(crate) fn encoded<T: Serialize>(value: &T) -> std::result::Result<Value, IdaError> {
    serde_json::to_value(value).map_err(|error| IdaError::parse(error.to_string()))
}

pub(crate) fn limit_value(limit: Option<u64>) -> Option<usize> {
    limit.map(|value| usize::try_from(value).unwrap_or(usize::MAX))
}
