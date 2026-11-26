//! One live engine table per process, shared by every surface.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, OnceLock},
};

use ida_domain::{IdaError, OpenIda, OpenIdaOptions};
use serde_json::{Value, json};

use crate::args::encoded;

pub(crate) struct Registry {
    next: u64,
    pub(crate) engines: HashMap<u64, OpenIda>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry { next: 1, engines: HashMap::new() }))
}

pub(crate) fn lock() -> std::result::Result<MutexGuard<'static, Registry>, IdaError> {
    registry().lock().map_err(|_| IdaError::io("the binary handle table is poisoned"))
}

pub(crate) fn missing(handle: u64) -> IdaError {
    IdaError::new("handle/invalid", format!("no live binary has handle {handle}"))
}

pub(crate) fn with_engine(
    handle: u64,
    work: impl FnOnce(&OpenIda) -> std::result::Result<Value, IdaError>,
) -> std::result::Result<Value, IdaError> {
    let registry = lock()?;
    let engine = registry.engines.get(&handle).ok_or_else(|| missing(handle))?;
    work(engine)
}

pub(crate) fn with_engine_mut(
    handle: u64,
    work: impl FnOnce(&mut OpenIda) -> std::result::Result<Value, IdaError>,
) -> std::result::Result<Value, IdaError> {
    let mut registry = lock()?;
    let engine = registry.engines.get_mut(&handle).ok_or_else(|| missing(handle))?;
    work(engine)
}

pub(crate) fn open_engine(options: OpenIdaOptions) -> std::result::Result<Value, IdaError> {
    let engine = OpenIda::new(options)?;
    let info = encoded(&engine.info()?)?;
    let mut registry = lock()?;
    let handle = registry.next;
    registry.next += 1;
    registry.engines.insert(handle, engine);
    Ok(json!({ "handle": handle, "info": info }))
}

pub(crate) fn close_engine(handle: u64) -> std::result::Result<(), IdaError> {
    let mut registry = lock()?;
    registry.engines.remove(&handle).map(|_| ()).ok_or_else(|| missing(handle))
}
