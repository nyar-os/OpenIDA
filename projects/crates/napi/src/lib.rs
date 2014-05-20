//! Thin Node-API surface for OpenIDA.
//!
//! Every export performs one orthogonal operation and returns a JSON string, so
//! the TypeScript layer owns argument parsing, help text and exit codes. Binary
//! semantics stay in `open-ida-core`; this layer only forwards operations, keeps
//! the live handle table and hosts the WebView window. The CLI and the studio
//! share the same table, so a file opened from one is visible to the other.

#![deny(missing_docs)]

use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use open_ida_core::{DisassembleOptions, IdaError, OpenIda, OpenIdaOptions, SearchOptions, StringsOptions};
use serde::Serialize;
use serde_json::{Value, json};
use wae::{
    CallContext, Error, JsValue, Result, function, optional_string_prop, register_module,
    webview::{IpcHandler, IpcOutcome, IpcSink, OpenOptions, WebViewError, WebViewHost},
};

fn failure(error: IdaError) -> Error {
    Error::new(format!("{}: {}", error.code(), error.message()))
}

fn argument(ctx: &CallContext, index: usize) -> Result<JsValue> {
    ctx.args().get(index).copied().ok_or_else(|| Error::new("binary/range: a required argument is missing"))
}

fn handle(ctx: &CallContext, index: usize) -> Result<u64> {
    number(ctx, index)
}

fn number(ctx: &CallContext, index: usize) -> Result<u64> {
    let raw = argument(ctx, index)?.as_i64()?;
    u64::try_from(raw).map_err(|_| Error::new("binary/range: the argument must be a non-negative integer"))
}

fn text(ctx: &CallContext, index: usize) -> Result<String> {
    argument(ctx, index)?.as_string()
}

fn optional_number(ctx: &CallContext, index: usize) -> Result<Option<u64>> {
    match ctx.args().get(index).copied() {
        Some(value) if !value.is_undefined()? => {
            let raw = value.as_i64()?;
            u64::try_from(raw).map(Some).map_err(|_| Error::new("binary/range: the argument must be a non-negative integer"))
        }
        _ => Ok(None),
    }
}

fn optional_text(ctx: &CallContext, index: usize) -> Result<Option<String>> {
    match ctx.args().get(index).copied() {
        Some(value) if !value.is_undefined()? => Ok(Some(value.as_string()?)),
        _ => Ok(None),
    }
}

fn respond<T: Serialize>(ctx: &CallContext, value: &T) -> Result<JsValue> {
    let encoded = serde_json::to_string(value).map_err(|error| Error::new(format!("binary/parse: {error}")))?;
    ctx.env().string(&encoded)
}

fn encoded<T: Serialize>(value: &T) -> std::result::Result<Value, IdaError> {
    serde_json::to_value(value).map_err(|error| IdaError::parse(error.to_string()))
}

// One live engine table per process shared by every surface.
struct Registry {
    next: u64,
    engines: HashMap<u64, OpenIda>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry { next: 1, engines: HashMap::new() }))
}

fn lock() -> std::result::Result<MutexGuard<'static, Registry>, IdaError> {
    registry().lock().map_err(|_| IdaError::io("the binary handle table is poisoned"))
}

fn missing(handle: u64) -> IdaError {
    IdaError::new("handle/invalid", format!("no live binary has handle {handle}"))
}

fn with_engine(
    handle: u64,
    work: impl FnOnce(&OpenIda) -> std::result::Result<Value, IdaError>,
) -> std::result::Result<Value, IdaError> {
    let registry = lock()?;
    let engine = registry.engines.get(&handle).ok_or_else(|| missing(handle))?;
    work(engine)
}

fn with_engine_mut(
    handle: u64,
    work: impl FnOnce(&mut OpenIda) -> std::result::Result<Value, IdaError>,
) -> std::result::Result<Value, IdaError> {
    let mut registry = lock()?;
    let engine = registry.engines.get_mut(&handle).ok_or_else(|| missing(handle))?;
    work(engine)
}

fn open_engine(options: OpenIdaOptions) -> std::result::Result<Value, IdaError> {
    let engine = OpenIda::new(options)?;
    let info = encoded(&engine.info()?)?;
    let mut registry = lock()?;
    let handle = registry.next;
    registry.next += 1;
    registry.engines.insert(handle, engine);
    Ok(json!({ "handle": handle, "info": info }))
}

fn section_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| Ok(json!({ "sections": encoded(&engine.sections()?)? })))
}

fn strings_report(handle: u64, min_len: Option<u64>, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
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

fn hexdump_report(handle: u64, offset: Option<u64>, length: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| {
        let resolved_offset = offset.unwrap_or(0);
        let resolved_length = length.unwrap_or(engine.options().hexdump_length);
        let text = engine.hexdump(Some(resolved_offset), Some(resolved_length))?;
        Ok(json!({ "offset": resolved_offset, "length": resolved_length, "text": text }))
    })
}

fn read_report(handle: u64, offset: u64, length: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| {
        let bytes = engine.read(offset, length)?;
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        Ok(json!({ "offset": offset, "length": length, "hex": hex }))
    })
}

fn patch_report(handle: u64, offset: u64, hex_bytes: &str, output: Option<&Path>) -> std::result::Result<Value, IdaError> {
    let bytes = open_ida_core::parse_hex(hex_bytes)?;
    with_engine_mut(handle, |engine| encoded(&engine.patch(offset, &bytes, output)?))
}

fn rva_report(handle: u64, rva: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| Ok(json!({ "rva": rva, "offset": engine.rva(rva)? })))
}

fn limit_value(limit: Option<u64>) -> Option<usize> {
    limit.map(|value| usize::try_from(value).unwrap_or(usize::MAX))
}

fn imports_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.imports(limit_value(limit))?))
}

fn exports_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.exports(limit_value(limit))?))
}

fn symbols_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.symbols(limit_value(limit))?))
}

fn debug_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.debug(limit_value(limit))?))
}

fn macho_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho()?))
}

fn macho_symbols_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_symbols(limit_value(limit))?))
}

fn macho_slices_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.macho_slices()?))
}

fn mitigations_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.mitigations()?))
}

fn resources_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.resources()?))
}

fn relocations_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.relocations()?))
}

fn version_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.version()?))
}

fn disasm_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<DisassembleOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid DisassembleOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.disasm(&options)?))
}

fn search_report(handle: u64, options_json: &str) -> std::result::Result<Value, IdaError> {
    let options = serde_json::from_str::<SearchOptions>(options_json)
        .map_err(|error| IdaError::parse(format!("invalid SearchOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.search(&options)?))
}

fn entropy_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| encoded(&engine.entropy()?))
}

fn diff_report(left: u64, right: u64) -> std::result::Result<Value, IdaError> {
    let registry = lock()?;
    let left_engine = registry.engines.get(&left).ok_or_else(|| missing(left))?;
    let right_engine = registry.engines.get(&right).ok_or_else(|| missing(right))?;
    encoded(&left_engine.diff(right_engine)?)
}

fn offset_to_va_report(handle: u64, offset: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| Ok(json!({ "offset": offset, "va": engine.offset_to_va(offset)? })))
}

fn offset_to_rva_report(handle: u64, offset: u64) -> std::result::Result<Value, IdaError> {
    with_engine(handle, |engine| Ok(json!({ "offset": offset, "rva": engine.offset_to_rva(offset)? })))
}

fn close_engine(handle: u64) -> std::result::Result<(), IdaError> {
    let mut registry = lock()?;
    registry.engines.remove(&handle).map(|_| ()).ok_or_else(|| missing(handle))
}

/// Library version of the native binding.
#[function]
fn version(ctx: CallContext) -> Result<JsValue> {
    ctx.env().string(env!("CARGO_PKG_VERSION"))
}

/// Reports the implemented and explicitly unsupported capability matrix.
#[function]
fn capabilities(ctx: CallContext) -> Result<JsValue> {
    let matrix = open_ida_core::capabilities().to_string();
    ctx.env().string(&matrix)
}

/// Opens a binary session from its options JSON and returns its handle and header summary.
#[function]
fn binary_open(ctx: CallContext) -> Result<JsValue> {
    let raw = text(&ctx, 0)?;
    let options = serde_json::from_str::<OpenIdaOptions>(&raw)
        .map_err(|error| Error::new(format!("binary/parse: invalid options: {error}")))?;
    match open_engine(options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Returns the header summary of an open binary.
#[function]
fn binary_info(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match with_engine(handle, |engine| encoded(&engine.info()?)) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Returns the section table of an open binary.
#[function]
fn binary_sections(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match section_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Extracts printable strings, bounded by a minimum length and an optional limit.
#[function]
fn binary_strings(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let min_len = optional_number(&ctx, 1)?;
    let limit = optional_number(&ctx, 2)?;
    match strings_report(handle, min_len, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Extracts ASCII or ASCII-in-UTF-16LE strings described by an options JSON.
#[function]
fn binary_strings_encoded(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match strings_encoded_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Renders a canonical hex dump of one byte range.
#[function]
fn binary_hexdump(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = optional_number(&ctx, 1)?;
    let length = optional_number(&ctx, 2)?;
    match hexdump_report(handle, offset, length) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Reads one byte range and returns it as a hex string.
#[function]
fn binary_read(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    let length = number(&ctx, 2)?;
    match read_report(handle, offset, length) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Patches bytes atomically, writing a copy when an output path is given.
#[function]
fn binary_patch(ctx: CallContext) -> Result<JsValue> {
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

/// Maps an RVA or virtual address onto a file offset.
#[function]
fn binary_rva(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let rva = number(&ctx, 1)?;
    match rva_report(handle, rva) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Lists imported functions.
#[function]
fn binary_imports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match imports_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Lists exported symbols.
#[function]
fn binary_exports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match exports_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Lists debug or dynamic symbols.
#[function]
fn binary_symbols(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match symbols_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Lists PE debug directory entries and `CodeView` PDB records.
#[function]
fn binary_debug(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match debug_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Decodes the PE version resource.
#[function]
fn binary_version(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match version_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Decodes Mach-O load commands, segments, sections, dylibs and identity.
#[function]
fn binary_macho(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Lists the PE resource directory leaves.
#[function]
fn binary_resources(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match resources_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Summarises the PE mitigation posture.
#[function]
fn binary_mitigations(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match mitigations_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Decodes the PE base relocation blocks.
#[function]
fn binary_relocations(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match relocations_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Lists the Mach-O `LC_SYMTAB` symbol table.
#[function]
fn binary_macho_symbols(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match macho_symbols_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Lists the architecture slices of a fat/universal Mach-O container.
#[function]
fn binary_macho_slices(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_slices_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Disassembles x86 / x64 instructions described by an options JSON.
#[function]
fn binary_disasm(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match disasm_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Searches for a hex, ASCII or UTF-16LE pattern described by an options JSON.
#[function]
fn binary_search(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match search_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Computes whole-file and per-section entropy plus the PE overlay.
#[function]
fn binary_entropy(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match entropy_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Compares two open binaries byte for byte.
#[function]
fn binary_diff(ctx: CallContext) -> Result<JsValue> {
    let left = handle(&ctx, 0)?;
    let right = handle(&ctx, 1)?;
    match diff_report(left, right) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Maps a file offset onto an absolute virtual address.
#[function]
fn binary_offset_to_va(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    match offset_to_va_report(handle, offset) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Maps a file offset onto a PE image-relative address.
#[function]
fn binary_offset_to_rva(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    match offset_to_rva_report(handle, offset) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Releases one binary handle.
#[function]
fn binary_close(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match close_engine(handle) {
        Ok(()) => ctx.env().boolean(true),
        Err(error) => Err(failure(error)),
    }
}

// One WebView host per process, owned by the thread that opened it.
thread_local! {
    static GUI: RefCell<Option<GuiState>> = const { RefCell::new(None) };
}

const GUI_CLOSED: &str = "gui_closed";
const GUI_HOST_EXITED: &str = "gui_host_exited";
const GUI_NOT_OPEN: &str = "gui_not_open";

struct GuiState {
    host: WebViewHost,
    backend: &'static str,
    opened_at: Instant,
    /// Set when the page asks the host to close, so a dead host is
    /// distinguishable from one that never processed the request.
    close_requested: Arc<AtomicBool>,
}

struct IdaIpcHandler {
    close_requested: Arc<AtomicBool>,
}

impl IpcHandler for IdaIpcHandler {
    fn on_ipc(&mut self, message: &str, _sink: &IpcSink) -> IpcOutcome {
        let Ok(value) = serde_json::from_str::<Value>(message)
        else {
            return IpcOutcome::Ignored;
        };
        let ty = value.get("type").and_then(Value::as_str).unwrap_or("");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        match ty {
            "close" => {
                self.close_requested.store(true, Ordering::SeqCst);
                IpcOutcome::CloseWindow
            }
            "ready" => reply(id, "readyResult", json!({ "version": env!("CARGO_PKG_VERSION"), "platform": platform_name() })),
            "capabilities" => reply(id, "capabilitiesResult", json!({ "capabilities": open_ida_core::capabilities() })),
            "binary.open" => {
                let options = value
                    .get("options")
                    .filter(|raw| raw.is_object())
                    .cloned()
                    .or_else(|| string_field(&value, "path").map(|path| json!({ "path": path })));
                match options {
                    Some(raw) => match serde_json::from_value::<OpenIdaOptions>(raw) {
                        Ok(options) => outcome(id, "openResult", open_engine(options)),
                        Err(error) => failure_reply(id, format!("binary/parse: invalid options: {error}")),
                    },
                    None => failure_reply(id, "binary/range: `options` or `path` is required".to_string()),
                }
            }
            "binary.info" => match handle_field(&value) {
                Some(handle) => outcome(id, "infoResult", with_engine(handle, |engine| encoded(&engine.info()?))),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.sections" => match handle_field(&value) {
                Some(handle) => outcome(id, "sectionsResult", section_report(handle)),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.strings" => match handle_field(&value) {
                Some(handle) => {
                    let min_len = value.get("minLen").and_then(Value::as_u64);
                    let limit = value.get("limit").and_then(Value::as_u64);
                    outcome(id, "stringsResult", strings_report(handle, min_len, limit))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.stringsEncoded" => match handle_field(&value) {
                Some(handle) => match serde_json::from_value::<StringsOptions>(value.clone()) {
                    Ok(options) => outcome(
                        id,
                        "stringsEncodedResult",
                        with_engine(handle, |engine| encoded(&engine.strings_encoded(&options)?)),
                    ),
                    Err(error) => failure_reply(id, format!("binary/parse: invalid StringsOptions: {error}")),
                },
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.hexdump" => match handle_field(&value) {
                Some(handle) => {
                    let offset = value.get("offset").and_then(Value::as_u64);
                    let length = value.get("length").and_then(Value::as_u64);
                    outcome(id, "hexdumpResult", hexdump_report(handle, offset, length))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.read" => match handle_field(&value) {
                Some(handle) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    let length = value.get("length").and_then(Value::as_u64).unwrap_or(256);
                    outcome(id, "readResult", read_report(handle, offset, length))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.patch" => match (handle_field(&value), string_field(&value, "hexBytes")) {
                (Some(handle), Some(hex_bytes)) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    let output = string_field(&value, "outputPath");
                    let path = output.as_deref().map(Path::new);
                    outcome(id, "patchResult", patch_report(handle, offset, &hex_bytes, path))
                }
                _ => failure_reply(id, "binary/range: `handle` and `hexBytes` are required".to_string()),
            },
            "binary.rva" => match handle_field(&value) {
                Some(handle) => {
                    let rva = value.get("rva").and_then(Value::as_u64).unwrap_or(0);
                    outcome(id, "rvaResult", rva_report(handle, rva))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.imports" => match handle_field(&value) {
                Some(handle) => {
                    outcome(id, "importsResult", imports_report(handle, value.get("limit").and_then(Value::as_u64)))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.exports" => match handle_field(&value) {
                Some(handle) => {
                    outcome(id, "exportsResult", exports_report(handle, value.get("limit").and_then(Value::as_u64)))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.symbols" => match handle_field(&value) {
                Some(handle) => {
                    outcome(id, "symbolsResult", symbols_report(handle, value.get("limit").and_then(Value::as_u64)))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.debug" => match handle_field(&value) {
                Some(handle) => outcome(id, "debugResult", debug_report(handle, value.get("limit").and_then(Value::as_u64))),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.disasm" => match (handle_field(&value), string_field(&value, "optionsJson")) {
                (Some(handle), Some(options)) => outcome(id, "disasmResult", disasm_report(handle, &options)),
                _ => failure_reply(id, "binary/parse: `handle` and `optionsJson` are required".to_string()),
            },
            "binary.search" => match (handle_field(&value), string_field(&value, "optionsJson")) {
                (Some(handle), Some(options)) => outcome(id, "searchResult", search_report(handle, &options)),
                _ => failure_reply(id, "binary/parse: `handle` and `optionsJson` are required".to_string()),
            },
            "binary.entropy" => match handle_field(&value) {
                Some(handle) => outcome(id, "entropyResult", entropy_report(handle)),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.diff" => {
                match (value.get("leftHandle").and_then(Value::as_u64), value.get("rightHandle").and_then(Value::as_u64)) {
                    (Some(left), Some(right)) => outcome(id, "diffResult", diff_report(left, right)),
                    _ => failure_reply(id, "handle/invalid: `leftHandle` and `rightHandle` are required".to_string()),
                }
            }
            "binary.offsetToVa" => match handle_field(&value) {
                Some(handle) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    outcome(id, "offsetToVaResult", offset_to_va_report(handle, offset))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.offsetToRva" => match handle_field(&value) {
                Some(handle) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    outcome(id, "offsetToRvaResult", offset_to_rva_report(handle, offset))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.close" => match handle_field(&value) {
                Some(handle) => outcome(id, "closeResult", close_engine(handle).map(|()| json!({ "closed": true }))),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            _ => IpcOutcome::Ignored,
        }
    }
}

fn reply(id: Value, kind: &str, payload: Value) -> IpcOutcome {
    let mut body = payload;
    body["type"] = Value::String(kind.to_string());
    body["id"] = id;
    IpcOutcome::ReplyToPage(body.to_string())
}

fn failure_reply(id: Value, message: String) -> IpcOutcome {
    reply(id, "binaryError", json!({ "message": message }))
}

fn outcome(id: Value, kind: &str, result: std::result::Result<Value, IdaError>) -> IpcOutcome {
    match result {
        Ok(value) => reply(id, kind, value),
        Err(error) => failure_reply(id, format!("{}: {}", error.code(), error.message())),
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn handle_field(value: &Value) -> Option<u64> {
    value.get("handle").and_then(Value::as_u64)
}

fn platform_name() -> &'static str {
    if cfg!(windows) {
        "win32"
    }
    else if cfg!(target_os = "macos") {
        "darwin"
    }
    else {
        "linux"
    }
}

fn gui_status(
    state: &'static str,
    code: Option<&'static str>,
    backend: Option<&'static str>,
    uptime_ms: u64,
    message: Option<String>,
) -> Value {
    json!({
        "state": state,
        "code": code,
        "backend": backend,
        "platform": platform_name(),
        "uptimeMs": uptime_ms,
        "message": message,
    })
}

fn gui_open_result(ok: bool, status: Value, error: Option<&WebViewError>) -> Value {
    let (stage, hresult, attempted) = match error {
        Some(error) => {
            let attempted = match error {
                WebViewError::Host(host) => host.attempted.clone(),
                _ => Vec::new(),
            };
            (error.stage(), error.hresult(), attempted)
        }
        None => (None, None, Vec::new()),
    };
    json!({ "ok": ok, "status": status, "stage": stage, "hresult": hresult, "attempted": attempted })
}

/// Resolves the GUI content directory: explicit override, then the built tree.
fn resolve_gui_dir() -> Option<PathBuf> {
    if let Ok(value) = std::env::var("OPEN_IDA_GUI") {
        let path = PathBuf::from(value);
        if path.is_dir() {
            return Some(path);
        }
        if path.is_file() {
            return path.parent().map(Path::to_path_buf);
        }
    }

    let manifest_relative = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("projects")
        .join("packages")
        .join("open-ida")
        .join("dist")
        .join("gui");
    if manifest_relative.join("index.html").is_file() {
        return Some(manifest_relative);
    }

    if let Ok(cwd) = std::env::current_dir() {
        for candidate in [cwd.join("projects/packages/open-ida/dist/gui"), cwd.join("dist/gui"), cwd.join("gui")] {
            if candidate.join("index.html").is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Opens the OpenIDA WebView window, or focuses the live one.
#[function(js_name = "openGui")]
fn open_gui(ctx: CallContext) -> Result<JsValue> {
    let mut title = "OpenIDA".to_string();
    let mut content_dir: Option<String> = None;
    let mut width = 1280i32;
    let mut height = 820i32;

    if let Some(arg) = ctx.args().first().copied()
        && !arg.is_undefined()?
    {
        if let Some(value) = optional_string_prop(arg, "title")? {
            title = value;
        }
        if let Some(value) = optional_string_prop(arg, "contentDir")? {
            content_dir = Some(value);
        }
        if let Ok(value) = arg.get_named("width")
            && let Ok(number) = value.as_i64()
        {
            width = number as i32;
        }
        if let Ok(value) = arg.get_named("height")
            && let Ok(number) = value.as_i64()
        {
            height = number as i32;
        }
    }

    let live = GUI.with(|slot| {
        let guard = slot.borrow();
        guard
            .as_ref()
            .filter(|state| state.host.is_alive())
            .map(|state| (state.backend, state.opened_at.elapsed().as_millis() as u64))
    });
    if let Some((backend, uptime_ms)) = live {
        GUI.with(|slot| {
            if let Some(state) = slot.borrow_mut().as_mut() {
                let _ = state.host.focus();
            }
        });
        let status = gui_status("open", None, Some(backend), uptime_ms, None);
        return respond(&ctx, &gui_open_result(true, status, None));
    }
    GUI.with(|slot| {
        *slot.borrow_mut() = None;
    });

    let dir = match content_dir {
        Some(dir) => PathBuf::from(dir),
        None => match resolve_gui_dir() {
            Some(dir) => dir,
            None => {
                let message = "the WebView content directory is missing; build the GUI first".to_string();
                let status = gui_status("failed", Some("gui_content_missing"), None, 0, Some(message));
                return respond(&ctx, &gui_open_result(false, status, None));
            }
        },
    };

    let close_requested = Arc::new(AtomicBool::new(false));
    let mut options = OpenOptions::from_content_dir(dir.display().to_string(), title);
    options.width = width;
    options.height = height;
    options.accept_file_drop = true;

    match WebViewHost::open(options, Box::new(IdaIpcHandler { close_requested: Arc::clone(&close_requested) })) {
        Ok(host) => {
            let backend = host.backend_name();
            GUI.with(|slot| {
                *slot.borrow_mut() = Some(GuiState { host, backend, opened_at: Instant::now(), close_requested });
            });
            let status = gui_status("open", None, Some(backend), 0, None);
            respond(&ctx, &gui_open_result(true, status, None))
        }
        Err(error) => {
            let status = gui_status("failed", error.code(), None, 0, Some(error.to_string()));
            respond(&ctx, &gui_open_result(false, status, Some(&error)))
        }
    }
}

/// Pumps the host message loop once and reports the observed lifecycle state.
#[function(js_name = "pumpEvents")]
fn pump_events(ctx: CallContext) -> Result<JsValue> {
    let status = GUI.with(|slot| {
        let mut guard = slot.borrow_mut();
        let Some(state) = guard.as_mut()
        else {
            return gui_status("closed", Some(GUI_NOT_OPEN), None, 0, Some("no OpenIDA window is open".to_string()));
        };
        let backend = state.backend;
        let uptime_ms = state.opened_at.elapsed().as_millis() as u64;
        if state.host.pump() {
            return gui_status("open", None, Some(backend), uptime_ms, None);
        }
        let requested = state.close_requested.swap(false, Ordering::SeqCst);
        *guard = None;
        if requested {
            gui_status("closed", Some(GUI_CLOSED), Some(backend), uptime_ms, None)
        }
        else {
            let message = format!("the {backend} webview host stopped without a page close request");
            gui_status("closed", Some(GUI_HOST_EXITED), Some(backend), uptime_ms, Some(message))
        }
    });
    respond(&ctx, &status)
}

/// Closes the OpenIDA window; the result distinguishes "already closed".
#[function(js_name = "closeGui")]
fn close_gui(ctx: CallContext) -> Result<JsValue> {
    let result = GUI.with(|slot| {
        let mut guard = slot.borrow_mut();
        let Some(state) = guard.as_mut()
        else {
            let message = "no OpenIDA window is open".to_string();
            return json!({
                "closed": false,
                "status": gui_status("not_open", Some(GUI_NOT_OPEN), None, 0, Some(message)),
            });
        };
        let backend = state.backend;
        let uptime_ms = state.opened_at.elapsed().as_millis() as u64;
        match state.host.close() {
            Ok(()) => {
                *guard = None;
                json!({ "closed": true, "status": gui_status("closed", None, Some(backend), uptime_ms, None) })
            }
            Err(error) => json!({
                "closed": false,
                "status": gui_status("open", Some("gui_close_failed"), Some(backend), uptime_ms, Some(error.to_string())),
            }),
        }
    });
    respond(&ctx, &result)
}

/// Reports whether the OpenIDA window is alive.
#[function(js_name = "isGuiOpen")]
fn is_gui_open(ctx: CallContext) -> Result<JsValue> {
    let open = GUI.with(|slot| slot.borrow().as_ref().is_some_and(|state| state.host.is_alive()));
    ctx.env().boolean(open)
}

register_module![
    version,
    capabilities,
    binary_open,
    binary_info,
    binary_sections,
    binary_strings,
    binary_strings_encoded,
    binary_hexdump,
    binary_read,
    binary_patch,
    binary_rva,
    binary_imports,
    binary_exports,
    binary_symbols,
    binary_debug,
    binary_version,
    binary_macho,
    binary_macho_symbols,
    binary_macho_slices,
    binary_mitigations,
    binary_resources,
    binary_relocations,
    binary_disasm,
    binary_diff,
    binary_entropy,
    binary_search,
    binary_offset_to_va,
    binary_offset_to_rva,
    binary_close,
    open_gui,
    pump_events,
    close_gui,
    is_gui_open
];
