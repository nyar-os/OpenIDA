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

use open_ida_core::{BinaryView, IdaError};
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

// One live handle table per process shared by every surface.
struct Registry {
    next: u64,
    views: HashMap<u64, BinaryView>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry { next: 1, views: HashMap::new() }))
}

fn lock() -> std::result::Result<MutexGuard<'static, Registry>, IdaError> {
    registry().lock().map_err(|_| IdaError::io("the binary handle table is poisoned"))
}

fn missing(handle: u64) -> IdaError {
    IdaError::new("handle/invalid", format!("no live binary has handle {handle}"))
}

fn with_view(
    handle: u64,
    work: impl FnOnce(&BinaryView) -> std::result::Result<Value, IdaError>,
) -> std::result::Result<Value, IdaError> {
    let registry = lock()?;
    let view = registry.views.get(&handle).ok_or_else(|| missing(handle))?;
    work(view)
}

fn with_view_mut(
    handle: u64,
    work: impl FnOnce(&mut BinaryView) -> std::result::Result<Value, IdaError>,
) -> std::result::Result<Value, IdaError> {
    let mut registry = lock()?;
    let view = registry.views.get_mut(&handle).ok_or_else(|| missing(handle))?;
    work(view)
}

fn open_view(path: &str) -> std::result::Result<Value, IdaError> {
    let view = BinaryView::open(path)?;
    let info = encoded(&view.info()?)?;
    let mut registry = lock()?;
    let handle = registry.next;
    registry.next += 1;
    registry.views.insert(handle, view);
    Ok(json!({ "handle": handle, "info": info }))
}

fn section_report(handle: u64) -> std::result::Result<Value, IdaError> {
    with_view(handle, |view| Ok(json!({ "sections": encoded(&view.sections()?)? })))
}

fn strings_report(handle: u64, min_len: u64, limit: Option<u64>) -> std::result::Result<Value, IdaError> {
    with_view(handle, |view| {
        let min_len = usize::try_from(min_len).map_err(|_| IdaError::range("`minLen` is too large"))?;
        let mut hits = view.strings(min_len);
        let total = hits.len();
        let limit = limit.map_or(usize::MAX, |value| usize::try_from(value).unwrap_or(usize::MAX));
        let truncated = total > limit;
        hits.truncate(limit);
        Ok(json!({ "hits": encoded(&hits)?, "total": total, "truncated": truncated }))
    })
}

fn hexdump_report(handle: u64, offset: u64, length: u64) -> std::result::Result<Value, IdaError> {
    with_view(handle, |view| Ok(json!({ "offset": offset, "length": length, "text": view.hexdump(offset, length)? })))
}

fn read_report(handle: u64, offset: u64, length: u64) -> std::result::Result<Value, IdaError> {
    with_view(handle, |view| {
        let bytes = view.read_bytes(offset, length)?;
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        Ok(json!({ "offset": offset, "length": length, "hex": hex }))
    })
}

fn patch_report(handle: u64, offset: u64, hex_bytes: &str, output: Option<&Path>) -> std::result::Result<Value, IdaError> {
    let bytes = open_ida_core::parse_hex(hex_bytes)?;
    with_view_mut(handle, |view| encoded(&view.patch_to(offset, &bytes, output)?))
}

fn rva_report(handle: u64, rva: u64) -> std::result::Result<Value, IdaError> {
    with_view(handle, |view| Ok(json!({ "rva": rva, "offset": view.rva_to_offset(rva)? })))
}

fn close_view(handle: u64) -> std::result::Result<(), IdaError> {
    let mut registry = lock()?;
    registry.views.remove(&handle).map(|_| ()).ok_or_else(|| missing(handle))
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

/// Opens a binary and returns its handle and header summary.
#[function]
fn binary_open(ctx: CallContext) -> Result<JsValue> {
    let path = text(&ctx, 0)?;
    match open_view(&path) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Returns the header summary of an open binary.
#[function]
fn binary_info(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match with_view(handle, |view| encoded(&view.info()?)) {
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
    let min_len = number(&ctx, 1)?;
    let limit = optional_number(&ctx, 2)?;
    match strings_report(handle, min_len, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Renders a canonical hex dump of one byte range.
#[function]
fn binary_hexdump(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    let length = number(&ctx, 2)?;
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

/// Releases one binary handle.
#[function]
fn binary_close(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match close_view(handle) {
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
            "binary.open" => match string_field(&value, "path") {
                Some(path) => outcome(id, "openResult", open_view(&path)),
                None => failure_reply(id, "binary/range: `path` is required".to_string()),
            },
            "binary.info" => match handle_field(&value) {
                Some(handle) => outcome(id, "infoResult", with_view(handle, |view| encoded(&view.info()?))),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.sections" => match handle_field(&value) {
                Some(handle) => outcome(id, "sectionsResult", section_report(handle)),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.strings" => match handle_field(&value) {
                Some(handle) => {
                    let min_len = value.get("minLen").and_then(Value::as_u64).unwrap_or(4);
                    let limit = value.get("limit").and_then(Value::as_u64);
                    outcome(id, "stringsResult", strings_report(handle, min_len, limit))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.hexdump" => match handle_field(&value) {
                Some(handle) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    let length = value.get("length").and_then(Value::as_u64).unwrap_or(256);
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
            "binary.close" => match handle_field(&value) {
                Some(handle) => outcome(id, "closeResult", close_view(handle).map(|()| json!({ "closed": true }))),
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
    binary_hexdump,
    binary_read,
    binary_patch,
    binary_rva,
    binary_close,
    open_gui,
    pump_events,
    close_gui,
    is_gui_open
];
