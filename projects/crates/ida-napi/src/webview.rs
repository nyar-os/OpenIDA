//! WebView host: the single GUI window state, the JSON IPC handler bridging
//! the page to the shared engine table, and the lifecycle entry points.

use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use open_ida_core::{IdaError, OpenIdaOptions, StringsOptions};
use serde_json::{Value, json};
use wae::{
    CallContext, JsValue, Result, optional_string_prop,
    webview::{IpcHandler, IpcOutcome, IpcSink, OpenOptions, WebViewError, WebViewHost},
};

use crate::{
    args::{encoded, respond},
    commands::{binary, pe, scan},
    registry::{close_engine, open_engine, with_engine},
};

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
                Some(handle) => outcome(id, "sectionsResult", binary::section_report(handle)),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.strings" => match handle_field(&value) {
                Some(handle) => {
                    let min_len = value.get("minLen").and_then(Value::as_u64);
                    let limit = value.get("limit").and_then(Value::as_u64);
                    outcome(id, "stringsResult", binary::strings_report(handle, min_len, limit))
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
                    outcome(id, "hexdumpResult", binary::hexdump_report(handle, offset, length))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.read" => match handle_field(&value) {
                Some(handle) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    let length = value.get("length").and_then(Value::as_u64).unwrap_or(256);
                    outcome(id, "readResult", binary::read_report(handle, offset, length))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.patch" => match (handle_field(&value), string_field(&value, "hexBytes")) {
                (Some(handle), Some(hex_bytes)) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    let output = string_field(&value, "outputPath");
                    let path = output.as_deref().map(Path::new);
                    outcome(id, "patchResult", binary::patch_report(handle, offset, &hex_bytes, path))
                }
                _ => failure_reply(id, "binary/range: `handle` and `hexBytes` are required".to_string()),
            },
            "binary.rva" => match handle_field(&value) {
                Some(handle) => {
                    let rva = value.get("rva").and_then(Value::as_u64).unwrap_or(0);
                    outcome(id, "rvaResult", binary::rva_report(handle, rva))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.imports" => match handle_field(&value) {
                Some(handle) => {
                    outcome(id, "importsResult", binary::imports_report(handle, value.get("limit").and_then(Value::as_u64)))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.exports" => match handle_field(&value) {
                Some(handle) => {
                    outcome(id, "exportsResult", binary::exports_report(handle, value.get("limit").and_then(Value::as_u64)))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.symbols" => match handle_field(&value) {
                Some(handle) => {
                    outcome(id, "symbolsResult", binary::symbols_report(handle, value.get("limit").and_then(Value::as_u64)))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.debug" => match handle_field(&value) {
                Some(handle) => {
                    outcome(id, "debugResult", pe::debug_report(handle, value.get("limit").and_then(Value::as_u64)))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.disasm" => match (handle_field(&value), string_field(&value, "optionsJson")) {
                (Some(handle), Some(options)) => outcome(id, "disasmResult", scan::disasm_report(handle, &options)),
                _ => failure_reply(id, "binary/parse: `handle` and `optionsJson` are required".to_string()),
            },
            "binary.search" => match (handle_field(&value), string_field(&value, "optionsJson")) {
                (Some(handle), Some(options)) => outcome(id, "searchResult", scan::search_report(handle, &options)),
                _ => failure_reply(id, "binary/parse: `handle` and `optionsJson` are required".to_string()),
            },
            "binary.entropy" => match handle_field(&value) {
                Some(handle) => outcome(id, "entropyResult", binary::entropy_report(handle)),
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.diff" => {
                match (value.get("leftHandle").and_then(Value::as_u64), value.get("rightHandle").and_then(Value::as_u64)) {
                    (Some(left), Some(right)) => outcome(id, "diffResult", binary::diff_report(left, right)),
                    _ => failure_reply(id, "handle/invalid: `leftHandle` and `rightHandle` are required".to_string()),
                }
            }
            "binary.offsetToVa" => match handle_field(&value) {
                Some(handle) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    outcome(id, "offsetToVaResult", binary::offset_to_va_report(handle, offset))
                }
                None => failure_reply(id, "handle/invalid: `handle` is required".to_string()),
            },
            "binary.offsetToRva" => match handle_field(&value) {
                Some(handle) => {
                    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
                    outcome(id, "offsetToRvaResult", binary::offset_to_rva_report(handle, offset))
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

pub(crate) fn open_gui(ctx: CallContext) -> Result<JsValue> {
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

pub(crate) fn pump_events(ctx: CallContext) -> Result<JsValue> {
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

pub(crate) fn close_gui(ctx: CallContext) -> Result<JsValue> {
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

pub(crate) fn is_gui_open(ctx: CallContext) -> Result<JsValue> {
    let open = GUI.with(|slot| slot.borrow().as_ref().is_some_and(|state| state.host.is_alive()));
    ctx.env().boolean(open)
}
