/**
 * Inspection surface of `@wae/open-ida`.
 *
 * The API, report shapes and error contract are declared here; the built-in
 * engine answers every operation. Analysis never happens in this package, so
 * the CLI and the studio cannot disagree about a file.
 */

export { OpenIDA, capabilities } from './api.js';
export type { OpenIdaOptions } from './api.js';
export { GuiError, closeGui, defaultGuiContentDir, isGuiOpen, openGui, pumpEvents, runGui } from './gui.js';
export type { GuiCloseResult, GuiOpenResult, GuiStatus, OpenGuiOptions } from './gui.js';
export { IdaError, NotImplementedError, errorCodes, isIdaError, translateNativeError } from './errors.js';
export type { IdaErrorCode, IdaErrorDetails, IdaErrorOptions } from './errors.js';
export { nativeBinding } from './native.js';
export type { NativeBinding } from './native.js';
export type * from './types.js';
