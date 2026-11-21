/**
 * Stable error surface of `@wae/open-ida`.
 *
 * Codes are contract, not prose: callers compare them, localize around them and
 * never parse the message. A failure therefore keeps its code even when the
 * text is translated.
 */

/** Every stable code the inspection surface may report. */
export const errorCodes = [
    'binary/parse',
    'binary/range',
    'binary/unsupported',
    'binary/io',
    'handle/invalid',
    'capability/not-implemented',
] as const;

/** Union of {@link errorCodes}. */
export type IdaErrorCode = (typeof errorCodes)[number];

/** Optional locators a failure can carry so callers can point at the input. */
export interface IdaErrorDetails {
    readonly offset?: number;
    readonly length?: number;
    readonly handle?: number;
    readonly format?: string;
    /** Capability involved in the failure, e.g. `binary.patch`. */
    readonly feature?: string;
}

/** Options accepted by {@link IdaError}. */
export interface IdaErrorOptions {
    readonly recoverable?: boolean;
    readonly details?: IdaErrorDetails;
    readonly cause?: unknown;
}

/** Every failure thrown or rejected by this package. */
export class IdaError extends Error {
    /** Stable, comparable code. */
    readonly code: IdaErrorCode;
    /** Whether retrying with different input or state can succeed. */
    readonly recoverable: boolean;
    /** Optional locators (`offset`, `length`, `handle`, `format`, `feature`). */
    readonly details: IdaErrorDetails;

    constructor(code: IdaErrorCode, message: string, options: IdaErrorOptions = {}) {
        super(message, options.cause === undefined ? undefined : { cause: options.cause });
        this.name = 'IdaError';
        this.code = code;
        this.recoverable = options.recoverable ?? false;
        this.details = Object.freeze({ ...options.details });
    }
}

/**
 * Reported by declared methods whose backing capability is not wired yet.
 *
 * An absent addon is a declarative state, not a crash. The CLI reports the same
 * code the studio shows instead of inventing an empty result.
 */
export class NotImplementedError extends IdaError {
    constructor(feature: string, message = `\`${feature}\` is not implemented yet`) {
        super('capability/not-implemented', message, { recoverable: false, details: { feature } });
        this.name = 'NotImplementedError';
    }
}

const knownCodes = new Set<string>(errorCodes);

/**
 * Maps an unknown thrown value onto {@link IdaError}.
 *
 * The engine prefixes every message with its stable code; a message without a
 * known code becomes `binary/io` and keeps the original value as the cause.
 */
export function translateNativeError(error: unknown): IdaError {
    if (error instanceof IdaError) {
        return error;
    }
    const message = error instanceof Error ? error.message : String(error);
    const separator = message.indexOf(': ');
    const code = separator > 0 ? message.slice(0, separator) : '';
    if (knownCodes.has(code)) {
        return new IdaError(code as IdaErrorCode, message.slice(separator + 2), { details: { feature: code } });
    }
    return new IdaError('binary/io', message, { cause: error });
}

/** Narrows an unknown thrown value to {@link IdaError}. */
export function isIdaError(value: unknown): value is IdaError {
    return value instanceof IdaError;
}
