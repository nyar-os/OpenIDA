/**
 * Smoke tests for the declared contract.
 *
 * Native-dependent assertions are skipped when the addon is absent; the error
 * mapping and the stable code set are always checked.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { IdaError, errorCodes, isIdaError, translateNativeError } from './errors.js';
import { nativeBinding } from './native.js';
import * as service from './service.js';

test('stable error codes are present', () => {
    for (const code of ['binary/parse', 'binary/range', 'binary/unsupported', 'handle/invalid', 'capability/not-implemented']) {
        assert.ok((errorCodes as readonly string[]).includes(code), `missing ${code}`);
    }
});

test('engine messages map onto stable codes', () => {
    const range = translateNativeError(new Error('binary/range: patch is outside the file'));
    assert.ok(isIdaError(range));
    assert.equal(range.code, 'binary/range');
    assert.equal(range.message, 'patch is outside the file');

    const unsupported = translateNativeError(new Error('binary/unsupported: Mach-O sections are not implemented'));
    assert.equal(unsupported.code, 'binary/unsupported');

    const unknown = translateNativeError(new Error('something else entirely'));
    assert.equal(unknown.code, 'binary/io');
});

test('IdaError keeps its code and recovers through translation', () => {
    const error = new IdaError('handle/invalid', 'no live binary has handle 7');
    assert.equal(translateNativeError(error), error);
    assert.equal(error.details.handle, undefined);
});

test('an absent addon reports capability/not-implemented', { skip: nativeBinding() !== undefined }, () => {
    assert.throws(
        () => service.open('anything.bin'),
        (error: unknown) => isIdaError(error) && error.code === 'capability/not-implemented',
    );
});
