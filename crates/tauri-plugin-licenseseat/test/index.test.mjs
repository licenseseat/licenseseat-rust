import assert from 'node:assert/strict';
import test from 'node:test';

import {
  LicenseSeatPluginError,
  normalizeError,
} from '../dist/index.js';

test('normalizeError preserves an already normalized error', () => {
  const original = new LicenseSeatPluginError('Already normalized', {
    code: 'known_error',
    status: 409,
  });

  assert.equal(normalizeError(original), original);
});

test('normalizeError extracts nested Tauri error fields', () => {
  const source = {
    error: {
      code: 'seat_limit_exceeded',
      message: 'No seats remain',
      status: 422,
    },
  };
  const error = normalizeError(source);

  assert.ok(error instanceof LicenseSeatPluginError);
  assert.equal(error.name, 'LicenseSeatError');
  assert.equal(error.message, 'No seats remain');
  assert.equal(error.code, 'seat_limit_exceeded');
  assert.equal(error.status, 422);
  assert.equal(error.cause, source);
});

test('normalizeError parses a JSON-encoded command error without losing metadata', () => {
  const source = JSON.stringify({
    code: 'license_revoked',
    detail: 'This license was revoked',
    status: 403,
  });
  const error = normalizeError(source);

  assert.equal(error.message, 'This license was revoked');
  assert.equal(error.code, 'license_revoked');
  assert.equal(error.status, 403);

  const wrapped = normalizeError({ message: source });
  assert.equal(wrapped.message, 'This license was revoked');
  assert.equal(wrapped.code, 'license_revoked');
  assert.equal(wrapped.status, 403);
});

test('normalizeError summarizes HTML proxy pages and retains status', () => {
  const error = normalizeError({
    status: 502,
    message:
      '<!doctype html><html><head><title>Bad Gateway</title></head><body>proxy internals</body></html>',
  });

  assert.equal(
    error.message,
    'License server returned an HTML error page (502): Bad Gateway'
  );
  assert.equal(error.status, 502);
  assert.ok(!error.message.includes('proxy internals'));
});

test('normalizeError has stable metadata fallbacks and bounds messages', () => {
  const metadataOnly = normalizeError({ code: 'rate_limited', status: 429 });
  assert.equal(metadataOnly.message, 'rate_limited (429)');

  const long = normalizeError('x'.repeat(1_000));
  assert.equal(long.message.length, 300);
  assert.ok(long.message.endsWith('...'));

  assert.equal(normalizeError(null).message, 'Unknown error');
});

test('normalizeError bounds recursively JSON-encoded messages', () => {
  let nested = JSON.stringify({ message: 'bounded leaf' });
  for (let index = 0; index < 20; index += 1) {
    nested = JSON.stringify({ message: nested });
  }

  const error = normalizeError(nested);
  assert.ok(error instanceof LicenseSeatPluginError);
  assert.ok(error.message.length <= 300);
});
