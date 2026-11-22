import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.VERCEL = '1';
process.env.API_KEY = 'smoke-test-key';

const MODULES = [
  '../src/adaptiveDirector.js',
  '../src/authenticate.js',
  '../src/compress.js',
  '../src/concurrencyGovernor.js',
  '../src/copyHeaders.js',
  '../src/inflight.js',
  '../src/memoryGovernor.js',
  '../src/params.js',
  '../src/proxy.js',
  '../src/rateLimiter.js',
  '../src/shouldCompress.js',
  '../src/urlGuard.js',
  '../src/vipsEnv.js',
  '../server.js'
];

for (const path of MODULES) {
  test(`loads ${path}`, async () => {
    await assert.doesNotReject(import(path));
  });
}
