import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import params from '../src/params.js';

function run({ query = {}, originalUrl = '/', headers = {} } = {}) {
  const req = { query, originalUrl, url: originalUrl, headers };
  const out = { nextCalled: false, status: null };
  const res = {
    status(code) {
      out.status = code;
      return this;
    },
    json() {
      return this;
    },
    send() {
      return this;
    }
  };
  params(req, res, () => {
    out.nextCalled = true;
  });
  return { req, out };
}

describe('params middleware', () => {
  test('missing url answers 200 and does not continue', () => {
    const { out } = run();
    assert.equal(out.nextCalled, false);
    assert.equal(out.status, 200);
  });

  test('blocks private and loopback targets with 403', () => {
    for (const url of ['http://127.0.0.1/a.jpg', 'http://169.254.169.254/latest/meta-data', 'http://localhost/a.jpg']) {
      const { out } = run({ query: { url } });
      assert.equal(out.nextCalled, false, url);
      assert.equal(out.status, 403, url);
    }
  });

  test('rejects a url without protocol and repeated url parameters with 400', () => {
    assert.equal(run({ query: { url: 'example.com/a.jpg' } }).out.status, 400);
    assert.equal(run({ query: { url: ['https://a.example/x.jpg', 'https://b.example/y.jpg'] } }).out.status, 400);
  });

  test('accepts a public url and fills defaults', () => {
    const { req, out } = run({ query: { url: 'https://example.com/a.jpg' } });
    assert.equal(out.nextCalled, true);
    assert.equal(req.opts.url, 'https://example.com/a.jpg');
    assert.equal(req.opts.format, 'avif');
    assert.equal(req.opts.mode, 'auto');
  });

  test('recovers an unencoded image url that contains its own query string', () => {
    const { req } = run({
      query: { url: 'https://example.com/a.jpg?x=1', y: '2', jpeg: '1' },
      originalUrl: '/?url=https://example.com/a.jpg?x=1&y=2&jpeg=1'
    });
    assert.equal(req.opts.url, 'https://example.com/a.jpg?x=1&y=2');
    assert.equal(req.opts.format, 'jpeg');
  });

  test('strip modes disable maxDim; unknown modes and unsafe rotations are ignored', () => {
    const strip = run({ query: { url: 'https://example.com/a.jpg', mode: 'webtoon' } }).req.opts;
    assert.equal(strip.maxDim, 0);
    const odd = run({ query: { url: 'https://example.com/a.jpg', mode: 'raw', rotate: '45' } }).req.opts;
    assert.equal(odd.mode, 'auto');
    assert.equal(odd.rotate, 0);
  });
});
