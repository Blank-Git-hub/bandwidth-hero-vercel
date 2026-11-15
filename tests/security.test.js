import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import shouldCompress from '../src/shouldCompress.js';
import { isPublicIP, parseSafeUrl } from '../src/urlGuard.js';

describe('urlGuard SSRF protection', () => {
  test('allows public IPv4', () => {
    assert.equal(isPublicIP('8.8.8.8'), true);
  });

  test('blocks private IPv4', () => {
    assert.equal(isPublicIP('192.168.1.1'), false);
    assert.equal(isPublicIP('10.0.0.1'), false);
    assert.equal(isPublicIP('172.16.0.1'), false);
    assert.equal(isPublicIP('127.0.0.1'), false);
    assert.equal(isPublicIP('169.254.169.254'), false);
  });

  test('blocks loopback IPv6', () => {
    assert.equal(isPublicIP('::1'), false);
  });

  test('blocks link-local IPv6', () => {
    assert.equal(isPublicIP('fe80::1'), false);
  });

  test('blocks unique local IPv6', () => {
    assert.equal(isPublicIP('fc00::1'), false);
    assert.equal(isPublicIP('fd00::1'), false);
  });

  test('blocks Teredo IPv6', () => {
    assert.equal(isPublicIP('2001:0000:1234:5678:9abc:def0:1234:5678'), false);
  });

  test('blocks 6to4 IPv6', () => {
    assert.equal(isPublicIP('2002:c0a8:0101::1'), false);
  });

  test('blocks NAT64 IPv6', () => {
    assert.equal(isPublicIP('64:ff9b::c0a8:0101'), false);
  });

  test('blocks multicast IPv6', () => {
    assert.equal(isPublicIP('ff02::1'), false);
  });

  test('blocks IPv4-mapped private IPv6', () => {
    assert.equal(isPublicIP('::ffff:192.168.1.1'), false);
    assert.equal(isPublicIP('::ffff:10.0.0.1'), false);
  });

    test('blocks IPv4-compatible IPv6 (::/96)', () => {
    assert.equal(isPublicIP('::7f00:1'), false);
    assert.equal(isPublicIP('::a00:1'), false);
    assert.equal(parseSafeUrl('http://[::7f00:1]/x'), null);
    assert.equal(parseSafeUrl('http://[::127.0.0.1]/x'), null);
  });

  test('allows IPv4-mapped public IPv6', () => {
    assert.equal(isPublicIP('::ffff:8.8.8.8'), true);
  });

  test('parseSafeUrl blocks localhost', () => {
    assert.equal(parseSafeUrl('http://localhost/admin'), null);
  });

  test('parseSafeUrl blocks blocked suffixes', () => {
    assert.equal(parseSafeUrl('http://service.internal/api'), null);
    assert.equal(parseSafeUrl('http://host.onion/page'), null);
  });

  test('parseSafeUrl blocks userinfo', () => {
    assert.equal(parseSafeUrl('http://user:pass@example.com/image.jpg'), null);
  });

  test('parseSafeUrl blocks non-http protocols', () => {
    assert.equal(parseSafeUrl('ftp://example.com/file'), null);
    assert.equal(parseSafeUrl('file:///etc/passwd'), null);
  });

  test('parseSafeUrl allows valid public URL', () => {
    const result = parseSafeUrl('https://example.com/image.jpg');
    assert.notEqual(result, null);
    assert.equal(result.hostname, 'example.com');
  });

  test('parseSafeUrl blocks dangerous service ports on public hosts', () => {
    assert.equal(parseSafeUrl('http://8.8.8.8:22/'), null);
    assert.equal(parseSafeUrl('http://8.8.8.8:25/'), null);
    assert.equal(parseSafeUrl('http://8.8.8.8:6379/'), null);
  });

  test('parseSafeUrl still allows normal and custom web ports', () => {
    assert.notEqual(parseSafeUrl('https://example.com/x.jpg'), null);
    assert.notEqual(parseSafeUrl('http://example.com:8080/x.jpg'), null);
    assert.notEqual(parseSafeUrl('https://example.com:8443/x.jpg'), null);
  });
});

describe('shouldCompress', () => {
  test('rejects empty buffer', () => {
    const req = { opts: { originType: 'image/jpeg' } };
    const emptyBuffer = Buffer.alloc(0);
    assert.equal(shouldCompress(req, emptyBuffer, null), false);
  });

  test('rejects non-buffer input', () => {
    const req = { opts: { originType: 'image/jpeg' } };
    assert.equal(shouldCompress(req, 'not a buffer', null), false);
  });

  test('rejects SVG', () => {
    const req = { opts: { originType: 'image/svg+xml' } };
    const buf = Buffer.from('<svg></svg>');
    assert.equal(shouldCompress(req, buf, null), false);
  });

  test('rejects PDF', () => {
    const req = { opts: { originType: 'application/pdf' } };
    const buf = Buffer.from('%PDF-1.4');
    assert.equal(shouldCompress(req, buf, null), false);
  });

  test('rejects favicon', () => {
    const req = { opts: { originType: 'image/x-icon' } };
    const buf = Buffer.from([0x00, 0x00, 0x01, 0x00]);
    assert.equal(shouldCompress(req, buf, null), false);
  });

  test('accepts JPEG with no governor', () => {
    const req = { opts: { originType: 'image/jpeg' } };
    const buf = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
    assert.equal(shouldCompress(req, buf, null), true);
  });

  // F19: Test adaptive size decision without allocating large buffers
  test('rejects when memory governor budget is too small', () => {
    const req = { opts: { originType: 'image/jpeg' } };
    const buf = Buffer.alloc(1024);

    const mockGovernor = {
      getDownloadBudget: () => 512
    };

    assert.equal(shouldCompress(req, buf, mockGovernor), false);
  });

  test('accepts when memory governor budget is sufficient', () => {
    const req = { opts: { originType: 'image/jpeg' } };
    const buf = Buffer.alloc(1024);

    const mockGovernor = {
      getDownloadBudget: () => 2048
    };

    assert.equal(shouldCompress(req, buf, mockGovernor), true);
  });
});
