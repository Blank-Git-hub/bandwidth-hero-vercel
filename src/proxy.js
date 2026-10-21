import * as crypto from 'node:crypto';
import { createGunzip, createInflate, createBrotliDecompress } from 'node:zlib';
import { Readable } from 'node:stream';
import { request, Agent } from 'undici';
import sharp from 'sharp';
import { LRUCache } from 'lru-cache';
import { parseSafeUrl, safeLookup } from './urlGuard.js';
import shouldCompress from './shouldCompress.js';
import compress from './compress.js';
import copyHeaders from './copyHeaders.js';
import memoryGovernor from './memoryGovernor.js';

const createHash = crypto.createHash;
const subtle = crypto.webcrypto?.subtle ?? globalThis.crypto?.subtle;

const UPSTREAM_ACCEPT_ENCODING = process.env.UPSTREAM_ACCEPT_ENCODING || 'identity';
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS, 10) || 15000;
const BODY_TIMEOUT_MS = parseInt(process.env.BODY_TIMEOUT_MS, 10) || 50000;
const UPSTREAM_DEADLINE_MS = parseInt(process.env.UPSTREAM_DEADLINE_MS, 10) || 55000;
const UPSTREAM_TOTAL_DEADLINE_MS = safeInt(process.env.UPSTREAM_TOTAL_DEADLINE_MS, 55000);
const MAX_RETRIES = safeInt(process.env.UPSTREAM_MAX_RETRIES, 2);

// FEATURE: Corrupted Image Auto-Retry
const MAX_DECODE_RETRIES = safeInt(process.env.MAX_DECODE_RETRIES, 1);
const ENABLE_CORRUPT_RETRY = envBoolLocal('ENABLE_CORRUPT_RETRY', true);

function safeInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function envBoolLocal(name, fallback = false) {
  const v = process.env[name];
  if (v === undefined) return fallback;
  return v === '1' || v === 'true' || v === 'yes';
}

const RAW_VAULT_MAX_BYTES = 20 * 1024 * 1024;
const RAW_VAULT_MAX_ENTRY = 4 * 1024 * 1024;
const RAW_VAULT_MAX_ENTRIES = 30;

const RAW_VAULT_ENTRY_OVERHEAD = 512;

function vaultEntrySize(entry, key) {
  const rawSize = Number.isFinite(entry?.size)
    ? entry.size
    : Buffer.byteLength(entry?.raw || '');

  const keySize = Buffer.byteLength(String(key || ''));
  const etagSize = Buffer.byteLength(String(entry?.etag || ''));
  const lastModifiedSize = Buffer.byteLength(String(entry?.lastModified || ''));

  return Math.max(
    1,
    rawSize + keySize + etagSize + lastModifiedSize + RAW_VAULT_ENTRY_OVERHEAD
  );
}

const RAW_VAULT = new LRUCache({
  max: RAW_VAULT_MAX_ENTRIES,
  maxSize: RAW_VAULT_MAX_BYTES,
  sizeCalculation: vaultEntrySize
});

function vaultGet(url) {
  return RAW_VAULT.get(url) ?? null;
}

function vaultSet(url, raw, etag, lastModified) {
  if (raw.length > RAW_VAULT_MAX_ENTRY) return;

  const entry = { raw, etag, lastModified, size: raw.length };
  const projectedSize = vaultEntrySize(entry, url);

  if (projectedSize > RAW_VAULT_MAX_BYTES) return;

  RAW_VAULT.set(url, entry);
}

const chromeDispatcher = new Agent({
  connect: {
    ciphers: [
      'TLS_AES_128_GCM_SHA256',
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384'
    ].join(':'),
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    lookup: safeLookup
  },
  headersTimeout: REQUEST_TIMEOUT_MS,
  bodyTimeout: BODY_TIMEOUT_MS,
  keepAliveTimeout: 10000
});

const UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'
];

function getRandomUA() {
  return UA_POOL[Math.floor(Math.random() * UA_POOL.length)];
}

const GHOST_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

const GHOST_SVG_MAX_DIM = 64;
const GHOST_MAX_DIM_PARSE = 100000;

function isValidGhostDim(value) {
  return Number.isInteger(value) && value > 0 && value <= GHOST_MAX_DIM_PARSE;
}

function ghostSvgFromDims(width, height) {
  if (!isValidGhostDim(width) || !isValidGhostDim(height)) {
    return null;
  }

  const longEdge = Math.max(width, height);
  const scale = Math.min(1, GHOST_SVG_MAX_DIM / longEdge);

  const outW = Math.max(1, Math.round(width * scale));
  const outH = Math.max(1, Math.round(height * scale));

  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="${outW}" height="${outH}" viewBox="0 0 ${width} ${height}">` +
    `<rect width="100%" height="100%" fill="transparent"/>` +
    `</svg>`;

  return Buffer.from(svg);
}

function extractGhostDims(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 10) {
    return null;
  }

  // PNG
  if (
    buffer.length >= 24 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4E &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0D &&
    buffer[5] === 0x0A &&
    buffer[6] === 0x1A &&
    buffer[7] === 0x0A
  ) {
    const width = buffer.readUInt32BE(16);
    const height = buffer.readUInt32BE(20);

    return isValidGhostDim(width) && isValidGhostDim(height)
      ? { width, height }
      : null;
  }

  // GIF
  const gifSig = buffer.toString('ascii', 0, 6);
  if (gifSig === 'GIF87a' || gifSig === 'GIF89a') {
    const width = buffer.readUInt16LE(6);
    const height = buffer.readUInt16LE(8);

    return isValidGhostDim(width) && isValidGhostDim(height)
      ? { width, height }
      : null;
  }

  // JPEG
  if (
    buffer[0] === 0xFF &&
    buffer[1] === 0xD8 &&
    buffer[2] === 0xFF
  ) {
    let offset = 2;
    const maxScan = Math.min(buffer.length, 1_000_000);

    while (offset + 4 <= maxScan) {
      if (buffer[offset] !== 0xFF) {
        offset++;
        continue;
      }

      const marker = buffer[offset + 1];

      // Skip fill bytes.
      if (marker === 0xFF) {
        offset++;
        continue;
      }

      // SOI.
      if (marker === 0xD8) {
        offset += 2;
        continue;
      }

      // EOI or SOS: stop scanning.
      if (marker === 0xD9 || marker === 0xDA) {
        break;
      }

      // SOF markers, excluding DHT/JPG/DAC-style markers.
      if (
        marker >= 0xC0 &&
        marker <= 0xCF &&
        marker !== 0xC4 &&
        marker !== 0xC8 &&
        marker !== 0xCC
      ) {
        if (offset + 9 <= maxScan) {
          const height = buffer.readUInt16BE(offset + 5);
          const width = buffer.readUInt16BE(offset + 7);

          return isValidGhostDim(width) && isValidGhostDim(height)
            ? { width, height }
            : null;
        }

        break;
      }

      const segmentLength = buffer.readUInt16BE(offset + 2);

      if (!Number.isFinite(segmentLength) || segmentLength < 2) {
        break;
      }

      offset += 2 + segmentLength;
    }
  }

  return null;
}

function sendGhost(res, cacheSeconds = 3600, hint = null, reason = 'unknown') {
  if (!res.headersSent) {
    res.setHeader('X-Ghost-Reason', reason);
    const accept = String(hint?.accept || '');
    const body = hint?.body;

    if (
      accept.includes('image/svg+xml') &&
      Buffer.isBuffer(body) &&
      body.length > 0
    ) {
      const dims = extractGhostDims(body);
      const svg = dims ? ghostSvgFromDims(dims.width, dims.height) : null;

      if (svg) {
        res.setHeader('Content-Type', 'image/svg+xml');
        res.setHeader('Cache-Control', `public, max-age=${cacheSeconds}`);
        res.setHeader('Vary', 'Accept');
        res.setHeader('x-ghost', 'true');
        res.status(200).end(svg);
        return;
      }
    }

    res.setHeader('Content-Type', 'image/gif');
    res.setHeader('Cache-Control', `public, max-age=${cacheSeconds}`);
    res.setHeader('x-ghost', 'true');
    res.status(200).end(GHOST_GIF);
  }
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value);
  return Buffer.alloc(0);
}

function bypass(req, res, rawBody, statusCode = 200) {
  if (!res.headersSent) res.status(statusCode);
  res.end(rawBody);
}

function sanitizeUrl(url) {
  try {
    const u = new URL(url);
    return u.origin + '/*';
  } catch {
    return String(url).split('?')[0].split('/').slice(0, 3).join('/') + '/*';
  }
}

function redactUrlForCache(urlStr) {
  try {
    const u = new URL(urlStr);
    const sensitiveParams = ['token', 'access_token', 'sig', 'signature', 'session', 'auth', 'secret', 'key', 'password', 'api', 'apikey', 'api_key'];
    for (const param of sensitiveParams) {
      if (u.searchParams.has(param)) {
        u.searchParams.set(param, '[REDACTED]');
      }
    }
    return u.href;
  } catch {
    return urlStr;
  }
}

function sanitizeError(err) {
  let msg = err?.message ? String(err.message) : 'Unknown error';
  msg = msg.replace(/\?[^\s]*/g, '');
  msg = msg.replace(/(api[_-]?key|apikey|api|key|token|secret|password)=([^\s&]*)/gi, '$1=[REDACTED]');
  return msg;
}

function isClientAborted(req) {
  return Boolean(req?.signal?.aborted);
}

// FEATURE: Corrupted Image Auto-Retry — detect sharp decode failures
function isSharpDecodeError(err) {
  if (!err) return false;
  const msg = String(err.message || '').toLowerCase();
  const code = String(err.code || '').toLowerCase();

  return (
    msg.includes('input buffer is corrupt') ||
    msg.includes('input file is missing') ||
    msg.includes('invalid image') ||
    msg.includes('image has corrupt') ||
    msg.includes('unable to open') ||
    msg.includes('not a valid') ||
    msg.includes('vips') ||
    msg.includes('decode') ||
    msg.includes('corrupt') ||
    code === 'err_sharp_decode' ||
    code === 'vips_error'
  );
}

function detectContentType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 2) return 'application/octet-stream';

  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';

  if (
    buffer.length >= 4 &&
    buffer[0] === 0x89 && buffer[1] === 0x50 &&
    buffer[2] === 0x4e && buffer[3] === 0x47
  ) return 'image/png';

  if (
    buffer.length >= 4 &&
    buffer[0] === 0x47 && buffer[1] === 0x49 &&
    buffer[2] === 0x46 && buffer[3] === 0x38
  ) return 'image/gif';

  if (buffer[0] === 0x42 && buffer[1] === 0x4d) return 'image/bmp';

  if (
    buffer.length >= 6 &&
    buffer[0] === 0x00 && buffer[1] === 0x00 &&
    buffer[2] === 0x01 && buffer[3] === 0x00
  ) return 'image/x-icon';

  if (
    buffer.length >= 12 &&
    buffer[0] === 0x52 && buffer[1] === 0x49 &&
    buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer.subarray(8, 12).toString('ascii') === 'WEBP'
  ) return 'image/webp';

  if (buffer.length >= 12 && buffer.subarray(4, 8).toString('ascii') === 'ftyp') {
    const brand = buffer.subarray(8, 12).toString('ascii');
    if (brand === 'avif' || brand === 'avis') return 'image/avif';
  }

  return 'application/octet-stream';
}

async function sha256Hex(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
  try {
    if (subtle) {
      const view = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      const digest = await subtle.digest('SHA-256', view);
      return Buffer.from(digest).toString('hex');
    }
  } catch {}

  if (typeof crypto.hash === 'function') {
    return crypto.hash('sha256', input, 'hex');
  }

  return createHash('sha256').update(input).digest('hex');
}

async function generateETag(req, targetUrl, upstreamHeaders, body) {
  const paramsFingerprint = JSON.stringify({
    url: targetUrl,
    format: req.opts?.format,
    quality: req.opts?.quality,
    grayscale: req.opts?.grayscale,
    maxDim: req.opts?.maxDim,
    maxStripWidth: req.opts?.maxStripWidth,
    sharpen: req.opts?.sharpen,
    rotate: req.opts?.rotate
  });

  const upstreamEtag = upstreamHeaders?.['etag'];
  const upstreamLM = upstreamHeaders?.['last-modified'];
  const upstreamLen = upstreamHeaders?.['content-length'];

  let upstreamIdentity;
  if (upstreamEtag || upstreamLM) {
    upstreamIdentity = `${upstreamEtag || ''}|${upstreamLM || ''}|${upstreamLen || ''}`;
  } else {
    upstreamIdentity = await sha256Hex(body);
  }

  const material = Buffer.from(paramsFingerprint + '|' + upstreamIdentity);
  const digest = await sha256Hex(material);
  return `"${digest.slice(0, 32)}"`;
}

async function decompressBody(buffer, encoding) {
  if (!encoding) return buffer;
  const enc = String(encoding).toLowerCase().trim();

  let decompressor;
  if (enc === 'gzip' || enc === 'x-gzip') decompressor = createGunzip();
  else if (enc === 'deflate') decompressor = createInflate();
  else if (enc === 'br') decompressor = createBrotliDecompress();
  else return buffer;

  const maxDecompressed = memoryGovernor.getDecompressBudget();

  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalLength = 0;
    const stream = Readable.from(buffer).pipe(decompressor);

    stream.on('data', (chunk) => {
      totalLength += chunk.length;
      if (totalLength > maxDecompressed) {
        stream.destroy(new Error('DECOMPRESS_BOMB'));
        return;
      }
      chunks.push(chunk);
    });

    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', (err) => reject(err));
  });
}

async function consumeWithLimit(body) {
  const maxDownload = memoryGovernor.getDownloadBudget();
  const chunks = [];
  let total = 0;

  for await (const chunk of body) {
    total += chunk.length;
    if (total > maxDownload) {
      body.destroy();
      const err = new Error('BODY_TOO_LARGE');
      err.code = 'BODY_TOO_LARGE';
      throw err;
    }
    chunks.push(chunk);
  }

  return Buffer.concat(chunks, total);
}

async function safeRequest(url, headers, signal, maxRedirects = 5, deadlineMs = UPSTREAM_DEADLINE_MS) {
  let currentUrl = url;
  let requestHeaders = headers;
  const deadline = Date.now() + deadlineMs;

  for (let i = 0; i <= maxRedirects; i++) {
    if (Date.now() > deadline) {
      const err = new Error('UPSTREAM_DEADLINE');
      err.code = 'UPSTREAM_DEADLINE';
      throw err;
    }

    const { statusCode, headers: resHeaders, body } = await request(currentUrl, {
      dispatcher: chromeDispatcher,
      method: 'GET',
      headers: requestHeaders,
      signal,
      maxRedirections: 0
    });

    if ([301, 302, 303, 307, 308].includes(statusCode)) {
      await body.dump().catch(() => {});
      const location = resHeaders['location'];

      if (!location) {
        return { statusCode, headers: resHeaders, body: Buffer.alloc(0) };
      }

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).href;
      } catch {
        const err = new Error('INVALID_REDIRECT');
        err.code = 'INVALID_REDIRECT';
        throw err;
      }

      if (!parseSafeUrl(nextUrl)) {
        const err = new Error('SSRF_BLOCKED_REDIRECT');
        err.code = 'SSRF_BLOCKED_REDIRECT';
        throw err;
      }

      currentUrl = nextUrl;

      if (requestHeaders && 'x-internal-key' in requestHeaders) {
        requestHeaders = { ...requestHeaders };
        delete requestHeaders['x-internal-key'];
      }

      continue;
    }

    const buffer = await consumeWithLimit(body);
    return { statusCode, headers: resHeaders, body: buffer };
  }

  const err = new Error('TOO_MANY_REDIRECTS');
  err.code = 'TOO_MANY_REDIRECTS';
  throw err;
}

const RETRYABLE_CODES = new Set([
  'ETIMEDOUT', 'ERR_GOT_REQUEST_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT', 'UPSTREAM_DEADLINE', 'ECONNRESET', 'UND_ERR_CONNECT_TIMEOUT'
]);

const RETRYABLE_STATUSES = new Set([502, 503, 504, 429, 520, 521, 522, 523, 524]);

async function fetchWithBackoff(url, headers, signal) {
  const totalDeadline = Date.now() + UPSTREAM_TOTAL_DEADLINE_MS;
  let lastError = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const remaining = totalDeadline - Date.now();

    if (signal?.aborted || remaining <= 0) {
      break;
    }

    try {
      const attemptDeadline = Math.min(remaining, UPSTREAM_DEADLINE_MS);
      const res = await safeRequest(url, headers, signal, 5, attemptDeadline);

      if (RETRYABLE_STATUSES.has(res.statusCode) && attempt < MAX_RETRIES) {
        lastError = new Error(`RETRYABLE_STATUS_${res.statusCode}`);
        lastError.code = `STATUS_${res.statusCode}`;
      } else {
        return res;
      }
    } catch (err) {
      lastError = err;

      if (!RETRYABLE_CODES.has(err.code)) {
        throw err;
      }
    }

    if (attempt < MAX_RETRIES) {
      const baseDelay = 400 * Math.pow(2, attempt);
      const jitter = Math.random() * 300;
      const delay = Math.min(baseDelay + jitter, totalDeadline - Date.now());

      if (delay <= 0) {
        break;
      }

      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError || new Error('UPSTREAM_TOTAL_DEADLINE');
}

export default async function proxy(req, res) {
  const startTime = Date.now();
  req.proxyStartedAt = startTime;
  const reqId = req.id || 'unknown';
  const log = req.log || console;

  if (memoryGovernor.isUnderPressure()) {
    res.setHeader('Retry-After', '10');
    return res.status(503).json({ error: 'Memory pressure. Try again shortly.' });
  }

  let targetUrl = req.opts?.url || req.query?.url;

  if (Array.isArray(targetUrl)) {
    targetUrl = targetUrl.find(u => u && typeof u === 'string') || String(targetUrl[0]);
  }

  if (!targetUrl || typeof targetUrl !== 'string') {
  return sendGhost(res, 60, null, 'missing_url');
  }

  targetUrl = targetUrl.trim();

  if (!targetUrl.startsWith('http')) {
    targetUrl = 'https://' + targetUrl;
  }

  try {
  targetUrl = new URL(targetUrl).href;
  } catch {
  return sendGhost(res, 60, null, 'invalid_url');
  }

  const { 'user-agent': userAgent } = req.headers;

  let autoReferer = '';
  try {
    const parsedTarget = new URL(targetUrl);
    autoReferer = parsedTarget.origin;
  } catch {}

  const headers = {
    'user-agent': userAgent || getRandomUA(),
    accept: req.headers.accept || 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'accept-encoding': UPSTREAM_ACCEPT_ENCODING,
    'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'sec-fetch-dest': 'image',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'cross-site',
    'sec-ch-ua': '"Chromium";v="148", "Not;A=Brand";v="24", "Google Chrome";v="148"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    ...(autoReferer ? { referer: autoReferer } : {})
  };

  const cacheKey = redactUrlForCache(targetUrl);
  const vaultEntry = vaultGet(cacheKey);
  if (vaultEntry) {
    if (vaultEntry.etag) headers['if-none-match'] = vaultEntry.etag;
    if (vaultEntry.lastModified) headers['if-modified-since'] = vaultEntry.lastModified;
  }

  let workerBase = process.env.CF_WORKER_URL || '';
  if (workerBase === 'undefined' || workerBase === 'null') workerBase = '';
  if (workerBase && !workerBase.startsWith('http')) workerBase = 'https://' + workerBase;
  if (workerBase.endsWith('/')) workerBase = workerBase.slice(0, -1);

  let fetchUrl = targetUrl;
  let fetchHeaders = headers;
  let isWorkerFetch = false;

  if (workerBase && workerBase.startsWith('https://')) {
    const internalKey = process.env.INTERNAL_KEY;
    if (internalKey) {
      isWorkerFetch = true;
      fetchUrl = `${workerBase}/raw?url=${encodeURIComponent(targetUrl)}`;
      fetchHeaders = { ...headers, 'x-internal-key': internalKey };
    }
  }

  let response;
  let statusCode;
  let responseHeaders;
  let activeUrl = fetchUrl;
  let activeHeaders = fetchHeaders;

  try {
    response = await fetchWithBackoff(activeUrl, activeHeaders, req?.signal);
    statusCode = response.statusCode;
    responseHeaders = response.headers;

    if (isWorkerFetch && (statusCode >= 500 || statusCode === 403 || statusCode === 404)) {
      throw new Error('WORKER_RELAY_FAILURE');
    }
  } catch (err) {
    if (isClientAborted(req)) return;

    if (isWorkerFetch) {
      activeUrl = targetUrl;
      activeHeaders = headers;

      try {
        response = await fetchWithBackoff(activeUrl, activeHeaders, req?.signal);
        statusCode = response.statusCode;
        responseHeaders = response.headers;
      } catch (fallbackErr) {
        if (isClientAborted(req)) return;
        throw fallbackErr;
      }
    } else {
      throw err;
    }
  }

  if (statusCode === 403 || statusCode === 404) {
    // WAFs/CDNs often block requests where Referer matches the image origin,
    // sometimes returning 403, sometimes 404 to hide the file's existence.
    // Strip referer on retry to mimic native app/direct load behavior.
    const { referer, 'sec-fetch-site': _sfs, ...restHeaders } = activeHeaders;
    const retryHeaders = {
      ...restHeaders,
      'user-agent': getRandomUA(),
      'sec-fetch-site': 'none'
    };

    try {
      response = await fetchWithBackoff(activeUrl, retryHeaders, req.signal);
      statusCode = response.statusCode;
      responseHeaders = response.headers;
    } catch (err) {
      if (isClientAborted(req)) return;
    }
  }

  try {
    let rawBody;

    if (statusCode === 304 && vaultEntry) {
      rawBody = vaultEntry.raw;
      res.setHeader('X-Conditional-Fetch', '304_VAULT_HIT');
    } else {
      rawBody = toBuffer(response.body);
      const encoding = responseHeaders?.['content-encoding'];

      if (encoding) {
        try {
          rawBody = await decompressBody(rawBody, encoding);
        } catch {
          return sendGhost(res, 60, null, 'decompress_failed');
        }
      }
    }

    log.info({ event: 'FETCH_COMPLETE', reqId, fetchMs: Date.now() - startTime, bytes: rawBody.length });
    
    const downloadBudget = memoryGovernor.getDownloadBudget();
    if (rawBody.length > downloadBudget) {
      return sendGhost(res, 3600, { body: rawBody, accept: req.headers.accept }, 'download_budget_exceeded');
    }
    
    if (statusCode === 200 && rawBody.length <= RAW_VAULT_MAX_ENTRY) {
      const upstreamEtag = responseHeaders['etag'] || null;
      const upstreamLastModified = responseHeaders['last-modified'] || null;
      if (upstreamEtag || upstreamLastModified) {
        vaultSet(cacheKey, rawBody, upstreamEtag, upstreamLastModified);
      }
    }

    const upstreamCacheControl = String(responseHeaders['cache-control'] || '').toLowerCase();
    const isNoStore = /no-store|private|no-cache/.test(upstreamCacheControl);
    const upstreamMaxAgeMatch = upstreamCacheControl.match(/max-age=(\d+)/i);
    const upstreamMaxAge = upstreamMaxAgeMatch ? parseInt(upstreamMaxAgeMatch[1], 10) : null;

    if (statusCode === 404) return sendGhost(res, 86400, { body: rawBody, accept: req.headers.accept }, 'upstream_404');
if (statusCode === 410) return sendGhost(res, 86400, { body: rawBody, accept: req.headers.accept }, 'upstream_410_gone');
if (statusCode === 403) return sendGhost(res, 3600, { body: rawBody, accept: req.headers.accept }, 'upstream_403');
if (statusCode !== 304 && (statusCode < 200 || statusCode >= 300)) return sendGhost(res, 60, { body: rawBody, accept: req.headers.accept }, 'upstream_error');

    const detectedType = detectContentType(rawBody);
if (!detectedType.startsWith('image/')) return sendGhost(res, 3600, { body: rawBody, accept: req.headers.accept }, 'not_an_image');
    
    if (req.query?.debug === '1') {
      try {
        const metadata = await sharp(rawBody).metadata();
        const report = {
          status: statusCode,
          originType: detectedType,
          format: metadata.format,
          width: metadata.width,
          height: metadata.height,
          space: metadata.space,
          channels: metadata.channels,
          isAnimated: (metadata.pages || 1) > 1,
          frames: metadata.pages || 1,
          hasAlpha: metadata.hasAlpha,
          exif: metadata.exif ? 'present' : 'none',
          sizeBytes: rawBody.length,
          upstreamCacheControl,
          executionTimeMs: Date.now() - startTime,
          requestId: reqId
        };
        return res.status(200).json(report);
      } catch (err) {
        return res.status(500).json({
          error: 'Debug analysis failed',
          message: sanitizeError(err),
          requestId: reqId
        });
      }
    }

    const etag = await generateETag(req, targetUrl, responseHeaders, rawBody);

    if (req.headers['if-none-match'] === etag) {
      res.setHeader('ETag', etag);
      return res.status(304).end();
    }

    delete responseHeaders['content-encoding'];
    delete responseHeaders['content-length'];

    copyHeaders({ headers: responseHeaders, status: statusCode }, res);

    res.setHeader('Content-Type', detectedType);
    res.setHeader('x-upstream-content-length', String(rawBody.length));
    res.setHeader('ETag', etag);
    res.setHeader('Vary', 'Accept, Accept-Encoding, Sec-CH-Save-Data');

    if (isNoStore) {
      res.setHeader('Cache-Control', 'no-store');
    } else if (upstreamMaxAge !== null && upstreamMaxAge > 0) {
      const ttl = Math.min(upstreamMaxAge, 30 * 24 * 60 * 60);
      res.setHeader('Cache-Control', `public, max-age=${ttl}, s-maxage=${ttl}, stale-while-revalidate=604800, stale-if-error=604800`);
      res.setHeader('x-upstream-max-age', String(upstreamMaxAge));
    } else {
      res.setHeader('Cache-Control', 'public, max-age=86400, s-maxage=86400, stale-while-revalidate=604800, stale-if-error=604800');
    }

    req.opts.originType = detectedType;

    const requestedFormat = req.opts?.format;
    const formatMatchesDetected =
      (requestedFormat === 'jpeg' && detectedType === 'image/jpeg') ||
      (requestedFormat === 'webp' && detectedType === 'image/webp') ||
      (requestedFormat === 'avif' && detectedType === 'image/avif');

    const isModernFormat = detectedType === 'image/webp' || detectedType === 'image/avif';
    const isSmallFile = rawBody.length < 150 * 1024;

    if (isModernFormat && isSmallFile && formatMatchesDetected) {
      return bypass(req, res, rawBody, statusCode);
    }

    const compressEligible = shouldCompress(req, rawBody, memoryGovernor);

    if (!compressEligible) {
      const { originType } = req.opts || {};
      const isImageType = originType && originType.startsWith('image/');
      const isExcludedType = ['image/svg+xml', 'application/pdf', 'image/x-icon', 'image/vnd.microsoft.icon'].includes(originType);

      // Force-AVIF: if it's a valid image but rejected due to memory budget, return 503
      if (isImageType && !isExcludedType) {
        res.setHeader('Retry-After', '5');
        res.setHeader('X-Force-AVIF', 'MEMORY_BUDGET_EXCEEDED');
        return res.status(503).json({ error: 'Memory budget exceeded. Try again shortly.' });
      }

      // Non-image or excluded type: bypass
      return bypass(req, res, rawBody, statusCode);
    }

    if (compressEligible) {
      let compressedResult = null;
      let compressError = null;

      try {
        compressedResult = await compress(req, res, rawBody, memoryGovernor);
      } catch (err) {
        compressError = err;
      }

      // FEATURE: Corrupted Image Auto-Retry
      if (compressError && ENABLE_CORRUPT_RETRY && isSharpDecodeError(compressError)) {
        res.setHeader('X-Corrupt-Retry', 'TRIGGERED');
        log.warn({ reqId }, '[CORRUPT RETRY] Decode failure detected, retrying with new UA');

        let retrySuccess = false;

        for (let attempt = 1; attempt <= MAX_DECODE_RETRIES; attempt++) {
          if (isClientAborted(req)) return;

          try {
            const retryHeaders = {
              ...activeHeaders,
              'user-agent': getRandomUA(),
              'cache-control': 'no-cache'
            };

            const retryResponse = await fetchWithBackoff(activeUrl, retryHeaders, req.signal);
            const retryBody = toBuffer(retryResponse.body);

            if (retryBody.length < 100) continue;

            const retryEncoding = retryResponse.headers?.['content-encoding'];
            let decompressedRetry = retryBody;

            if (retryEncoding) {
              try {
                decompressedRetry = await decompressBody(retryBody, retryEncoding);
              } catch {
                continue;
              }
            }

            const retryBudget = memoryGovernor.getDownloadBudget();
            if (decompressedRetry.length > retryBudget) continue;

            const retryType = detectContentType(decompressedRetry);
            if (!retryType.startsWith('image/')) continue;

            // Retry compress with fresh body
            compressedResult = await compress(req, res, decompressedRetry, memoryGovernor);
            retrySuccess = true;
            res.setHeader('X-Corrupt-Retry', `SUCCESS_ATTEMPT_${attempt}`);
            rawBody = decompressedRetry;
            break;
          } catch (retryErr) {
            if (isClientAborted(req)) return;
            if (!isSharpDecodeError(retryErr)) {
              compressedResult = null;
              break;
            }
            res.setHeader('X-Corrupt-Retry', `FAILED_ATTEMPT_${attempt}`);
          }
        }

        if (!retrySuccess && !compressedResult) {
          log.error({ reqId }, '[CORRUPT RETRY] All retry attempts exhausted');
          return sendGhost(res, 3600, { body: rawBody, accept: req.headers.accept }, 'corrupt_image');
        }
      } else if (compressError) {
        throw compressError;
      }

      if (!res.writableEnded) {
        if (compressedResult && compressedResult.length > 0) {
          res.end(compressedResult);
        } else {
          res.end();
        }
      }

      return;
    }

    return bypass(req, res, rawBody, statusCode);
  } catch (error) {
    if (isClientAborted(req)) return;

    const isBodyTooLarge =
      error.message === 'BODY_TOO_LARGE' ||
      error.code === 'ERR_BODY_LARGE' ||
      error.code === 'BODY_TOO_LARGE';

    if (isBodyTooLarge) return sendGhost(res, 3600, null, 'body_too_large');
    const code = error.code;

    if (code === 'SSRF_BLOCKED_REDIRECT' || code === 'SSRF_BLOCKED_DNS') {
      return sendGhost(res, 86400, null, 'ssrf_blocked');
    }

    if (
      code === 'ETIMEDOUT' ||
      code === 'ERR_GOT_REQUEST_TIMEOUT' ||
      code === 'UND_ERR_HEADERS_TIMEOUT' ||
      code === 'UND_ERR_BODY_TIMEOUT' ||
      code === 'UPSTREAM_DEADLINE'
    ) {
      return sendGhost(res, 60, null, 'upstream_timeout');
    }

    log.error({ reqId, error: sanitizeError(error) }, '[PROXY ERROR]');
    return sendGhost(res, 60, null, 'proxy_error');
  }
}
