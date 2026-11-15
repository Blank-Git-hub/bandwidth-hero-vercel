import { parseSafeUrl } from './urlGuard.js';

const PROTOCOL_REGEX = /^https?:\/\//i;

const BLOCKED_QUERY_NAMES = new Set(['__proto__', 'constructor', 'prototype']);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function firstQueryString(value) {
  if (typeof value === 'string') {
    return value;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === 'string') {
        return item;
      }
    }
  }

  return undefined;
}

function getQueryString(req, name) {
  if (!req || typeof req.query !== 'object' || req.query === null) {
    return undefined;
  }

  if (BLOCKED_QUERY_NAMES.has(name)) {
    return undefined;
  }

  if (!Object.prototype.hasOwnProperty.call(req.query, name)) {
    return undefined;
  }

  const value = req.query[name];

  if (isPlainObject(value)) {
    return undefined;
  }

  return firstQueryString(value);
}

function getFirstQueryString(req, names) {
  for (const name of names) {
    const value = getQueryString(req, name);

    if (value !== undefined) {
      return value;
    }
  }

  return undefined;
}

const clampInt = (value, fallback, min, max) => {
  const n = parseInt(value, 10);
  return Number.isNaN(n) ? fallback : Math.min(Math.max(n, min), max);
};

const DEFAULT_QUALITY = clampInt(process.env.DEFAULT_QUALITY, 40, 10, 100);
const MAX_QUALITY = clampInt(process.env.MAX_QUALITY, 100, 10, 100);
const MIN_QUALITY = clampInt(process.env.MIN_QUALITY, 10, 1, 100);

const DEFAULT_MAX_OUTPUT_DIM = clampInt(process.env.MAX_OUTPUT_DIM, 2560, 0, 4096);
const DEFAULT_MAX_STRIP_WIDTH = clampInt(process.env.MAX_STRIP_WIDTH, 1600, 0, 4096);

const DEFAULT_GRAYSCALE = ['1', 'true', 'yes', 'on'].includes(
  String(process.env.DEFAULT_GRAYSCALE || process.env.DEFAULT_BW || '').trim().toLowerCase()
);

const ALLOW_ACCEPT_FALLBACK = ['1', 'true', 'yes', 'on'].includes(
  String(process.env.ALLOW_ACCEPT_FALLBACK || '').trim().toLowerCase()
);

const AUTH_PARAMS = [
  'api',
  'apikey',
  'api_key'
];

// F12-MODIFIED: raw/bypass removed
const ALLOWED_MODES = new Set([
  'auto',
  'photo',
  'normal',
  'manga',
  'comic',
  'strip',
  'webtoon',
  'manhwa',
  'manhua'
]);

// F13-MODIFIED: Safe rotation increments only
const SAFE_ROTATIONS = new Set([90, 180, 270]);

const INTERNAL_FORMAT_PARAM = '__bw_fmt';
const INTERNAL_FORMATS = new Set(['jpeg', 'avif', 'webp']);

function parseBoolean(value, defaultValue) {
  if (Array.isArray(value)) {
    value = value.find((item) => typeof item === 'string');
  }

  if (value === undefined || value === null || typeof value !== 'string') {
    return defaultValue;
  }

  const str = value.trim().toLowerCase();

  if (['1', 'true', 'yes', 'on'].includes(str)) return true;
  if (['0', 'false', 'no', 'off'].includes(str)) return false;

  return defaultValue;
}

function parseQuality(q, defaultValue, min, max) {
  const n = parseInt(q, 10);

  if (Number.isNaN(n)) return defaultValue;
  if (n < min) return min;
  if (n > max) return max;

  return n;
}

// F13-MODIFIED: Parse safe rotation
function parseRotation(value) {
  const n = parseInt(value, 10);
  if (SAFE_ROTATIONS.has(n)) return n;
  return 0;
}

function parseInternalFormat(req) {
  const raw = getQueryString(req, INTERNAL_FORMAT_PARAM);
  const fmt = String(raw || '').toLowerCase();

  return INTERNAL_FORMATS.has(fmt) ? fmt : null;
}

function parseFormat(req) {
  const internalFormat = parseInternalFormat(req);
  if (internalFormat) return internalFormat;

  if (parseBoolean(getQueryString(req, 'jpeg'), false)) return 'jpeg';
  if (parseBoolean(getQueryString(req, 'avif'), false)) return 'avif';
  if (parseBoolean(getQueryString(req, 'webp'), false)) return 'webp';

  if (ALLOW_ACCEPT_FALLBACK) {
    const accept = String(req.headers.accept || '').toLowerCase();
    const wantsJpeg = accept.includes('image/jpeg');
    const wantsWebp = accept.includes('image/webp');
    const wantsAvif = accept.includes('image/avif');
    const isWildcard = !accept || accept === '*/*' || accept.includes('*/*');

    if (wantsJpeg && !wantsAvif && !wantsWebp && !isWildcard) return 'jpeg';
    if (wantsWebp && !wantsAvif) return 'webp';

    return 'avif';
  }

  return 'avif';
}

const PROXY_PARAM_NAMES = new Set([
  'api', 'apikey', 'api_key', 'jpeg', 'avif', 'webp', 'bw', 'l', 'q', 'quality',
  'max_dim', 'maxdim', 'max', 'strip_w', 'stripw', 'strip_width', 'rotate', 'mode',
  'sharpen', 'minsize', 'etag', 'conditional', 'debug', INTERNAL_FORMAT_PARAM
]);

// Some clients append the image URL UNENCODED (...&url=https://cdn/x.jpg?a=1&b=2).
// The query parser then cuts it at the first "&". Recover the full URL from the raw query string.
// Percent-encoded URLs (url=https%3A%2F%2F...) never match, so well-behaved clients are unaffected.
function recoverUnencodedUrl(req) {
  const rawUrl = req.originalUrl || req.url || '';
  const qIndex = rawUrl.indexOf('?');
  if (qIndex === -1) return undefined;

  const match = rawUrl.slice(qIndex + 1).match(/(?:^|[?&])url=(https?:\/\/.+)$/i);
  if (!match) return undefined;

  let value = match[1];

  // Peel trailing "&name=value" segments that belong to this proxy, not to the image URL.
  for (;;) {
    const amp = value.lastIndexOf('&');
    if (amp === -1) break;
    const name = value.slice(amp + 1).split('=')[0].toLowerCase();
    if (!PROXY_PARAM_NAMES.has(name)) break;
    value = value.slice(0, amp);
  }

  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function extractHiddenUrlFromRaw(req) {
  const rawUrl = req.originalUrl || req.url || '';
  const qIndex = rawUrl.indexOf('?');
  if (qIndex === -1) return undefined;

  const rawQuery = rawUrl.slice(qIndex + 1);

  const match = rawQuery.match(/(?:^|[?&])url=(.+)$/);

  if (match) {
    try {
      return decodeURIComponent(match[1]);
    } catch {
      return match[1];
    }
  }

  return undefined;
}

function params(req, res, next) {
  try {
    let url;

    if (
      req.query &&
      typeof req.query === 'object' &&
      Object.prototype.hasOwnProperty.call(req.query, 'url')
    ) {
      url = req.query.url;
    }

    if (Array.isArray(url)) {
      return res.status(400).json({ error: 'Multiple URL parameters are not allowed.' });
    }

    if (isPlainObject(url)) {
      return res.status(400).json({ error: 'Invalid URL parameter.' });
    }

    const recoveredUrl = recoverUnencodedUrl(req);
    if (recoveredUrl) {
      url = recoveredUrl;
    }

    if (url === undefined || url === null || url === '') {
      const hiddenUrl = extractHiddenUrlFromRaw(req);

      if (hiddenUrl) {
        url = hiddenUrl;
      }
    }

    if (url === undefined || url === null || url === '') {
      return res.status(200).send('bandwidth-hero-proxy');
    }

    if (typeof url !== 'string') {
      return res.status(400).json({ error: 'Invalid URL parameter.' });
    }

    url = url.trim();

    if (!url) {
      return res.status(200).send('bandwidth-hero-proxy');
    }

    if (!PROTOCOL_REGEX.test(url)) {
      return res.status(400).json({
        error: 'Invalid URL. Must include protocol (http or https).'
      });
    }

    const safeUrl = parseSafeUrl(url);

    if (!safeUrl) {
      return res.status(403).json({
        error: 'Blocked or invalid URL.'
      });
    }

    const saveData = ['1', 'true', 'yes', 'on'].includes(
      String(req.headers['save-data'] || req.headers['sec-ch-save-data'] || '').toLowerCase()
    );

    const baseQuality = saveData ? Math.max(MIN_QUALITY, DEFAULT_QUALITY - 20) : DEFAULT_QUALITY;
    const baseMaxDim = saveData ? 1440 : DEFAULT_MAX_OUTPUT_DIM;
    const baseStripWidth = saveData ? 1080 : DEFAULT_MAX_STRIP_WIDTH;

    req.opts = {
      url: safeUrl.href,
      format: parseFormat(req),
      grayscale: parseBoolean(getQueryString(req, 'bw'), DEFAULT_GRAYSCALE),
      quality: parseQuality(
        getFirstQueryString(req, ['l', 'q', 'quality']),
        baseQuality,
        MIN_QUALITY,
        MAX_QUALITY
      ),
      maxDim: clampInt(
        getFirstQueryString(req, ['max_dim', 'maxdim', 'max']),
        baseMaxDim,
        0,
        4096
      ),
      maxStripWidth: clampInt(
        getFirstQueryString(req, ['strip_w', 'stripw', 'strip_width']),
        baseStripWidth,
        0,
        4096
      ),
      rotate: parseRotation(getQueryString(req, 'rotate'))
    };
    
    // F12-MODIFIED: Normalize mode, raw/bypass treated as auto
    const rawMode = getQueryString(req, 'mode');
    const modeInput = String(rawMode || '').toLowerCase();
    const mode = ALLOWED_MODES.has(modeInput) ? modeInput : 'auto';

    let sharpenDefault;

    if (
      mode === 'manga' ||
      mode === 'comic' ||
      mode === 'strip' ||
      mode === 'webtoon' ||
      mode === 'manhwa' ||
      mode === 'manhua'
    ) {
      sharpenDefault = true;
    } else if (
      mode === 'photo' ||
      mode === 'normal'
    ) {
      sharpenDefault = false;
    } else {
      sharpenDefault = undefined;
    }

    let sharpenQuery = getQueryString(req, 'sharpen');

    if (mode === 'manga' || mode === 'comic') {
      req.opts.maxDim = req.opts.maxDim || baseMaxDim;
      req.opts.maxStripWidth = 0;
      if (sharpenQuery === undefined) sharpenQuery = '1';

    } else if (mode === 'strip' || mode === 'webtoon' || mode === 'manhwa' || mode === 'manhua') {
      req.opts.maxDim = 0;
      req.opts.maxStripWidth = req.opts.maxStripWidth || baseStripWidth;
      if (sharpenQuery === undefined) sharpenQuery = '1';

    } else if (mode === 'photo' || mode === 'normal') {
      req.opts.maxDim = req.opts.maxDim || baseMaxDim;
      req.opts.maxStripWidth = 0;
      if (sharpenQuery === undefined) sharpenQuery = '0';
    }

    req.opts.mode = mode;
    req.opts.sharpen = parseBoolean(sharpenQuery, sharpenDefault);

    return next();
  } catch (err) {
    const safeMessage = err?.message ? String(err.message).split('?')[0] : 'Unknown error';
    console.error('[Params Middleware Error]', safeMessage);

    if (!res.headersSent) {
      res.status(500).json({
        error: 'Internal server error in params middleware.'
      });
    }
  }
}

export default params;
