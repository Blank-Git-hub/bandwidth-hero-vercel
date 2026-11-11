import crypto from 'node:crypto';
import pino from 'pino';
import ipaddr from 'ipaddr.js';
import rateLimiter from './rateLimiter.js';

const logger = pino({
  level: process.env.LOG_LEVEL || 'info'
});

const { LOGIN, PASSWORD, API_KEY, VERCEL_SERVICE_KEY } = process.env;

// F5-MODIFIED: Legacy query auth toggle
const ALLOW_QUERY_API_KEY = ['1', 'true', 'yes', 'on'].includes(
  String(process.env.ALLOW_QUERY_API_KEY || 'false').trim().toLowerCase()
);

if (ALLOW_QUERY_API_KEY && API_KEY) {
  logger.warn(
    '[AUTH WARNING] ALLOW_QUERY_API_KEY is enabled. Query-string API keys can leak into proxy logs, browser history, and referrers. Prefer x-api-key header auth.'
  );
}

const AUTH_FAILURE_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000;
const AUTH_FAILURE_MAX = parseInt(process.env.RATE_LIMIT_MAX_AUTH_FAILURES, 10) || 10;
const AUTH_RATE_LIMIT_SCOPE = 'auth-fail';

const REQ_RATE_LIMIT_WINDOW_MS = parseInt(process.env.REQ_RATE_LIMIT_WINDOW_MS, 10) || 60000;
const REQ_RATE_LIMIT_MAX = parseInt(process.env.REQ_RATE_LIMIT_MAX, 10) || 1200;
const REQ_RATE_LIMIT_SCOPE = 'req-success';

// --- ITEM 3: Per-Key Rate Limiting Config ---
const parsedKeyWindowMs = parseInt(process.env.KEY_RATE_LIMIT_WINDOW_MS, 10);
const KEY_RATE_LIMIT_WINDOW_MS =
  Number.isFinite(parsedKeyWindowMs) && parsedKeyWindowMs > 0
    ? parsedKeyWindowMs
    : REQ_RATE_LIMIT_WINDOW_MS;

const parsedKeyMax = parseInt(process.env.KEY_RATE_LIMIT_MAX, 10);
const KEY_RATE_LIMIT_MAX =
  Number.isFinite(parsedKeyMax) && parsedKeyMax >= 0
    ? parsedKeyMax
    : REQ_RATE_LIMIT_MAX * 10;

const parsedServiceKeyMax = parseInt(process.env.SERVICE_KEY_RATE_LIMIT_MAX, 10);
const SERVICE_KEY_RATE_LIMIT_MAX =
Number.isFinite(parsedServiceKeyMax) && parsedServiceKeyMax > 0
? parsedServiceKeyMax
: REQ_RATE_LIMIT_MAX * 100;

// Rate-limit bucket: IPv4 as-is; IPv6 collapsed to its /64 so one host cannot rotate addresses to dodge limits.
function clientBucket(ip) {
  try {
    const addr = ipaddr.process(String(ip));
    if (addr.kind() === 'ipv6') {
      return addr.toNormalizedString().split(':').slice(0, 4).join(':') + '::/64';
    }
    return addr.toString();
  } catch {
    return String(ip);
  }
}

function credentialIdentity(label, secret) {
  if (!secret || typeof secret !== 'string') return null;

  const hash = crypto
    .createHash('sha256')
    .update(secret)
    .digest('hex')
    .slice(0, 16);

  return `${label}:${hash}`;
}

async function allowKeyRequest(identity, max) {
  if (!identity || !Number.isFinite(max) || max <= 0) {
    return true;
  }

  try {
    const result = await rateLimiter.keyIncrement({
      key: identity,
      windowMs: KEY_RATE_LIMIT_WINDOW_MS,
      max
    });

    return result.allowed !== false;
  } catch {
    return true;
  }
}
// -------------------------------------------

async function recordSuccessfulRequest(key) {
  // Success increment and auth-failure reset run concurrently (one round-trip, not two).
  await Promise.all([
    rateLimiter.increment({
      scope: REQ_RATE_LIMIT_SCOPE,
      key,
      windowMs: REQ_RATE_LIMIT_WINDOW_MS,
      max: REQ_RATE_LIMIT_MAX
    }).catch(() => {}),
    rateLimiter.reset({
      scope: AUTH_RATE_LIMIT_SCOPE,
      key,
      windowMs: AUTH_FAILURE_WINDOW_MS
    }).catch(() => {})
  ]);
}

async function isRequestRateLimited(key) {
  try {
    const state = await rateLimiter.peek({
      scope: REQ_RATE_LIMIT_SCOPE,
      key,
      windowMs: REQ_RATE_LIMIT_WINDOW_MS
    });
    return state.count >= REQ_RATE_LIMIT_MAX;
  } catch {
    return false;
  }
}

async function recordAuthFailure(key) {
  await rateLimiter.increment({
    scope: AUTH_RATE_LIMIT_SCOPE,
    key,
    windowMs: AUTH_FAILURE_WINDOW_MS,
    max: AUTH_FAILURE_MAX
  }).catch(() => {});
}

async function isAuthRateLimited(key) {
  try {
    const state = await rateLimiter.peek({
      scope: AUTH_RATE_LIMIT_SCOPE,
      key,
      windowMs: AUTH_FAILURE_WINDOW_MS
    });

    return state.count >= AUTH_FAILURE_MAX;
  } catch {
    return false;
  }
}

async function clearAuthFailure(_key) {
  // Intentionally a no-op: the reset now runs inside recordSuccessfulRequest() so both calls are concurrent.
}

function parseBasicAuth(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Basic ')) return undefined;

  try {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const colonIndex = decoded.indexOf(':');

    if (colonIndex === -1) return undefined;

    return {
      name: decoded.slice(0, colonIndex),
      pass: decoded.slice(colonIndex + 1)
    };
  } catch {
    return undefined;
  }
}

function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length === 0 || b.length === 0) return false;

  const hashA = crypto.createHash('sha256').update(a).digest();
  const hashB = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

export default async function authenticate(req, res, next) {
  if (!LOGIN && !PASSWORD && !API_KEY && !VERCEL_SERVICE_KEY) {
    const log = req.log || logger;

    log.error('🚨 CRITICAL: No authentication configured. Refusing to serve.');

    return res.status(500).json({
      error: 'Server misconfigured: Authentication is required.'
    });
  }

  // F5-MODIFIED: Prevent referer leakage of query keys
  res.setHeader('Referrer-Policy', 'no-referrer');

  // F6: Rate limit auth failures by IP to prevent bucket-churning via rotating fake keys.
  const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
  const clientKey = `ip:${clientBucket(clientIp)}`;

    // 0. Detect Internal Service Key (from Cloudflare Worker - F10 FIX)
  const serviceKey = req.headers['x-vercel-service-key'];
  const isServiceCall = Boolean(VERCEL_SERVICE_KEY && serviceKey && safeCompare(serviceKey, VERCEL_SERVICE_KEY));

  // F6 + Item 9: peek both limiters in parallel (one round-trip instead of two).
  // Service calls arrive from the worker's shared egress IP and are limited per credential below,
  // so the per-IP success limiter is skipped for them.
  const [authLimited, reqLimited] = await Promise.all([
    isServiceCall ? Promise.resolve(false) : isAuthRateLimited(clientKey),
    isServiceCall ? Promise.resolve(false) : isRequestRateLimited(clientKey)
  ]);

  if (authLimited) {
    return res.status(429).json({ error: 'Too many authentication failures. Try again later.' });
  }

  if (reqLimited) {
    res.setHeader('Retry-After', String(Math.ceil(REQ_RATE_LIMIT_WINDOW_MS / 1000)));
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }

  if (isServiceCall) {
req.authVia = 'service';
const serviceIdentity = credentialIdentity('svc', VERCEL_SERVICE_KEY);

    if (!(await allowKeyRequest(serviceIdentity, SERVICE_KEY_RATE_LIMIT_MAX))) {
      res.setHeader('Retry-After', String(Math.ceil(KEY_RATE_LIMIT_WINDOW_MS / 1000)));
      return res.status(429).json({
        error: 'Too many requests for this service credential. Try again later.'
      });
    }

    await clearAuthFailure(clientKey);
    await recordSuccessfulRequest(clientKey);
    return next();
  }

  // 1. Check Header API Key (preferred)
  const headerKey = req.headers['x-api-key'];
  if (API_KEY && headerKey && safeCompare(headerKey, API_KEY)) {
    const apiIdentity = credentialIdentity('api', API_KEY);

    if (!(await allowKeyRequest(apiIdentity, KEY_RATE_LIMIT_MAX))) {
      res.setHeader('Retry-After', String(Math.ceil(KEY_RATE_LIMIT_WINDOW_MS / 1000)));
      return res.status(429).json({
        error: 'Too many requests for this API key. Try again later.'
      });
    }

    await clearAuthFailure(clientKey);
await recordSuccessfulRequest(clientKey);
return next();
}

  // 2. Check Query String API Key (F5-MODIFIED: legacy support)
  if (ALLOW_QUERY_API_KEY) {
    let queryKey = req.query.api || req.query.apikey || req.query.api_key;
    if (typeof queryKey === 'string') {
      queryKey = queryKey.split(/[\/\?]/)[0].trim();
    }

    if (API_KEY && queryKey && safeCompare(String(queryKey), API_KEY)) {
      const apiIdentity = credentialIdentity('api', API_KEY);

      if (!(await allowKeyRequest(apiIdentity, KEY_RATE_LIMIT_MAX))) {
        res.setHeader('Retry-After', String(Math.ceil(KEY_RATE_LIMIT_WINDOW_MS / 1000)));
        return res.status(429).json({
          error: 'Too many requests for this API key. Try again later.'
        });
      }

      await clearAuthFailure(clientKey);
await recordSuccessfulRequest(clientKey);
return next();
}
  }

  // 3. Check Basic Auth
  if (LOGIN && PASSWORD) {
    const credentials = parseBasicAuth(req);
    if (
      credentials &&
      safeCompare(credentials.name, LOGIN) &&
      safeCompare(credentials.pass, PASSWORD)
    ) {
      const basicIdentity = credentialIdentity('basic', `${credentials.name}:${credentials.pass}`);

      if (!(await allowKeyRequest(basicIdentity, KEY_RATE_LIMIT_MAX))) {
        res.setHeader('Retry-After', String(Math.ceil(KEY_RATE_LIMIT_WINDOW_MS / 1000)));
        return res.status(429).json({
          error: 'Too many requests for this credential. Try again later.'
        });
      }

      await clearAuthFailure(clientKey);
await recordSuccessfulRequest(clientKey);
return next();
}
  }

  // 4. Deny access
  await recordAuthFailure(clientKey);

  if (LOGIN && PASSWORD) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Bandwidth-Hero Compression Service"');
  }

  return res.status(401).json({ error: 'Access denied. Provide valid Basic Auth or x-api-key header.' });
    }
