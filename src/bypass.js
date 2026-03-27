import { URL } from 'url';
import sanitizeFilename from 'sanitize-filename';

// --- Constants ---
const MAX_BUFFER_SIZE =
  parseInt(process.env.MAX_BUFFER_SIZE, 10) || 25 * 1024 * 1024; // 25 MB
const DEFAULT_FILENAME = process.env.DEFAULT_FILENAME || 'file.bin';

// MIME types safe for inline display in-browser
const INLINE_MIME_PATTERN =
  /^(image\/(jpeg|png|gif|webp|avif|svg\+xml)|text\/(plain|html|css)|application\/(pdf|json)|video\/(mp4|webm|ogg)|audio\/(mpeg|ogg|wav))$/i;

/**
 * Extract a safe, RFC 5987-encoded filename from the URL or fall back to default.
 *
 * Bug fixed: bare `filename=` doesn't handle Unicode/spaces correctly.
 * We now emit both the ASCII fallback and filename*= (RFC 5987) so all
 * browsers get the right name.
 */
function extractFilename(urlString, defaultFilename) {
  try {
    const parsed = new URL(urlString);

    // 1. Prefer ?filename= query param if caller supplies one
    const qpFilename = parsed.searchParams.get('filename');
    if (qpFilename) {
      const safe = sanitizeFilename(decodeURIComponent(qpFilename));
      if (safe) return safe;
    }

    // 2. Fall back to last non-empty path segment
    const lastSegment = parsed.pathname.split('/').filter(Boolean).pop();
    if (!lastSegment) return defaultFilename;

    // Strip query strings that may have leaked into the path
    const withoutQuery = lastSegment.split('?')[0];
    const decoded = decodeURIComponent(withoutQuery);
    return sanitizeFilename(decoded) || defaultFilename;
  } catch {
    return defaultFilename;
  }
}

/**
 * Build a Content-Disposition header value that is safe for all clients.
 *
 * Bug fixed: bare filename="…" breaks on filenames with non-ASCII chars or
 * commas/quotes.  RFC 5987 (filename*=UTF-8''…) is the correct solution.
 */
function buildContentDisposition(disposition, filename) {
  // ASCII-safe fallback (strip anything outside printable ASCII)
  const asciiFallback = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');

  // Percent-encode for RFC 5987
  const encoded = encodeURIComponent(filename).replace(
    /['()*!]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
  );

  return `${disposition}; filename="${asciiFallback}"; filename*=UTF-8''${encoded}`;
}

/**
 * Determine whether the content should render inline or prompt a download.
 *
 * Bug fixed: the original regex matched `svg` but the real MIME type is
 * `image/svg+xml`.  Also `application/json` and others were missing.
 */
function getDisposition(contentType) {
  if (!contentType) return 'attachment';
  // Strip parameters like "; charset=utf-8" before testing
  const mime = contentType.split(';')[0].trim();
  return INLINE_MIME_PATTERN.test(mime) ? 'inline' : 'attachment';
}

/**
 * Validate that req.params carries the required fields and that the buffer
 * is usable before we touch the response object.
 *
 * Returns null on success, or an { status, body } error descriptor.
 */
function validateInputs(req, buffer) {
  if (!Buffer.isBuffer(buffer)) {
    return { status: 500, body: { error: 'Internal Server Error: Invalid content buffer' } };
  }
  if (buffer.length === 0) {
    return { status: 204, body: null }; // Nothing to send
  }
  if (buffer.length > MAX_BUFFER_SIZE) {
    return {
      status: 413,
      body: { error: `Content Too Large: ${buffer.length} bytes exceeds ${MAX_BUFFER_SIZE} byte limit` },
    };
  }
  if (!req || typeof req !== 'object') {
    return { status: 500, body: { error: 'Internal Server Error: Invalid request object' } };
  }
  return null; // All good
}

/**
 * Safely end the response.  Guards against writing to an already-closed socket.
 */
function safeEnd(res, status, body) {
  try {
    if (!res || res.headersSent || res.writableEnded) return;
    if (body === null) {
      res.status(status).end();
    } else {
      res.status(status).json(body);
    }
  } catch (err) {
    // Socket was destroyed before we could respond — nothing we can do
    console.warn(`⚠️ Could not send error response: ${err.message}`);
  }
}

/**
 * Main Bypass Function
 *
 * Sends a pre-buffered response directly to the client, bypassing any
 * upstream transform pipeline.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {Buffer}                     buffer  — fully-loaded response body
 */
export default function bypass(req, res, buffer) {
  // ── 0. Guard: response must still be writable ────────────────────────────
  if (!res || res.headersSent || res.writableEnded) {
    console.warn('⚠️ bypass() called on an already-finished response — skipping');
    return;
  }

  // ── 1. Validate inputs ───────────────────────────────────────────────────
  const validationError = validateInputs(req, buffer);
  if (validationError) {
    console.error(`❌ Bypass validation failed: ${JSON.stringify(validationError)}`);
    safeEnd(res, validationError.status, validationError.body);
    return;
  }

  try {
    // ── 2. Derive metadata ─────────────────────────────────────────────────
    const originUrl   = req.params?.url   ?? '';
    // Bug fixed: fall back to 'application/octet-stream' only when the value
    // is truly absent — an empty string should also trigger the default.
    const contentType = req.params?.originType?.trim() || 'application/octet-stream';
    const filename    = extractFilename(originUrl, DEFAULT_FILENAME);
    const disposition = getDisposition(contentType);

    // ── 3. Set response headers ────────────────────────────────────────────

    // Security hardening
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    // Prevent the proxied content from leaking the referrer of the proxy itself
    res.setHeader('Referrer-Policy', 'no-referrer');

    // Content metadata
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Length', buffer.length);
    res.setHeader('Content-Disposition', buildContentDisposition(disposition, filename));

    // Proxy identification
    res.setHeader('X-Proxy-Bypass', '1');

    // Bug fixed: the original code used `public, immutable` as a default for
    // ALL content, including authenticated or user-specific responses. That
    // can cause sensitive data to be cached by shared CDN/proxy nodes.
    // A `private` default is correct; callers that want aggressive caching
    // should set Cache-Control upstream before calling bypass().
    if (!res.getHeader('Cache-Control')) {
      res.setHeader('Cache-Control', 'private, max-age=0, must-revalidate');
    }

    // ── 4. Send the buffer ─────────────────────────────────────────────────
    // res.end(buffer) is optimal — no PassThrough stream needed since the
    // data is already fully materialised in memory.
    res.end(buffer);

    console.debug(
      `✅ bypass() → ${res.statusCode} | ${contentType} | ${buffer.length} B | ${filename}`
    );
  } catch (error) {
    console.error(`❌ bypass() failed: ${error.message}`, error);
    safeEnd(res, 500, { error: 'Failed to send proxied content' });
  }
}
