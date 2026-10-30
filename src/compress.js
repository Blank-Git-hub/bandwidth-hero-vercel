import sharp from 'sharp';
import { createHash, webcrypto } from 'node:crypto';
import { LRUCache } from 'lru-cache';
import memoryGovernor from './memoryGovernor.js';
import concurrencyGovernor from './concurrencyGovernor.js';
import adaptiveDirector from './adaptiveDirector.js';

const subtle = webcrypto?.subtle ?? globalThis.crypto?.subtle;

function safeInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function safeFloat(value, fallback) {
  const n = parseFloat(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function envBool(name, fallback = false) {
  const v = process.env[name];
  if (v === undefined) return fallback;
  return v === '1' || v === 'true' || v === 'yes';
}

async function getTmpFreeMB() {
  try {
    const { statfs } = await import('node:fs/promises');
    const stats = await statfs('/tmp');
    return Math.floor((stats.bavail * stats.bsize) / (1024 * 1024));
  } catch {
    return -1;
  }
}

sharp.cache({ memory: 0, files: 0, items: 0 });

async function generateExactHash(buffer) {
  try {
    if (subtle) {
      const digest = await subtle.digest('SHA-256', buffer);
      return Buffer.from(digest).toString('hex').slice(0, 16);
    }
    return createHash('sha256').update(buffer).digest('hex').slice(0, 16);
  } catch {
    return null;
  }
}

const MAX_OUTPUT_DIM = safeInt(process.env.MAX_OUTPUT_DIM, 2560);
const DEFAULT_QUALITY = safeInt(process.env.DEFAULT_QUALITY, 55);
const MAX_STRIP_WIDTH = safeInt(process.env.MAX_STRIP_WIDTH, 1600);
const MAX_ANIMATION_FRAMES = safeInt(process.env.MAX_ANIMATION_FRAMES, 2147483647);
const VIEWPORT_FALLBACK = safeInt(process.env.VIEWPORT_FALLBACK, 1080);
const HEALTH_LAG_THRESHOLD = safeInt(process.env.HEALTH_LAG_THRESHOLD, 100);
const SHUTDOWN_TIMEOUT = safeInt(process.env.SHUTDOWN_TIMEOUT, 10000);
const SHARP_HARD_TIMEOUT_MS = safeInt(process.env.SHARP_HARD_TIMEOUT_MS, 50000);

const AVIF_MAX_PIXELS = safeInt(process.env.AVIF_MAX_PIXELS, 50_000_000);
const AVIF_MAX_DIMENSION = safeInt(process.env.AVIF_MAX_DIMENSION, 16383);
const AVIF_MAX_ASPECT_RATIO = safeInt(process.env.AVIF_MAX_ASPECT_RATIO, 200);
const MIN_AVIF_RESIZED_DIMENSION = safeInt(process.env.MIN_AVIF_RESIZED_DIMENSION, 600);
const ENABLE_AVIF_EXTREME_FALLBACK = envBool('ENABLE_AVIF_EXTREME_FALLBACK', true);
const AVIF_LIMIT_RESIZE_QUALITY_BOOST = safeInt(process.env.AVIF_LIMIT_RESIZE_QUALITY_BOOST, 8);

const ANALYSIS_MAX_DIM = safeInt(process.env.ANALYSIS_MAX_DIM, 4096);
const ANALYSIS_MAX_PIXELS = safeInt(process.env.ANALYSIS_MAX_PIXELS, 16_000_000);

// FEATURE: CPU/event-loop pressure governor
const CPU_LAG_THRESHOLD_MS = safeInt(process.env.CPU_LAG_THRESHOLD_MS, 80);
const EVENT_LOOP_MAX_MS = safeInt(process.env.ADAPTIVE_EVENT_LOOP_MAX_MS, CPU_LAG_THRESHOLD_MS);

// FEATURE: HDR/wide-gamut safe downconversion
const ENABLE_HDR_SAFE_CONVERSION = envBool('ENABLE_HDR_SAFE_CONVERSION', true);

// FEATURE: Text/OCR Region Preservation
const ENABLE_TEXT_PRESERVATION = envBool('ENABLE_TEXT_PRESERVATION', true);
const TEXT_SHARPNESS_THRESHOLD = safeInt(process.env.TEXT_SHARPNESS_THRESHOLD, 55);
const TEXT_ENTROPY_MAX = safeFloat(process.env.TEXT_ENTROPY_MAX, 6.0);
const TEXT_QUALITY_BOOST = safeInt(process.env.TEXT_QUALITY_BOOST, 15);

// FEATURE: Smart Alpha Channel Trimming
const ENABLE_ALPHA_TRIM = envBool('ENABLE_ALPHA_TRIM', true);
const ALPHA_TRIM_MAX_PIXELS = safeInt(process.env.ALPHA_TRIM_MAX_PIXELS, 8_000_000);

// FEATURE: Animated Frame Dropping
const ENABLE_FRAME_DROPPING = envBool('ENABLE_FRAME_DROPPING', true);
const FRAME_DROP_THRESHOLD = safeInt(process.env.FRAME_DROP_THRESHOLD, 50);

// FEATURE: Safe Metadata Exceptions
const ENABLE_SAFE_METADATA = envBool('ENABLE_SAFE_METADATA', true);

const metrics = {
  startTime: Date.now(),
  totalRequests: 0,
  cacheHits: 0,
  cacheMisses: 0,
  totalBytesIn: 0,
  totalBytesOut: 0,
  totalBytesSaved: 0,
  totalEncodeTime: 0,
  encodeCount: 0,
  memoryRejections: 0,
  voidDetections: 0,
  encodingFailures: 0,
  cpuPressureEvents: 0,
  hdrConversions: 0,
  textPreservations: 0,
  alphaTrims: 0,
  frameDrops: 0,
  formatCounts: { avif: 0, webp: 0, jpeg: 0 },
  featureActivations: {
    deskew: 0,
    alphaSentinel: 0,
    moireRemoval: 0,
    lineDenoise: 0,
    luminanceFix: 0,
    ghostStripper: 0,
    bandingExorcist: 0,
    metadataReaper: 0
  }
};

let activeRequests = 0;
let activeEncodes = 0;
let isShuttingDown = false;

function recordMetric(key, value = 1) {
  if (metrics.featureActivations[key] !== undefined) {
    metrics.featureActivations[key] += value;
  }
}

export function getMetrics() {
  const uptime = Date.now() - metrics.startTime;
  const avgEncodeTime = metrics.encodeCount > 0
    ? Math.round(metrics.totalEncodeTime / metrics.encodeCount) : 0;
  const cacheHitRate = metrics.totalRequests > 0
    ? ((metrics.cacheHits / metrics.totalRequests) * 100).toFixed(2) + '%' : '0%';
  const compressionRatio = metrics.totalBytesIn > 0
    ? ((1 - metrics.totalBytesOut / metrics.totalBytesIn) * 100).toFixed(2) + '%' : '0%';


  return {
    uptime: `${Math.floor(uptime / 1000)}s`,
    totalRequests: metrics.totalRequests,
    cacheHits: metrics.cacheHits,
    cacheMisses: metrics.cacheMisses,
    cacheHitRate,
    totalBytesIn: `${(metrics.totalBytesIn / 1024 / 1024).toFixed(2)}MB`,
    totalBytesOut: `${(metrics.totalBytesOut / 1024 / 1024).toFixed(2)}MB`,
    totalBytesSaved: `${(metrics.totalBytesSaved / 1024 / 1024).toFixed(2)}MB`,
    compressionRatio,
    avgEncodeTime: `${avgEncodeTime}ms`,
    memoryRejections: metrics.memoryRejections,
    voidDetections: metrics.voidDetections,
    encodingFailures: metrics.encodingFailures,
    cpuPressureEvents: metrics.cpuPressureEvents,
    hdrConversions: metrics.hdrConversions,
    textPreservations: metrics.textPreservations,
    alphaTrims: metrics.alphaTrims,
    frameDrops: metrics.frameDrops,
    formatCounts: metrics.formatCounts,
    featureActivations: metrics.featureActivations,
    activeRequests,
    activeEncodes,
    isShuttingDown,
    memoryGovernor: {
      rssMB: memoryGovernor.getRssMB(),
      availableMB: memoryGovernor.getAvailableMB(),
      pixelBudget: memoryGovernor.getPixelBudget(),
      activePixels: memoryGovernor.getActivePixelCost(),
      ceilingMB: memoryGovernor.MEMORY_CEILING_MB
    },
    concurrencyGovernor: concurrencyGovernor.getStatus()
  };
}

export function checkHealth() {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    setImmediate(() => {
      const lag = Number(process.hrtime.bigint() - start) / 1e6;
      const healthy = lag < HEALTH_LAG_THRESHOLD;
      resolve({
        healthy,
        eventLoopLag: `${lag.toFixed(2)}ms`,
        threshold: `${HEALTH_LAG_THRESHOLD}ms`,
        uptime: `${Math.floor(process.uptime())}s`,
        activeRequests,
        activeEncodes,
        isShuttingDown,
        memory: {
          rssMB: memoryGovernor.getRssMB(),
          ceilingMB: memoryGovernor.MEMORY_CEILING_MB,
          underPressure: memoryGovernor.isUnderPressure()
        }
      });
    });
  });
}

function gracefulShutdown(signal) {
  if (isShuttingDown) return;

  console.warn({
    event: 'GRACEFUL_SHUTDOWN',
    signal,
    activeRequests,
    activeEncodes,
    rssMB: memoryGovernor.getRssMB(),
    uptimeSec: Math.floor(process.uptime())
  }, '[SHUTDOWN] Instance shutdown requested');

  isShuttingDown = true;
  const forceTimeout = setTimeout(() => process.exit(1), SHUTDOWN_TIMEOUT);
  const checkInterval = setInterval(() => {
    if (activeRequests === 0 && activeEncodes === 0) {
      clearTimeout(forceTimeout);
      clearInterval(checkInterval);
      process.exit(0);
    }
  }, 100);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// RESOURCE WATCHDOG:
// If the instance is idle and /tmp or RSS is exhausted, recycle cleanly.
setInterval(async () => {
  if (isShuttingDown || activeRequests > 0 || activeEncodes > 0) return;

  // Best-effort cleanup of stale libvips temp files.
  try {
    const { readdirSync, statSync, rmSync } = await import('node:fs');
    const { join } = await import('node:path');
    const now = Date.now();

    for (const entry of readdirSync('/tmp')) {
      if (!entry.startsWith('vips-')) continue;

      const fullPath = join('/tmp', entry);

      try {
        const st = statSync(fullPath);

        if (now - st.mtimeMs > 5 * 60 * 1000) {
          rmSync(fullPath, { recursive: true, force: true });
        }
      } catch {}
    }
  } catch {}

  const tmpFreeMB = await getTmpFreeMB();
  const rssMB = memoryGovernor.getRssMB();

  const tmpLow = tmpFreeMB >= 0 && tmpFreeMB < 64;
  const rssHigh = rssMB > 950;

  if (tmpLow || rssHigh) {
    console.warn({
      event: 'RESOURCE_SELF_RECYCLE',
      rssMB,
      tmpFreeMB,
      activeRequests,
      activeEncodes
    }, '[RESOURCE SELF-RECYCLE] Idle instance resource pressure, exiting gracefully');

    process.exit(0);
  }
}, 10000).unref();

process.on('exit', (code) => {
  console.warn({
    event: 'PROCESS_EXIT',
    code,
    activeRequests,
    activeEncodes,
    rssMB: memoryGovernor.getRssMB(),
    uptimeSec: Math.floor(process.uptime())
  }, '[PROCESS EXIT]');
});

const EXACT_CACHE_MAX_ENTRIES = safeInt(process.env.EXACT_CACHE_MAX_ENTRIES, 30);
const EXACT_CACHE_MAX_MB = safeInt(process.env.EXACT_CACHE_MAX_MB, 32);

const exactCache = new LRUCache({
  max: EXACT_CACHE_MAX_ENTRIES,
  maxSize: EXACT_CACHE_MAX_MB * 1024 * 1024,
  sizeCalculation: (entry) => entry.buffer.length
});

// ============================================================
// FEATURE FLAGS
// ============================================================

const FORCE_GRAYSCALE = envBool('FORCE_GRAYSCALE', false);
const STRIP_ALPHA = envBool('STRIP_ALPHA', true);
const ENABLE_PLACEHOLDER = envBool('ENABLE_PLACEHOLDER', true);
const ENABLE_PALETTE = envBool('ENABLE_PALETTE', true);
const ENABLE_VOID_WATCHER = envBool('ENABLE_VOID_WATCHER', true);
const ENABLE_JUDGE = envBool('ENABLE_JUDGE', true);
const ENABLE_MOIRE = envBool('ENABLE_MOIRE', true);
const ENABLE_LINE_DENOISE = envBool('ENABLE_LINE_DENOISE', true);
const ENABLE_LUMINANCE = envBool('ENABLE_LUMINANCE', true);
const ENABLE_DESKEW = envBool('ENABLE_DESKEW', true);
const ENABLE_BANDING_EXORCIST = envBool('ENABLE_BANDING_EXORCIST', true);
const ENABLE_ALPHA_SENTINEL = envBool('ENABLE_ALPHA_SENTINEL', true);
const ENABLE_LAYOUT_PROPHET = envBool('ENABLE_LAYOUT_PROPHET', true);
const ENABLE_ENCODING_VERIFIER = envBool('ENABLE_ENCODING_VERIFIER', true);
const ENABLE_GHOST_STRIPPER = envBool('ENABLE_GHOST_STRIPPER', true);
const ENABLE_METADATA_REAPER = envBool('ENABLE_METADATA_REAPER', true);
const ENABLE_WEBP_PRESET = envBool('ENABLE_WEBP_PRESET', true);
const ENABLE_TIMEOUT_GUILLOTINE = envBool('ENABLE_TIMEOUT_GUILLOTINE', true);
const ENABLE_DIMENSION_OVERLORD = envBool('ENABLE_DIMENSION_OVERLORD', true);
const ENABLE_ORACLE_LEDGER = envBool('ENABLE_ORACLE_LEDGER', true);

function parseTriState(value, defaultValue) {
  if (Array.isArray(value)) value = value[0];
  if (value === undefined) return defaultValue;
  const str = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(str)) return true;
  if (['0', 'false', 'no', 'off'].includes(str)) return false;
  return defaultValue;
}

// ============================================================
// FEATURE: CPU/event-loop pressure governor helper
// ============================================================
async function measureEventLoopLag() {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    setImmediate(() => {
      const lag = Number(process.hrtime.bigint() - start) / 1e6;
      resolve(lag);
    });
  });
}

function computeAdaptivePressure({ eventLoopLag, activeEncodes, encodeLimit, memoryUnderPressure }) {
  let pressure = 1.0;

  // Event loop lag: scale from 1.0 to 1.5 based on how far over threshold
  if (eventLoopLag > EVENT_LOOP_MAX_MS) {
    const overshoot = (eventLoopLag - EVENT_LOOP_MAX_MS) / EVENT_LOOP_MAX_MS;
    pressure += Math.min(overshoot * 0.5, 0.5);
  }

  // Active encodes: scale based on contention
  if (encodeLimit > 0 && activeEncodes >= encodeLimit) {
    pressure += 0.3;
  } else if (encodeLimit > 0 && activeEncodes >= encodeLimit * 0.5) {
    pressure += 0.15;
  }

  // Memory pressure: fixed boost
  if (memoryUnderPressure) {
    pressure += 0.4;
  }

  // Cap pressure at 2.5x to avoid over-suppressing effort
  return Math.min(pressure, 2.5);
}

// ============================================================
// FEATURE: Smart Alpha Channel Trimming helper
// ============================================================
async function detectAlphaBounds(buffer, metadata) {
  if (!metadata.hasAlpha) return null;

  const pixelCount = (metadata.width || 0) * (metadata.height || 0);
  if (pixelCount > ALPHA_TRIM_MAX_PIXELS) return null;

  try {
    const sampleDim = 256;
    const { data, info } = await sharp(buffer)
      .resize(sampleDim, sampleDim, { fit: 'inside', withoutEnlargement: true })
      .raw()
      .toBuffer({ resolveWithObject: true });

    const w = info.width;
    const h = info.height;
    const channels = info.channels;
    const alphaIdx = channels - 1;

    let minX = w, minY = h, maxX = 0, maxY = 0;
let foundOpaque = false;
let fullBounds = false;
let idx = alphaIdx;

for (let y = 0; y < h; y++) {
  for (let x = 0; x < w; x++, idx += channels) {
    if (data[idx] > 0) {
      foundOpaque = true;

      if (x < minX) minX = x;
      if (x > maxX) maxX = x;
      if (y < minY) minY = y;
      if (y > maxY) maxY = y;

      // If opaque pixels touch all four sampled edges, bounds cannot expand further.
      if (minX === 0 && minY === 0 && maxX === w - 1 && maxY === h - 1) {
        fullBounds = true;
        break;
      }
    }
  }

  if (fullBounds) break;
}

    if (!foundOpaque) return null;
    if (minX >= maxX || minY >= maxY) return null;

    // Check if trim would save meaningful space (at least 5% on any side)
    const trimLeft = minX / w;
    const trimTop = minY / h;
    const trimRight = (w - 1 - maxX) / w;
    const trimBottom = (h - 1 - maxY) / h;

    if (trimLeft < 0.02 && trimTop < 0.02 && trimRight < 0.02 && trimBottom < 0.02) {
      return null;
    }

    const scaleX = metadata.width / w;
    const scaleY = metadata.height / h;

    return {
      left: Math.max(0, Math.floor(minX * scaleX)),
      top: Math.max(0, Math.floor(minY * scaleY)),
      width: Math.min(metadata.width, Math.ceil((maxX - minX + 1) * scaleX)),
      height: Math.min(metadata.height, Math.ceil((maxY - minY + 1) * scaleY)),
      originalWidth: metadata.width,
      originalHeight: metadata.height,
      padLeft: Math.floor(minX * scaleX),
      padTop: Math.floor(minY * scaleY),
      padRight: Math.max(0, metadata.width - Math.ceil((maxX + 1) * scaleX)),
      padBottom: Math.max(0, metadata.height - Math.ceil((maxY + 1) * scaleY))
    };
  } catch {
    return null;
  }
}

// ============================================================
// FEATURE: Text/OCR detection helper
// ============================================================
function isTextHeavyImage(analysis) {
  if (!analysis) return false;
  const sharpness = analysis.sharpness || 0;
  const entropy = analysis.entropy || 0;
  const colorVariance = analysis.colorVariance || 0;

  // Text/OCR heuristic: high sharpness, low entropy, low color variance
  return sharpness > TEXT_SHARPNESS_THRESHOLD &&
         entropy < TEXT_ENTROPY_MAX &&
         colorVariance < 40;
}

// ============================================================
// FEATURE: HDR/wide-gamut detection helper
// ============================================================
function detectHDRCharacteristics(metadata) {
  const space = (metadata.space || '').toLowerCase();
  const depth = metadata.depth || 'uchar';
  const hasICC = Boolean(metadata.icc);

  const wideGamutSpaces = ['display-p3', 'adobe-rgb', 'prophoto-rgb', 'rec2020', 'a98-rgb'];
  const isWideGamut = wideGamutSpaces.includes(space);

  // 16-bit depth with ICC profile is a strong HDR indicator
  const isHighBitDepth = depth === 'ushort' || depth === 'uint' || depth === 'float';
  const isPotentialHDR = isHighBitDepth && hasICC;

  return { isWideGamut, isPotentialHDR, space, depth, hasICC };
}

// ============================================================
// ANALYSIS HELPERS (existing)
// ============================================================
async function generatePlaceholderAndPalette(buffer) {
  try {
    // Allow sharp to use shrink-on-load for extreme vertical strips
    const { data, info } = await sharp(buffer, { limitInputPixels: 0 })
      .resize(32, 32, { fit: 'inside' })
      .raw()
      .toBuffer({ resolveWithObject: true });

    const channels = info.channels;
    let sum = 0, sumSq = 0;
    const pixelCount = data.length / channels;
    const colorCounts = new Map();

    for (let i = 0; i < data.length; i += channels) {
      const r = data[i], g = data[i + 1], b = data[i + 2];
      const lum = 0.299 * r + 0.587 * g + 0.114 * b;
      sum += lum;
      sumSq += lum * lum;
      const colorKey = (r << 16) | (g << 8) | b;
      colorCounts.set(colorKey, (colorCounts.get(colorKey) || 0) + 1);
    }

    const mean = sum / pixelCount;
    const stdev = Math.sqrt(Math.max(0, sumSq / pixelCount - mean * mean));
    const isVoid = stdev < 1;

    let palette = [];
    if (!isVoid) {
      const sorted = [...colorCounts.entries()].sort((a, b) => b[1] - a[1]);
      palette = sorted.slice(0, 3).map(([colorKey]) => {
        const hex = colorKey.toString(16).padStart(6, '0');
        return `#${hex}`;
      });
    }

    let placeholder = null;
    if (ENABLE_PLACEHOLDER && !isVoid) {
      const thumbBuffer = await sharp(buffer, { limitInputPixels: 4_000_000 })
        .resize(32, 32, { fit: 'inside' })
        .blur(2)
        .grayscale()
        .jpeg({ quality: 20 })
        .toBuffer();
      placeholder = 'data:image/jpeg;base64,' + thumbBuffer.toString('base64');
    }

    return { placeholder, palette, stdev, isVoid };
  } catch {
    return { placeholder: null, palette: [], stdev: 0, isVoid: false };
  }
}

async function detectSkew(buffer) {
  try {
    const { data, info } = await sharp(buffer)
      .resize(512, 512, { fit: 'inside' })
      .grayscale()
      .raw()
      .toBuffer({ resolveWithObject: true });

    const w = info.width, h = info.height;
    const corners = [data[0], data[w - 1], data[(h - 1) * w], data[h * w - 1]];
    const bgValue = corners.reduce((a, b) => a + b, 0) / 4;

    // Build binary mask of content pixels
    const mask = new Uint8Array(w * h);
    let contentCount = 0;
    for (let i = 0; i < w * h; i++) {
      if (Math.abs(data[i] - bgValue) > 30) {
        mask[i] = 1;
        contentCount++;
      }
    }

    if (contentCount < 500) return 0;

    // Projection profile method:
    // Test small angles. The correct angle produces the sharpest
    // horizontal projection peaks (highest variance) because text
    // lines align into distinct rows.
    let bestAngle = 0;
    let bestVariance = 0;

    for (let testAngle = -4; testAngle <= 4; testAngle += 0.5) {
      const rad = (testAngle * Math.PI) / 180;
      const cosA = Math.cos(rad);
      const sinA = Math.sin(rad);
      const cx = w / 2;
      const cy = h / 2;

      const projection = new Float64Array(h);

      for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
          if (!mask[y * w + x]) continue;

          const dx = x - cx;
          const dy = y - cy;
          const ry = Math.round(dx * sinA + dy * cosA + cy);

          if (ry >= 0 && ry < h) {
            projection[ry]++;
          }
        }
      }

      const mean = projection.reduce((a, b) => a + b, 0) / h;
      const variance = projection.reduce((s, v) => s + (v - mean) ** 2, 0) / h;

      if (variance > bestVariance) {
        bestVariance = variance;
        bestAngle = testAngle;
      }
    }

    // Reject if the detected angle is too small to matter
    if (Math.abs(bestAngle) < 0.5) return 0;

    return bestAngle;
  } catch {
    return 0;
  }
}

let _noiseTilePromise = null;
function getNoiseTile() {
  if (!_noiseTilePromise) {
    _noiseTilePromise = (async () => {
      const size = 128, channels = 4;
      const data = Buffer.alloc(size * size * channels);
      for (let i = 0; i < size * size; i++) {
        const noise = Math.floor(Math.random() * 256);
        data[i * channels] = noise;
        data[i * channels + 1] = noise;
        data[i * channels + 2] = noise;
        data[i * channels + 3] = 6;
      }
      return sharp(data, { raw: { width: size, height: size, channels } }).png().toBuffer();
    })();
  }
  return _noiseTilePromise;
}

async function detectAlphaStrippable(buffer, metadata) {
  if (!metadata.hasAlpha) return false;
  try {
    const sampleSize = 64;
    const { data, info } = await sharp(buffer)
      .resize(sampleSize, sampleSize, { fit: 'inside' })
      .raw()
      .toBuffer({ resolveWithObject: true });

    const channels = info.channels;
    const alphaIdx = channels - 1;
    let minAlpha = 255;

    for (let i = alphaIdx; i < data.length; i += channels) {
      if (data[i] < minAlpha) {
        minAlpha = data[i];
        if (minAlpha < 255) return false;
      }
    }
    return minAlpha === 255;
  } catch {
    return false;
  }
}

function verifyOutput(buffer, format) {
  if (!buffer || buffer.length < 100) return false;
  switch (format) {
    case 'jpeg':
      return buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
    case 'webp':
      return buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
             buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50;
    case 'avif':
      return buffer[4] === 0x66 && buffer[5] === 0x74 && buffer[6] === 0x79 && buffer[7] === 0x70;
    default:
      return true;
  }
}

function getWebpPreset(analysis, lineArtResult, origW, origH) {
  if (!ENABLE_WEBP_PRESET) return 'default';

  // Manga/grayscale line art benefits from the drawing preset.
  if (
    analysis.isMangaStrip ||
    analysis.isMangaPage ||
    analysis.isMangaWidePage ||
    analysis.isGrayscale
  ) {
    return 'drawing';
  }

  if (lineArtResult && lineArtResult.isLineArt && lineArtResult.confidence > 0.85) return 'drawing';
  if (analysis.isAnime) return 'picture';
  if (analysis.entropy > 7.5) return 'photo';
  if (origW < 256 && origH < 256) return 'icon';
  return 'default';
}

function judgeQuality(analysis, metadata, mode) {
  const sharpness = analysis.sharpness || 0;
  const width = metadata.width || 0;
  const height = metadata.height || 0;
  const entropy = analysis.entropy || 0;
  const colorVariance = analysis.colorVariance || 0;
  const aspectRatio = height / Math.max(width, 1);
  const isVerticalStrip = aspectRatio > 2.5;

  const explicitMangaModes = ['manga', 'comic', 'strip', 'webtoon', 'manhwa', 'manhua'];
  const explicitPhotoModes = ['photo', 'normal'];

  let isMangaContent;
  if (explicitMangaModes.includes(mode)) {
    isMangaContent = true;
  } else if (explicitPhotoModes.includes(mode)) {
    isMangaContent = false;
  } else {
    isMangaContent = analysis.isMangaStrip || analysis.isMangaPage ||
                     analysis.isMangaWidePage;
  }

  const resolution = isVerticalStrip
    ? Math.min(width * 2, 3000)
    : Math.max(width, height);

  let score = 0;

  // Sharpness — relaxed thresholds (~30% lower)
  if (isMangaContent) {
    if (sharpness > 45) score += 35;
    else if (sharpness > 30) score += 30;
    else if (sharpness > 18) score += 22;
    else if (sharpness > 10) score += 14;
    else if (sharpness > 5) score += 7;
  } else {
    if (sharpness > 60) score += 35;
    else if (sharpness > 45) score += 28;
    else if (sharpness > 30) score += 21;
    else if (sharpness > 18) score += 14;
    else if (sharpness > 10) score += 7;
  }

  // Resolution — lowered thresholds
  if (resolution > 1600) score += 25;
  else if (resolution > 1200) score += 20;
  else if (resolution > 800) score += 15;
  else if (resolution > 500) score += 10;
  else if (resolution > 250) score += 5;

  // Entropy — widened acceptable ranges
  if (isMangaContent) {
    if (entropy > 2 && entropy < 7) score += 25;
    else if (entropy > 1.5 && entropy < 8) score += 20;
    else if (entropy > 1 && entropy < 8.5) score += 14;
    else score += 8;
  } else {
    if (entropy > 4 && entropy < 8) score += 25;
    else if (entropy > 3 && entropy < 9) score += 18;
    else if (entropy > 2 && entropy < 9.5) score += 12;
    else score += 5;
  }

  // Color variance — penalty removed, bonuses preserved
  if (isMangaContent && analysis.isGrayscale) {
    if (colorVariance < 15) score += 5;
  } else if (colorVariance > 80) {
    score += 15;
  } else if (colorVariance > 40) {
    score += 10;
  } else if (colorVariance > 20) {
    score += 5;
  }
  // No negative penalty for low color variance

  // Grade thresholds — shifted down for less punitive grading
  let grade, qualityAdjust;
  if (score >= 85) { grade = 'S'; qualityAdjust = -15; }
  else if (score >= 70) { grade = 'A'; qualityAdjust = -10; }
  else if (score >= 55) { grade = 'B'; qualityAdjust = -5; }
  else if (score >= 40) { grade = 'C'; qualityAdjust = 0; }
  else if (score >= 25) { grade = 'D'; qualityAdjust = 5; }
  else if (score >= 10) { grade = 'E'; qualityAdjust = 10; }
  else { grade = 'F'; qualityAdjust = 15; }

  return { grade, qualityAdjust, score };
}

async function detectHalftone(buffer, metadata, analysis) {
  if (analysis.colorVariance > 50) return { isHalftone: false, confidence: 0 };
  try {
    const width = metadata.width, height = metadata.height;
    const sampleSize = Math.min(200, Math.min(width, height));
    if (sampleSize < 32) return { isHalftone: false, confidence: 0 };

    const left = Math.floor((width - sampleSize) / 2);
    const top = Math.floor((height - sampleSize) / 2);

    const { data } = await sharp(buffer)
      .extract({ left, top, width: sampleSize, height: sampleSize })
      .grayscale()
      .raw()
      .toBuffer({ resolveWithObject: true });

    let microSum = 0, microCount = 0;
    for (let y = 0; y < sampleSize - 2; y += 3) {
      for (let x = 0; x < sampleSize - 2; x += 3) {
        let sum = 0, sumSq = 0;
        for (let dy = 0; dy < 3; dy++) {
          for (let dx = 0; dx < 3; dx++) {
            const v = data[(y + dy) * sampleSize + (x + dx)];
            sum += v; sumSq += v * v;
          }
        }
        const mean = sum / 9;
        microSum += sumSq / 9 - mean * mean;
        microCount++;
      }
    }
    const microVariance = microSum / Math.max(microCount, 1);

    let macroSum = 0, macroCount = 0;
    const macroSize = Math.min(24, sampleSize);
    for (let y = 0; y < sampleSize - macroSize + 1; y += macroSize) {
      for (let x = 0; x < sampleSize - macroSize + 1; x += macroSize) {
        let sum = 0, sumSq = 0, count = 0;
        for (let dy = 0; dy < macroSize; dy++) {
          for (let dx = 0; dx < macroSize; dx++) {
            const v = data[(y + dy) * sampleSize + (x + dx)];
            sum += v; sumSq += v * v; count++;
          }
        }
        const mean = sum / count;
        macroSum += sumSq / count - mean * mean;
        macroCount++;
      }
    }
    const macroVariance = macroSum / Math.max(macroCount, 1);
    const ratio = microVariance / Math.max(macroVariance, 1);
    const isHalftone = microVariance > 150 && macroVariance < 600 && ratio > 0.35;

    return { isHalftone, confidence: isHalftone ? 0.9 : 0.1, microVariance, macroVariance };
  } catch {
    return { isHalftone: false, confidence: 0 };
  }
}

async function detectLineArt(buffer, analysis) {
  if (!analysis.isGrayscale) return { isLineArt: false, confidence: 0 };
  try {
    const { data } = await sharp(buffer)
      .resize(256, 256, { fit: 'inside' })
      .grayscale()
      .raw()
      .toBuffer({ resolveWithObject: true });

    const hist = new Array(256).fill(0);
    for (let i = 0; i < data.length; i++) hist[data[i]]++;

    const total = data.length;
    let darkPeak = 0, lightPeak = 0;
    for (let i = 0; i <= 80; i++) darkPeak = Math.max(darkPeak, hist[i]);
    for (let i = 175; i <= 255; i++) lightPeak = Math.max(lightPeak, hist[i]);

    let middleSum = 0;
    for (let i = 100; i <= 155; i++) middleSum += hist[i];

    const darkRatio = darkPeak / total;
    const lightRatio = lightPeak / total;
    const middleRatio = middleSum / total;

    const isBimodal = darkRatio > 0.05 && lightRatio > 0.15 && middleRatio < 0.15;
    const isSharp = analysis.sharpness > 30;
    const isLineArt = isBimodal && isSharp;

    return { isLineArt, confidence: isLineArt ? 0.93 : 0.1, darkRatio, lightRatio, middleRatio };
  } catch {
    return { isLineArt: false, confidence: 0 };
  }
}

async function detectImageType(buffer, metadata) {
  const width = metadata.width || 0;
  const height = metadata.height || 0;

  let analysisWidth = width;
  let analysisHeight = height;

  if (width > ANALYSIS_MAX_DIM || height > ANALYSIS_MAX_DIM) {
    const scale = Math.min(
      ANALYSIS_MAX_DIM / Math.max(width, 1),
      ANALYSIS_MAX_DIM / Math.max(height, 1)
    );
    analysisWidth = Math.max(1, Math.round(width * scale));
    analysisHeight = Math.max(1, Math.round(height * scale));
  }

  const analysisPixels = analysisWidth * analysisHeight;
  if (analysisPixels > ANALYSIS_MAX_PIXELS) {
    const scale = Math.sqrt(ANALYSIS_MAX_PIXELS / analysisPixels);
    analysisWidth = Math.max(1, Math.round(analysisWidth * scale));
    analysisHeight = Math.max(1, Math.round(analysisHeight * scale));
  }

  let statsPipeline = sharp(buffer, { limitInputPixels: 0 });

  if (analysisWidth < width || analysisHeight < height) {
    statsPipeline = statsPipeline.resize(analysisWidth, analysisHeight, {
      fit: 'inside',
      withoutEnlargement: true
    });
  }

  const stats = await statsPipeline.stats();
  const { channels } = stats;

  let totalEntropy = 0, totalSharpness = 0, colorVariance = 0;
  let meanLuminance = 128, stdevLuminance = 50, maxLuminance = 255;

  if (channels && channels.length > 0) {
    meanLuminance = channels[0].mean || 128;
    stdevLuminance = channels[0].stdev || 50;
    maxLuminance = channels[0].max || 255;

    for (const ch of channels) {
      totalEntropy += ch.entropy || 0;
      totalSharpness += ch.sharpness || 0;
    }
    totalEntropy /= channels.length;
    totalSharpness /= channels.length;

    if (channels.length >= 3) {
      const rMean = channels[0].mean || 0;
      const gMean = channels[1].mean || 0;
      const bMean = channels[2].mean || 0;
      colorVariance = Math.abs(rMean - gMean) + Math.abs(gMean - bMean) + Math.abs(rMean - bMean);
    }
  }

  const isGrayscale = colorVariance < 15;
  const isHighContrast = totalEntropy > 6.5;
  const isColorful = colorVariance > 80;
  const aspectRatio = (metadata.height || 0) / Math.max(metadata.width || 1, 1);
  const isMangaStrip = aspectRatio > 2.5;
  const isMangaPage = aspectRatio > 1.2 && aspectRatio < 2.0 && isGrayscale;
  const isMangaWidePage = aspectRatio < 1.0 && aspectRatio > 0.4 && isGrayscale;
  const isAnime = isColorful && totalSharpness > 100;

  return {
    isGrayscale, isHighContrast, isColorful,
    isMangaStrip, isMangaPage, isMangaWidePage, isAnime,
    entropy: totalEntropy, sharpness: totalSharpness,
    colorVariance, aspectRatio,
    meanLuminance, stdevLuminance, maxLuminance
  };
}

function getViewportMaxDim(req) {
  const viewportWidth = parseInt(req.headers['sec-ch-viewport-width']) ||
    parseInt(req.headers['viewport-width']) || VIEWPORT_FALLBACK;
  const dpr = parseFloat(req.headers['sec-ch-dpr']) || parseFloat(req.headers['dpr']) || 1;
  const effectiveWidth = Math.round(viewportWidth * dpr);
  return Math.max(320, Math.min(effectiveWidth, MAX_OUTPUT_DIM));
}

function getChromaSubsampling(analysis, format) {
  // JPEG bandwidth mode: always 4:2:0 for maximum savings.
  // AVIF/WebP handle chroma internally and don't need this override.
  if (format === 'jpeg') return '4:2:0';
  if (analysis.isColorful && analysis.sharpness > 80) return '4:4:4';
  return '4:2:0';
}

function getAvifLimitScale(width, height, totalPixelCost) {
  let scale = 1;

  const w = Math.max(1, Number(width) || 1);
  const h = Math.max(1, Number(height) || 1);
  const maxDimension = Math.max(w, h);

  if (maxDimension > AVIF_MAX_DIMENSION) {
    scale = Math.min(scale, AVIF_MAX_DIMENSION / maxDimension);
  }

  if (totalPixelCost > AVIF_MAX_PIXELS) {
    scale = Math.min(scale, Math.sqrt(AVIF_MAX_PIXELS / totalPixelCost));
  }

  return scale;
}

function chooseOutputFormat(metadata, totalPixelCost) {
  const isAnimated = (metadata.pages || 1) > 1;
  const format = metadata.format;

  if (format === 'gif' || isAnimated) {
    return { format: 'webp', reason: 'animated_or_gif' };
  }

  const width = metadata.width || 0;
  const height = metadata.height || 0;

  if (width <= 0 || height <= 0) {
    return { format: 'avif', reason: 'unknown_dimensions_force_avif' };
  }

  // EXTREME DIMENSION HANDLING:
  // AVIF/WebP cannot physically encode dimensions > 16383px.
  // Instead of immediately forcing JPEG, calculate if resizing to fit 16383px
  // would result in acceptable dimensions (not a "blurry mess").
  if (width > AVIF_MAX_DIMENSION || height > AVIF_MAX_DIMENSION) {
    const scale = Math.min(AVIF_MAX_DIMENSION / Math.max(width, 1), AVIF_MAX_DIMENSION / Math.max(height, 1));
    const projectedMinDimension = Math.floor(Math.min(width, height) * scale);

    // If the resized short side is still >= MIN_AVIF_RESIZED_DIMENSION (default 600px),
    // it's safe to use AVIF. The later AVIF resize block will handle the actual scaling.
    if (projectedMinDimension >= MIN_AVIF_RESIZED_DIMENSION) {
      return { format: 'avif', reason: 'avif_extreme_resized_to_fit' };
    }

    // If resizing would make the short side too small (blurry mess), fallback to JPEG.
    return { format: 'jpeg', reason: 'extreme_dimension_force_jpeg' };
  }

  // SOFT FALLBACK: If AVIF resize would make the short side too small, use JPEG.
  const limitScale = getAvifLimitScale(width, height, totalPixelCost);

  if (ENABLE_AVIF_EXTREME_FALLBACK && limitScale < 1) {
    const minDimension = Math.min(width, height);
    const projectedMinDimension = Math.floor(minDimension * limitScale);

    if (projectedMinDimension < MIN_AVIF_RESIZED_DIMENSION) {
      return { format: 'jpeg', reason: 'avif_extreme_dimension_fallback' };
    }
  }

  if (limitScale >= 1) {
    return { format: 'avif', reason: 'avif_allowed' };
  }

  return { format: 'avif', reason: 'avif_resized_to_fit' };
}

// ============================================================
// FEATURE: Animated Frame Splicing (60fps -> <=15fps)
// Uses sharp's native array join syntax: sharp([buf1, buf2], { join: { animated: true } })
// ============================================================
const SPLICE_TARGET_FRAME_MS = safeInt(process.env.SPLICE_TARGET_FRAME_MS, 66);
const SPLICE_MAX_RAW_MB = safeInt(process.env.SPLICE_MAX_RAW_MB, 800);

function computeSpliceStride(delays, frames) {
  if (!Array.isArray(delays) || delays.length === 0 || frames < 2) return 1;
  const valid = delays.slice(0, frames).map((d) => Number(d)).filter((d) => Number.isFinite(d) && d > 0);
  if (valid.length === 0) return 1;
  const avgDelay = valid.reduce((sum, d) => sum + d, 0) / valid.length;
  if (avgDelay >= SPLICE_TARGET_FRAME_MS) return 1;
  return Math.max(2, Math.ceil(SPLICE_TARGET_FRAME_MS / avgDelay));
}

function patchWebpFrameDurations(buffer, delaysMs) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 16) return buffer;
  if (buffer.toString('ascii', 0, 4) !== 'RIFF') return buffer;
  if (buffer.toString('ascii', 8, 12) !== 'WEBP') return buffer;
  const out = Buffer.from(buffer);
  let offset = 12;
  let frameIndex = 0;
  while (offset + 8 <= out.length) {
    const fourcc = out.toString('ascii', offset, offset + 4);
    const chunkSize = out.readUInt32LE(offset + 4);
    const payloadStart = offset + 8;
    if (fourcc === 'ANMF' && payloadStart + 16 <= out.length && frameIndex < delaysMs.length) {
      const ms = Math.max(0, Math.min(0xFFFFFF, Math.round(Number(delaysMs[frameIndex]) || 0)));
      out.writeUIntLE(ms, payloadStart + 12, 3);
      frameIndex++;
    }
    if (chunkSize <= 0) break;
    offset = payloadStart + chunkSize + (chunkSize % 2);
  }
  return out;
}

async function spliceAnimatedFrames(buffer, metadata, log, reqId) {
  const frames = metadata.pages || 1;
  if (frames < Math.max(2, FRAME_DROP_THRESHOLD)) return null;

  const delays = Array.isArray(metadata.delay) ? metadata.delay : [];
  const stride = computeSpliceStride(delays, frames);
  if (stride < 2) return null;

  const width = metadata.width || 0;
  const pageHeight = metadata.pageHeight || metadata.height || 0;
  if (width <= 0 || pageHeight <= 0) return null;

  const keptIndices = [];
  for (let i = 0; i < frames; i += stride) keptIndices.push(i);
  if (keptIndices[keptIndices.length - 1] !== frames - 1) keptIndices.push(frames - 1);
  if (keptIndices.length < 2 || keptIndices.length >= frames) return null;

  const keptDelays = keptIndices.map((idx, k) => {
    const own = Number(delays[idx]) > 0 ? Number(delays[idx]) : SPLICE_TARGET_FRAME_MS;
    const isTrailingExtra = k === keptIndices.length - 1 && idx % stride !== 0;
    return isTrailingExtra ? own : own * stride;
  });

  const estimatedRawMB = Math.ceil((width * pageHeight * frames * 4) / (1024 * 1024));
  if (estimatedRawMB > SPLICE_MAX_RAW_MB) return null;

  // 1. Decode every frame once into a tall RGBA buffer.
  const { data, info } = await sharp(buffer, { animated: true, limitInputPixels: 0 })
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const channels = info.channels;
  const frameBytes = pageHeight * info.width * channels;
  if (frameBytes <= 0 || data.length < frameBytes * frames) return null;

  // 2. Extract kept frames and encode them to fast intermediate WebP buffers.
  const frameBuffers = [];
  for (let k = 0; k < keptIndices.length; k++) {
    const idx = keptIndices[k];
    const start = idx * frameBytes;
    const end = start + frameBytes;
    if (end > data.length) continue;
    
    const frameRaw = Buffer.from(data.subarray(start, end));
    const frameBuf = await sharp(frameRaw, {
      raw: { width: info.width, height: pageHeight, channels }
    }).webp({ lossless: false, quality: 80, effort: 0 }).toBuffer();
    
    frameBuffers.push(frameBuf);
  }

  if (frameBuffers.length !== keptIndices.length) return null;

  // 3. Join the frames using sharp's official array syntax
  const joinedBuffer = await sharp(frameBuffers, { join: { animated: true } })
    .webp({ lossless: false, quality: 80, effort: 0 })
    .toBuffer();

  const joinedMeta = await sharp(joinedBuffer).metadata();
  if ((joinedMeta.pages || 1) !== keptIndices.length) return null;

  // 4. Patch per-frame durations in the RIFF container
  const patched = patchWebpFrameDurations(joinedBuffer, keptDelays);

  // Aggressively drop references to massive buffers to hint the Garbage Collector
  // before the main pipeline checks RSS for SELF_RECYCLE.
  frameBuffers.length = 0; 

  if (ENABLE_ORACLE_LEDGER) metrics.frameDrops += (frames - keptIndices.length);
  log.info({ event: 'FRAME_SPLICE', reqId, framesIn: frames, framesOut: keptIndices.length, stride }, '[FRAME-SPLICE]');

  return patched;
}

// ============================================================
// MAIN COMPRESS FUNCTION
// ============================================================
export default async function compress(req, res, buffer, governor) {
  const memGov = governor || memoryGovernor;
  const reqId = req.id || 'unknown';
  const log = req.log || console;

  if (isShuttingDown) {
    res.status(503);
    res.setHeader('X-Guillotine-Grace', 'SHUTTING_DOWN');
    res.setHeader('Retry-After', '10');
    return Buffer.alloc(0);
  }

  // Adaptive concurrency admission
  if (!concurrencyGovernor.tryAdmit()) {
    res.status(503);
    res.setHeader('X-Adaptive-Concurrency', 'REJECTED');
    res.setHeader('X-Adaptive-Limit', String(concurrencyGovernor.getLimit()));
    res.setHeader('X-Adaptive-Active', String(concurrencyGovernor.getActive()));
    res.setHeader('Retry-After', '2');
    return Buffer.alloc(0);
  }

  res.setHeader('X-Adaptive-Concurrency', 'ADMITTED');
  res.setHeader('X-Adaptive-Limit', String(concurrencyGovernor.getLimit()));
  res.setHeader('X-Adaptive-Active', String(concurrencyGovernor.getActive()));

  activeRequests++;
  
  if (ENABLE_ORACLE_LEDGER) {
    metrics.totalRequests++;
    metrics.totalBytesIn += buffer.length;
  }

  const abortController = new AbortController();
  const { signal } = abortController;
  let clientDisconnected = false;
  const startedAt = Date.now();
  const watchdog = {};
  let phaseStart = Date.now();

  const initialDeadline = adaptiveDirector.getEncodeBudget({
  startedAt: req.proxyStartedAt || startedAt
});

const hardTimeoutMs = Math.max(
  250,
  Math.min(SHARP_HARD_TIMEOUT_MS, Math.floor(initialDeadline.remainingMs))
);

res.setHeader('X-Sharp-Hard-Timeout', String(hardTimeoutMs));

const timeoutHandle = setTimeout(() => {
  clientDisconnected = true;
  abortController.abort(new Error('SHARP_HARD_TIMEOUT'));
}, hardTimeoutMs);

  if (ENABLE_TIMEOUT_GUILLOTINE) {
    req.on('close', () => {
      if (!res.writableEnded) {
        clientDisconnected = true;
        abortController.abort(new Error('CLIENT_DISCONNECT'));
      }
    });
    res.on('close', () => {
      if (!res.writableEnded) {
        clientDisconnected = true;
        abortController.abort(new Error('RESPONSE_CLOSED'));
      }
    });
  }

  let totalPixelCost = 0;
let pixelsAdmitted = false;
let finalEncodeTime = 0;
let eventLoopLag;

  try {
    if (signal.aborted) {
      res.setHeader('X-Timeout-Guillotine', 'ABORTED');
      res.status(499);
      return Buffer.alloc(0);
    }

    let metadata = await sharp(buffer).metadata();
    const format = metadata.format;

    if (!format || format === 'raw') return buffer;

    const mode = req.opts?.mode || 'auto';
    const isPhotoMode = mode === 'photo' || mode === 'normal';
    const isMangaMode = mode === 'manga' || mode === 'comic';
    const isStripMode = ['strip', 'webtoon', 'manhwa', 'manhua'].includes(mode);
    const sharpenPreference = parseTriState(req.query?.sharpen, req.opts?.sharpen);

    let allowEnhancements = true;
    let allowLineArtFilters = allowEnhancements && !isPhotoMode;
    let allowPhotoFilters = allowEnhancements && !isMangaMode && !isStripMode;

    // Dimension overlord
   if (signal.aborted) {
      res.setHeader('X-Timeout-Guillotine', 'ABORTED');
      res.status(499);
      return Buffer.alloc(0);
    }

    let frames = metadata.pages || 1;
    let width = metadata.width || 0;
    let height = metadata.height || 0;

    // PRE-CALCULATION DIMENSION CAP
    // Prevents massive pixel cost calculations (e.g., 184MP for a 55k tall strip)
    // which would instantly trigger a 503 rejection from the memory governor.
    const PRE_CAP_MAX_DIM = 16383;
    if (width > PRE_CAP_MAX_DIM || height > PRE_CAP_MAX_DIM) {
      const scale = Math.min(PRE_CAP_MAX_DIM / Math.max(width, 1), PRE_CAP_MAX_DIM / Math.max(height, 1));
      width = Math.max(1, Math.round(width * scale));
      height = Math.max(1, Math.round(height * scale));
    }
    
    const metadataChannels = Math.max(
  1,
  Number(metadata.channels) || (metadata.hasAlpha ? 4 : 3)
);

const metadataDepth = String(metadata.depth || 'uchar').toLowerCase();

const bytesPerChannel =
  metadataDepth === 'float' || metadataDepth === 'double'
    ? 4
    : metadataDepth === 'ushort' || metadataDepth === 'uint'
      ? 2
      : 1;

const bytesPerPixel = Math.max(3, metadataChannels * bytesPerChannel);
const pixelWeight = Math.max(1, bytesPerPixel / 6);

totalPixelCost = Math.ceil(width * height * frames * pixelWeight);

    const formatDecision = chooseOutputFormat(metadata, totalPixelCost);
    const outputFormat = formatDecision.format;

    const avifLimitScale = outputFormat === 'avif'
      ? getAvifLimitScale(width, height, totalPixelCost)
      : 1;

    const avifLimitResize = avifLimitScale < 1;

    let logUrl = 'unknown';
 try {
   const u = new URL(req.opts?.url);
   logUrl = u.origin + '/*';
 } catch {}

    // Dimension overlord
    if (ENABLE_DIMENSION_OVERLORD) {
      const MAX_DIMENSION = 16383;
      const MAX_ASPECT_RATIO = 200;

      // 1. Check Dimensions
      if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
        log.info({
       event: 'DIMENSION_OVERLORD_RESIZE',
       reqId,
       url: logUrl,
       mode,
       width,
       height,
       reason: 'RESIZED_DIMENSION',
       maxDimension: MAX_DIMENSION
     });
        res.setHeader('X-Dimension-Overlord', 'RESIZED_DIMENSION');
      }

      // 2. Check Aspect Ratio
      const minDim = Math.max(1, Math.min(width, height));
      const maxDim = Math.max(width, height);
      const aspectRatio = maxDim / minDim;

      if (aspectRatio > MAX_ASPECT_RATIO) {
        log.info({
       event: 'DIMENSION_OVERLORD_ASPECT',
       reqId,
       url: logUrl,
       mode,
       width,
       height,
       aspectRatio: Number(aspectRatio.toFixed(2)),
       reason: 'ASPECT_EXCEEDED',
       maxAspectRatio: MAX_ASPECT_RATIO
     });
        res.setHeader('X-Dimension-Overlord', 'ASPECT_EXCEEDED');
      }
    }

    res.setHeader('X-Format-Reason', formatDecision.reason);

    log.info({
      event: 'FORMAT_DECISION',
      reqId,
      elapsedMs: Date.now() - (req.proxyStartedAt || startedAt),
      url: logUrl,
      format: outputFormat,
      reason: formatDecision.reason,
      width,
      height,
      frames,
      totalPixelCost,
      avifMaxPixels: AVIF_MAX_PIXELS,
      rssMB: memGov.getRssMB(),
      availableMB: memGov.getAvailableMB(),
      pixelBudget: memGov.getPixelBudget(),
      activePixelCost: memGov.getActivePixelCost()
    });
    
    const viewportCacheKey = req.opts?.maxDim > 0
  ? 'md-fixed'
  : `vp-${getViewportMaxDim(req)}`;

const paramFingerprint = [
  outputFormat, req.opts?.quality, req.opts?.grayscale,
  req.opts?.maxDim, req.opts?.maxStripWidth, mode,
  sharpenPreference === undefined ? '' : String(sharpenPreference),
  req.opts?.rotate || 0,
  viewportCacheKey
].join('|');

    const exactHash = await generateExactHash(buffer);
    const exactKey = exactHash ? `${exactHash}:${paramFingerprint}` : null;

    if (exactKey) {
      const exactHit = exactCache.get(exactKey);
      if (exactHit) {
        res.setHeader('X-Exact-Cache', 'HIT');
        res.setHeader('Content-Type', exactHit.contentType);
        if (exactHit.placeholder) res.setHeader('X-Placeholder', exactHit.placeholder);
        if (exactHit.grade) res.setHeader('X-Quality-Grade', exactHit.grade);
        if (exactHit.palette && exactHit.palette.length > 0) {
          res.setHeader('X-Palette', exactHit.palette.join(','));
        }
        if (ENABLE_ORACLE_LEDGER) {
          metrics.cacheHits++;
          metrics.totalBytesOut += exactHit.buffer.length;
          metrics.totalBytesSaved += buffer.length - exactHit.buffer.length;
        }
        return exactHit.buffer;
    }
  }

    if ((metadata.pages || 1) > 1 && ENABLE_FRAME_DROPPING) {
    if (signal.aborted) { res.setHeader('X-Timeout-Guillotine', 'ABORTED'); res.status(499); return Buffer.alloc(0); }
    try {
      const preSpliceFrames = metadata.pages || 1;
      const splicedBuffer = await spliceAnimatedFrames(buffer, metadata, log, reqId);
      if (splicedBuffer && splicedBuffer.length > 0) {
        buffer = splicedBuffer;
        metadata = await sharp(buffer).metadata();
        frames = metadata.pages || 1;
        totalPixelCost = Math.ceil(width * height * frames * pixelWeight);
        res.setHeader('X-Frame-Splice', `${preSpliceFrames}->${frames}`);
      }
    } catch (spliceErr) {
      log.warn({ reqId, error: String(spliceErr?.message || spliceErr).split('?')[0] }, '[FRAME-SPLICE-FALLBACK]');
    }
    }

  let thumbResult = null;
    if ((ENABLE_VOID_WATCHER || ENABLE_PALETTE || ENABLE_PLACEHOLDER) && allowEnhancements) {
      phaseStart = Date.now();
      thumbResult = await generatePlaceholderAndPalette(buffer);
      watchdog.palette = Date.now() - phaseStart;
      if (ENABLE_VOID_WATCHER && thumbResult.isVoid) {
        res.setHeader('X-Void', 'TRUE');
        res.setHeader('Content-Type', `image/${format}`);
        if (ENABLE_ORACLE_LEDGER) {
          metrics.voidDetections++;
          metrics.totalBytesOut += buffer.length;
        }
        return buffer;
      }
    }

    if (signal.aborted) {
      res.setHeader('X-Timeout-Guillotine', 'ABORTED');
      res.status(499);
      return Buffer.alloc(0);
    }

    if (ENABLE_ORACLE_LEDGER) metrics.cacheMisses++;

    if (!memGov.admitPixels(totalPixelCost)) {
  adaptiveDirector.recordRejection({
    format: outputFormat,
    width,
    height,
    frames,
    pixelCost: totalPixelCost
  });

  res.status(503);
  res.setHeader('X-Memory-Governor', 'REJECTED');
  res.setHeader('Retry-After', '5');
  if (ENABLE_ORACLE_LEDGER) metrics.memoryRejections++;
  return Buffer.alloc(0);
}

pixelsAdmitted = true;

res.setHeader('X-Memory-Governor', 'ADMITTED');
    res.setHeader('X-Pixel-Cost', String(totalPixelCost));
    
    // FEATURE: CPU/event-loop pressure governor
eventLoopLag = await measureEventLoopLag();
    const cpuPressure = eventLoopLag > CPU_LAG_THRESHOLD_MS;

    res.setHeader('X-CPU-Lag', `${eventLoopLag.toFixed(2)}ms`);
    res.setHeader('X-CPU-Pressure', cpuPressure ? 'TRUE' : 'FALSE');

    if (cpuPressure) {
      allowEnhancements = false;
      allowLineArtFilters = false;
      allowPhotoFilters = false;
      if (ENABLE_ORACLE_LEDGER) metrics.cpuPressureEvents++;
    }

    if (signal.aborted) {
      res.setHeader('X-Timeout-Guillotine', 'ABORTED');
      res.status(499);
      return Buffer.alloc(0);
    }

    try {
      let analysis;
      if (cpuPressure) {
        // Under CPU pressure, skip expensive sharp().stats() analysis.
        // All enhancement features are already disabled, so neutral defaults are safe.
        analysis = {
          isGrayscale: false, isHighContrast: false, isColorful: false,
          isMangaStrip: false, isMangaPage: false, isMangaWidePage: false, isAnime: false,
          entropy: 0, sharpness: 0, colorVariance: 0, aspectRatio: 1,
          meanLuminance: 128, stdevLuminance: 50, maxLuminance: 255
        };
      } else {
        phaseStart = Date.now();
        analysis = await detectImageType(buffer, metadata);
        watchdog.stats = Date.now() - phaseStart;
      }
      const viewportMaxDim = getViewportMaxDim(req);

      let placeholder = thumbResult ? thumbResult.placeholder : null;
      let palette = thumbResult ? thumbResult.palette : [];

      if (ENABLE_PALETTE && palette.length > 0) {
        res.setHeader('X-Palette', palette.join(','));
      }

      // FEATURE: Text/OCR Region Preservation detection
      const isTextHeavy = ENABLE_TEXT_PRESERVATION && isTextHeavyImage(analysis);
      if (isTextHeavy) {
        res.setHeader('X-Text-Preservation', 'ACTIVE');
        if (ENABLE_ORACLE_LEDGER) metrics.textPreservations++;
      }

      // FEATURE: HDR/wide-gamut detection
      const hdrInfo = detectHDRCharacteristics(metadata);
      const needsHDRConversion = ENABLE_HDR_SAFE_CONVERSION &&
        (hdrInfo.isWideGamut || hdrInfo.isPotentialHDR);

      if (needsHDRConversion) {
        res.setHeader('X-HDR-Conversion', 'ACTIVE');
        res.setHeader('X-HDR-Space', hdrInfo.space);
        if (ENABLE_ORACLE_LEDGER) metrics.hdrConversions++;
      }

      // FEATURE: Smart Alpha Channel Trimming detection
      let alphaBounds = null;
      if (ENABLE_ALPHA_TRIM && metadata.hasAlpha && !cpuPressure) {
        phaseStart = Date.now();
        alphaBounds = await detectAlphaBounds(buffer, metadata);
        watchdog.alpha = Date.now() - phaseStart;
        if (alphaBounds) {
          res.setHeader('X-Alpha-Trim', 'ACTIVE');
          res.setHeader('X-Alpha-Trim-Pad', `${alphaBounds.padLeft},${alphaBounds.padTop},${alphaBounds.padRight},${alphaBounds.padBottom}`);
          if (ENABLE_ORACLE_LEDGER) metrics.alphaTrims++;
        }
      }

       // Deskew — only for grayscale/scanned document content.
   // Photos, anime, and colorful content produce false positives.
   let skewAngle = 0;
   if (ENABLE_DESKEW && allowEnhancements && analysis.isGrayscale && !isMangaMode && !isStripMode && !analysis.isMangaStrip && !analysis.isMangaPage && !analysis.isMangaWidePage) {
     phaseStart = Date.now();
     skewAngle = await detectSkew(buffer);
     watchdog.skew = Date.now() - phaseStart;
        if (skewAngle !== 0) {
          res.setHeader('X-Deskew-Angle', skewAngle.toFixed(2));
          recordMetric('deskew');
        }
      }

      if (signal.aborted) {
        res.setHeader('X-Timeout-Guillotine', 'ABORTED');
        res.status(499);
        return Buffer.alloc(0);
      }

      // Judge quality — skip for animated content (GIF / animated WebP).
   // Animated images have inherently low sharpness, limited palettes,
   // and low entropy. Running the judge on them produces unfairly low
   // grades (D/E/F) that inflate quality and bloat the output WebP.
   let judgeResult = null;
   const isAnimatedForJudge = (metadata.pages || 1) > 1 || metadata.format === 'gif';
   if (ENABLE_JUDGE && allowEnhancements && !isAnimatedForJudge) {
     judgeResult = judgeQuality(analysis, metadata, req.opts?.mode);
   }

      // Halftone / moire detection
      let halftoneResult = null;
      if (ENABLE_MOIRE && allowEnhancements && !isStripMode) {
        phaseStart = Date.now();
        halftoneResult = await detectHalftone(buffer, metadata, analysis);
        watchdog.halftone = Date.now() - phaseStart;
      }

      // Line art detection
      let lineArtResult = null;
      if (ENABLE_LINE_DENOISE && allowLineArtFilters) {
        phaseStart = Date.now();
        lineArtResult = await detectLineArt(buffer, analysis);
        watchdog.line = Date.now() - phaseStart;
      }

      // Alpha sentinel
      let alphaStrippable = false;
      const isAnimated = metadata.pages > 1;

      if (ENABLE_ALPHA_SENTINEL && metadata.hasAlpha && !isAnimated) {
        alphaStrippable = await detectAlphaStrippable(buffer, metadata);
        if (alphaStrippable) {
          res.setHeader('X-Alpha-Sentinel', 'STRIPPED');
          recordMetric('alphaSentinel');
        }
      }

      if (signal.aborted) {
        res.setHeader('X-Timeout-Guillotine', 'ABORTED');
        res.status(499);
        return Buffer.alloc(0);
      }

      // ADAPTIVE DIRECTOR v3
      const budget = adaptiveDirector.getEncodeBudget({ startedAt: req.proxyStartedAt || startedAt });
      const adaptivePressure = computeAdaptivePressure({
        eventLoopLag,
        activeEncodes,
        encodeLimit: concurrencyGovernor.getEncodeLimit(),
        memoryUnderPressure: memoryGovernor.isUnderPressure()
      });

      const adaptive = adaptiveDirector.chooseEffort({
      format: outputFormat,
      width,
      height,
      frames,
      pixelCost: totalPixelCost,
      inputFormat: req.opts?.originType || 'image/jpeg',
      budgetMs: budget.budgetMs,
      pressure: adaptivePressure
    });

    let effort = adaptive.effort;
    const predictedEncodeMs = adaptive.predictedMs;
    const risk = adaptive.risk;
    const bucket = adaptive.bucket;

      // FEATURE: CPU pressure reduces effort
      if (cpuPressure) {
        effort = Math.max(2, effort - 2);
        res.setHeader('X-CPU-Effort-Reduced', 'TRUE');
      }

      res.setHeader('X-Adaptive-Bucket', adaptive.bucket);
      res.setHeader('X-Adaptive-Budget', String(budget.budgetMs));
      res.setHeader('X-Adaptive-Predicted', String(adaptive.predictedMs));
      res.setHeader('X-Adaptive-Effort', String(effort));
      res.setHeader('X-Adaptive-Risk', adaptive.risk);
      res.setHeader('X-Adaptive-Pressure', String(Math.round(adaptivePressure * 100) / 100));

      // Quality
      let quality = req.opts?.quality ?? (parseInt(req.query.q || req.query.quality) || DEFAULT_QUALITY);

      if (judgeResult) {
        quality = Math.max(10, Math.min(95, quality + judgeResult.qualityAdjust));
      }

      // FEATURE: Text/OCR quality boost
      if (isTextHeavy) {
        quality = Math.min(95, quality + TEXT_QUALITY_BOOST);
        res.setHeader('X-Text-Quality-Boost', `+${TEXT_QUALITY_BOOST}`);
      }

      // AVIF limit resize quality boost
      if (outputFormat === 'avif' && avifLimitResize) {
        quality = Math.min(63, quality + AVIF_LIMIT_RESIZE_QUALITY_BOOST);
        res.setHeader('X-AVIF-Resize-Quality-Boost', `+${AVIF_LIMIT_RESIZE_QUALITY_BOOST}`);
      }
      
      const frameCount = metadata.pages || 1;
      if (isAnimated && frameCount > MAX_ANIMATION_FRAMES) {
        res.setHeader('X-Frame-Cap', 'EXCEEDED_ATTEMPTING_ENCODE');
      }

      // Banding exorcist check
      let bandingExorcistActive = false;
      if (ENABLE_BANDING_EXORCIST && allowPhotoFilters && !isAnimated) {
        if (analysis.stdevLuminance > 20 && analysis.stdevLuminance < 50 && analysis.sharpness < 30) {
          bandingExorcistActive = true;
          recordMetric('bandingExorcist');
        }
      }

      if (signal.aborted) {
        res.setHeader('X-Timeout-Guillotine', 'ABORTED');
        res.status(499);
        return Buffer.alloc(0);
      }

      // Build Sharp pipeline
      const sharpPixelLimit = Math.max(1, totalPixelCost, memGov.getPixelBudget());

let pipeline = sharp(buffer, {
  animated: isAnimated,
  limitInputPixels: sharpPixelLimit
});

      // FEATURE: Safe Metadata Exceptions
      if (ENABLE_SAFE_METADATA && ENABLE_METADATA_REAPER) {
        // Keep orientation but strip GPS/sensitive EXIF
        // Sharp's rotate() normalizes orientation from EXIF
        pipeline = pipeline.rotate();
        // Do NOT pass withMetadata() to avoid leaking GPS/device data
        recordMetric('metadataReaper');
      } else if (ENABLE_METADATA_REAPER) {
        pipeline = pipeline.rotate();
        recordMetric('metadataReaper');
      } else {
        pipeline = pipeline.withMetadata({ orientation: metadata.orientation || 1 });
      }

      pipeline = pipeline.toColourspace('srgb');

      // FEATURE: HDR/wide-gamut safe downconversion
      if (needsHDRConversion) {
        if (hdrInfo.isPotentialHDR) {
          // Approximate HDR to SDR tone mapping via gamma
          pipeline = pipeline.gamma(1.0 / 2.2);
          res.setHeader('X-HDR-ToneMap', 'GAMMA_2.2');
        }
        // Wide gamut is handled by toColourspace('srgb') above
        res.setHeader('X-HDR-Source-Space', hdrInfo.space);
      }

      if (req.opts?.rotate) {
        pipeline = pipeline.rotate(req.opts.rotate);
      }

      // Grayscale
      const userExplicitlyWantsColor = req.opts?.grayscale === false;
      const userExplicitlyWantsBW = req.opts?.grayscale === true;

      if (FORCE_GRAYSCALE || userExplicitlyWantsBW ||
          (!userExplicitlyWantsColor && analysis.isGrayscale && !analysis.isColorful)) {
        pipeline = pipeline.grayscale();
      }

      // Luminance fix
      if (ENABLE_LUMINANCE && allowPhotoFilters && !isAnimated) {
        if (analysis.meanLuminance < 85 && analysis.stdevLuminance < 50) {
          pipeline = pipeline.gamma(1.4);
          res.setHeader('X-Luminance-Fix', 'UNDEREXPOSED');
          recordMetric('luminanceFix');
        } else if (isPhotoMode && analysis.meanLuminance > 210 && analysis.stdevLuminance < 50) {
          pipeline = pipeline.linear(0.7, 0);
          res.setHeader('X-Luminance-Fix', 'OVEREXPOSED');
          res.setHeader('X-Luminance-Method', 'LINEAR_DARKEN');
          recordMetric('luminanceFix');
        }
      }

      // Ghost stripper
      if (ENABLE_GHOST_STRIPPER && allowPhotoFilters && !isAnimated) {
        if (analysis.meanLuminance > 150 && analysis.maxLuminance > 200 && analysis.maxLuminance < 253) {
          const stretch = 255 / analysis.maxLuminance;
          pipeline = pipeline.linear(stretch, 0);
          res.setHeader('X-Ghost-Stripper', `STRETCHED`);
          recordMetric('ghostStripper');
        }
      }

      // Deskew rotation (negative angle corrects the detected tilt)
      if (ENABLE_DESKEW && allowEnhancements && !isMangaMode && skewAngle !== 0) {
        pipeline = pipeline.rotate(-skewAngle, {
          background: analysis.isGrayscale
            ? { r: 255, g: 255, b: 255 }
            : { r: 255, g: 255, b: 255, alpha: 0 },
        });
      }
      
      // FEATURE: Smart Alpha Channel Trimming - apply extract
      if (alphaBounds) {
        pipeline = pipeline.extract({
          left: alphaBounds.left,
          top: alphaBounds.top,
          width: alphaBounds.width,
          height: alphaBounds.height
        });
      }

      // Moire removal
      if (allowEnhancements && halftoneResult && halftoneResult.isHalftone && halftoneResult.confidence > 0.85) {
        pipeline = pipeline.median(3);
        res.setHeader('X-Moire-Removed', 'true');
        recordMetric('moireRemoval');
      }

      // Line denoise
      if (allowLineArtFilters && lineArtResult && lineArtResult.isLineArt && lineArtResult.confidence > 0.85) {
        pipeline = pipeline.median(3);
        if (sharpenPreference !== false) {
          pipeline = pipeline.sharpen({ sigma: 0.6, flat: 3.0, jagged: 1.5 });
        }
        res.setHeader('X-Line-Denoise', 'true');
        recordMetric('lineDenoise');
      }

      // --- AVIF EFFORT SAFETY FOR MASSIVE STRIPS ---
// Prevents Vercel 60s hard-kills on tall manhwa strips by reducing libaom CPU effort
const adaptiveCeiling = adaptiveDirector.getEffortCeiling({
  format: outputFormat,
  bucket: adaptive.bucket
});

let safeEncodeEffort = Math.min(effort, adaptiveCeiling);

if (safeEncodeEffort !== effort) {
  res.setHeader('X-Adaptive-Ceiling-Applied', String(safeEncodeEffort));
}

// --- COMPRESS OR SHRINK WATCHDOG ---
// If AdaptiveDirector predicts budget_exceeded, force minimum effort.
// If still over budget, shrink dimensions to fit.
let watchdogScaleFactor = 1;

if (adaptive.risk === 'budget_exceeded') {
  safeEncodeEffort = 0;
  res.setHeader('X-Watchdog', 'EFFORT_FORCED_0');

  const effortZeroPrediction = adaptiveDirector.predictEncodeMs({
      format: outputFormat,
      width,
      height,
      frames,
      pixelCost: totalPixelCost,
      inputFormat: req.opts?.originType || 'image/jpeg',
      effort: 0,
      pressure: adaptivePressure
    });
  
  if (effortZeroPrediction > budget.budgetMs) {
    // Still over budget. Shrink dimensions to fit.
    watchdogScaleFactor = Math.sqrt(budget.budgetMs / effortZeroPrediction);
    
    // ANIMATED PENALTY: Force extra shrink for animations to guarantee <60s encode
    if (isAnimated) {
      watchdogScaleFactor *= 0.7; // 30% additional shrink
    }
    
    watchdogScaleFactor = Math.max(0.25, Math.min(watchdogScaleFactor, 1));
    res.setHeader('X-Watchdog', `SHRINK_${Math.round(watchdogScaleFactor * 100)}%`);
  }
}

      // Resize
let targetWidth = null;
let targetHeight = null;

const origW = alphaBounds ? alphaBounds.width : width;
const origH = alphaBounds ? alphaBounds.height : height;

const baseW = Math.max(1, Math.round(origW * watchdogScaleFactor));
const baseH = Math.max(1, Math.round(origH * watchdogScaleFactor));

const effectiveStripWidth = (req.opts?.maxStripWidth > 0)
  ? req.opts.maxStripWidth
  : MAX_STRIP_WIDTH;

const effectiveMaxDim = (req.opts?.maxDim > 0)
  ? req.opts.maxDim
  : viewportMaxDim;

if (analysis.isMangaStrip) {
  if (effectiveStripWidth > 0 && baseW > effectiveStripWidth) {
    targetWidth = effectiveStripWidth;
  } else if (watchdogScaleFactor < 1) {
    targetWidth = baseW;
    targetHeight = baseH;
  }
} else {
  if (effectiveMaxDim > 0 && (baseW > effectiveMaxDim || baseH > effectiveMaxDim)) {
    const scale = Math.min(effectiveMaxDim / baseW, effectiveMaxDim / baseH);
    targetWidth = Math.round(baseW * scale);
    targetHeight = Math.round(baseH * scale);
  } else if (watchdogScaleFactor < 1) {
    targetWidth = baseW;
    targetHeight = baseH;
  }
}

      // Layout prophet headers
      if (ENABLE_LAYOUT_PROPHET) {
  let outW = baseW;
  let outH = baseH;

  if (targetWidth && targetHeight) {
    outW = targetWidth;
    outH = targetHeight;
  } else if (targetWidth) {
    outW = targetWidth;
    outH = Math.round(baseH * (targetWidth / baseW));
  } else if (targetHeight) {
    outH = targetHeight;
    outW = Math.round(baseW * (targetHeight / baseH));
  }

  res.setHeader('X-Output-Width', String(outW));
  res.setHeader('X-Output-Height', String(outH));
  res.setHeader('X-Aspect-Ratio', (outW / Math.max(outH, 1)).toFixed(4));
  res.setHeader('X-Orientation', outW > outH ? 'landscape' : outH > outW ? 'portrait' : 'square');
}

      // Forced AVIF resize: handle pixel cost, dimension limits, and aspect ratio.
      if (outputFormat === 'avif') {
        let scaleFactor = 1;
        let resizeReason = '';

        // Pixel cost resize.
        if (totalPixelCost > AVIF_MAX_PIXELS) {
          scaleFactor = Math.sqrt(AVIF_MAX_PIXELS / totalPixelCost);
          resizeReason = 'PIXEL_COST';
        }

        // Dimension limit resize.
        if (origW > AVIF_MAX_DIMENSION || origH > AVIF_MAX_DIMENSION) {
          const dimScale = Math.min(
            AVIF_MAX_DIMENSION / origW,
            AVIF_MAX_DIMENSION / origH
          );
          if (dimScale < scaleFactor) {
            scaleFactor = dimScale;
            resizeReason = 'DIMENSION';
          }
        }
        
        // Aspect ratio passthrough: extreme ratios cannot be fixed without cropping.
        const currentAspectRatio = Math.max(origW / Math.max(origH, 1), origH / Math.max(origW, 1));
        if (currentAspectRatio > AVIF_MAX_ASPECT_RATIO) {
          res.setHeader('X-AVIF-Aspect-Passthrough', `RATIO_${Number(currentAspectRatio.toFixed(1))}`);
        }

        if (scaleFactor < 1) {
          const currentW = targetWidth || baseW;
          const currentH = targetHeight || baseH;

          targetWidth = Math.round(currentW * scaleFactor);
          targetHeight = Math.round(currentH * scaleFactor);

          res.setHeader('X-AVIF-Resize-To-Fit', resizeReason);
        }
      }

   const HARD_MAX_DIM = 16383;
   if (targetWidth || targetHeight || width > HARD_MAX_DIM || height > HARD_MAX_DIM) {
     const resizeW = targetWidth || HARD_MAX_DIM;
     const resizeH = targetHeight || HARD_MAX_DIM;
     
     pipeline = pipeline.resize(resizeW, resizeH, {
       fit: 'inside',
       withoutEnlargement: true,
       kernel: sharp.kernel.lanczos3,
     });
   }
      // Sharpen - boosted for text images and AVIF limit resizes
      const contentWantsSharpen =
        sharpenPreference !== false &&
        (
          isTextHeavy ||
          ((analysis.sharpness < 50 || analysis.isMangaWidePage) && !analysis.isMangaStrip) ||
          (avifLimitResize && analysis.isMangaStrip)
        );

      if (allowEnhancements && (sharpenPreference === true || contentWantsSharpen)) {
        const alreadySharpened = allowLineArtFilters && lineArtResult &&
          lineArtResult.isLineArt && lineArtResult.confidence > 0.85;

        if (!alreadySharpened) {
          const sharpenSigma = isTextHeavy ? 1.0 : 0.8;
          const sharpenFlat = isTextHeavy ? 3.0 : 2.0;
          const sharpenJagged = isTextHeavy ? 2.0 : 1.0;

          pipeline = pipeline.sharpen({
            sigma: sharpenSigma,
            flat: sharpenFlat,
            jagged: sharpenJagged,
          });

          res.setHeader('X-Sharpen', isTextHeavy ? 'BOOSTED' : 'APPLIED');

          if (isTextHeavy) {
            res.setHeader('X-Text-Sharpen', 'BOOSTED');
          }
        }
       } 

      // Alpha handling
      if (alphaStrippable) {
        pipeline = pipeline.flatten({ background: { r: 255, g: 255, b: 255 } });
      } else if (STRIP_ALPHA && outputFormat === 'jpeg') {
        pipeline = pipeline.flatten({ background: { r: 255, g: 255, b: 255 } });
      }

      // Banding exorcist
      if (bandingExorcistActive) {
        const noiseTile = await getNoiseTile();
        pipeline = pipeline.composite([{ input: noiseTile, tile: true, blend: 'over' }]);
        res.setHeader('X-Banding-Exorcist', 'ACTIVE');
      }

      if (signal.aborted) {
        res.setHeader('X-Timeout-Guillotine', 'ABORTED');
        res.status(499);
        return Buffer.alloc(0);
      }

      // -----------------------------------
      // --------------------------------------------
      // ENCODE
   let outputBuffer;
   let contentType;
   phaseStart = Date.now();
      const encodeStart = Date.now();
      let encodeTime = 0;
      // Encode-level adaptive admission with waiting queue
      const encodeWaitStartedAt = Date.now();
      const remainingHardMs = Math.max(0, hardTimeoutMs - (encodeWaitStartedAt - startedAt));
      const encodeWaitTimeoutMs = Math.max(
        250,
        Math.min(
          Math.max(250, Number(budget.budgetMs) - 500),
          Math.max(250, remainingHardMs - 500)
        )
      );

      try {
        const encodeAdmission = await concurrencyGovernor.waitForEncodeSlot({
          timeoutMs: encodeWaitTimeoutMs,
          signal
        });

        res.setHeader('X-Adaptive-Encode-Wait', `${encodeAdmission.waitedMs}ms`);
        res.setHeader('X-Adaptive-Encode-Queued', encodeAdmission.queued ? 'TRUE' : 'FALSE');
      } catch (waitErr) {
        if (waitErr?.code !== 'ENCODE_WAIT_ABORTED') {
          adaptiveDirector.recordRejection({
            format: outputFormat,
            width,
            height,
            frames,
            pixelCost: totalPixelCost
          });
        }

        if (waitErr?.code === 'ENCODE_WAIT_ABORTED') {
          const abortMessage = signal?.reason?.message || '';

          if (!res.headersSent) {
            res.status(abortMessage === 'SHARP_HARD_TIMEOUT' ? 504 : 499);
          }

          res.setHeader('X-Timeout-Guillotine', 'ABORTED');
        } else if (waitErr?.code === 'ENCODE_WAIT_TIMEOUT') {
          if (!res.headersSent) res.status(504);
          res.setHeader('X-Adaptive-Concurrency', 'ENCODE_WAIT_TIMEOUT');
        } else {
          if (!res.headersSent) res.status(503);
          res.setHeader('X-Adaptive-Concurrency', 'ENCODE_QUEUE_REJECTED');
          res.setHeader('Retry-After', '3');
        }

        res.setHeader('X-Adaptive-Encode-Limit', String(concurrencyGovernor.getEncodeLimit()));
        return Buffer.alloc(0);
      }

      res.setHeader('X-Adaptive-Encode-Active', String(concurrencyGovernor.getStatus().encode.active));

      activeEncodes++;

      try {
        if (ENABLE_TIMEOUT_GUILLOTINE) {
          const onAbort = () => { pipeline.destroy(); };
          signal.addEventListener('abort', onAbort, { once: true });

          try {
            switch (outputFormat) {
              case 'avif':
                outputBuffer = await pipeline.avif({
                  quality: Math.min(quality, 63),
                  effort: Math.min(Math.max(safeEncodeEffort, 0), 9),
                  chromaSubsampling: getChromaSubsampling(analysis, 'avif'),
                }).toBuffer();
                contentType = 'image/avif';
                break;
              case 'webp':
                outputBuffer = await pipeline.webp({
                  quality,
                  effort: Math.min(Math.max(safeEncodeEffort, 0), 6),
                  smartSubsample: true,
                  preset: getWebpPreset(analysis, lineArtResult, origW, origH),
                  minSize: parseTriState(req.query?.minsize, false),
                }).toBuffer();
                contentType = 'image/webp';
                break;
              case 'jpeg':
              default:
                const isExtremeJpeg = width > AVIF_MAX_DIMENSION || height > AVIF_MAX_DIMENSION;

                // Bandwidth-optimized JPEG quality:
                // Manga/line art tolerates lower quality than photos.
                // Reduce by 2 for manga strips to squeeze more bytes.
                let jpegQuality = isExtremeJpeg ? Math.min(quality, 75) : quality;
                if (!isExtremeJpeg && (analysis.isMangaStrip || analysis.isMangaPage || analysis.isMangaWidePage || analysis.isGrayscale)) {
                  jpegQuality = Math.max(1, jpegQuality - 2);
                }

                const jpegChroma = getChromaSubsampling(analysis, 'jpeg');

                outputBuffer = await pipeline.jpeg({
                  quality: jpegQuality,
                  progressive: true,
                  mozjpeg: true,
                  chromaSubsampling: jpegChroma,
                  trellisQuantisation: true,
                  overshootDeringing: true,
                  optimiseScans: true,
                }).toBuffer();
                contentType = 'image/jpeg';
                if (isExtremeJpeg) {
                  res.setHeader('X-Extreme-JPEG', 'OPTIMIZED');
                }
                res.setHeader('X-Jpeg-Bandwidth-Mode', 'ACTIVE');
                break;
            }
          } finally {
            signal.removeEventListener('abort', onAbort);
          }
        } else {
          switch (outputFormat) {
            case 'avif':
              outputBuffer = await pipeline.avif({
                quality: Math.min(quality, 63),
                effort: Math.min(Math.max(safeEncodeEffort, 0), 9),
                chromaSubsampling: getChromaSubsampling(analysis),
              }).toBuffer();
              contentType = 'image/avif';
              break;
            case 'webp':
              outputBuffer = await pipeline.webp({
                quality,
                effort: Math.min(Math.max(safeEncodeEffort, 0), 6),
                smartSubsample: true,
                preset: getWebpPreset(analysis, lineArtResult, origW, origH),
                  minSize: parseTriState(req.query?.minsize, false),
                }).toBuffer();
              contentType = 'image/webp';
              break;
            case 'jpeg':
              default:
                const isExtremeJpeg = width > AVIF_MAX_DIMENSION || height > AVIF_MAX_DIMENSION;

                let jpegQuality = isExtremeJpeg ? Math.min(quality, 75) : quality;
                if (!isExtremeJpeg && (analysis.isMangaStrip || analysis.isMangaPage || analysis.isMangaWidePage || analysis.isGrayscale)) {
                  jpegQuality = Math.max(1, jpegQuality - 2);
                }

                const jpegChroma = getChromaSubsampling(analysis, 'jpeg');

                outputBuffer = await pipeline.jpeg({
                  quality: jpegQuality,
                  progressive: true,
                  mozjpeg: true,
                  chromaSubsampling: jpegChroma,
                  trellisQuantisation: true,
                  overshootDeringing: true,
                  optimiseScans: true,
                }).toBuffer();
                contentType = 'image/jpeg';
                if (isExtremeJpeg) {
                  res.setHeader('X-Extreme-JPEG', 'OPTIMIZED');
                }
                res.setHeader('X-Jpeg-Bandwidth-Mode', 'ACTIVE');
                break;
          }
        }
      } finally {
     const encodeEnd = Date.now();
     encodeTime = encodeEnd - encodeStart;
     finalEncodeTime = encodeTime;
     watchdog.encode = encodeTime;

     activeEncodes--;
     concurrencyGovernor.releaseEncode({
       success: !clientDisconnected && !signal.aborted,
       timedOut: signal.aborted,
       encodeTimeMs: encodeTime
     });
   }

   const finalRecordedEffort = typeof safeEncodeEffort !== 'undefined' ? safeEncodeEffort : effort;

   const calibrationPredictedMs = adaptiveDirector.predictEncodeMs({
     format: outputFormat,
     width: origW,
     height: origH,
     frames,
     pixelCost: totalPixelCost,
     inputFormat: req.opts?.originType || 'image/jpeg',
     effort: finalRecordedEffort,
     pressure: adaptivePressure
   });

   adaptiveDirector.recordEncode({
     format: outputFormat,
     width: origW,
     height: origH,
     frames,
     pixelCost: totalPixelCost,
     effort: finalRecordedEffort,
     encodeMs: encodeTime,
     predictedMs: calibrationPredictedMs,
     pressure: adaptivePressure,
     success: !clientDisconnected && !signal.aborted,
     timedOut: signal.aborted
   });

      res.setHeader('X-Processing-Time', `${encodeTime}ms`);
      res.setHeader('X-Adaptive-Actual', `${encodeTime}ms`);
      res.setHeader('X-Adaptive-Error', calibrationPredictedMs > 0
        ? `${Math.round(((encodeTime - calibrationPredictedMs) / calibrationPredictedMs) * 100)}%`
        : 'N/A');
      res.setHeader('X-Encode-Effort', String(finalRecordedEffort));

      // Request-level release is handled exactly once in the outer finally.

      if (ENABLE_ORACLE_LEDGER) {
        metrics.formatCounts[outputFormat] = (metrics.formatCounts[outputFormat] || 0) + 1;
        metrics.totalEncodeTime += encodeTime;
        metrics.encodeCount++;
      }

      if (signal.aborted) {
        res.setHeader('X-Timeout-Guillotine', 'ABORTED');
        res.status(499);
        return Buffer.alloc(0);
      }

      // Encoding verifier
      if (ENABLE_ENCODING_VERIFIER) {
        if (!verifyOutput(outputBuffer, outputFormat)) {
          res.setHeader('X-Encoding-Verifier', 'FAILED');
          res.status(404);
          if (ENABLE_ORACLE_LEDGER) metrics.encodingFailures++;
          return Buffer.alloc(0);
        }
        res.setHeader('X-Encoding-Verifier', 'PASSED');
      }

      // If compressed is larger than original, return original
      if (outputBuffer.length >= buffer.length) {
        res.setHeader('X-Compression', 'SKIPPED');
        res.setHeader('Content-Type', `image/${format}`);
        if (placeholder) res.setHeader('X-Placeholder', placeholder);
        if (judgeResult) res.setHeader('X-Quality-Grade', judgeResult.grade);
        if (palette.length > 0) res.setHeader('X-Palette', palette.join(','));
        if (ENABLE_ORACLE_LEDGER) metrics.totalBytesOut += buffer.length;
        return buffer;
      }

      if (ENABLE_ORACLE_LEDGER) {
        metrics.totalBytesOut += outputBuffer.length;
        metrics.totalBytesSaved += buffer.length - outputBuffer.length;
      }

      const bytesSaved = buffer.length - outputBuffer.length;
      res.setHeader('X-Bytes-Saved', `${(bytesSaved / 1024).toFixed(1)}KB`);

      // Cache set
      const cacheEntry = {
        buffer: outputBuffer,
        contentType,
        placeholder,
        grade: judgeResult ? judgeResult.grade : null,
        palette,
      };
      if (exactKey) exactCache.set(exactKey, cacheEntry);

      res.setHeader('X-Perceptual-Cache', 'REMOVED');
      res.setHeader('X-Encode-Quality', String(quality));
      res.setHeader('X-Encode-Dims', `${targetWidth || origW}x${targetHeight || origH}`);
      res.setHeader('Content-Type', contentType);
      res.setHeader('X-Compression-Ratio', ((1 - outputBuffer.length / buffer.length) * 100).toFixed(1) + '%');

      if (placeholder) res.setHeader('X-Placeholder', placeholder);
      if (judgeResult) {
        res.setHeader('X-Quality-Grade', judgeResult.grade);
        res.setHeader('X-Quality-Score', String(judgeResult.score));
      }

      res.setHeader('X-Image-Type', analysis.isMangaStrip ? 'manga-strip' :
        analysis.isMangaWidePage ? 'manga-wide' :
        analysis.isMangaPage ? 'manga-page' :
        analysis.isAnime ? 'anime' :
        analysis.isGrayscale ? 'grayscale' : 'photo');
      
      const getHeaderStr = (name) => {
        const v = res.getHeader(name);
        return Array.isArray(v) ? String(v[0] ?? '') : String(v ?? '');
      };

      const enhancementState = {
        deskew: getHeaderStr('X-Deskew-Angle') || false,
        moire: getHeaderStr('X-Moire-Removed') === 'true',
        lineDenoise: getHeaderStr('X-Line-Denoise') === 'true',
        luminanceFix: getHeaderStr('X-Luminance-Fix') || false,
        ghostStripper: getHeaderStr('X-Ghost-Stripper') || false,
        bandingExorcist: getHeaderStr('X-Banding-Exorcist') === 'ACTIVE',
        alphaSentinel: getHeaderStr('X-Alpha-Sentinel') === 'STRIPPED',
        sharpen: getHeaderStr('X-Sharpen') || false,
        textPreservation: getHeaderStr('X-Text-Preservation') === 'ACTIVE',
        textSharpen: getHeaderStr('X-Text-Sharpen') === 'BOOSTED',
        hdrConversion: getHeaderStr('X-HDR-Conversion') === 'ACTIVE',
        hdrToneMap: getHeaderStr('X-HDR-ToneMap') || false,
        alphaTrim: getHeaderStr('X-Alpha-Trim') === 'ACTIVE',
        alphaTrimPad: getHeaderStr('X-Alpha-Trim-Pad') || false,
        frameDrop: getHeaderStr('X-Frame-Drop') || false,
        metadataReaper: ENABLE_METADATA_REAPER,
        safeMetadata: ENABLE_SAFE_METADATA,

        // Structural transformations
        grayscale: Boolean(
          FORCE_GRAYSCALE ||
          userExplicitlyWantsBW ||
          (!userExplicitlyWantsColor && analysis.isGrayscale && !analysis.isColorful)
        ),

        resize: (targetWidth || targetHeight)
          ? `${targetWidth || origW}x${targetHeight || origH}`
          : false,

        colorspaceNormalization: 'srgb',

        alphaFlatten: Boolean(
          metadata.hasAlpha &&
          (alphaStrippable || (STRIP_ALPHA && outputFormat === 'jpeg'))
        ),

        manualRotation: req.opts?.rotate ? String(req.opts.rotate) : false
      };

      const appliedEnhancements = Object.keys(enhancementState).filter((key) => {
        const value = enhancementState[key];
        return value === true || (typeof value === 'string' && value.length > 0 && value !== 'false');
      });
      
      const concurrencyStatus = concurrencyGovernor.getStatus();
   log.info({
     event: 'COMPRESS',
        reqId,
        activeRequests,
        activeEncodes,
        concurrency: {
          enabled: concurrencyStatus.enabled,
          requestLimit: concurrencyStatus.limit,
          requestActive: concurrencyStatus.active,
          requestReason: concurrencyStatus.lastReason,
          encodeLimit: concurrencyStatus.encode.limit,
          encodeActive: concurrencyStatus.encode.active,
          encodeReason: concurrencyStatus.encode.lastReason
        },
        url: (() => {
          try {
            const u = new URL(req.opts?.url);
            return u.origin + '/*';
          } catch {
            return 'unknown';
          }
        })(),
        format: outputFormat,
        quality,
        effort,
        grade: judgeResult ? judgeResult.grade : null,
        score: judgeResult ? judgeResult.score : null,
        inputBytes: buffer.length,
        outputBytes: outputBuffer.length,
        savedBytes: buffer.length - outputBuffer.length,
        compressionRatio: ((1 - outputBuffer.length / buffer.length) * 100).toFixed(1) + '%',
        encodeTimeMs: encodeTime,
        inputDims: `${width}x${height}`,
        outputDims: `${targetWidth || origW}x${targetHeight || origH}`,
        pixelCost: totalPixelCost,
        imageType: analysis.isMangaStrip ? 'manga-strip' :
          analysis.isMangaWidePage ? 'manga-wide' :
          analysis.isMangaPage ? 'manga-page' :
          analysis.isAnime ? 'anime' :
          analysis.isGrayscale ? 'grayscale' : 'photo',
        frames,
        mode,
        cpuPressure,
        cpuLagMs: Math.round(eventLoopLag * 100) / 100,
        cpuPressureDisabledEnhancements: cpuPressure,
       enhancements: enhancementState,
       appliedEnhancements,
       watchdog,
       totalElapsedMs: Date.now() - (req.proxyStartedAt || startedAt),
       adaptive: {
         bucket: adaptive.bucket,
         budgetMs: budget.budgetMs,
         predictedMs: calibrationPredictedMs,
         actualMs: encodeTime,
         errorPercent: calibrationPredictedMs > 0
           ? Math.round(((encodeTime - calibrationPredictedMs) / calibrationPredictedMs) * 100)
           : 0,
         risk: adaptive.risk,
         pressure: adaptivePressure,
         eventLoopLagMs: eventLoopLag,
         activeEncodes,
         memoryPressure: memoryGovernor.isUnderPressure(),
         watchdogScaleFactor: watchdogScaleFactor,
         finalEffort: safeEncodeEffort
       }
     });
      
      res.setHeader('X-Watchdog', Object.entries(watchdog).map(([k,v])=>`${k}:${v}ms`).join(','));
      res.setHeader('Content-Length', outputBuffer.length);
      return outputBuffer;

    } finally {
      if (pixelsAdmitted) {
        memGov.releasePixels(totalPixelCost);
        pixelsAdmitted = false;
      }
    }
  } catch (err) {
    if (clientDisconnected || signal.aborted) {
      const abortMessage = signal.reason?.message || '';

      log.warn({
        reqId,
        encodeTimeMs: Date.now() - startedAt,
        pixelCost: totalPixelCost,
        abortReason: abortMessage || 'UNKNOWN'
      }, '[CLIENT_DISCONNECT] Client aborted connection');

      if (!res.headersSent) {
        res.status(abortMessage === 'SHARP_HARD_TIMEOUT' ? 504 : 499);
      }

      res.setHeader('X-Timeout-Guillotine', 'ABORTED');
      return Buffer.alloc(0);
    }

    const safeMessage = err?.message ? String(err.message).split('?')[0] : 'Unknown compress error';
    const tmpFreeMB = await getTmpFreeMB();

    log.error({
      reqId,
      watchdog,
      error: safeMessage,
      tmpFreeMB,
      rssMB: memGov.getRssMB()
    }, '[WATCHDOG_FATAL]');
    res.setHeader('X-Compression', 'FAILED');

    if (ENABLE_ORACLE_LEDGER) {
      metrics.encodingFailures++;
      metrics.totalBytesOut += buffer.length;
    }

    if (!res.headersSent && !res.writableEnded) {
      const fallbackType = req.opts?.originType || 'image/jpeg';
      const safeType = fallbackType.startsWith('image/') ? fallbackType : `image/${fallbackType}`;
      res.setHeader('Content-Type', safeType);
      res.end(buffer);
    } else {
      req.socket?.destroy();
    }
    return null;
  } finally {
    if (timeoutHandle) clearTimeout(timeoutHandle);

    if (pixelsAdmitted) {
      memGov.releasePixels(totalPixelCost);
      pixelsAdmitted = false;
    }

    activeRequests--;
    concurrencyGovernor.release({
      success: !clientDisconnected && !signal.aborted,
      timedOut: signal.aborted,
      encodeTimeMs: finalEncodeTime,
      eventLoopLag: typeof eventLoopLag === 'number' ? eventLoopLag : 0
    });

    // ANTI-OOM SELF-RECYCLE:
    // If RSS is dangerously high and no other requests are active,
    // gracefully exit to force Vercel to spin up a fresh instance.
    // This prevents the OS OOM-killer from severing active TCP sockets.
    const currentRssMB = memGov.getRssMB();
    if (activeRequests === 0 && currentRssMB > 950) {
      log.warn({ event: 'SELF_RECYCLE', rssMB: currentRssMB }, '[SELF-RECYCLE] High RSS with empty queue, exiting gracefully');
      process.exit(0);
    }
  }
}
