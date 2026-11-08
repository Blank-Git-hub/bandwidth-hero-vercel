function safeInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const TOTAL_DEADLINE_MS = safeInt(process.env.ADAPTIVE_TOTAL_DEADLINE_MS, 55000);
const SAFETY_MARGIN_MS = safeInt(process.env.ADAPTIVE_SAFETY_MARGIN_MS, 5000);
const MIN_ENCODE_MS = safeInt(process.env.ADAPTIVE_MIN_ENCODE_MS, 4000);
const ROLLING_WINDOW = safeInt(process.env.ADAPTIVE_ROLLING_WINDOW, 20);
const MIN_SAMPLES = safeInt(process.env.ADAPTIVE_MIN_SAMPLES, 3);

const EFFORT_CEILINGS = {
  avif: {
    tiny: 9,
    normal: 9,
    portrait: 9,
    strip: 9,
    extreme_strip: 9,
    animated: 9
  },
  webp: {
    tiny: 6,
    normal: 6,
    portrait: 6,
    strip: 6,
    extreme_strip: 6,
    animated: 6
  },
  jpeg: {
    tiny: 0,
    normal: 0,
    portrait: 0,
    strip: 0,
    extreme_strip: 0,
    animated: 0
  }
};

// Real-world libaom exponential scaling
const AVIF_EFFORT_FACTOR = [
  0.30, // 0
  0.40, // 1
  0.55, // 2
  0.75, // 3
  1.00, // 4 baseline
  1.60, // 5
  2.80, // 6
  5.00, // 7
  9.00, // 8
  16.00 // 9
];

// Real-world libwebp scaling
const WEBP_EFFORT_FACTOR = [
  0.40, // 0
  0.55, // 1
  0.70, // 2
  0.85, // 3
  1.00, // 4 baseline
  1.50, // 5
  2.50  // 6
];

// Decode cost multipliers (relative to JPEG)
const DECODE_COST_FACTOR = {
  'image/jpeg': 1.0,
  'image/webp': 1.8,
  'image/png': 2.5,
  'image/avif': 4.5,
  'image/jxl': 6.0,
  'image/gif': 2.0,
  'default': 2.0
};

const DEFAULT_MS_PER_MP = {
  avif: {
    tiny: 450,
    normal: 900,
    portrait: 1000,
    strip: 1700,
    extreme_strip: 2600,
    animated: 1300
  },
  webp: {
tiny: 100,
normal: 180,
portrait: 200,
strip: 320,
extreme_strip: 480,
animated: 300
},
  jpeg: {
    tiny: 80,
    normal: 120,
    portrait: 130,
    strip: 180,
    extreme_strip: 240,
    animated: 160
  }
};

const FORMAT_MAX_EFFORT = {
  avif: 9,
  webp: 6,
  jpeg: 0
};

const BASELINE_EFFORT = {
  avif: 4,
  webp: 4,
  jpeg: 0
};

const stats = new Map();
const calibration = new Map();

function statsKey(format, bucket) {
  return `${format}:${bucket}`;
}

function clampInt(value, min, max) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return min;
  return Math.min(Math.max(n, min), max);
}

function average(arr) {
  if (!arr.length) return 0;
  return arr.reduce((sum, item) => sum + item, 0) / arr.length;
}

function effortFactor(format, effort) {
  if (format === 'avif') {
    const safe = clampInt(effort, 0, AVIF_EFFORT_FACTOR.length - 1);
    return AVIF_EFFORT_FACTOR[safe];
  }

  if (format === 'webp') {
    const safe = clampInt(effort, 0, WEBP_EFFORT_FACTOR.length - 1);
    return WEBP_EFFORT_FACTOR[safe];
  }

  return 1;
}

export function getEffortCeiling({ format = 'avif', bucket = 'normal' } = {}) {
  return EFFORT_CEILINGS[format]?.[bucket] ?? FORMAT_MAX_EFFORT[format] ?? 0;
}

export function getEffortLimitByMp({
  format = 'avif',
  width = 0,
  height = 0,
  frames = 1,
  pixelCost = 0
} = {}) {
  const px = Number(pixelCost) || (Number(width) || 1) * (Number(height) || 1) * (frames || 1);
  const mp = px / 1_000_000;

  if (format === 'avif') {
    if (mp <= 1) return 6;
    if (mp <= 3) return 4;
    if (mp <= 6) return 3;
    if (mp <= 10) return 3;
    if (mp <= 18) return 3;
    return 2;
  }

  if (format === 'webp') {
    if (mp <= 2) return 6;
    if (mp <= 8) return 5;
    if (mp <= 20) return 4;
    return 2;
  }

  return 4;
}

export function classifyGeometry({ width = 0, height = 0, frames = 1, pixelCost = 0 } = {}) {
  if ((frames || 1) > 1) {
    return 'animated';
  }

  const w = Math.max(1, Number(width) || 1);
  const h = Math.max(1, Number(height) || 1);
  const aspect = Math.max(w, h) / Math.max(Math.min(w, h), 1);

  const px = Number(pixelCost) || (w * h * (frames || 1));

  if (px < 1_000_000) {
    return 'tiny';
  }

  if (aspect > 8) {
    return 'extreme_strip';
  }

  if (aspect > 4) {
    return 'strip';
  }

  if (aspect > 1.5) {
    return 'portrait';
  }

  return 'normal';
}

export function getEncodeBudget({
  startedAt,
  now = Date.now(),
  totalDeadlineMs = TOTAL_DEADLINE_MS,
  safetyMarginMs = SAFETY_MARGIN_MS,
  minEncodeMs = MIN_ENCODE_MS
} = {}) {
  const start = Number(startedAt) || now;
  const elapsed = Math.max(0, now - start);
  const remaining = totalDeadlineMs - elapsed - safetyMarginMs;

  return {
    totalDeadlineMs,
    elapsedMs: elapsed,
    safetyMarginMs,
    remainingMs: remaining,
    budgetMs: Math.max(minEncodeMs, Math.floor(remaining)),
    enough: remaining >= minEncodeMs
  };
}

function getStatsEntry(format, bucket) {
  return stats.get(statsKey(format, bucket)) || null;
}

function getAverageNormalized(format, bucket) {
  const entry = getStatsEntry(format, bucket);

  if (!entry || entry.samples.length < MIN_SAMPLES) {
    return null;
  }

  return average(entry.samples.map(sample => sample.normalizedMsPerMp));
}

function getFormatAverage(format) {
  const samples = [];

  for (const [key, entry] of stats) {
    if (!key.startsWith(`${format}:`)) {
      continue;
    }

    samples.push(...entry.samples);
  }

  if (samples.length < MIN_SAMPLES) {
    return null;
  }

  return average(samples.map(sample => sample.normalizedMsPerMp));
}

function getSampleCount(format, bucket) {
  const bucketEntry = getStatsEntry(format, bucket);

  if (bucketEntry && bucketEntry.samples.length >= MIN_SAMPLES) {
    return bucketEntry.samples.length;
  }

  let count = 0;

  for (const [key, entry] of stats) {
    if (!key.startsWith(`${format}:`)) {
      continue;
    }

    count += entry.samples.length;
  }

  return count;
}

function getCalibration(format) {
  return calibration.get(format) || { factor: 1, samples: 0 };
}

function updateCalibration(format, predictedMs, actualMs, pressure) {
  if (!Number.isFinite(predictedMs) || predictedMs <= 0) return;
  if (!Number.isFinite(actualMs) || actualMs <= 0) return;

  // Do not learn from pressured requests.
  if (Number.isFinite(pressure) && pressure > 1.15) return;

  const correction = Math.min(4, Math.max(0.25, actualMs / predictedMs));
  const cal = calibration.get(format) || { factor: 1, samples: 0 };

  // Learn fast at first, then dampen to prevent oscillation.
  const alpha = cal.samples < 5 ? 0.35 : 0.15;

  cal.factor *= Math.pow(correction, alpha);
  cal.factor = Math.min(3, Math.max(0.33, cal.factor));
  cal.samples += 1;

  calibration.set(format, cal);
}

export function predictEncodeMs({
  format = 'avif',
  width = 0,
  height = 0,
  frames = 1,
  pixelCost = 0,
  inputFormat = 'image/jpeg',
  effort = 0,
  pressure = 1
} = {}) {
  const bucket = classifyGeometry({ width, height, frames, pixelCost });

  const px = Number(pixelCost) || (Number(width) || 1) * (Number(height) || 1) * (frames || 1);
  const mp = Math.max(0.1, px / 1_000_000);

  const statsEntry = getStatsEntry(format, bucket);

  const learned =
    getAverageNormalized(format, bucket) ??
    getFormatAverage(format);

  const defaultBase = DEFAULT_MS_PER_MP[format]?.[bucket] ?? 1000;

  // Vercel Node 24 + libvips microVMs are highly optimized. 
// The legacy 3.5x penalty causes the Watchdog to falsely panic and crush resolutions.
const SERVERLESS_PENALTY = 1.5;
  const priorBase = defaultBase * SERVERLESS_PENALTY;

  // Blend learned stats gradually to prevent sudden prediction jumps.
  const sampleCount = getSampleCount(format, bucket);

  let base;
  if (!learned) {
    base = priorBase;
  } else {
    const trust = Math.min(1, sampleCount / 10);
    base = (learned * trust) + (priorBase * (1 - trust));
  }

  const baseline = BASELINE_EFFORT[format] ?? 0;
  const factor = effortFactor(format, effort) / effortFactor(format, baseline);

  const pressureMultiplier = Number.isFinite(pressure) && pressure > 0 ? pressure : 1;
  const failurePenalty = statsEntry ? Math.min(0.5, (statsEntry.failures || 0) * 0.05) : 0;

  // Decode time.
  const decodeFactor = DECODE_COST_FACTOR[inputFormat] || DECODE_COST_FACTOR['default'];
  const decodeMs = mp * 150 * decodeFactor;

  // Encode time.
  const encodeMs = mp * base * factor;

  // Fixed encoder overhead.
  const baseOverhead = format === 'avif' ? 2500 : format === 'webp' ? 600 : 150;
  const overheadMs = baseOverhead + (mp * 100);

  // Live calibration from previous real encodes.
  const cal = getCalibration(format);
  const calibrationFactor = Number.isFinite(cal.factor) && cal.factor > 0 ? cal.factor : 1;

  const predicted =
    (decodeMs + encodeMs + overheadMs) *
    (pressureMultiplier + failurePenalty) *
    calibrationFactor;

  return Math.max(1, Math.round(predicted));
}

export function chooseEffort({
  format = 'avif',
  width = 0,
  height = 0,
  frames = 1,
  pixelCost = 0,
  inputFormat = 'image/jpeg',
  budgetMs = MIN_ENCODE_MS,
  pressure = 1,
  maxEffort,
  minEffort = 0
} = {}) {
  const maxFormatEffort = FORMAT_MAX_EFFORT[format] ?? 0;
  const bucket = classifyGeometry({ width, height, frames, pixelCost });
  
  // MP ceiling as starting reference. Time budget governs the final selection.
  const mpCeiling = getEffortLimitByMp({ format, width, height, frames, pixelCost });
  const max = Math.min(
    Number.isFinite(maxEffort) ? maxEffort : maxFormatEffort,
    maxFormatEffort,
    mpCeiling
  );

  const min = Math.max(0, Math.min(Number.isFinite(minEffort) ? minEffort : 0, max));

  let chosenEffort = min;
  let predictedMs = predictEncodeMs({
      format,
      width,
      height,
      frames,
      pixelCost,
      inputFormat,
      effort: min,
      pressure
    });

  for (let effort = max; effort >= min; effort--) {
    const predicted = predictEncodeMs({
      format,
      width,
      height,
      frames,
      pixelCost,
      inputFormat,
      effort,
      pressure
    });

    if (predicted <= budgetMs) {
      chosenEffort = effort;
      predictedMs = predicted;
      break;
    }
  }

  return {
    format,
    bucket,
    effort: chosenEffort,
    predictedMs,
    budgetMs: Number(budgetMs),
    risk: predictedMs <= budgetMs ? 'ok' : 'budget_exceeded'
  };
}

export function recordEncode({
  format,
  width = 0,
  height = 0,
  frames = 1,
  pixelCost = 0,
  effort = 0,
  encodeMs = 0,
  predictedMs = 0,
  pressure = 1,
  success = true,
  timedOut = false
} = {}) {
  if (!Object.prototype.hasOwnProperty.call(FORMAT_MAX_EFFORT, format)) {
    return;
  }

  const bucket = classifyGeometry({ width, height, frames, pixelCost });
  const key = statsKey(format, bucket);

  const entry = stats.get(key) || {
    samples: [],
    timeouts: 0,
    failures: 0
  };

  if (timedOut) {
    entry.timeouts++;
  }

  if (!success) {
    entry.failures++;
  }

  if (Number.isFinite(encodeMs) && encodeMs > 0) {
    if (success && !timedOut) {
      updateCalibration(format, predictedMs, encodeMs, pressure);
    }

    const px = Number(pixelCost) || (Number(width) || 1) * (Number(height) || 1) * (frames || 1);
    const mp = Math.max(0.1, px / 1_000_000);

    const msPerMp = encodeMs / mp;
    const baseline = BASELINE_EFFORT[format] ?? 0;

    const normalizedMsPerMp =
      msPerMp *
      (effortFactor(format, baseline) / effortFactor(format, effort));

    entry.samples.push({
      at: Date.now(),
      effort,
      encodeMs,
      mp,
      msPerMp,
      normalizedMsPerMp,
      timedOut,
      success
    });

    while (entry.samples.length > ROLLING_WINDOW) {
      entry.samples.shift();
    }
  }

  stats.set(key, entry);
}

export function recordRejection({
  format = 'avif',
  width = 0,
  height = 0,
  frames = 1,
  pixelCost = 0
} = {}) {
  if (!Object.prototype.hasOwnProperty.call(FORMAT_MAX_EFFORT, format)) {
    return;
  }

  const bucket = classifyGeometry({ width, height, frames, pixelCost });
  const key = statsKey(format, bucket);

  const entry = stats.get(key) || {
    samples: [],
    timeouts: 0,
    failures: 0
  };

  entry.failures = Math.min(1000, entry.failures + 1);

  stats.set(key, entry);
}

export function getStatus() {
  const entries = {};

  for (const [key, entry] of stats) {
    entries[key] = {
      samples: entry.samples.length,
      timeouts: entry.timeouts,
      failures: entry.failures,
      avgNormalizedMsPerMp: average(entry.samples.map(sample => sample.normalizedMsPerMp))
    };
  }

  return {
    config: {
      TOTAL_DEADLINE_MS,
      SAFETY_MARGIN_MS,
      MIN_ENCODE_MS,
      ROLLING_WINDOW,
      MIN_SAMPLES
    },
    entries,
    calibration: Object.fromEntries(calibration)
  };
}

export function resetStats() {
  stats.clear();
  calibration.clear();
}

export default {
  classifyGeometry,
  getEffortCeiling,
  getEffortLimitByMp,
  getEncodeBudget,
  predictEncodeMs,
  chooseEffort,
  recordEncode,
  recordRejection,
  getStatus,
  resetStats,
  TOTAL_DEADLINE_MS,
  SAFETY_MARGIN_MS,
  MIN_ENCODE_MS,
  ROLLING_WINDOW,
  MIN_SAMPLES,
  FORMAT_MAX_EFFORT
};
