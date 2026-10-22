// src/adaptiveDirector.js

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
    tiny: 6,
    normal: 4,
    portrait: 6,
    strip: 5,
    extreme_strip: 3,
    animated: 5
  },
  webp: {
    tiny: 60,
    normal: 6,
    portrait: 4,
    strip: 4,
    extreme_strip: 3,
    animated: 4
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

const AVIF_EFFORT_FACTOR = [
  0.55, // 0
  0.65, // 1
  0.75, // 2
  0.85, // 3
  1.00, // 4 baseline
  1.15, // 5
  1.35, // 6
  1.60, // 7
  1.90, // 8
  2.30  // 9
];

const WEBP_EFFORT_FACTOR = [
  0.60, // 0
  0.70, // 1
  0.80, // 2
  0.90, // 3
  1.00, // 4 baseline
  1.15, // 5
  1.35  // 6
];

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

export function predictEncodeMs({
  format = 'avif',
  width = 0,
  height = 0,
  frames = 1,
  pixelCost = 0,
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
  const base = learned ?? defaultBase;

  const baseline = BASELINE_EFFORT[format] ?? 0;
  const factor = effortFactor(format, effort) / effortFactor(format, baseline);

  const pressureMultiplier = Number.isFinite(pressure) && pressure > 0 ? pressure : 1;
  const failurePenalty = statsEntry ? Math.min(0.5, (statsEntry.failures || 0) * 0.05) : 0;

  // Fixed overhead: AVIF/WebP encoding has setup cost that doesn't scale with MP.
  // Without this, small images are massively underestimated at high effort.
  const overheadMs = format === 'avif' ? 4000 : format === 'webp' ? 800 : 200;
  const effortOverhead = overheadMs * (factor - 1);

  const predicted = (mp * base * factor + overheadMs + effortOverhead) * (pressureMultiplier + failurePenalty);

  return Math.max(1, Math.round(predicted));
}

export function chooseEffort({
  format = 'avif',
  width = 0,
  height = 0,
  frames = 1,
  pixelCost = 0,
  budgetMs = MIN_ENCODE_MS,
  pressure = 1,
  maxEffort,
  minEffort = 0
} = {}) {
  const maxFormatEffort = FORMAT_MAX_EFFORT[format] ?? 0;
  const bucket = classifyGeometry({ width, height, frames, pixelCost });
  const ceiling = getEffortCeiling({ format, bucket });

  const max = Math.min(
    Number.isFinite(maxEffort) ? maxEffort : maxFormatEffort,
    maxFormatEffort,
    ceiling
  );

  const min = Math.max(0, Math.min(Number.isFinite(minEffort) ? minEffort : 0, max));

  let chosenEffort = min;
  let predictedMs = predictEncodeMs({
    format,
    width,
    height,
    frames,
    pixelCost,
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
    entries
  };
}

export function resetStats() {
  stats.clear();
}

export default {
  classifyGeometry,
  getEffortCeiling,
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
