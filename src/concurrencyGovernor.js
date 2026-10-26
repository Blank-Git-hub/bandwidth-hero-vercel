import memoryGovernor from './memoryGovernor.js';

function safeInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function safeFloat(value, fallback) {
  const n = parseFloat(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const ENABLED = ['1', 'true', 'yes', 'on'].includes(
  String(process.env.ENABLE_ADAPTIVE_CONCURRENCY || 'true').trim().toLowerCase()
);

const MIN_LIMIT = safeInt(process.env.ADAPTIVE_CONCURRENCY_MIN, 1);
const INITIAL_LIMIT = safeInt(process.env.ADAPTIVE_CONCURRENCY_INITIAL, 4);
const MAX_LIMIT = safeInt(process.env.ADAPTIVE_CONCURRENCY_MAX, 8);
const EVENT_LOOP_MAX_MS = safeInt(process.env.ADAPTIVE_EVENT_LOOP_MAX_MS, 80);
const RSS_SAFE_OFFSET_MB = safeInt(process.env.ADAPTIVE_RSS_SAFE_OFFSET_MB, 150);
const COOLDOWN_MS = safeInt(process.env.ADAPTIVE_COOLDOWN_MS, 5000);
const DECREASE_FACTOR = safeFloat(process.env.ADAPTIVE_DECREASE_FACTOR, 0.5);
const HEALTHY_WINDOW = safeInt(process.env.ADAPTIVE_HEALTHY_WINDOW, 5);

let limit = Math.min(Math.max(INITIAL_LIMIT, MIN_LIMIT), MAX_LIMIT);
let active = 0;
let lastAdjustAt = 0;
let lastReason = 'init';
let healthyStreak = 0;

// Encode-level adaptive concurrency
const ENCODE_MIN_LIMIT = safeInt(process.env.ADAPTIVE_ENCODE_MIN, 1);
const ENCODE_INITIAL_LIMIT = safeInt(process.env.ADAPTIVE_ENCODE_INITIAL, 1);
const ENCODE_MAX_LIMIT = safeInt(process.env.ADAPTIVE_ENCODE_MAX, 1);
const ENCODE_COOLDOWN_MS = safeInt(process.env.ADAPTIVE_ENCODE_COOLDOWN_MS, 8000);
const ENCODE_TIME_THRESHOLD_MS = safeInt(process.env.ADAPTIVE_ENCODE_TIME_MS, 15000);
const ENCODE_WAIT_QUEUE_MAX = safeInt(process.env.ADAPTIVE_ENCODE_WAIT_QUEUE_MAX, 32);

let encodeLimit = Math.min(Math.max(ENCODE_INITIAL_LIMIT, ENCODE_MIN_LIMIT), ENCODE_MAX_LIMIT);
let encodeActive = 0;
let encodeLastAdjustAt = 0;
let encodeLastReason = 'init';
let encodeHealthyStreak = 0;
const encodeWaiters = [];

const recentEncodeTimes = [];
const MAX_SAMPLES = 10;

function getLimit() {
  return limit;
}

function getEncodeLimit() {
  return encodeLimit;
}

function getActive() {
  return active;
}

function getLastReason() {
  return lastReason;
}

function getEnabled() {
  return ENABLED;
}

function tryAdmit() {
  if (!ENABLED) return true;

  if (active >= limit) {
    return false;
  }

  active++;
  return true;
}

function release(outcome = {}) {
  if (active > 0) active--;

  if (!ENABLED) return;

  const {
    success = true,
    timedOut = false,
    encodeTimeMs = 0,
    eventLoopLag = 0
  } = outcome;

  if (encodeTimeMs > 0) {
    recentEncodeTimes.push(encodeTimeMs);
    if (recentEncodeTimes.length > MAX_SAMPLES) {
      recentEncodeTimes.shift();
    }
  }

  const now = Date.now();
  if (now - lastAdjustAt < COOLDOWN_MS) return;

  const rss = memoryGovernor.getRssMB();
  const ceiling = memoryGovernor.MEMORY_CEILING_MB;
  const rssSafe = ceiling - RSS_SAFE_OFFSET_MB;
  const underPressure = memoryGovernor.isUnderPressure();
  const critical = memoryGovernor.isCritical();
  const highLag = eventLoopLag > EVENT_LOOP_MAX_MS;

  // DECREASE conditions
  if (timedOut || critical || underPressure || highLag || rss > rssSafe) {
    const newLimit = Math.max(MIN_LIMIT, Math.floor(limit * DECREASE_FACTOR));
    if (newLimit < limit) {
      limit = newLimit;
      lastAdjustAt = now;
      healthyStreak = 0;

      if (timedOut) lastReason = 'timeout';
      else if (critical) lastReason = 'memory_critical';
      else if (underPressure) lastReason = 'memory_pressure';
      else if (highLag) lastReason = 'event_loop_lag';
      else lastReason = 'rss_high';
    }
    return;
  }

  if (!success) {
    const newLimit = Math.max(MIN_LIMIT, Math.floor(limit * DECREASE_FACTOR));
    if (newLimit < limit) {
      limit = newLimit;
      lastAdjustAt = now;
      healthyStreak = 0;
      lastReason = 'failure';
    }
    return;
  }

  // INCREASE conditions
  healthyStreak++;

  if (healthyStreak >= HEALTHY_WINDOW && active >= limit - 1) {
    const newLimit = Math.min(MAX_LIMIT, limit + 1);
    if (newLimit > limit) {
      limit = newLimit;
      lastAdjustAt = now;
      healthyStreak = 0;
      lastReason = 'healthy_ramp';
    }
  }
}

function removeEncodeWaiter(waiter) {
  const index = encodeWaiters.indexOf(waiter);
  if (index !== -1) encodeWaiters.splice(index, 1);
}

function pumpEncodeWaiters() {
  while (encodeWaiters.length > 0 && encodeActive < encodeLimit) {
    const waiter = encodeWaiters.shift();

    if (!waiter || waiter.settled) {
      continue;
    }

    waiter.settled = true;

    if (waiter.timer) clearTimeout(waiter.timer);

    if (waiter.signal && waiter.onAbort) {
      waiter.signal.removeEventListener('abort', waiter.onAbort);
    }

    encodeActive++;
    waiter.resolve({ waitedMs: Date.now() - waiter.enqueuedAt, queued: true });
  }
}

function waitForEncodeSlot({ timeoutMs = 30000, signal = null } = {}) {
  if (!ENABLED) {
    return Promise.resolve({ waitedMs: 0, queued: false });
  }

  if (encodeActive < encodeLimit) {
    encodeActive++;
    return Promise.resolve({ waitedMs: 0, queued: false });
  }

  if (encodeWaiters.length >= ENCODE_WAIT_QUEUE_MAX) {
    const err = new Error('ENCODE_QUEUE_FULL');
    err.code = 'ENCODE_QUEUE_FULL';
    return Promise.reject(err);
  }

  return new Promise((resolve, reject) => {
    const waiter = {
      resolve,
      reject,
      settled: false,
      enqueuedAt: Date.now(),
      timer: null,
      signal: null,
      onAbort: null
    };

    const fail = (err) => {
      if (waiter.settled) return;

      waiter.settled = true;
      removeEncodeWaiter(waiter);

      if (waiter.timer) clearTimeout(waiter.timer);

      if (waiter.signal && waiter.onAbort) {
        waiter.signal.removeEventListener('abort', waiter.onAbort);
      }

      reject(err);
    };

    waiter.timer = setTimeout(() => {
      const err = new Error('ENCODE_WAIT_TIMEOUT');
      err.code = 'ENCODE_WAIT_TIMEOUT';
      fail(err);
    }, Math.max(1, Number(timeoutMs) || 30000));

    if (signal) {
      waiter.signal = signal;

      waiter.onAbort = () => {
        const err = new Error(signal?.reason?.message || 'ENCODE_WAIT_ABORTED');
        err.code = 'ENCODE_WAIT_ABORTED';
        fail(err);
      };

      if (signal.aborted) {
        const err = new Error(signal?.reason?.message || 'ENCODE_WAIT_ABORTED');
        err.code = 'ENCODE_WAIT_ABORTED';
        fail(err);
        return;
      }

      signal.addEventListener('abort', waiter.onAbort, { once: true });
    }

    encodeWaiters.push(waiter);
  });
}

function getStatus() {
  return {
    enabled: ENABLED,
    limit,
    active,
    lastReason,
    healthyStreak,
    recentEncodeTimes: recentEncodeTimes.length,
    encode: {
      limit: encodeLimit,
      active: encodeActive,
      waiting: encodeWaiters.length,
      queueMax: ENCODE_WAIT_QUEUE_MAX,
      lastReason: encodeLastReason,
      healthyStreak: encodeHealthyStreak
    }
  };
}

function tryAdmitEncode() {
  if (!ENABLED) return true;

  if (encodeActive >= encodeLimit) {
    return false;
  }

  encodeActive++;
  return true;
}

function releaseEncode(outcome = {}) {
  if (encodeActive > 0) encodeActive--;

  if (typeof setImmediate === 'function') {
    setImmediate(pumpEncodeWaiters);
  } else {
    setTimeout(pumpEncodeWaiters, 0);
  }

  if (!ENABLED) return;

  const {
    success = true,
    timedOut = false,
    encodeTimeMs = 0
  } = outcome;

  const now = Date.now();
  if (now - encodeLastAdjustAt < ENCODE_COOLDOWN_MS) return;

  const rss = memoryGovernor.getRssMB();
  const critical = memoryGovernor.isCritical();

  // DECREASE: timeout, critical memory, or very slow encode
  if (timedOut || critical || encodeTimeMs > ENCODE_TIME_THRESHOLD_MS) {
    const newLimit = Math.max(ENCODE_MIN_LIMIT, Math.floor(encodeLimit * DECREASE_FACTOR));
    if (newLimit < encodeLimit) {
      encodeLimit = newLimit;
      encodeLastAdjustAt = now;
      encodeHealthyStreak = 0;

      if (timedOut) encodeLastReason = 'timeout';
      else if (critical) encodeLastReason = 'memory_critical';
      else encodeLastReason = 'slow_encode';
    }
    return;
  }

  if (!success) {
    const newLimit = Math.max(ENCODE_MIN_LIMIT, Math.floor(encodeLimit * DECREASE_FACTOR));
    if (newLimit < encodeLimit) {
      encodeLimit = newLimit;
      encodeLastAdjustAt = now;
      encodeHealthyStreak = 0;
      encodeLastReason = 'failure';
    }
    return;
  }

  // INCREASE: healthy encodes
  encodeHealthyStreak++;

  if (encodeHealthyStreak >= HEALTHY_WINDOW && encodeActive >= encodeLimit - 1) {
    const newLimit = Math.min(ENCODE_MAX_LIMIT, encodeLimit + 1);
    if (newLimit > encodeLimit) {
      encodeLimit = newLimit;
      encodeLastAdjustAt = now;
      encodeHealthyStreak = 0;
      encodeLastReason = 'healthy_ramp';
    }
  }
}

export default {
  tryAdmit,
  release,
  getLimit,
  getEncodeLimit,
  getActive,
  getLastReason,
  getEnabled,
  getStatus,
  tryAdmitEncode,
  waitForEncodeSlot,
  releaseEncode,
  ENABLED,
  MIN_LIMIT,
  MAX_LIMIT,
  INITIAL_LIMIT,
  ENCODE_MIN_LIMIT,
  ENCODE_MAX_LIMIT,
  ENCODE_INITIAL_LIMIT
};
