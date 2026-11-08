import process from 'node:process';

const MB = 1024 * 1024;

function safeInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function safeFloat(value, fallback) {
  const n = parseFloat(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const MEMORY_CEILING_MB = safeInt(process.env.MEMORY_CEILING_MB, 1024);
const RSS_WALL_OFFSET_MB = safeInt(process.env.RSS_WALL_OFFSET_MB, 25);
const RSS_ADMISSION_OFFSET_MB = safeInt(process.env.RSS_ADMISSION_OFFSET_MB, 60);
const PIXEL_MEMORY_DIVISOR = safeInt(process.env.PIXEL_MEMORY_DIVISOR, 6);

let DOWNLOAD_BYTE_RATIO = safeFloat(process.env.DOWNLOAD_BYTE_RATIO, 0.35);
let DECOMPRESS_BYTE_RATIO = safeFloat(process.env.DECOMPRESS_BYTE_RATIO, 0.50);

DOWNLOAD_BYTE_RATIO = Math.min(Math.max(DOWNLOAD_BYTE_RATIO, 0.01), 0.95);
DECOMPRESS_BYTE_RATIO = Math.min(Math.max(DECOMPRESS_BYTE_RATIO, 0.01), 0.95);

const RSS_WALL_MB = Math.max(1, MEMORY_CEILING_MB - RSS_WALL_OFFSET_MB);
const RSS_ADMISSION_MB = Math.max(1, RSS_WALL_MB - RSS_ADMISSION_OFFSET_MB);

let activePixelCost = 0;
let activeByteCost = 0;

function getRssMB() {
  return Math.round(process.memoryUsage().rss / MB);
}

function getAvailableMB() {
  const rss = getRssMB();
  return Math.max(0, RSS_ADMISSION_MB - rss);
}

function getPixelBudget() {
  const availableMB = getAvailableMB();
  return Math.floor((availableMB * MB) / PIXEL_MEMORY_DIVISOR);
}

function getDownloadBudget() {
  const availableMB = getAvailableMB();
  return Math.floor(availableMB * MB * DOWNLOAD_BYTE_RATIO);
}

function getDecompressBudget() {
  const availableMB = getAvailableMB();
  return Math.floor(availableMB * MB * DECOMPRESS_BYTE_RATIO);
}

function admitPixels(cost) {
  if (!Number.isFinite(cost) || cost < 0) {
    return false;
  }

  if (cost === 0) {
    return true;
  }

  const budget = getPixelBudget();

  if (activePixelCost + cost > budget) {
    return false;
  }

  activePixelCost += cost;
  return true;
}

function releasePixels(cost) {
  if (!Number.isFinite(cost) || cost <= 0) {
    return;
  }

  activePixelCost = Math.max(0, activePixelCost - cost);
}

function admitBytes(cost) {
  if (!Number.isFinite(cost) || cost < 0) {
    return false;
  }

  if (cost === 0) {
    return true;
  }

  const budget = getDownloadBudget();

  if (activeByteCost + cost > budget) {
    return false;
  }

  activeByteCost += cost;
  return true;
}

function releaseBytes(cost) {
  if (!Number.isFinite(cost) || cost <= 0) {
    return;
  }

  activeByteCost = Math.max(0, activeByteCost - cost);
}

function isUnderPressure() {
  return getRssMB() > RSS_WALL_MB;
}

function isCritical() {
  return getRssMB() > (MEMORY_CEILING_MB - 10);
}

function getActivePixelCost() {
  return activePixelCost;
}

function getActiveByteCost() {
  return activeByteCost;
}

export default {
  getRssMB,
  getAvailableMB,
  getPixelBudget,
  getDownloadBudget,
  getDecompressBudget,
  admitPixels,
  releasePixels,
  admitBytes,
  releaseBytes,
  isUnderPressure,
  isCritical,
  getActivePixelCost,
  getActiveByteCost,
  MEMORY_CEILING_MB,
  RSS_WALL_MB,
  RSS_ADMISSION_MB
};
