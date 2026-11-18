const EXCLUDED_TYPES = new Set(['application/pdf', 'image/x-icon', 'image/vnd.microsoft.icon']);

export default function shouldCompress(req, buffer, memoryGovernor) {
  const { originType } = req.opts || {};

  if (!originType || !Buffer.isBuffer(buffer) || buffer.length === 0) {
    return false;
  }

  if (!originType.startsWith('image/') || EXCLUDED_TYPES.has(originType)) {
    return false;
  }

  // Adaptive: let the memory governor decide if we have room
  if (memoryGovernor) {
    const budget = memoryGovernor.getDownloadBudget();
    if (buffer.length > budget) {
      return false;
    }
  }

  return true;
}
