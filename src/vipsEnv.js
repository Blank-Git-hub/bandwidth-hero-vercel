// libvips writes large intermediate images to /tmp while it works, and a Vercel function only gets about 512 MB there.
// Measured: holding the same pixels in memory costs no extra RSS, so keep them in memory instead of failing with
// "No space left on device".
process.env.VIPS_DISC_THRESHOLD ??= '4g';

