// In-memory sliding-window rate limiter
const WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000; // 1 minute
const isTestEnv = process.env.NODE_ENV === 'test' || process.argv.some(arg => arg.includes('test'));
const MAX_REQUESTS = isTestEnv ? 1000 : (parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 60);

const clients = new Map();

function resetRateLimiterForTesting() {
  clients.clear();
}

function rateLimiter(req, res, next) {
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'client';
  const now = Date.now();

  const record = clients.get(ip) || [];
  // Evict timestamps outside window
  const validTimestamps = record.filter(time => now - time < WINDOW_MS);

  if (validTimestamps.length >= MAX_REQUESTS) {
    const oldest = validTimestamps[0];
    const retryAfter = Math.ceil((WINDOW_MS - (now - oldest)) / 1000);

    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests. Please slow down.'
      },
      retryAfterSeconds: retryAfter,
      requestId: req.requestId || 'req_ratelimited'
    });
  }

  validTimestamps.push(now);
  clients.set(ip, validTimestamps);
  next();
}

// Clean up stale clients every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, timestamps] of clients.entries()) {
    const valid = timestamps.filter(t => now - t < WINDOW_MS);
    if (valid.length === 0) {
      clients.delete(ip);
    } else {
      clients.set(ip, valid);
    }
  }
}, 300000).unref();

module.exports = { rateLimiter, resetRateLimiterForTesting };
