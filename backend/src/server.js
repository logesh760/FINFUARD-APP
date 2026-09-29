const express = require('express');
const crypto = require('crypto');
const { authenticateClient } = require('./middleware/auth');
const { rateLimiter } = require('./middleware/rateLimiter');
const authRoutes = require('./routes/authRoutes');
const aiRoutes = require('./routes/aiRoutes');

const app = express();
const PORT = process.env.PORT || 8080;

// Security: Disable x-powered-by header
app.disable('x-powered-by');

// Enforce request size limit (10kb maximum for text fraud analysis)
app.use(express.json({ limit: '10kb' }));

// Strict Mobile & Web CORS headers
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()) : [];
  if (origin && (allowed.includes(origin) || allowed.includes('*'))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID, X-Timestamp, X-Nonce');
  }
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Request Timeout Middleware (15-second cutoff for threat analysis)
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS, 10) || 15000;
app.use((req, res, next) => {
  req.setTimeout(REQUEST_TIMEOUT_MS, () => {
    if (!res.headersSent) {
      res.status(504).json({
        success: false,
        error: { code: 'GATEWAY_TIMEOUT', message: 'Request processing exceeded timeout.' },
        requestId: req.requestId
      });
    }
  });
  next();
});

// Assign unique Request ID to each incoming call
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || `req_${crypto.randomBytes(8).toString('hex')}`;
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

// Health check endpoint (Public)
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'HEALTHY',
    service: 'FinGuard-AI-Gateway',
    timestamp: new Date().toISOString(),
    aiEngine: process.env.GEMINI_API_KEY ? 'gemini-3.5-flash' : 'local-deterministic-expert'
  });
});

// Session Token Issuance (Public with Rate Limiting)
app.use('/api/v1/auth', rateLimiter, authRoutes);

// Protected AI routes
app.use('/api/v1/ai', authenticateClient, rateLimiter, aiRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: { code: 'NOT_FOUND', message: 'Endpoint not found.' },
    requestId: req.requestId
  });
});

// Centralized error handler — NEVER leak stack traces or internal details
app.use((err, req, res, next) => {
  const isPayloadTooLarge = err.type === 'entity.too.large' || err.status === 413;
  res.status(isPayloadTooLarge ? 413 : 500).json({
    success: false,
    error: {
      code: isPayloadTooLarge ? 'PAYLOAD_TOO_LARGE' : 'INTERNAL_SERVER_ERROR',
      message: isPayloadTooLarge ? 'Request payload exceeds 10KB limit.' : 'An internal security gateway error occurred.'
    },
    requestId: req.requestId
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[FinGuard Security Gateway] Running on port ${PORT}`);
  });
}

module.exports = app;
