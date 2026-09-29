// Authentication & Replay Protection Middleware for FinGuard AI Gateway
const { verifySessionToken, validateReplayProtection } = require('../services/sessionService');

function authenticateClient(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['x-finguard-client-token'] || req.headers['x-finguard-session-token'];

  if (!authHeader) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED_CLIENT',
        message: 'Valid client credentials required to access FinGuard AI Gateway.'
      },
      requestId: req.requestId || 'req_unauth'
    });
  }

  // Verify short-lived session token
  const verification = verifySessionToken(authHeader);
  if (!verification.valid) {
    const isExpired = verification.reason === 'TOKEN_EXPIRED';
    return res.status(401).json({
      success: false,
      error: {
        code: isExpired ? 'TOKEN_EXPIRED' : 'INVALID_CREDENTIALS',
        message: isExpired
          ? 'Session token has expired. Please refresh your session.'
          : 'Invalid or tampered session token.'
      },
      requestId: req.requestId || 'req_auth_fail'
    });
  }

  // Replay Protection Check: enforce freshness and nonce uniqueness if headers provided
  const timestampHeader = req.headers['x-timestamp'];
  const nonceHeader = req.headers['x-nonce'];
  if (timestampHeader || nonceHeader) {
    const replayResult = validateReplayProtection(timestampHeader, nonceHeader);
    if (!replayResult.valid) {
      return res.status(403).json({
        success: false,
        error: {
          code: replayResult.code,
          message: replayResult.message
        },
        requestId: req.requestId || 'req_replay_blocked'
      });
    }
  }

  req.session = verification.payload;
  next();
}

module.exports = { authenticateClient };
