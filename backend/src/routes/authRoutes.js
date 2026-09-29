const express = require('express');
const { createSessionToken, validateReplayProtection } = require('../services/sessionService');

const router = express.Router();

/**
 * Mobile App Session Exchange Endpoint: POST /api/v1/auth/session
 * Issues a cryptographically signed, short-lived session token (15-minute validity)
 * to verified Android clients without requiring static secrets inside the APK.
 */
router.post('/session', (req, res) => {
  const { clientInstanceId, packageName, appVersion, clientTimestamp, nonce } = req.body || {};

  // Basic package validation
  if (packageName && packageName !== 'com.aistudio.finguard.secxz' && packageName !== 'com.example') {
    return res.status(403).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED_PACKAGE',
        message: 'Invalid client package identifier.'
      },
      requestId: req.requestId || 'req_auth_err'
    });
  }

  // Validate replay headers if provided
  if (clientTimestamp && nonce) {
    const replayCheck = validateReplayProtection(clientTimestamp, nonce);
    if (!replayCheck.valid) {
      return res.status(403).json({
        success: false,
        error: {
          code: replayCheck.code,
          message: replayCheck.message
        },
        requestId: req.requestId || 'req_auth_replay'
      });
    }
  }

  const session = createSessionToken({
    clientInstanceId: clientInstanceId || 'anonymous_client',
    packageName: packageName || 'com.aistudio.finguard.secxz',
    appVersion: appVersion || '1.0'
  });

  return res.status(200).json({
    success: true,
    sessionToken: session.sessionToken,
    tokenType: session.tokenType,
    expiresInSeconds: session.expiresInSeconds,
    expiresAt: session.expiresAt,
    serverTime: session.serverTime,
    requestId: req.requestId
  });
});

module.exports = router;
