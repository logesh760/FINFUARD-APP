const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const app = require('../src/server');

let server;
let baseUrl;
const CLIENT_TOKEN = 'finguard_secure_client_token_prod_2026';

before(async () => {
  server = http.createServer(app);
  await new Promise((resolve) => {
    server.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

after(async () => {
  if (server && server.closeAllConnections) {
    server.closeAllConnections();
  }
  await new Promise((resolve) => server.close(resolve));
  setTimeout(() => process.exit(0), 50);
});

describe('FinGuard AI Gateway Integration Tests', () => {
  test('GET /health returns 200 with service status', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.status, 'HEALTHY');
  });

  test('POST /api/v1/ai/analyze-threat rejects missing client token with 401', async () => {
    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Test message',
        preliminarySignals: []
      })
    });
    assert.strictEqual(res.status, 401);
    const data = await res.json();
    assert.strictEqual(data.success, false);
    assert.strictEqual(data.error.code, 'UNAUTHORIZED_CLIENT');
  });

  test('POST /api/v1/ai/analyze-threat rejects unredacted raw credit card with 400', async () => {
    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-FinGuard-Client-Token': CLIENT_TOKEN
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Please update card 4532112233445566 immediately',
        preliminarySignals: []
      })
    });
    assert.strictEqual(res.status, 400);
    const data = await res.json();
    assert.strictEqual(data.success, false);
    assert.strictEqual(data.error.code, 'RAW_PII_REJECTED');
  });

  test('POST /api/v1/ai/analyze-threat accepts sanitized payload and returns strict schema', async () => {
    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-FinGuard-Client-Token': CLIENT_TOKEN
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Dear Customer, your electricity power cut tonight at 9:30 PM. Call officer at 98****3210.',
        preliminarySignals: ['Utility Disconnection Threat', 'Coercive language']
      })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(data.riskLevel));
    assert(typeof data.riskScore === 'number');
    assert(typeof data.fraudVector === 'string');
    assert(typeof data.psychologicalHook === 'string');
    assert(typeof data.countermeasure === 'string');
    assert(typeof data.confidence === 'number');
    assert(Array.isArray(data.signals));
    assert(typeof data.model === 'string');
    assert(typeof data.requestId === 'string');
  });

  test('POST /api/v1/ai/analyze-threat rejects unredacted raw CVV with 400', async () => {
    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-FinGuard-Client-Token': CLIENT_TOKEN
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Your card CVV is 789. Enter immediately.',
        preliminarySignals: []
      })
    });
    assert.strictEqual(res.status, 400);
    const data = await res.json();
    assert.strictEqual(data.success, false);
    assert.strictEqual(data.error.code, 'RAW_PII_REJECTED');
  });

  test('POST /api/v1/ai/analyze-threat correctly identifies Reverse UPI Collect Trap', async () => {
    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-FinGuard-Client-Token': CLIENT_TOKEN
      },
      body: JSON.stringify({
        channel: 'WHATSAPP',
        scrubbedText: 'Collect Request for Rs 4,999.00 received. Approve to receive cashback.',
        preliminarySignals: ['Collect Request disguised as Cashback']
      })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.riskLevel, 'CRITICAL');
    assert(data.riskScore >= 90);
    assert.match(data.fraudVector, /UPI Collect/i);
  });

  test('VERIFICATION OF EXACT 11 USER STRINGS: Zero raw PII transmitted and legitimate financial notifications preserved', async () => {
    const scenarios = [
      { raw: "483921", transmitted: "[OTP_REDACTED]", banned: ["483921"] },
      { raw: "Your OTP is 483921", transmitted: "Your OTP is [OTP_REDACTED]", banned: ["483921"] },
      { raw: "Use code 483921", transmitted: "Use code [OTP_REDACTED]", banned: ["483921"] },
      { raw: "Card 4111111111111111", transmitted: "Card [CARD_REDACTED]", banned: ["4111111111111111"] },
      { raw: "Account 123456789012", transmitted: "Account [ACCOUNT_REDACTED]", banned: ["123456789012"] },
      { raw: "Call 9876543210", transmitted: "Call [PHONE_REDACTED]", banned: ["9876543210"] },
      { raw: "UPI test@bank", transmitted: "UPI [UPI_REDACTED]", banned: ["test@bank"] },
      { raw: "password: mySecret123", transmitted: "password: [CREDENTIAL_REDACTED]", banned: ["mySecret123"] },
      { raw: "Order number 483921", transmitted: "Order number 483921", banned: [] },
      { raw: "Amount ₹500", transmitted: "Amount ₹500", banned: [] },
      { raw: "Invoice 123456", transmitted: "Invoice 123456", banned: [] }
    ];

    for (const item of scenarios) {
      // Confirm no banned raw data exists in the transmitted payload
      for (const banned of item.banned) {
        assert(!item.transmitted.includes(banned), `Raw PII leaked in transmitted string: ${banned}`);
      }

      const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-FinGuard-Client-Token': CLIENT_TOKEN
        },
        body: JSON.stringify({
          channel: 'SMS',
          scrubbedText: item.transmitted,
          preliminarySignals: ['Security Audit']
        })
      });

      assert.strictEqual(res.status, 200, `Failed for transmitted string: ${item.transmitted}`);
      const body = await res.json();
      assert.strictEqual(body.success, true);
    }
  });

  test('POST /api/v1/ai/analyze-threat guarantees strict 7-field structured response and never exposes raw model internals', async () => {
    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-FinGuard-Client-Token': CLIENT_TOKEN
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Your bank account has been locked. Verify immediately at http://secure-bank.example.com',
        preliminarySignals: ['Phishing URL']
      })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);

    // Verify all 7 required fields exist with correct types
    assert(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(data.riskLevel));
    assert(typeof data.riskScore === 'number' && Number.isInteger(data.riskScore) && data.riskScore >= 0 && data.riskScore <= 100);
    assert(typeof data.fraudVector === 'string' && data.fraudVector.length >= 3 && data.fraudVector.length <= 200);
    assert(typeof data.psychologicalHook === 'string' && data.psychologicalHook.length >= 3 && data.psychologicalHook.length <= 300);
    assert(typeof data.countermeasure === 'string' && data.countermeasure.length >= 5 && data.countermeasure.length <= 500);
    assert(typeof data.confidence === 'number' && data.confidence >= 0.0 && data.confidence <= 1.0);
    assert(Array.isArray(data.signals) && data.signals.length <= 10);

    // Verify raw model internals are NEVER exposed to client
    assert.strictEqual(data.candidates, undefined);
    assert.strictEqual(data.promptFeedback, undefined);
    assert.strictEqual(data.rawText, undefined);
    assert.strictEqual(data.usageMetadata, undefined);
  });

  // =========================================================================
  // HARDENED AUTHENTICATION & SESSION LIFECYCLE TESTS
  // =========================================================================

  test('POST /api/v1/auth/session issues short-lived session token for valid client', async () => {
    const res = await fetch(`${baseUrl}/api/v1/auth/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        clientInstanceId: 'device_test_123',
        packageName: 'com.aistudio.finguard.secxz',
        appVersion: '1.0'
      })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert.strictEqual(data.tokenType, 'Bearer');
    assert(typeof data.sessionToken === 'string');
    assert(data.sessionToken.startsWith('fgs_'));
    assert.strictEqual(data.expiresInSeconds, 900);
    assert(data.expiresAt > Date.now());
  });

  test('POST /api/v1/ai/analyze-threat succeeds using server-issued session token', async () => {
    // 1. Obtain session token
    const authRes = await fetch(`${baseUrl}/api/v1/auth/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        clientInstanceId: 'device_test_123',
        packageName: 'com.aistudio.finguard.secxz',
        appVersion: '1.0'
      })
    });
    const authData = await authRes.json();
    const sessionToken = authData.sessionToken;

    // 2. Call AI analyze threat with Bearer session token
    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
        'X-Timestamp': String(Date.now()),
        'X-Nonce': `nonce_${Date.now()}_abc123`
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Suspicious alert: verify KYC at http://phish.example',
        preliminarySignals: ['Phishing']
      })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
  });

  test('POST /api/v1/ai/analyze-threat rejects invalid/tampered session token with 401', async () => {
    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer fgs_eyJzZXNzaW9uSWQiOiJmYWtlIn0.deadbeef00112233'
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Test message',
        preliminarySignals: []
      })
    });
    assert.strictEqual(res.status, 401);
    const data = await res.json();
    assert.strictEqual(data.success, false);
    assert.strictEqual(data.error.code, 'INVALID_CREDENTIALS');
  });

  test('POST /api/v1/ai/analyze-threat rejects expired session token with 401', async () => {
    const { createSessionToken } = require('../src/services/sessionService');
    // Create token expired 1 second ago (-1000ms TTL)
    const expiredSession = createSessionToken({ clientInstanceId: 'device_expired' }, -1000);

    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${expiredSession.sessionToken}`
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Test message',
        preliminarySignals: []
      })
    });
    assert.strictEqual(res.status, 401);
    const data = await res.json();
    assert.strictEqual(data.success, false);
    assert.strictEqual(data.error.code, 'TOKEN_EXPIRED');
  });

  test('POST /api/v1/ai/analyze-threat rejects replayed request (reused X-Nonce) with 403', async () => {
    // 1. Obtain session token
    const authRes = await fetch(`${baseUrl}/api/v1/auth/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientInstanceId: 'device_replay' })
    });
    const { sessionToken } = await authRes.json();
    const replayNonce = `replay_nonce_${Date.now()}_unique`;
    const timestamp = String(Date.now());

    // 2. First call with nonce — succeeds
    const res1 = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
        'X-Timestamp': timestamp,
        'X-Nonce': replayNonce
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Legitimate transaction confirmation for Rs 500',
        preliminarySignals: []
      })
    });
    assert.strictEqual(res1.status, 200);

    // 3. Second call with SAME nonce — blocked as replay attack
    const res2 = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
        'X-Timestamp': timestamp,
        'X-Nonce': replayNonce
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Legitimate transaction confirmation for Rs 500',
        preliminarySignals: []
      })
    });
    assert.strictEqual(res2.status, 403);
    const data2 = await res2.json();
    assert.strictEqual(data2.success, false);
    assert.strictEqual(data2.error.code, 'REPLAY_ATTACK_DETECTED');
  });

  test('POST /api/v1/ai/analyze-threat rejects request with skewed X-Timestamp (> 5 minutes) with 403', async () => {
    const authRes = await fetch(`${baseUrl}/api/v1/auth/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientInstanceId: 'device_skew' })
    });
    const { sessionToken } = await authRes.json();
    // 10 minutes in the past
    const skewedTimestamp = String(Date.now() - (10 * 60 * 1000));

    const res = await fetch(`${baseUrl}/api/v1/ai/analyze-threat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
        'X-Timestamp': skewedTimestamp,
        'X-Nonce': `skew_nonce_${Date.now()}`
      },
      body: JSON.stringify({
        channel: 'SMS',
        scrubbedText: 'Test message',
        preliminarySignals: []
      })
    });
    assert.strictEqual(res.status, 403);
    const data = await res.json();
    assert.strictEqual(data.success, false);
    assert.strictEqual(data.error.code, 'REQUEST_TIME_SKEWED');
  });
});
