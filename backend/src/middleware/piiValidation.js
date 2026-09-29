// PII Validation & Schema Guard Middleware
const VALID_CHANNELS = ['SMS', 'WHATSAPP', 'TELEGRAM', 'INSTAGRAM', 'MANUAL_SCAN'];

// Credit / Debit Card regex (Luhn-candidate card sequences)
const RAW_CARD_REGEX = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4})\b/;

// Unmasked CVV regex
const RAW_CVV_REGEX = /\b(?:cvv[2]?|cvc[2]?|security\s*code|card\s*security\s*code)\s*(?:is|:|=|-)?\s*[0-9]{3,4}\b/i;

function validateThreatRequest(req, res, next) {
  const { channel, scrubbedText, preliminarySignals } = req.body || {};

  // 1. Schema Validation
  if (!channel || typeof channel !== 'string') {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_SCHEMA', message: 'Field "channel" is required and must be a string.' },
      requestId: req.requestId
    });
  }

  const normalizedChannel = channel.toUpperCase();
  if (!VALID_CHANNELS.includes(normalizedChannel)) {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_CHANNEL', message: `Field "channel" must be one of: ${VALID_CHANNELS.join(', ')}` },
      requestId: req.requestId
    });
  }

  if (!scrubbedText || typeof scrubbedText !== 'string' || scrubbedText.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_SCHEMA', message: 'Field "scrubbedText" is required and cannot be empty.' },
      requestId: req.requestId
    });
  }

  if (scrubbedText.length > 4000) {
    return res.status(400).json({
      success: false,
      error: { code: 'PAYLOAD_TOO_LARGE', message: 'Payload exceeds maximum allowed length of 4000 characters.' },
      requestId: req.requestId
    });
  }

  if (preliminarySignals && !Array.isArray(preliminarySignals)) {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_SCHEMA', message: 'Field "preliminarySignals" must be an array of strings.' },
      requestId: req.requestId
    });
  }

  // 2. Second-Layer Server-Side PII Inspection
  // If the client failed to redact raw cards or CVVs, reject outright to enforce zero-leakage
  if (RAW_CARD_REGEX.test(scrubbedText)) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'RAW_PII_REJECTED',
        message: 'Security Violation: Unredacted payment card number detected. Client-side scrubbing must occur prior to transmission.'
      },
      requestId: req.requestId
    });
  }

  if (RAW_CVV_REGEX.test(scrubbedText)) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'RAW_PII_REJECTED',
        message: 'Security Violation: Unredacted card CVV code detected in payload.'
      },
      requestId: req.requestId
    });
  }

  // 3. Second-Layer Server-Side Defense-in-Depth Sanitization
  // Sanitizes any lingering secrets, passwords, credentials or standalone OTPs
  let sanitizedText = scrubbedText
    .replace(/\b(?:seed\s*phrase|recovery\s*phrase|backup\s*phrase)\s*[:=\-]\s*([a-z]{3,12}(?:\s+[a-z]{3,12}){11,23})\b/gi, '[SECRET_REDACTED]')
    .replace(/\bAIza[0-9A-Za-z\-_]{35}\b/g, '[SECRET_REDACTED]')
    .replace(/\b(?:ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{20,})\b/g, '[SECRET_REDACTED]')
    .replace(/\b(?:password|passwd|pwd|passcode)\s*[:=\-]?\s*([^\s,;]{3,})/gi, 'password: [CREDENTIAL_REDACTED]')
    .replace(/\b(?:upi\s*(?:id|vpa)?|pay\s*to)\s*[:=\-]?\s*([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-_]+)\b/gi, 'UPI [UPI_REDACTED]')
    .replace(/\b(?:otp|code|one[- ]?time[- ]?password|verification(?:[- ]?code)?|pin)\s*(?:is|:|-)?\s*([0-9]{4,8})\b/gi, (match, code) => {
      if (code.startsWith('202')) return match;
      return match.replace(code, '[OTP_REDACTED]');
    });

  // Preserve legitimate non-OTP numbers (Order number, Invoice, Amount, Ref)
  const LEGITIMATE_PREFIX_REGEX = /\b(?:order(?:\s*(?:number|no|id|#))?|invoice(?:\s*(?:number|no|id|#))?|bill(?:\s*(?:number|no|id|#))?|tracking(?:\s*(?:id|number|no|#))?|ticket(?:\s*(?:number|no|id|#))?|amount|amt|[₹$€£]|rs\.?|inr|usd|pnr|postal|zip(?:code)?|ref(?:\s*(?:no|number|#))?)\s*[:#\-]?\s*$/i;

  sanitizedText = sanitizedText.replace(/\b(?<!\d)[0-9]{6}(?!\d)\b/g, (match, offset, fullStr) => {
    if (match.startsWith('202')) return match;
    const preceding = fullStr.substring(Math.max(0, offset - 35), offset);
    if (LEGITIMATE_PREFIX_REGEX.test(preceding)) {
      return match; // Keep legitimate order / invoice / amount
    }
    return '[OTP_REDACTED]';
  });

  req.sanitizedPayload = {
    channel: normalizedChannel,
    scrubbedText: sanitizedText,
    preliminarySignals: Array.isArray(preliminarySignals) ? preliminarySignals : []
  };

  next();
}

module.exports = { validateThreatRequest };
