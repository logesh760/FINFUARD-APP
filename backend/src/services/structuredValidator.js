// FinGuard Security — Structured AI Response Validator
// Enforces strict schema, value constraints, prompt injection sanitization, and type safety

const ALLOWED_RISK_LEVELS = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

const CONSTRAINTS = {
  riskScore: { min: 0, max: 100 },
  confidence: { min: 0.0, max: 1.0 },
  fraudVector: { minLength: 3, maxLength: 200 },
  psychologicalHook: { minLength: 3, maxLength: 300 },
  countermeasure: { minLength: 5, maxLength: 500 },
  maxSignalsCount: 10,
  signalItem: { minLength: 1, maxLength: 100 }
};

// Patterns indicating potential prompt injection or jailbreak payload reflection
const PROMPT_INJECTION_PATTERNS = [
  /\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b/i,
  /\bsystem\s*prompt\b/i,
  /\byou\s+are\s+now\b/i,
  /\bjailbreak\b/i,
  /\bDAN\s+mode\b/i,
  /<script[\s\S]*?>[\s\S]*?<\/script>/i,
  /<[^>]+>/g, // Any HTML tags
  /javascript\s*:/i,
  /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/ // Unprintable control characters
];

/**
 * Sanitizes a string by stripping dangerous control characters, HTML tags,
 * and normalizing whitespace.
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/<[^>]+>/g, '') // Strip HTML tags
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Strip control chars
    .trim();
}

/**
 * Checks if a string contains known adversarial prompt injection indicators.
 */
function containsPromptInjection(str) {
  if (typeof str !== 'string') return false;
  return PROMPT_INJECTION_PATTERNS.some(pattern => pattern.test(str));
}

/**
 * Validates and sanitizes a parsed JSON threat evaluation from Gemini.
 * Returns { isValid: true, data: { ... } } or { isValid: false, reason: "..." }
 */
function validateThreatSchema(rawJson) {
  // 1. Must be a non-null, plain object (not an array, not a primitive)
  if (!rawJson || typeof rawJson !== 'object' || Array.isArray(rawJson)) {
    return { isValid: false, reason: 'Response is not a valid JSON object' };
  }

  // 2. Validate all 7 required fields are present
  const requiredFields = [
    'riskLevel',
    'riskScore',
    'fraudVector',
    'psychologicalHook',
    'countermeasure',
    'confidence',
    'signals'
  ];

  for (const field of requiredFields) {
    if (rawJson[field] === undefined || rawJson[field] === null) {
      return { isValid: false, reason: `Missing required field: ${field}` };
    }
  }

  // 3. Validate riskLevel enum
  if (typeof rawJson.riskLevel !== 'string' || !ALLOWED_RISK_LEVELS.has(rawJson.riskLevel)) {
    return {
      isValid: false,
      reason: `Invalid riskLevel '${rawJson.riskLevel}'. Expected one of: LOW, MEDIUM, HIGH, CRITICAL`
    };
  }

  // 4. Validate riskScore: integer 0..100
  if (
    typeof rawJson.riskScore !== 'number' ||
    !Number.isInteger(rawJson.riskScore) ||
    rawJson.riskScore < CONSTRAINTS.riskScore.min ||
    rawJson.riskScore > CONSTRAINTS.riskScore.max
  ) {
    return {
      isValid: false,
      reason: `Invalid riskScore '${rawJson.riskScore}'. Must be an integer between 0 and 100`
    };
  }

  // 5. Validate confidence: number 0.0..1.0
  if (
    typeof rawJson.confidence !== 'number' ||
    Number.isNaN(rawJson.confidence) ||
    !Number.isFinite(rawJson.confidence) ||
    rawJson.confidence < CONSTRAINTS.confidence.min ||
    rawJson.confidence > CONSTRAINTS.confidence.max
  ) {
    return {
      isValid: false,
      reason: `Invalid confidence '${rawJson.confidence}'. Must be a number between 0.0 and 1.0`
    };
  }

  // 6. Validate string lengths and check for injection in fraudVector
  if (typeof rawJson.fraudVector !== 'string') {
    return { isValid: false, reason: 'fraudVector must be a string' };
  }
  const cleanFraudVector = sanitizeString(rawJson.fraudVector);
  if (
    cleanFraudVector.length < CONSTRAINTS.fraudVector.minLength ||
    cleanFraudVector.length > CONSTRAINTS.fraudVector.maxLength
  ) {
    return {
      isValid: false,
      reason: `fraudVector length must be between ${CONSTRAINTS.fraudVector.minLength} and ${CONSTRAINTS.fraudVector.maxLength}`
    };
  }
  if (containsPromptInjection(rawJson.fraudVector)) {
    return { isValid: false, reason: 'Prompt injection or dangerous payload detected in fraudVector' };
  }

  // 7. Validate string lengths and check for injection in psychologicalHook
  if (typeof rawJson.psychologicalHook !== 'string') {
    return { isValid: false, reason: 'psychologicalHook must be a string' };
  }
  const cleanPsychologicalHook = sanitizeString(rawJson.psychologicalHook);
  if (
    cleanPsychologicalHook.length < CONSTRAINTS.psychologicalHook.minLength ||
    cleanPsychologicalHook.length > CONSTRAINTS.psychologicalHook.maxLength
  ) {
    return {
      isValid: false,
      reason: `psychologicalHook length must be between ${CONSTRAINTS.psychologicalHook.minLength} and ${CONSTRAINTS.psychologicalHook.maxLength}`
    };
  }
  if (containsPromptInjection(rawJson.psychologicalHook)) {
    return { isValid: false, reason: 'Prompt injection or dangerous payload detected in psychologicalHook' };
  }

  // 8. Validate string lengths and check for injection in countermeasure
  if (typeof rawJson.countermeasure !== 'string') {
    return { isValid: false, reason: 'countermeasure must be a string' };
  }
  const cleanCountermeasure = sanitizeString(rawJson.countermeasure);
  if (
    cleanCountermeasure.length < CONSTRAINTS.countermeasure.minLength ||
    cleanCountermeasure.length > CONSTRAINTS.countermeasure.maxLength
  ) {
    return {
      isValid: false,
      reason: `countermeasure length must be between ${CONSTRAINTS.countermeasure.minLength} and ${CONSTRAINTS.countermeasure.maxLength}`
    };
  }
  if (containsPromptInjection(rawJson.countermeasure)) {
    return { isValid: false, reason: 'Prompt injection or dangerous payload detected in countermeasure' };
  }

  // 9. Validate signals array
  if (!Array.isArray(rawJson.signals)) {
    return { isValid: false, reason: 'signals must be an array' };
  }
  if (rawJson.signals.length > CONSTRAINTS.maxSignalsCount) {
    return {
      isValid: false,
      reason: `signals array exceeds maximum count of ${CONSTRAINTS.maxSignalsCount} items`
    };
  }

  const cleanSignals = [];
  for (let i = 0; i < rawJson.signals.length; i++) {
    const item = rawJson.signals[i];
    if (typeof item !== 'string') {
      return { isValid: false, reason: `signals item at index ${i} must be a string` };
    }
    const cleanItem = sanitizeString(item);
    if (
      cleanItem.length < CONSTRAINTS.signalItem.minLength ||
      cleanItem.length > CONSTRAINTS.signalItem.maxLength
    ) {
      return {
        isValid: false,
        reason: `signal item at index ${i} length out of range (${CONSTRAINTS.signalItem.minLength}..${CONSTRAINTS.signalItem.maxLength})`
      };
    }
    if (containsPromptInjection(item)) {
      return { isValid: false, reason: `Prompt injection detected in signal at index ${i}` };
    }
    cleanSignals.push(cleanItem);
  }

  // Return strictly validated and sanitized output
  return {
    isValid: true,
    data: {
      riskLevel: rawJson.riskLevel,
      riskScore: rawJson.riskScore,
      fraudVector: cleanFraudVector,
      psychologicalHook: cleanPsychologicalHook,
      countermeasure: cleanCountermeasure,
      confidence: Number(rawJson.confidence.toFixed(2)),
      signals: cleanSignals
    }
  };
}

module.exports = {
  validateThreatSchema,
  ALLOWED_RISK_LEVELS,
  CONSTRAINTS,
  sanitizeString,
  containsPromptInjection
};
