// Server-Side Gemini AI Service
// Uses process.env.GEMINI_API_KEY exclusively on server side.
const { evaluateLocalFallback } = require('./localExpertEngine');
const { validateThreatSchema } = require('./structuredValidator');

const MODEL_NAME = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const GEMINI_API_BASE = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:generateContent`;
const TIMEOUT_MS = process.env.NODE_ENV === 'test' ? 1200 : 4000;
const MAX_RETRIES = 1;

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// OpenAPI-compliant JSON schema for Gemini structured output
const GEMINI_RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    riskLevel: {
      type: 'STRING',
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      description: 'Threat risk category classification'
    },
    riskScore: {
      type: 'INTEGER',
      description: 'Numerical risk assessment from 0 (safe) to 100 (critical)'
    },
    fraudVector: {
      type: 'STRING',
      description: 'Specific attack vector or mechanism'
    },
    psychologicalHook: {
      type: 'STRING',
      description: 'Psychological manipulation or social engineering technique'
    },
    countermeasure: {
      type: 'STRING',
      description: 'Concise, actionable advice for the victim'
    },
    confidence: {
      type: 'NUMBER',
      description: 'Model confidence score between 0.0 and 1.0'
    },
    signals: {
      type: 'ARRAY',
      items: { type: 'STRING' },
      description: 'Array of detected threat signals and forensic indicators'
    }
  },
  required: [
    'riskLevel',
    'riskScore',
    'fraudVector',
    'psychologicalHook',
    'countermeasure',
    'confidence',
    'signals'
  ]
};

/**
 * Safely parses and validates the raw Gemini response string.
 * Never exposes raw model text, tokens, or unvalidated fields.
 * If validation fails, returns null.
 */
function parseAndValidateModelResponse(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    return null; // Malformed JSON syntax rejected
  }

  const validation = validateThreatSchema(parsed);
  if (!validation.isValid) {
    return null; // Schema violation, out-of-range, or prompt injection rejected
  }

  return validation.data;
}

async function analyzeWithGemini(channel, scrubbedText, preliminarySignals = [], requestId = '') {
  const apiKey = process.env.GEMINI_API_KEY;

  // If no server-side API key configured, use deterministic expert engine
  if (!apiKey || apiKey === 'your_server_gemini_api_key_here') {
    return evaluateLocalFallback(channel, scrubbedText, preliminarySignals, requestId);
  }

  const systemPrompt = `You are FinGuard AI, an elite cybersecurity and financial fraud investigator.
Analyze the incoming ${channel} communication (all PII is already redacted).
Evaluate the threat and return strict JSON conforming to the requested schema.
Requirements:
- "riskLevel": one of "LOW", "MEDIUM", "HIGH", "CRITICAL"
- "riskScore": integer from 0 to 100
- "fraudVector": specific attack method (e.g. Reverse UPI Collect, Sideloaded APK Malware, KYC Phishing)
- "psychologicalHook": manipulation tactic (e.g. Manufactured Urgency, Greed/Prize Lure, Fear of Penalty)
- "countermeasure": concise actionable advice for the victim
- "confidence": float between 0.0 and 1.0
- "signals": array of strings identifying threat indicators (max 10 items)`;

  const payload = {
    contents: [
      {
        parts: [
          { text: systemPrompt },
          { text: `COMMUNICATION CHANNEL: ${channel}\nMESSAGE:\n"""${scrubbedText}"""\n\nPRELIMINARY SIGNALS: ${preliminarySignals.join(', ')}` }
        ]
      }
    ],
    generationConfig: {
      temperature: 0.1,
      maxOutputTokens: 500,
      responseMimeType: 'application/json',
      responseSchema: GEMINI_RESPONSE_SCHEMA
    }
  };

  let attempt = 0;

  while (attempt <= MAX_RETRIES) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const response = await fetch(`${GEMINI_API_BASE}?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // Handle Rate Limiting / 429 Quota Exhaustion immediately with deterministic fallback
      if (response.status === 429) {
        break;
      }

      // Retry only transient 503/504 gateway errors
      if (response.status === 503 || response.status === 504) {
        attempt++;
        if (attempt <= MAX_RETRIES) {
          await sleep(50);
          continue;
        }
        break;
      }

      if (!response.ok) {
        break;
      }

      const responseData = await response.json();
      const rawText = responseData?.candidates?.[0]?.content?.parts?.[0]?.text;

      if (!rawText) {
        break;
      }

      // Validate schema on backend - reject malformed responses, enforce enums, score, confidence, lengths
      const validatedData = parseAndValidateModelResponse(rawText);
      if (!validatedData) {
        // Validation failed (schema violation, injection, or invalid bounds) -> use deterministic local fallback
        break;
      }

      // Return strict validated schema — never expose raw Gemini response to Android
      return {
        success: true,
        riskLevel: validatedData.riskLevel,
        riskScore: validatedData.riskScore,
        fraudVector: validatedData.fraudVector,
        psychologicalHook: validatedData.psychologicalHook,
        countermeasure: validatedData.countermeasure,
        confidence: validatedData.confidence,
        signals: validatedData.signals,
        model: 'gemini-3.5-flash',
        requestId: requestId
      };
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        break; // Timeout reached, return local fallback immediately
      }
      attempt++;
      if (attempt <= MAX_RETRIES) {
        await sleep(50);
      }
    }
  }

  // Graceful deterministic fallback
  return evaluateLocalFallback(channel, scrubbedText, preliminarySignals, requestId);
}

module.exports = {
  analyzeWithGemini,
  parseAndValidateModelResponse,
  GEMINI_RESPONSE_SCHEMA
};
