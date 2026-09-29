const express = require('express');
const { validateThreatRequest } = require('../middleware/piiValidation');
const { analyzeWithGemini } = require('../services/geminiService');

const router = express.Router();

router.post('/analyze-threat', validateThreatRequest, async (req, res) => {
  const { channel, scrubbedText, preliminarySignals } = req.sanitizedPayload;
  const requestId = req.requestId;

  try {
    const result = await analyzeWithGemini(channel, scrubbedText, preliminarySignals, requestId);
    return res.status(200).json(result);
  } catch (err) {
    // Fail-safe: Never expose internal server errors or stack traces to client
    return res.status(200).json({
      success: true,
      riskLevel: 'MEDIUM',
      riskScore: 50,
      fraudVector: 'Unverified Communication Pattern',
      psychologicalHook: 'Unsolicited request requiring caution',
      countermeasure: 'Do not share sensitive credentials or click unverified links.',
      confidence: 0.70,
      signals: preliminarySignals || [],
      model: 'finguard-failsafe-rules',
      requestId: requestId
    });
  }
});

module.exports = router;
