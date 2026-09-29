// Deterministic Local Fraud Reasoning Engine
// Used as guaranteed server-side fallback when Gemini API is unavailable, rate-limited, or offline.

function evaluateLocalFallback(channel, scrubbedText, signals = [], requestId = '') {
  const lower = scrubbedText.toLowerCase();

  let riskLevel = 'LOW';
  let riskScore = 15;
  let fraudVector = 'Authentic Communication Pattern';
  let psychologicalHook = 'Standard transactional or informational update';
  let countermeasure = 'Standard verification: Maintain routine security awareness.';
  let confidence = 0.88;
  const detectedSignals = [...signals];

  if (lower.includes('collect') || lower.includes('approve to receive') || lower.includes('enter pin')) {
    riskLevel = 'CRITICAL';
    riskScore = 95;
    fraudVector = 'Reverse UPI Collect Request Trap';
    psychologicalHook = 'Exploits misconception that entering UPI PIN receives money into account';
    countermeasure = 'Decline collect request immediately. UPI PIN is exclusively used for debiting money.';
    confidence = 0.98;
    if (!detectedSignals.includes('Reverse UPI Collect Request Trap')) {
      detectedSignals.push('Reverse UPI Collect Request Trap');
    }
  } else if (lower.includes('.apk') || lower.includes('install app') || lower.includes('download patch')) {
    riskLevel = 'CRITICAL';
    riskScore = 96;
    fraudVector = 'Sideloaded Banking Trojan / Remote Access Tool (RAT)';
    psychologicalHook = 'Fabricated compliance or account unlock requirement forcing APK download';
    countermeasure = 'Never download or install APK files from SMS/WhatsApp links. Install only from Google Play.';
    confidence = 0.97;
    if (!detectedSignals.includes('Sideloaded APK Malware Dropper')) {
      detectedSignals.push('Sideloaded APK Malware Dropper');
    }
  } else if (lower.includes('electricity') || lower.includes('power cut') || lower.includes('bill')) {
    riskLevel = 'HIGH';
    riskScore = 88;
    fraudVector = 'Utility Disconnection Impersonation Extortion';
    psychologicalHook = 'High-pressure manufactured urgency threatening immediate utility cutoff';
    countermeasure = 'Do not call telephone numbers in the SMS. Pay utilities exclusively through the official state electricity portal.';
    confidence = 0.94;
    if (!detectedSignals.includes('Utility Disconnection Scam Pattern')) {
      detectedSignals.push('Utility Disconnection Scam Pattern');
    }
  } else if (lower.includes('lottery') || lower.includes('kbc') || lower.includes('won') || lower.includes('part-time job') || lower.includes('earn daily')) {
    riskLevel = 'HIGH';
    riskScore = 90;
    fraudVector = 'Advance-Fee Job / Lottery Scam';
    psychologicalHook = 'Greed lure offering effortless high returns or cash prizes';
    countermeasure = 'Block sender. Legitimate organizations or employers never demand upfront fees or OTPs.';
    confidence = 0.95;
    if (!detectedSignals.includes('Advance-Fee / Lottery Pattern')) {
      detectedSignals.push('Advance-Fee / Lottery Pattern');
    }
  } else if (lower.includes('kyc') || lower.includes('pan') || lower.includes('blocked') || lower.includes('suspended')) {
    riskLevel = 'HIGH';
    riskScore = 86;
    fraudVector = 'Credential Harvester / Bank Phishing';
    psychologicalHook = 'Panic over frozen netbanking or account penalty';
    countermeasure = 'Never click banking links in text messages. Contact bank through official customer care.';
    confidence = 0.92;
    if (!detectedSignals.includes('Bank Phishing / KYC Trap')) {
      detectedSignals.push('Bank Phishing / KYC Trap');
    }
  }

  return {
    success: true,
    riskLevel,
    riskScore,
    fraudVector,
    psychologicalHook,
    countermeasure,
    confidence,
    signals: detectedSignals.slice(0, 10),
    model: 'finguard-deterministic-rules-v1',
    requestId: requestId || `req_local_${Date.now()}`
  };
}

module.exports = { evaluateLocalFallback };
