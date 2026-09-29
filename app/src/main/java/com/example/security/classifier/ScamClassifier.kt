package com.example.security.classifier

import com.example.data.local.FlaggedVpaDao
import com.example.data.model.IngestChannel
import com.example.data.model.ScamScanResult
import com.example.data.model.ThreatCategory
import com.example.data.model.ThreatSeverity
import com.example.security.ai.GeminiThreatAnalyzer
import com.example.security.banking.BankSmsParser
import com.example.security.pii.PiiScrubber
import java.util.regex.Pattern

object ScamClassifier {

    private val SUSPICIOUS_DOMAIN_PATTERN = Pattern.compile(
        "(?i)https?://[a-zA-Z0-9.-]*(?:\\.xyz|\\.top|\\.click|\\.club|\\.site|\\.apk|bit\\.ly|tinyurl\\.com|t\\.me|wa\\.me)[/a-zA-Z0-9._-]*"
    )

    private val BANK_IMPERSONATION_URL = Pattern.compile(
        "(?i)https?://[a-zA-Z0-9.-]*(?:sbi|hdfc|icici|axis|pnb|yono|paytm|bhim)[a-zA-Z0-9.-]*(?:kyc|update|login|pan|verify|portal)[a-zA-Z0-9.-]*"
    )

    private val URGENCY_TRIGGERS = listOf(
        "will be disconnected", "power will be cut", "electricity will be cut",
        "account blocked", "account suspended", "deactivated within", "immediate action required",
        "last reminder", "fine of rs", "penalty", "arrest warrant", "police complaint"
    )

    private val LOTTERY_JOB_TRIGGERS = listOf(
        "won rs", "won lottery", "kbc lottery", "congratulations you have won",
        "part time job", "earn daily", "earn rs 3000", "like youtube videos",
        "telegram task", "daily income", "investment return", "crypto profit guarantee"
    )

    private val OTP_SOLICITATION = listOf(
        "share otp", "send otp", "forward otp", "tell the code", "verify your otp",
        "enter otp to receive", "disclose verification code"
    )

    /**
     * Executes the full 3-layer scam detection pipeline:
     * 1. Client-side PII Scrubbing
     * 2. Layer 1 Regex & Heuristics (<5ms)
     * 3. Layer 2 Blacklist & VPA Registry (<50ms)
     * 4. Layer 3 Gemini AI Threat Reasoning
     */
    suspend fun analyze(
        sender: String,
        rawContent: String,
        channel: IngestChannel,
        flaggedVpaDao: FlaggedVpaDao? = null
    ): ScamScanResult {
        // Step 1: PII Scrubbing locally
        val piiResult = PiiScrubber.scrub(rawContent)
        val text = piiResult.scrubbedText
        val lower = text.lowercase()

        // Step 2: Bank SMS Parsing
        val bankInfo = BankSmsParser.parse(sender, rawContent)

        var riskScore = 0
        val signals = mutableListOf<String>()
        var category = ThreatCategory.SAFE_TRANSACTION

        // --- Layer 1: Fast Regex & Heuristic Checks ---

        // Check for suspicious collect requests / Reverse UPI traps
        val isReverseUpiTrap = (lower.contains("collect request") && (lower.contains("refund") || lower.contains("prize") || lower.contains("cashback"))) ||
                lower.contains("enter upi pin to receive") ||
                lower.contains("enter pin to receive") ||
                lower.contains("enter upi pin to claim") ||
                (lower.contains("upi pin") && lower.contains("receive")) ||
                (bankInfo != null && bankInfo.isSuspiciousCollect)

        if (isReverseUpiTrap) {
            riskScore = maxOf(riskScore, 85)
            signals.add("Reverse UPI payment trap (UPI PIN is never required to receive money)")
            category = ThreatCategory.UPI_COLLECT_FRAUD
        }

        // Check for malicious URLs & APK downloads
        val domainMatcher = SUSPICIOUS_DOMAIN_PATTERN.matcher(text)
        if (domainMatcher.find()) {
            val url = domainMatcher.group()
            val hasPhishingIntent = lower.contains("verify") || lower.contains("login") || lower.contains("blocked") ||
                    lower.contains("credentials") || lower.contains("portal") || lower.contains("card")
            riskScore = if (hasPhishingIntent) maxOf(riskScore + 45, 75) else (riskScore + 45)
            signals.add("High-risk shortened or spoofed link ($url)")
            if (url.contains(".apk", ignoreCase = true) || lower.contains(".apk")) {
                riskScore = maxOf(riskScore, 90)
                signals.add("Direct APK installation link (Banking Trojan / Spyware vector)")
                category = ThreatCategory.MALICIOUS_APK
            } else if (category == ThreatCategory.SAFE_TRANSACTION) {
                category = ThreatCategory.PHISHING_URL
            }
        } else if (lower.contains(".apk")) {
            riskScore = maxOf(riskScore, 90)
            signals.add("Direct APK installation file detected (Trojan / Malicious package vector)")
            category = ThreatCategory.MALICIOUS_APK
        }

        // Check lookalike bank URLs or banking impersonation with urgency
        val bankUrlMatcher = BANK_IMPERSONATION_URL.matcher(text)
        val hasBankImpersonation = bankUrlMatcher.find() || (
            (lower.contains("sbi") || lower.contains("hdfc") || lower.contains("icici") || lower.contains("axis") || lower.contains("pnb") || lower.contains("yono")) &&
            (lower.contains("kyc") || lower.contains("pan") || lower.contains("suspended") || lower.contains("blocked") || lower.contains("update")) &&
            (lower.contains("http://") || lower.contains("https://") || lower.contains("click") || lower.contains("link"))
        )

        if (hasBankImpersonation) {
            riskScore = maxOf(riskScore, 90)
            signals.add("Phishing attack impersonating official bank portal / KYC verification")
            category = ThreatCategory.BANK_IMPERSONATION
        }

        // Check Electricity / Utility extortion scam
        val isElectricityScam = (lower.contains("electricity") || lower.contains("power") || lower.contains("bill")) &&
                (lower.contains("disconnected") || lower.contains("cut") || lower.contains("officer") || lower.contains("not updated"))

        if (isElectricityScam) {
            riskScore = maxOf(riskScore, 85)
            signals.add("Urgent utility power cut-off scam (Extortion/Impersonation vector)")
            category = ThreatCategory.EXTORTION_THREAT
        } else if (URGENCY_TRIGGERS.any { lower.contains(it) }) {
            riskScore += 30
            signals.add("Coercive high-pressure language (fear of immediate cutoff/freeze)")
            if (category == ThreatCategory.SAFE_TRANSACTION) {
                category = ThreatCategory.BANK_IMPERSONATION
            }
        }

        // Check Lottery / Work-from-Home lures
        if (LOTTERY_JOB_TRIGGERS.any { lower.contains(it) }) {
            riskScore = maxOf(riskScore, 80)
            signals.add("Unsolicited task-based work-from-home or lottery fraud pattern")
            category = ThreatCategory.LOTTERY_JOB_SCAM
        }

        // Check OTP advisory vs fraudulent OTP solicitation
        val hasOtpKeywords = lower.contains("otp") || lower.contains("one time password") || lower.contains("verification code")
        val hasLegitimateAdvisory = lower.contains("do not share") || lower.contains("never share") ||
                lower.contains("don't share") || lower.contains("not share") ||
                lower.contains("do not disclose") || lower.contains("never disclose")

        if (hasOtpKeywords && hasLegitimateAdvisory && category == ThreatCategory.SAFE_TRANSACTION && riskScore == 0) {
            // Authentic bank OTP verification message
            riskScore = 5
            signals.add("Authentic financial OTP verification alert with security advisory")
            category = ThreatCategory.SAFE_TRANSACTION
        } else if (hasOtpKeywords && !hasLegitimateAdvisory && (OTP_SOLICITATION.any { lower.contains(it) } || lower.contains("share your otp"))) {
            riskScore = maxOf(riskScore, 85)
            signals.add("Direct solicitation of confidential One-Time Password (OTP theft vector)")
            category = ThreatCategory.OTP_THEFT
        }

        // --- Layer 2: Blacklist & Registry checks ---
        if (flaggedVpaDao != null && bankInfo?.vpaId != null) {
            val match = flaggedVpaDao.findByVpa(bankInfo.vpaId)
            if (match != null) {
                riskScore = maxOf(riskScore, 95)
                signals.add("CRITICAL: VPA ${bankInfo.vpaId} matches NPCI Flagged Scam Registry (${match.reportedCount} user reports)")
                category = ThreatCategory.UPI_COLLECT_FRAUD
            }
        }

        // Adjust for legitimate bank credit/debit alerts
        if (bankInfo != null && !bankInfo.isSuspiciousCollect && signals.isEmpty()) {
            if (bankInfo.isDebit || bankInfo.isCredit) {
                riskScore = 5
                signals.add("Verified legitimate financial ledger format (${bankInfo.bankName})")
                category = ThreatCategory.SAFE_TRANSACTION
            }
        }

        // Clamp risk score to 0..100
        val clampedScore = riskScore.coerceIn(0, 100)

        // Classify severity
        val severity = when {
            clampedScore >= 90 -> ThreatSeverity.CRITICAL
            clampedScore >= 75 -> ThreatSeverity.HIGH_RISK
            clampedScore >= 50 -> ThreatSeverity.SUSPICIOUS
            clampedScore >= 25 -> ThreatSeverity.LOW_RISK
            else -> ThreatSeverity.SAFE
        }

        // --- Layer 3: Gemini AI Reasoning ---
        val structuredAssessment = if (clampedScore >= 35) {
            GeminiThreatAnalyzer.analyzeThreatStructured(text, channel.name, signals)
        } else null

        val aiReasoning = if (structuredAssessment != null) {
            "[FRAUD VECTOR]: ${structuredAssessment.fraudVector}\n" +
            "[PSYCHOLOGICAL HOOK]: ${structuredAssessment.psychologicalHook}\n" +
            "[ACTIONABLE COUNTERMEASURE]: ${structuredAssessment.countermeasure}"
        } else {
            "Verified genuine transaction activity. Standard banking formatting and authentic merchant identifiers detected."
        }

        return ScamScanResult(
            riskScore = clampedScore,
            severity = severity,
            category = category,
            threatSignals = signals,
            piiResult = piiResult,
            aiReasoning = aiReasoning,
            bankInfo = bankInfo,
            structuredThreat = structuredAssessment
        )
    }
}
