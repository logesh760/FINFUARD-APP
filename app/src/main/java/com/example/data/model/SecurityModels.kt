package com.example.data.model

enum class ThreatSeverity {
    SAFE,
    LOW_RISK,
    SUSPICIOUS,
    HIGH_RISK,
    CRITICAL
}

enum class ThreatCategory {
    SAFE_TRANSACTION,
    UPI_COLLECT_FRAUD,
    PHISHING_URL,
    BANK_IMPERSONATION,
    LOTTERY_JOB_SCAM,
    MALICIOUS_APK,
    OTP_THEFT,
    EXTORTION_THREAT
}

enum class IngestChannel {
    SMS,
    WHATSAPP,
    TELEGRAM,
    INSTAGRAM,
    MANUAL_SCAN
}

data class PiiScrubResult(
    val originalText: String,
    val scrubbedText: String,
    val redactedTokens: List<String>,
    val redactedCount: Int
)

data class BankTransactionInfo(
    val bankName: String,
    val senderHeader: String,
    val amount: String?,
    val isDebit: Boolean,
    val isCredit: Boolean,
    val isCollectRequest: Boolean,
    val accountMasked: String?,
    val vpaId: String?,
    val referenceNo: String?,
    val isSuspiciousCollect: Boolean
)

data class ScamScanResult(
    val riskScore: Int, // 0 to 100
    val severity: ThreatSeverity,
    val category: ThreatCategory,
    val threatSignals: List<String>,
    val piiResult: PiiScrubResult,
    val aiReasoning: String?,
    val bankInfo: BankTransactionInfo? = null,
    val structuredThreat: StructuredThreatResponse? = null
)

data class StructuredThreatResponse(
    val riskLevel: String,
    val riskScore: Int,
    val fraudVector: String,
    val psychologicalHook: String,
    val countermeasure: String,
    val confidence: Double,
    val signals: List<String>,
    val isLocalFallback: Boolean = false
)
