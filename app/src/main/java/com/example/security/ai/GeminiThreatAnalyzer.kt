package com.example.security.ai

import com.example.data.model.StructuredThreatResponse
import com.example.security.auth.AuthTokenManager
import com.example.security.logging.SecureLogger
import com.example.security.network.ClientRateLimiter
import com.example.security.network.GatewayPayloadValidator
import com.example.security.network.NetworkSecurity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Backend AI Gateway Client for FinGuard Security with Enterprise-Grade API Security Hardening (Phase 5).
 *
 * Security Architecture:
 * 1. HTTPS only transport enforcement.
 * 2. Certificate validation via system trust anchors.
 * 3. Dynamic authentication architecture with short-lived session access tokens.
 * 4. Secure in-memory token storage with dynamic refresh and zero secrets in source code.
 * 5. Request authentication with Bearer token headers.
 * 6. Unique Request IDs (X-Request-ID) for auditable transaction tracing.
 * 7. Client-side rate limiting to prevent API abuse and cost inflation.
 * 8. Strict request payload body size limits (32 KB max).
 * 9. Input schema validation (channel, length, forbidden control characters).
 * 10. Output schema validation (strict JSON verification, range & enum validation).
 * 11. Cryptographic replay protection via X-Timestamp and 128-bit X-Nonce.
 * 12. Server-side authorization claims (role, package identity, client version).
 * 13. Secure error responses and zero leakage of stack traces or credentials.
 * 14. Zero secrets, zero API keys, and zero PII written to logs.
 * 15. Circuit Breaker protection and local deterministic fallback.
 */
object GeminiThreatAnalyzer {

    private const val TAG = "BackendAiGateway"

    // Default production gateway endpoint (Strictly HTTPS).
    var gatewayBaseUrl: String = "https://gateway.finguard.internal"

    var okHttpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .build()

    var authTokenManager: AuthTokenManager = AuthTokenManager()

    var rateLimiter: ClientRateLimiter = ClientRateLimiter(
        maxPermits = 10,
        windowDurationMs = 60_000L
    )

    var circuitBreaker: GatewayCircuitBreaker = GatewayCircuitBreaker(
        failureThreshold = 3,
        resetTimeoutMs = 30_000L
    )

    var retryPolicy: GatewayRetryPolicy = GatewayRetryPolicy(
        maxRetries = 2,
        initialBackoffMs = 500L,
        maxBackoffMs = 4000L,
        backoffMultiplier = 2.0,
        maxRetryAfterSeconds = 10L
    )

    // Configurable delay provider for coroutine backoff (can be customized or bypassed in unit tests)
    var delayProvider: suspend (Long) -> Unit = { durationMs ->
        if (durationMs > 0) {
            delay(durationMs)
        }
    }

    // Telemetry & verification metrics
    @Volatile var lastAttemptCount: Int = 0
    @Volatile var lastRetryReason: String? = null
    @Volatile var lastUsedFallback: Boolean = false
    @Volatile var lastHttpStatus: Int = 0
    @Volatile var lastRequestId: String? = null

    /**
     * Sends sanitized, PII-scrubbed payload to the secure backend AI Gateway.
     * Incorporates end-to-end API security hardening, input/output validation, and deterministic local fallback.
     */
    suspend fun analyzeThreatStructured(
        scrubbedText: String,
        channel: String,
        preliminarySignals: List<String>
    ): StructuredThreatResponse = withContext(Dispatchers.IO) {
        lastAttemptCount = 0
        lastRetryReason = null
        lastUsedFallback = false
        lastHttpStatus = 0
        lastRequestId = null

        // 1. Input Schema Validation
        try {
            GatewayPayloadValidator.validateInput(channel, scrubbedText, preliminarySignals)
        } catch (e: Exception) {
            SecureLogger.w(TAG, "Input schema validation rejected request: ${e.message}")
            lastUsedFallback = true
            lastRetryReason = "INVALID_INPUT_SCHEMA"
            return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
        }

        // 2. Transport Security: Ensure HTTPS-only
        try {
            NetworkSecurity.ensureHttps(gatewayBaseUrl)
        } catch (e: SecurityException) {
            SecureLogger.e(TAG, "Transport security failure: ${e.message}")
            lastUsedFallback = true
            lastRetryReason = "INSECURE_HTTP_PROHIBITED"
            return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
        }

        // 3. Client Rate Limiting: Prevent API abuse or runaway loop costs
        if (!rateLimiter.tryAcquire()) {
            SecureLogger.w(TAG, "Client rate limit reached. Throttling request to protect backend and local resources.")
            lastUsedFallback = true
            lastRetryReason = "CLIENT_RATE_LIMITED"
            return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
        }

        // 4. Circuit Breaker Protection: If tripped, fast-fail immediately without network calls
        if (!circuitBreaker.canExecute()) {
            SecureLogger.w(TAG, "Gateway Circuit Breaker is OPEN. Fast-failing directly to local deterministic engine.")
            lastUsedFallback = true
            lastRetryReason = "CIRCUIT_BREAKER_OPEN"
            return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
        }

        // 5. Construct Secure JSON Payload
        val requestJson = JSONObject().apply {
            put("channel", channel)
            put("scrubbedText", scrubbedText)
            val signalsArray = JSONArray()
            preliminarySignals.forEach { signalsArray.put(it) }
            put("preliminarySignals", signalsArray)
        }
        val payloadString = requestJson.toString()
        val payloadBytes = payloadString.toByteArray(Charsets.UTF_8)

        // 6. Request Body Size Limit
        try {
            GatewayPayloadValidator.validateRequestBodySize(payloadBytes)
        } catch (e: IllegalArgumentException) {
            SecureLogger.w(TAG, "Request payload exceeds size limit: ${e.message}")
            lastUsedFallback = true
            lastRetryReason = "PAYLOAD_TOO_LARGE"
            return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
        }

        val requestBody = payloadBytes.toRequestBody("application/json".toMediaType())
        val endpoint = "$gatewayBaseUrl/api/v1/ai/analyze-threat"
        val totalMaxAttempts = 1 + retryPolicy.maxRetries

        for (attempt in 0 until totalMaxAttempts) {
            lastAttemptCount = attempt + 1

            // Dynamic Token Retrieval from Authentication Architecture
            val token = try {
                authTokenManager.getValidToken()
            } catch (e: Exception) {
                SecureLogger.e(TAG, "Failed to obtain valid session token: ${e.message}")
                lastUsedFallback = true
                lastRetryReason = "AUTH_TOKEN_ACQUISITION_FAILED"
                return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
            }

            // Security Headers: Request ID, Replay Protection (Nonce & Timestamp), Authorization Context
            val requestId = NetworkSecurity.generateRequestId()
            lastRequestId = requestId
            val timestamp = NetworkSecurity.generateTimestamp().toString()
            val nonce = NetworkSecurity.generateNonce()

            val request = Request.Builder()
                .url(endpoint)
                .addHeader("Content-Type", "application/json")
                .addHeader("Authorization", "${token.tokenType} ${token.tokenValue}")
                .addHeader("X-Request-ID", requestId)
                .addHeader("X-Timestamp", timestamp)
                .addHeader("X-Nonce", nonce)
                .addHeader("X-Client-Role", "security_agent")
                .addHeader("X-App-Version", "1.0")
                .addHeader("X-Package-ID", "com.aistudio.finguard.secxz")
                .post(requestBody)
                .build()

            try {
                val response = okHttpClient.newCall(request).execute()
                val code = response.code
                lastHttpStatus = code
                val responseBody = response.body?.string()

                if (response.isSuccessful && !responseBody.isNullOrBlank()) {
                    try {
                        // Strict Output Schema Validation
                        val parsed = GatewayPayloadValidator.validateOutput(responseBody)
                        circuitBreaker.recordSuccess()
                        lastUsedFallback = false
                        return@withContext parsed
                    } catch (e: Exception) {
                        SecureLogger.w(TAG, "Malformed or invalid gateway output schema: ${e.message}. Skipping unsafe retry.")
                        lastUsedFallback = true
                        lastRetryReason = "MALFORMED_RESPONSE"
                        return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
                    }
                }

                // Authentication Failure (HTTP 401, 403): Invalidate session and abort without retry
                if (code == 401 || code == 403) {
                    SecureLogger.e(TAG, "Gateway authentication rejected (HTTP $code). Invalidating token session.")
                    authTokenManager.invalidateSession()
                    lastUsedFallback = true
                    lastRetryReason = "AUTH_FAILURE_$code"
                    return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
                }

                // Client Validation Error (HTTP 400..499, except 429): Abort without retry
                if (code in 400..499 && code != 429) {
                    SecureLogger.e(TAG, "Gateway client validation error (HTTP $code). Will not retry.")
                    lastUsedFallback = true
                    lastRetryReason = "CLIENT_ERROR_$code"
                    return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
                }

                // Retryable Server & Rate Limit Responses (HTTP 429, 500, 502, 503, 504)
                if (retryPolicy.isRetryableStatusCode(code)) {
                    circuitBreaker.recordFailure()
                    val retryAfterHeader = response.header("Retry-After")
                    val backoffMs = retryPolicy.computeBackoffMs(attempt, retryAfterHeader)

                    if (backoffMs < 0) {
                        SecureLogger.w(TAG, "Retry-After header exceeds allowed threshold. Aborting to fallback.")
                        lastUsedFallback = true
                        lastRetryReason = "RETRY_AFTER_EXCEEDED"
                        return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
                    }

                    if (attempt < totalMaxAttempts - 1) {
                        lastRetryReason = "HTTP_$code"
                        SecureLogger.i(TAG, "Transient HTTP $code on attempt ${attempt + 1}. Retrying safely...")
                        delayProvider(backoffMs)
                        continue
                    } else {
                        SecureLogger.w(TAG, "Gateway retries exhausted for HTTP $code. Using deterministic local fallback.")
                        lastUsedFallback = true
                        lastRetryReason = "RETRIES_EXHAUSTED_HTTP_$code"
                        return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
                    }
                }

                lastUsedFallback = true
                return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)

            } catch (e: Exception) {
                // Network or Timeout failures
                if (retryPolicy.isRetryableException(e)) {
                    circuitBreaker.recordFailure()
                    if (attempt < totalMaxAttempts - 1) {
                        val backoffMs = retryPolicy.computeBackoffMs(attempt)
                        lastRetryReason = e.javaClass.simpleName
                        SecureLogger.i(TAG, "Transient network issue (${e.javaClass.simpleName}) on attempt ${attempt + 1}. Retrying...")
                        delayProvider(backoffMs)
                        continue
                    } else {
                        SecureLogger.w(TAG, "Gateway retries exhausted for network error. Using deterministic local fallback.")
                        lastUsedFallback = true
                        lastRetryReason = "RETRIES_EXHAUSTED_${e.javaClass.simpleName}"
                        return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
                    }
                } else {
                    SecureLogger.e(TAG, "Fatal non-retryable exception: ${e.message}")
                    lastUsedFallback = true
                    lastRetryReason = "NON_RETRYABLE_EXCEPTION"
                    return@withContext generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
                }
            }
        }

        lastUsedFallback = true
        generateLocalExpertAssessmentStructured(scrubbedText, channel, preliminarySignals)
    }

    /**
     * Backward-compatible helper returning structured analysis formatted as readable text.
     */
    suspend fun analyzeThreat(
        scrubbedText: String,
        channel: String,
        preliminarySignals: List<String>
    ): String {
        val structured = analyzeThreatStructured(scrubbedText, channel, preliminarySignals)
        return "[FRAUD VECTOR]: ${structured.fraudVector}\n" +
                "[PSYCHOLOGICAL HOOK]: ${structured.psychologicalHook}\n" +
                "[ACTIONABLE COUNTERMEASURE]: ${structured.countermeasure}"
    }

    /**
     * Deterministic local fraud engine returning structured response.
     * Guarantees 100% scam detection availability even with zero network connectivity.
     */
    fun generateLocalExpertAssessmentStructured(
        text: String,
        channel: String,
        signals: List<String>
    ): StructuredThreatResponse {
        val lower = text.lowercase()
        return when {
            lower.contains("collect") || lower.contains("approve to receive") || lower.contains("enter pin") ->
                StructuredThreatResponse(
                    riskLevel = "CRITICAL",
                    riskScore = 95,
                    fraudVector = "Reverse UPI Collect Trap",
                    psychologicalHook = "Exploits misconception that entering UPI PIN receives money into account",
                    countermeasure = "Decline the collect request immediately. UPI PIN is exclusively used for debiting money.",
                    confidence = 0.98,
                    signals = (signals + "Reverse UPI Collect Trap").distinct().take(10),
                    isLocalFallback = true
                )

            lower.contains(".apk") || lower.contains("download app") || lower.contains("install") ->
                StructuredThreatResponse(
                    riskLevel = "CRITICAL",
                    riskScore = 96,
                    fraudVector = "Sideloaded Banking Trojan / Remote Access Tool (RAT)",
                    psychologicalHook = "Fake utility or government compliance requirement forcing APK download",
                    countermeasure = "Never install APK files from SMS/WhatsApp links. Install apps only via Google Play.",
                    confidence = 0.97,
                    signals = (signals + "Sideloaded APK Malware Dropper").distinct().take(10),
                    isLocalFallback = true
                )

            lower.contains("electricity") || lower.contains("power") || lower.contains("bill") ->
                StructuredThreatResponse(
                    riskLevel = "HIGH",
                    riskScore = 88,
                    fraudVector = "Utility Bill Impersonation Extortion",
                    psychologicalHook = "High-pressure fear and urgency threatening immediate utility cutoff",
                    countermeasure = "Do not call unverified numbers. Pay bills solely through official state electricity board portals.",
                    confidence = 0.94,
                    signals = (signals + "Utility Disconnection Scam Pattern").distinct().take(10),
                    isLocalFallback = true
                )

            lower.contains("lottery") || lower.contains("kbc") || lower.contains("won") || lower.contains("job") ->
                StructuredThreatResponse(
                    riskLevel = "HIGH",
                    riskScore = 90,
                    fraudVector = "Advance-Fee Job / Lottery Scam",
                    psychologicalHook = "Greed and effortless reward lure with false legitimacy",
                    countermeasure = "Block sender and report phone number. Legitimate employers or lotteries never demand upfront fees.",
                    confidence = 0.95,
                    signals = (signals + "Advance-Fee / Lottery Pattern").distinct().take(10),
                    isLocalFallback = true
                )

            lower.contains("kyc") || lower.contains("pan") || lower.contains("blocked") || lower.contains("suspend") ->
                StructuredThreatResponse(
                    riskLevel = "HIGH",
                    riskScore = 86,
                    fraudVector = "Credential Harvester / Bank Phishing",
                    psychologicalHook = "Panic over frozen netbanking or account penalty",
                    countermeasure = "Never enter credentials on web links. Visit official bank branch or official app directly.",
                    confidence = 0.92,
                    signals = (signals + "Bank Phishing / KYC Trap").distinct().take(10),
                    isLocalFallback = true
                )

            else ->
                StructuredThreatResponse(
                    riskLevel = if (signals.isNotEmpty()) "MEDIUM" else "LOW",
                    riskScore = if (signals.isNotEmpty()) 50 else 15,
                    fraudVector = "Suspicious Communication Pattern via $channel",
                    psychologicalHook = if (signals.isNotEmpty()) signals.first() else "Standard transactional update",
                    countermeasure = "Verify sender authenticity through official channels before sharing information.",
                    confidence = 0.85,
                    signals = signals.take(10),
                    isLocalFallback = true
                )
        }
    }

    /**
     * Backward-compatible text helper.
     */
    fun generateLocalExpertAssessment(
        text: String,
        channel: String,
        signals: List<String>
    ): String {
        val s = generateLocalExpertAssessmentStructured(text, channel, signals)
        return "[FRAUD VECTOR]: ${s.fraudVector}\n" +
                "[PSYCHOLOGICAL HOOK]: ${s.psychologicalHook}\n" +
                "[ACTIONABLE COUNTERMEASURE]: ${s.countermeasure}"
    }
}
