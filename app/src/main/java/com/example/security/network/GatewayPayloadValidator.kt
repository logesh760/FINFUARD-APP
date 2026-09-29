package com.example.security.network

import com.example.data.model.StructuredThreatResponse
import org.json.JSONObject

/**
 * Enforces strict input and output schema validation and payload size limits
 * on all AI Gateway communication.
 */
object GatewayPayloadValidator {

    const val MAX_REQUEST_SIZE_BYTES = 32 * 1024 // 32 KB limit
    const val MAX_TEXT_LENGTH = 10_000
    const val MAX_SIGNALS_COUNT = 10
    const val MAX_SIGNAL_LENGTH = 120

    private val ALLOWED_CHANNELS = setOf(
        "SMS", "WHATSAPP", "TELEGRAM", "INSTAGRAM", "EMAIL", "CALL", "NOTIFICATION", "OTHER"
    )

    private val ALLOWED_RISK_LEVELS = setOf(
        "LOW", "MEDIUM", "HIGH", "CRITICAL"
    )

    /**
     * Requirement 9: Validates request payload body size.
     */
    fun validateRequestBodySize(bytes: ByteArray) {
        if (bytes.size > MAX_REQUEST_SIZE_BYTES) {
            throw IllegalArgumentException(
                "Request payload size (${bytes.size} bytes) exceeds maximum limit of $MAX_REQUEST_SIZE_BYTES bytes."
            )
        }
    }

    /**
     * Requirement 10: Strict input schema validation.
     */
    fun validateInput(channel: String, scrubbedText: String, signals: List<String>) {
        val normalizedChannel = channel.trim().uppercase()
        if (normalizedChannel !in ALLOWED_CHANNELS) {
            throw IllegalArgumentException("Invalid channel identifier: $channel. Allowed: $ALLOWED_CHANNELS")
        }

        if (scrubbedText.isBlank()) {
            throw IllegalArgumentException("Scrubbed text must not be empty or blank.")
        }

        if (scrubbedText.length > MAX_TEXT_LENGTH) {
            throw IllegalArgumentException("Input text exceeds maximum allowed length ($MAX_TEXT_LENGTH characters).")
        }

        // Check for disallowed control / null characters
        if (scrubbedText.contains('\u0000')) {
            throw IllegalArgumentException("Input contains prohibited null control character.")
        }

        if (signals.size > MAX_SIGNALS_COUNT) {
            throw IllegalArgumentException("Signals list exceeds max limit of $MAX_SIGNALS_COUNT items.")
        }

        signals.forEach { signal ->
            if (signal.length > MAX_SIGNAL_LENGTH) {
                throw IllegalArgumentException("Signal item exceeds max length of $MAX_SIGNAL_LENGTH characters.")
            }
        }
    }

    /**
     * Requirement 11: Strict output schema validation on gateway JSON response.
     */
    fun validateOutput(responseBody: String): StructuredThreatResponse {
        val json = try {
            JSONObject(responseBody)
        } catch (e: Exception) {
            throw IllegalArgumentException("Response is not valid JSON.", e)
        }

        if (!json.has("success") || !json.optBoolean("success")) {
            val errorMsg = json.optString("error", "Unknown gateway processing error")
            throw IllegalStateException("Gateway responded with failure: $errorMsg")
        }

        val riskLevel = json.optString("riskLevel", "").trim().uppercase()
        if (riskLevel !in ALLOWED_RISK_LEVELS) {
            throw IllegalArgumentException("Invalid or missing riskLevel in output schema: '$riskLevel'")
        }

        if (!json.has("riskScore")) {
            throw IllegalArgumentException("Missing riskScore in output schema.")
        }
        val riskScore = json.getInt("riskScore")
        if (riskScore !in 0..100) {
            throw IllegalArgumentException("riskScore ($riskScore) out of valid bounds (0..100).")
        }

        val fraudVector = json.optString("fraudVector", "").trim()
        if (fraudVector.isBlank()) {
            throw IllegalArgumentException("Missing or blank fraudVector in output schema.")
        }

        val psychologicalHook = json.optString("psychologicalHook", "Suspicious interaction detected").trim()
        val countermeasure = json.optString("countermeasure", "Verify authenticity through official channels").trim()

        val confidence = json.optDouble("confidence", 0.85)
        if (confidence !in 0.0..1.0) {
            throw IllegalArgumentException("confidence ($confidence) out of valid bounds (0.0..1.0).")
        }

        val signalsList = mutableListOf<String>()
        val signalsArr = json.optJSONArray("signals")
        if (signalsArr != null) {
            for (i in 0 until minOf(signalsArr.length(), MAX_SIGNALS_COUNT)) {
                val item = signalsArr.optString(i, "").trim()
                if (item.isNotEmpty()) {
                    signalsList.add(item.take(MAX_SIGNAL_LENGTH))
                }
            }
        }

        return StructuredThreatResponse(
            riskLevel = riskLevel,
            riskScore = riskScore,
            fraudVector = fraudVector,
            psychologicalHook = psychologicalHook,
            countermeasure = countermeasure,
            confidence = confidence,
            signals = signalsList,
            isLocalFallback = false
        )
    }
}
