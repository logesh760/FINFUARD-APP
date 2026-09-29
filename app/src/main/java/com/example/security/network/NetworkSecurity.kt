package com.example.security.network

import java.security.SecureRandom
import java.util.UUID

/**
 * Network Security utility enforcing HTTPS-only transport, request tracking,
 * and cryptographic replay protection.
 */
object NetworkSecurity {

    private val secureRandom = SecureRandom()

    /**
     * Requirement 1: Enforces that all endpoints communicate strictly over HTTPS.
     * Throws SecurityException if cleartext HTTP is attempted.
     */
    fun ensureHttps(url: String) {
        if (!url.startsWith("https://", ignoreCase = true)) {
            throw SecurityException("Insecure cleartext HTTP is strictly prohibited. Endpoint must use HTTPS: $url")
        }
    }

    /**
     * Requirement 7: Generates a unique, non-sequential Request ID for end-to-end tracing.
     */
    fun generateRequestId(): String {
        return "req_${UUID.randomUUID()}"
    }

    /**
     * Requirement 12: Generates a cryptographically strong 128-bit hex nonce for replay protection.
     */
    fun generateNonce(): String {
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Requirement 12: Generates current UTC epoch timestamp in milliseconds for replay protection.
     */
    fun generateTimestamp(): Long {
        return System.currentTimeMillis()
    }

    /**
     * Verifies if a request timestamp is within the acceptable time drift window (default 5 minutes).
     */
    fun isTimestampValid(timestampMs: Long, allowedDriftMs: Long = 300_000L): Boolean {
        val now = System.currentTimeMillis()
        val drift = Math.abs(now - timestampMs)
        return drift <= allowedDriftMs
    }
}
