package com.example.security.network

import com.example.security.auth.AuthToken
import com.example.security.auth.AuthTokenManager
import com.example.security.auth.InMemorySecureTokenStorage
import com.example.security.logging.SecureLogger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ApiSecurityHardeningTest {

    // 1. HTTPS Only
    @Test
    fun `test cleartext HTTP is strictly rejected`() {
        try {
            NetworkSecurity.ensureHttps("http://insecure-backend.internal/api")
            fail("Expected SecurityException for cleartext HTTP")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("Insecure cleartext HTTP is strictly prohibited"))
        }

        // HTTPS passes without exception
        NetworkSecurity.ensureHttps("https://secure-gateway.finguard.internal/api")
    }

    // 2. Request ID Generation
    @Test
    fun `test request IDs are unique and formatted with req prefix`() {
        val id1 = NetworkSecurity.generateRequestId()
        val id2 = NetworkSecurity.generateRequestId()
        assertTrue(id1.startsWith("req_"))
        assertTrue(id2.startsWith("req_"))
        assertFalse(id1 == id2)
    }

    // 3. Replay Protection: Nonce & Timestamp
    @Test
    fun `test nonce generation and timestamp validation`() {
        val nonce1 = NetworkSecurity.generateNonce()
        val nonce2 = NetworkSecurity.generateNonce()
        assertEquals(32, nonce1.length) // 16 bytes = 32 hex chars
        assertFalse(nonce1 == nonce2)

        val now = System.currentTimeMillis()
        assertTrue(NetworkSecurity.isTimestampValid(now))
        assertTrue(NetworkSecurity.isTimestampValid(now - 60_000L)) // 1 min ago is valid
        assertFalse(NetworkSecurity.isTimestampValid(now - 600_000L)) // 10 min ago exceeds 5 min drift
    }

    // 4. Client Rate Limiter
    @Test
    fun `test client rate limiter enforces max permits within window`() {
        var currentTime = 1000L
        val limiter = ClientRateLimiter(maxPermits = 3, windowDurationMs = 10_000L, clock = { currentTime })

        assertTrue(limiter.tryAcquire())
        assertTrue(limiter.tryAcquire())
        assertTrue(limiter.tryAcquire())
        // 4th request within window is rate-limited
        assertFalse(limiter.tryAcquire())

        // Advance past window duration
        currentTime += 10_001L
        assertTrue(limiter.tryAcquire())
    }

    // 5. Short-lived Access Token Lifecycle & Secure Storage
    @Test
    fun `test auth token expiration and refresh lifecycle`() = runBlocking {
        val storage = InMemorySecureTokenStorage()
        var tokenCounter = 1

        val manager = AuthTokenManager(
            storage = storage,
            tokenProvider = {
                AuthToken(
                    tokenValue = "token_${tokenCounter++}",
                    expiresAtEpochMs = System.currentTimeMillis() + 60_000L // 1 minute
                )
            }
        )

        val firstToken = manager.getValidToken()
        assertEquals("token_1", firstToken.tokenValue)
        assertFalse(firstToken.isExpired())

        // Re-requesting before expiry returns same token
        val sameToken = manager.getValidToken()
        assertEquals("token_1", sameToken.tokenValue)

        // If storage is cleared or invalidated, generates fresh token
        manager.invalidateSession()
        val refreshedToken = manager.getValidToken()
        assertEquals("token_2", refreshedToken.tokenValue)

        // Verify toString redacts sensitive token value
        assertTrue(refreshedToken.toString().contains("[REDACTED]"))
        assertFalse(refreshedToken.toString().contains("token_2"))
    }

    // 6. Request Body Size Limit
    @Test
    fun `test payload validator rejects request exceeding size budget`() {
        val validBytes = ByteArray(1024) // 1 KB
        GatewayPayloadValidator.validateRequestBodySize(validBytes)

        val oversizedBytes = ByteArray(35 * 1024) // 35 KB exceeds 32 KB limit
        try {
            GatewayPayloadValidator.validateRequestBodySize(oversizedBytes)
            fail("Expected IllegalArgumentException for oversized payload")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("exceeds maximum limit"))
        }
    }

    // 7. Input Schema Validation
    @Test
    fun `test input schema validator checks channels and forbidden characters`() {
        // Valid input
        GatewayPayloadValidator.validateInput("SMS", "Scrubbed safe text", listOf("Urgency"))

        // Invalid channel
        try {
            GatewayPayloadValidator.validateInput("UNTRUSTED_SOCKET", "Text", emptyList())
            fail("Expected exception for invalid channel")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Invalid channel"))
        }

        // Empty text
        try {
            GatewayPayloadValidator.validateInput("SMS", "   ", emptyList())
            fail("Expected exception for empty text")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("must not be empty"))
        }

        // Null byte injection attempt
        try {
            GatewayPayloadValidator.validateInput("SMS", "Text with \u0000 control char", emptyList())
            fail("Expected exception for null control char")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("prohibited null control character"))
        }

        // Excess signals count
        val excessSignals = (1..15).map { "Signal $it" }
        try {
            GatewayPayloadValidator.validateInput("SMS", "Text", excessSignals)
            fail("Expected exception for excess signals")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("exceeds max limit"))
        }
    }

    // 8. Output Schema Validation
    @Test
    fun `test output schema validation on gateway responses`() {
        val validJson = """
            {
                "success": true,
                "riskLevel": "CRITICAL",
                "riskScore": 95,
                "fraudVector": "Reverse UPI Collect Trap",
                "psychologicalHook": "Misconception of PIN crediting money",
                "countermeasure": "Decline collect request",
                "confidence": 0.98,
                "signals": ["Collect"]
            }
        """.trimIndent()

        val parsed = GatewayPayloadValidator.validateOutput(validJson)
        assertEquals("CRITICAL", parsed.riskLevel)
        assertEquals(95, parsed.riskScore)

        // Invalid risk level
        val badRiskLevelJson = validJson.replace("CRITICAL", "SUPER_DANGEROUS")
        try {
            GatewayPayloadValidator.validateOutput(badRiskLevelJson)
            fail("Expected exception for invalid riskLevel")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Invalid or missing riskLevel"))
        }

        // Out of bound riskScore
        val outOfBoundsScoreJson = validJson.replace("95", "150")
        try {
            GatewayPayloadValidator.validateOutput(outOfBoundsScoreJson)
            fail("Expected exception for out of bound riskScore")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("out of valid bounds"))
        }
    }

    // 9. Secure Logging Sanitization
    @Test
    fun `test secure logger redacts auth tokens and PII`() {
        val sampleLogWithSecret = "Sending request with authorization: Bearer sec_xyz123456789 and phone: +919876543210"
        val sanitized = SecureLogger.sanitize(sampleLogWithSecret)

        assertFalse(sanitized.contains("sec_xyz123456789"))
        assertFalse(sanitized.contains("9876543210"))
        assertTrue(sanitized.contains("[REDACTED]"))
    }
}
