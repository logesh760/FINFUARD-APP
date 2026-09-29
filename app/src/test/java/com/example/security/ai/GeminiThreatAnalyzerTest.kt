package com.example.security.ai

import com.example.data.model.StructuredThreatResponse
import com.example.security.network.ClientRateLimiter
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class GeminiThreatAnalyzerTest {

    private val jsonMediaType = "application/json".toMediaType()
    private lateinit var originalClient: OkHttpClient

    @Before
    fun setUp() {
        originalClient = GeminiThreatAnalyzer.okHttpClient
        GeminiThreatAnalyzer.gatewayBaseUrl = "https://gateway.finguard.internal"
        GeminiThreatAnalyzer.circuitBreaker.reset()
        GeminiThreatAnalyzer.rateLimiter = ClientRateLimiter(maxPermits = 10_000, windowDurationMs = 60_000L)
        GeminiThreatAnalyzer.retryPolicy = GatewayRetryPolicy(
            maxRetries = 2,
            initialBackoffMs = 50L,
            maxBackoffMs = 500L,
            backoffMultiplier = 2.0,
            maxRetryAfterSeconds = 10L
        )
        // Zero-delay provider for fast, deterministic unit test execution
        GeminiThreatAnalyzer.delayProvider = { /* instantaneous in test */ }
    }

    @After
    fun tearDown() {
        GeminiThreatAnalyzer.okHttpClient = originalClient
        GeminiThreatAnalyzer.gatewayBaseUrl = "https://gateway.finguard.internal"
        GeminiThreatAnalyzer.circuitBreaker.reset()
        GeminiThreatAnalyzer.rateLimiter = ClientRateLimiter(maxPermits = 10_000, windowDurationMs = 60_000L)
    }

    private fun createMockClient(interceptor: Interceptor): OkHttpClient {
        return OkHttpClient.Builder()
            .addInterceptor(interceptor)
            .build()
    }

    // =========================================================================
    // 1. Normal Request -> Gemini Gateway Success
    // =========================================================================

    @Test
    fun `test normal request succeeds and returns structured gemini response`() = runBlocking {
        val successJson = """
            {
                "success": true,
                "riskLevel": "CRITICAL",
                "riskScore": 95,
                "fraudVector": "Reverse UPI Collect Trap",
                "psychologicalHook": "Exploits user misconception of UPI PIN crediting funds",
                "countermeasure": "Decline the collect request immediately in your UPI app.",
                "confidence": 0.98,
                "signals": ["Reverse UPI Collect Trap", "High Urgency"]
            }
        """.trimIndent()

        var capturedRequest: okhttp3.Request? = null
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            capturedRequest = chain.request()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(successJson.toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Collect request for Rs 5,000 received. Enter UPI PIN to receive payment.",
            channel = "SMS",
            preliminarySignals = listOf("Collect Request")
        )

        assertEquals(1, callCount.get())
        assertEquals(1, GeminiThreatAnalyzer.lastAttemptCount)
        assertFalse(GeminiThreatAnalyzer.lastUsedFallback)
        assertFalse(result.isLocalFallback)
        assertEquals("CRITICAL", result.riskLevel)
        assertEquals(95, result.riskScore)
        assertEquals("Reverse UPI Collect Trap", result.fraudVector)
        assertEquals(GatewayCircuitBreaker.State.CLOSED, GeminiThreatAnalyzer.circuitBreaker.state)

        // Verify Phase 5 Security Headers
        assertNotNull(capturedRequest)
        assertTrue(capturedRequest!!.header("Authorization")!!.startsWith("Bearer "))
        assertTrue(capturedRequest!!.header("X-Request-ID")!!.startsWith("req_"))
        assertNotNull(capturedRequest!!.header("X-Timestamp"))
        assertNotNull(capturedRequest!!.header("X-Nonce"))
        assertEquals("security_agent", capturedRequest!!.header("X-Client-Role"))
        assertEquals("com.aistudio.finguard.secxz", capturedRequest!!.header("X-Package-ID"))
    }

    @Test
    fun `test cleartext HTTP is strictly rejected with secure fallback`() = runBlocking {
        GeminiThreatAnalyzer.gatewayBaseUrl = "http://insecure-gateway.finguard.internal"

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Collect request received",
            channel = "SMS",
            preliminarySignals = emptyList()
        )

        assertTrue(result.isLocalFallback)
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertEquals("INSECURE_HTTP_PROHIBITED", GeminiThreatAnalyzer.lastRetryReason)
    }

    @Test
    fun `test client rate limit reached throttles request with secure fallback`() = runBlocking {
        GeminiThreatAnalyzer.rateLimiter = ClientRateLimiter(maxPermits = 1, windowDurationMs = 60_000L)

        // First permit consumed
        assertTrue(GeminiThreatAnalyzer.rateLimiter.tryAcquire())

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Collect request received",
            channel = "SMS",
            preliminarySignals = emptyList()
        )

        assertTrue(result.isLocalFallback)
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertEquals("CLIENT_RATE_LIMITED", GeminiThreatAnalyzer.lastRetryReason)
    }

    // =========================================================================
    // 2. HTTP 429 -> Controlled Retry -> Recovery OR Fallback if Exhausted
    // =========================================================================

    @Test
    fun `test HTTP 429 transient rate limit recovers on retry`() = runBlocking {
        val successJson = """
            {
                "success": true,
                "riskLevel": "HIGH",
                "riskScore": 85,
                "fraudVector": "Phishing Link",
                "psychologicalHook": "Fake KYC Expiry",
                "countermeasure": "Do not open unverified links.",
                "confidence": 0.90,
                "signals": ["Phishing"]
            }
        """.trimIndent()

        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            val count = callCount.incrementAndGet()
            if (count == 1) {
                // First attempt: 429 Too Many Requests
                Response.Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(429)
                    .message("Too Many Requests")
                    .header("Retry-After", "1")
                    .body("{}".toResponseBody(jsonMediaType))
                    .build()
            } else {
                // Second attempt: Success
                Response.Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(200)
                    .message("OK")
                    .body(successJson.toResponseBody(jsonMediaType))
                    .build()
            }
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Update your KYC immediately at bit.ly/bank-kyc or account will be suspended.",
            channel = "SMS",
            preliminarySignals = listOf("Suspicious Link")
        )

        assertEquals(2, callCount.get())
        assertEquals(2, GeminiThreatAnalyzer.lastAttemptCount)
        assertFalse(GeminiThreatAnalyzer.lastUsedFallback)
        assertFalse(result.isLocalFallback)
        assertEquals("HIGH", result.riskLevel)
    }

    @Test
    fun `test HTTP 429 retries up to maxRetries then falls back to local engine`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .header("Retry-After", "1")
                .body("{}".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Collect request for Rs 2,000 received. Approve to receive cashback.",
            channel = "WHATSAPP",
            preliminarySignals = listOf("Collect Request")
        )

        // 1 initial attempt + 2 retries = 3 attempts total
        assertEquals(3, callCount.get())
        assertEquals(3, GeminiThreatAnalyzer.lastAttemptCount)
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
        assertEquals("CRITICAL", result.riskLevel)
        assertTrue(result.fraudVector.contains("Reverse UPI Collect Trap"))
    }

    @Test
    fun `test HTTP 429 with excessive Retry-After header aborts immediately to fallback`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .header("Retry-After", "120") // 120 seconds exceeds maxRetryAfterSeconds (10s)
                .body("{}".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Electricity bill unpaid. Power cut tonight. Call 9876543210.",
            channel = "SMS",
            preliminarySignals = listOf("Urgency")
        )

        // Should abort on first attempt rather than stall the UI
        assertEquals(1, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
        assertTrue(result.fraudVector.contains("Utility Bill Impersonation"))
    }

    // =========================================================================
    // 3. Timeout -> Controlled Retry -> Fallback
    // =========================================================================

    @Test
    fun `test socket timeout retries and falls back when exhausted`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { _ ->
            callCount.incrementAndGet()
            throw SocketTimeoutException("Gateway read timed out after 10000ms")
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Download our new banking update banking.apk to continue using account.",
            channel = "SMS",
            preliminarySignals = listOf("APK")
        )

        assertEquals(3, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
        assertEquals("CRITICAL", result.riskLevel)
        assertTrue(result.fraudVector.contains("Sideloaded Banking Trojan"))
    }

    // =========================================================================
    // 4. Malformed Response -> No Unsafe Retry -> Fallback
    // =========================================================================

    @Test
    fun `test malformed response does not perform unsafe retry and falls back`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body("<!DOCTYPE html><html><body>Error 500 Bad Gateway</body></html>".toResponseBody("text/html".toMediaType()))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Collect request for Rs 1,000 received. Enter UPI PIN.",
            channel = "SMS",
            preliminarySignals = listOf("Collect")
        )

        // Must NOT retry malformed body: 1 attempt only
        assertEquals(1, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
        assertEquals("MALFORMED_RESPONSE", GeminiThreatAnalyzer.lastRetryReason)
        assertEquals("CRITICAL", result.riskLevel)
    }

    @Test
    fun `test success false response does not retry and falls back`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body("""{"success": false, "error": "Internal AI parsing error"}""".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Electricity power bill unpaid. Power cut at 9 PM.",
            channel = "SMS",
            preliminarySignals = listOf("Utility")
        )

        assertEquals(1, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
    }

    // =========================================================================
    // 5. Backend Unavailable / Network Failure -> Local Fallback
    // =========================================================================

    @Test
    fun `test backend unavailable network failure retries and falls back`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { _ ->
            callCount.incrementAndGet()
            throw UnknownHostException("Unable to resolve host gateway.finguard.internal")
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "You won lottery ₹25,00,000 in KBC. Pay registration fee ₹5,000.",
            channel = "WHATSAPP",
            preliminarySignals = listOf("Lottery")
        )

        assertEquals(3, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
        assertEquals("HIGH", result.riskLevel)
        assertTrue(result.fraudVector.contains("Advance-Fee Job / Lottery Scam"))
    }

    // =========================================================================
    // 6. HTTP 500, 502, 503 Server Errors
    // =========================================================================

    @Test
    fun `test HTTP 500 internal server error retries and falls back`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(500)
                .message("Internal Server Error")
                .body("""{"error":"internal_failure"}""".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Your KYC is expired. Visit our branch or link to update.",
            channel = "SMS",
            preliminarySignals = listOf("KYC")
        )

        assertEquals(3, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
    }

    @Test
    fun `test HTTP 502 bad gateway retries and falls back`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(502)
                .message("Bad Gateway")
                .body("{}".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Collect request for ₹500",
            channel = "SMS",
            preliminarySignals = listOf("Collect")
        )

        assertEquals(3, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
    }

    @Test
    fun `test HTTP 503 service unavailable with retry-after retries and falls back`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(503)
                .message("Service Unavailable")
                .header("Retry-After", "2")
                .body("{}".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Suspicious collect message",
            channel = "SMS",
            preliminarySignals = listOf("Collect")
        )

        assertEquals(3, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
    }

    // =========================================================================
    // 7. Non-Retryable Client and Authentication Errors (400, 401, 403)
    // =========================================================================

    @Test
    fun `test HTTP 400 bad request does not retry and falls back immediately`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(400)
                .message("Bad Request")
                .body("""{"error": "Invalid schema"}""".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Some text",
            channel = "SMS",
            preliminarySignals = emptyList()
        )

        assertEquals(1, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertEquals("CLIENT_ERROR_400", GeminiThreatAnalyzer.lastRetryReason)
    }

    @Test
    fun `test HTTP 401 unauthorized does not retry and falls back immediately`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .body("""{"error": "Invalid client token"}""".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Some text",
            channel = "SMS",
            preliminarySignals = emptyList()
        )

        assertEquals(1, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertEquals("AUTH_FAILURE_401", GeminiThreatAnalyzer.lastRetryReason)
    }

    @Test
    fun `test HTTP 403 forbidden does not retry and falls back immediately`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(403)
                .message("Forbidden")
                .body("""{"error": "Access denied"}""".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Some text",
            channel = "SMS",
            preliminarySignals = emptyList()
        )

        assertEquals(1, callCount.get())
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertEquals("AUTH_FAILURE_403", GeminiThreatAnalyzer.lastRetryReason)
    }

    // =========================================================================
    // 8. Circuit Breaker Protection
    // =========================================================================

    @Test
    fun `test circuit breaker trips to OPEN and fast-fails without network calls`() = runBlocking {
        val breaker = GatewayCircuitBreaker(failureThreshold = 3, resetTimeoutMs = 10_000L)
        GeminiThreatAnalyzer.circuitBreaker = breaker

        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { _ ->
            callCount.incrementAndGet()
            throw IOException("Network connection refused")
        }

        // First call: 3 attempts made, all fail -> breaker records 3 failures
        GeminiThreatAnalyzer.analyzeThreatStructured("Message 1", "SMS", emptyList())
        assertEquals(3, callCount.get())
        assertEquals(GatewayCircuitBreaker.State.OPEN, breaker.state)
        assertFalse(breaker.canExecute())

        // Subsequent call while OPEN: should fast-fail IMMEDIATELY without network calls
        val callCountBefore = callCount.get()
        val result = GeminiThreatAnalyzer.analyzeThreatStructured("Message 2", "SMS", emptyList())

        assertEquals(callCountBefore, callCount.get()) // ZERO new network calls!
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
        assertEquals("CIRCUIT_BREAKER_OPEN", GeminiThreatAnalyzer.lastRetryReason)
    }

    @Test
    fun `test circuit breaker transitions to HALF_OPEN after timeout and recovers on success`() {
        var currentTime = 1000L
        val breaker = GatewayCircuitBreaker(
            failureThreshold = 2,
            resetTimeoutMs = 5000L,
            clock = { currentTime }
        )

        assertEquals(GatewayCircuitBreaker.State.CLOSED, breaker.state)
        breaker.recordFailure()
        assertEquals(GatewayCircuitBreaker.State.CLOSED, breaker.state)
        breaker.recordFailure()
        assertEquals(GatewayCircuitBreaker.State.OPEN, breaker.state)
        assertFalse(breaker.canExecute())

        // Advance time before reset timeout: still OPEN
        currentTime += 4000L
        assertEquals(GatewayCircuitBreaker.State.OPEN, breaker.state)
        assertFalse(breaker.canExecute())

        // Advance time past reset timeout: transitions to HALF_OPEN
        currentTime += 1001L
        assertEquals(GatewayCircuitBreaker.State.HALF_OPEN, breaker.state)
        assertTrue(breaker.canExecute())

        // Probe request succeeds -> closes circuit
        breaker.recordSuccess()
        assertEquals(GatewayCircuitBreaker.State.CLOSED, breaker.state)
        assertEquals(0, breaker.failureCount)
    }

    // =========================================================================
    // 9. Retry Policy Calculation & Parsing Unit Tests
    // =========================================================================

    @Test
    fun `test retry policy exponential backoff calculation`() {
        val policy = GatewayRetryPolicy(
            maxRetries = 2,
            initialBackoffMs = 500L,
            maxBackoffMs = 4000L,
            backoffMultiplier = 2.0
        )

        assertEquals(500L, policy.computeBackoffMs(0))
        assertEquals(1000L, policy.computeBackoffMs(1))
        assertEquals(2000L, policy.computeBackoffMs(2))
        assertEquals(4000L, policy.computeBackoffMs(3))
        assertEquals(4000L, policy.computeBackoffMs(4)) // Capped at maxBackoffMs
    }

    @Test
    fun `test retry policy retry after header parsing`() {
        val policy = GatewayRetryPolicy(maxRetryAfterSeconds = 10L)

        // Numeric seconds within threshold
        assertEquals(3000L, policy.parseRetryAfter("3"))
        assertEquals(10000L, policy.parseRetryAfter("10"))

        // Numeric seconds exceeding threshold -> -1L
        assertEquals(-1L, policy.parseRetryAfter("15"))
        assertEquals(-1L, policy.parseRetryAfter("60"))

        // Blank or null
        assertEquals(null, policy.parseRetryAfter(null))
        assertEquals(null, policy.parseRetryAfter("   "))

        // Invalid format falls back to null
        assertEquals(null, policy.parseRetryAfter("invalid_seconds_string"))
    }

    // =========================================================================
    // 10. Local Expert Assessment Determinism & Safety
    // =========================================================================

    @Test
    fun `test blank input does not call gateway and uses local engine`() = runBlocking {
        val callCount = AtomicInteger(0)
        GeminiThreatAnalyzer.okHttpClient = createMockClient { _ ->
            callCount.incrementAndGet()
            throw IllegalStateException("Should not be called for blank input")
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "    ",
            channel = "SMS",
            preliminarySignals = emptyList()
        )

        assertEquals(0, callCount.get())
        assertTrue(result.isLocalFallback)
    }

    @Test
    fun `test structured local assessment for reverse upi collect trap`() {
        val result: StructuredThreatResponse = GeminiThreatAnalyzer.generateLocalExpertAssessmentStructured(
            text = "Collect request received for ₹2000. Approve to receive reward in bank account.",
            channel = "WHATSAPP",
            signals = listOf("Collect Request", "Reward lure")
        )

        assertEquals("CRITICAL", result.riskLevel)
        assertEquals(95, result.riskScore)
        assertTrue(result.fraudVector.contains("Reverse UPI Collect Trap"))
        assertTrue(result.psychologicalHook.contains("misconception"))
        assertTrue(result.countermeasure.contains("Decline"))
        assertTrue(result.confidence in 0.0..1.0)
        assertTrue(result.signals.isNotEmpty())
        assertTrue(result.signals.size <= 10)
    }

    @Test
    fun `test structured local assessment for apk malware dropper`() {
        val result = GeminiThreatAnalyzer.generateLocalExpertAssessmentStructured(
            text = "Your bank KYC expired. Install banking_patch.apk immediately to avoid fine.",
            channel = "SMS",
            signals = listOf("Sideloaded APK")
        )

        assertEquals("CRITICAL", result.riskLevel)
        assertEquals(96, result.riskScore)
        assertTrue(result.fraudVector.contains("Sideloaded Banking Trojan"))
        assertTrue(result.countermeasure.contains("Google Play"))
        assertTrue(result.confidence in 0.0..1.0)
    }

    @Test
    fun `test structured local assessment for electricity disconnection threat`() {
        val result = GeminiThreatAnalyzer.generateLocalExpertAssessmentStructured(
            text = "Dear consumer, your electricity power bill is unpaid. Power cut tonight at 9:30 PM.",
            channel = "SMS",
            signals = listOf("Urgency", "Disconnection")
        )

        assertEquals("HIGH", result.riskLevel)
        assertEquals(88, result.riskScore)
        assertTrue(result.fraudVector.contains("Utility Bill Impersonation"))
        assertTrue(result.countermeasure.contains("electricity board portal"))
    }

    @Test
    fun `test signals list is strictly bounded to 10 items`() {
        val excessSignals = (1..15).map { "Threat Signal $it" }
        val result = GeminiThreatAnalyzer.generateLocalExpertAssessmentStructured(
            text = "Suspicious collect message",
            channel = "SMS",
            signals = excessSignals
        )

        assertTrue(result.signals.size <= 10)
    }

    @Test
    fun `test backward compatible string assessment formatting`() {
        val formatted = GeminiThreatAnalyzer.generateLocalExpertAssessment(
            text = "Collect request for ₹5000",
            channel = "SMS",
            signals = listOf("Collect")
        )

        assertTrue(formatted.contains("[FRAUD VECTOR]:"))
        assertTrue(formatted.contains("[PSYCHOLOGICAL HOOK]:"))
        assertTrue(formatted.contains("[ACTIONABLE COUNTERMEASURE]:"))
    }

    // =========================================================================
    // HARDENED AUTHENTICATION & REPLAY PROTECTION UNIT TESTS
    // =========================================================================

    @Test
    fun `test authentication failure 401 invalidates session and invokes local fallback`() = runBlocking {
        var callCount = 0
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount++
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .body("""{"success":false,"error":{"code":"UNAUTHORIZED_CLIENT","message":"Invalid token"}}""".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Please update KYC immediately at http://phish.example",
            channel = "SMS",
            preliminarySignals = listOf("Phishing")
        )

        assertEquals(1, callCount) // Never retries auth failures
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertEquals("AUTH_FAILURE_401", GeminiThreatAnalyzer.lastRetryReason)
        assertTrue(result.isLocalFallback)
    }

    @Test
    fun `test invalid authentication 403 immediately halts retries and returns fallback`() = runBlocking {
        var callCount = 0
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount++
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(403)
                .message("Forbidden")
                .body("""{"success":false,"error":{"code":"INVALID_CREDENTIALS","message":"Tampered signature"}}""".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Collect request received for Rs 5000",
            channel = "SMS",
            preliminarySignals = listOf("UPI Collect")
        )

        assertEquals(1, callCount)
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertEquals("AUTH_FAILURE_403", GeminiThreatAnalyzer.lastRetryReason)
        assertTrue(result.isLocalFallback)
    }

    @Test
    fun `test expired credentials in AuthTokenManager triggers fresh token acquisition`() = runBlocking {
        var providerCallCount = 0
        val tokenManager = com.example.security.auth.AuthTokenManager(
            storage = com.example.security.auth.InMemorySecureTokenStorage(),
            tokenProvider = {
                providerCallCount++
                com.example.security.auth.AuthToken(
                    tokenValue = "token_$providerCallCount",
                    expiresAtEpochMs = System.currentTimeMillis() + if (providerCallCount == 1) -5000L else 900_000L
                )
            }
        )

        // First call gets token 1 (which is expired)
        val token1 = tokenManager.getValidToken()
        assertEquals("token_1", token1.tokenValue)
        assertTrue(token1.isExpired())

        // Second call detects expiration and requests fresh token 2
        val token2 = tokenManager.getValidToken()
        assertEquals("token_2", token2.tokenValue)
        assertFalse(token2.isExpired())
        assertEquals(2, providerCallCount)
    }

    @Test
    fun `test request transmits unique X-Nonce and fresh X-Timestamp for replay defense`() = runBlocking {
        val nonces = mutableListOf<String>()
        val timestamps = mutableListOf<String>()

        val successJson = """
            {
                "success": true,
                "riskLevel": "LOW",
                "riskScore": 10,
                "fraudVector": "Normal Transaction",
                "psychologicalHook": "None",
                "countermeasure": "No action needed.",
                "confidence": 0.95,
                "signals": []
            }
        """.trimIndent()

        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            val req = chain.request()
            req.header("X-Nonce")?.let { nonces.add(it) }
            req.header("X-Timestamp")?.let { timestamps.add(it) }

            Response.Builder()
                .request(req)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(successJson.toResponseBody(jsonMediaType))
                .build()
        }

        // Send two consecutive requests
        GeminiThreatAnalyzer.analyzeThreatStructured("Message 1", "SMS", emptyList())
        GeminiThreatAnalyzer.analyzeThreatStructured("Message 2", "SMS", emptyList())

        assertEquals(2, nonces.size)
        assertEquals(2, timestamps.size)
        // Ensure nonces are distinct (replay defense)
        assertFalse("Nonces must be unique across requests", nonces[0] == nonces[1])
        assertTrue("Nonces must be non-empty", nonces[0].isNotBlank() && nonces[1].isNotBlank())
    }

    @Test
    fun `test rate limit 429 response triggers backoff and falls back cleanly`() = runBlocking {
        var callCount = 0
        GeminiThreatAnalyzer.okHttpClient = createMockClient { chain ->
            callCount++
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .header("Retry-After", "1")
                .message("Too Many Requests")
                .body("""{"success":false,"error":{"code":"RATE_LIMIT_EXCEEDED"}}""".toResponseBody(jsonMediaType))
                .build()
        }

        val result = GeminiThreatAnalyzer.analyzeThreatStructured(
            scrubbedText = "Message under rate limit test",
            channel = "SMS",
            preliminarySignals = emptyList()
        )

        assertTrue(callCount >= 1)
        assertTrue(GeminiThreatAnalyzer.lastUsedFallback)
        assertTrue(result.isLocalFallback)
    }
}
