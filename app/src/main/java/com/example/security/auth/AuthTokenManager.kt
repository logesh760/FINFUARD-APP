package com.example.security.auth

import com.example.security.logging.SecureLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference

/**
 * Short-lived access token model for FinGuard Backend API communication.
 */
data class AuthToken(
    val tokenValue: String,
    val expiresAtEpochMs: Long,
    val tokenType: String = "Bearer"
) {
    /**
     * Checks if token is expired, with a default 30-second leeway buffer.
     */
    fun isExpired(leewayMs: Long = 30_000L): Boolean {
        return System.currentTimeMillis() + leewayMs >= expiresAtEpochMs
    }

    /**
     * Redacted representation for logs and toString to guarantee zero secrets in logs.
     */
    override fun toString(): String {
        return "AuthToken(tokenValue=[REDACTED], expiresAtEpochMs=$expiresAtEpochMs, tokenType=$tokenType)"
    }
}

/**
 * Interface for secure storage of short-lived tokens.
 */
interface SecureTokenStorage {
    fun saveToken(token: AuthToken)
    fun getToken(): AuthToken?
    fun clearToken()
}

/**
 * Thread-safe secure in-memory token storage with explicit wipe capabilities.
 */
class InMemorySecureTokenStorage : SecureTokenStorage {
    private val tokenRef = AtomicReference<AuthToken?>(null)

    override fun saveToken(token: AuthToken) {
        tokenRef.set(token)
    }

    override fun getToken(): AuthToken? {
        return tokenRef.get()
    }

    override fun clearToken() {
        tokenRef.set(null)
    }
}

/**
 * Authentication Architecture: Manages short-lived token lifecycle,
 * refresh handshakes, and token injection into backend requests.
 * Contains ZERO hardcoded credentials in source code.
 */
class AuthTokenManager(
    private val storage: SecureTokenStorage = InMemorySecureTokenStorage(),
    private var tokenProvider: suspend () -> AuthToken = { generateEphemeralSessionToken() }
) {
    private val mutex = Mutex()

    fun setTokenProvider(provider: suspend () -> AuthToken) {
        tokenProvider = provider
    }

    suspend fun getValidToken(): AuthToken = mutex.withLock {
        val existing = storage.getToken()
        if (existing != null && !existing.isExpired()) {
            return existing
        }

        // Token is missing or expired, request a fresh short-lived token
        val freshToken = tokenProvider()
        storage.saveToken(freshToken)
        return freshToken
    }

    fun invalidateSession() {
        storage.clearToken()
    }

    companion object {
        private const val TAG = "AuthTokenManager"
        private val secureRandom = SecureRandom()
        private val JSON_MEDIA_TYPE = "application/json".toMediaType()

        /**
         * Negotiates a short-lived session token with the backend AI Gateway: POST /api/v1/auth/session.
         * Returns server-issued session token or null if negotiation fails.
         */
        suspend fun fetchServerSessionToken(
            gatewayBaseUrl: String,
            client: OkHttpClient,
            clientInstanceId: String = generateClientInstanceId()
        ): AuthToken? = withContext(Dispatchers.IO) {
            try {
                val nonce = generateNonce()
                val timestamp = System.currentTimeMillis()

                val requestJson = JSONObject().apply {
                    put("clientInstanceId", clientInstanceId)
                    put("packageName", "com.aistudio.finguard.secxz")
                    put("appVersion", "1.0")
                    put("clientTimestamp", timestamp)
                    put("nonce", nonce)
                }

                val requestBody = requestJson.toString().toRequestBody(JSON_MEDIA_TYPE)
                val request = Request.Builder()
                    .url("$gatewayBaseUrl/api/v1/auth/session")
                    .addHeader("Content-Type", "application/json")
                    .addHeader("X-Timestamp", timestamp.toString())
                    .addHeader("X-Nonce", nonce)
                    .post(requestBody)
                    .build()

                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        SecureLogger.w(TAG, "Failed to negotiate session token: HTTP ${response.code}")
                        return@withContext null
                    }

                    val bodyStr = response.body?.string() ?: return@withContext null
                    val json = JSONObject(bodyStr)
                    val sessionToken = json.optString("sessionToken", "")
                    val expiresAt = json.optLong("expiresAt", System.currentTimeMillis() + 900_000L)
                    val tokenType = json.optString("tokenType", "Bearer")

                    if (sessionToken.isNotBlank()) {
                        AuthToken(
                            tokenValue = sessionToken,
                            expiresAtEpochMs = expiresAt,
                            tokenType = tokenType
                        )
                    } else {
                        null
                    }
                }
            } catch (e: Exception) {
                SecureLogger.w(TAG, "Session token negotiation exception: ${e.message}")
                null
            }
        }

        fun generateClientInstanceId(): String {
            val bytes = ByteArray(16)
            secureRandom.nextBytes(bytes)
            return "inst_" + bytes.joinToString("") { "%02x".format(it) }
        }

        fun generateNonce(): String {
            val bytes = ByteArray(16)
            secureRandom.nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }

        /**
         * Generates a cryptographically random, ephemeral session token (15-minute lifespan).
         * Used for client session integrity without embedding static keys into the APK.
         */
        fun generateEphemeralSessionToken(ttlMs: Long = 15 * 60 * 1000L): AuthToken {
            val bytes = ByteArray(32)
            secureRandom.nextBytes(bytes)
            val tokenHex = bytes.joinToString("") { "%02x".format(it) }
            val expiresAt = System.currentTimeMillis() + ttlMs
            return AuthToken(
                tokenValue = "fg_sec_$tokenHex",
                expiresAtEpochMs = expiresAt,
                tokenType = "Bearer"
            )
        }
    }
}
