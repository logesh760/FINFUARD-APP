package com.example.security.ai

import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import kotlin.math.min
import kotlin.math.pow

/**
 * Reliability and retry policy for Backend AI Gateway calls.
 * Enforces exponential backoff, rate limit handling, and strict limits against API abuse.
 */
data class GatewayRetryPolicy(
    val maxRetries: Int = 2, // Total attempts = 1 + maxRetries (default max 3 attempts)
    val initialBackoffMs: Long = 500L,
    val maxBackoffMs: Long = 4000L,
    val backoffMultiplier: Double = 2.0,
    val maxRetryAfterSeconds: Long = 10L // Cap to avoid freezing UI
) {
    /**
     * Determines if an HTTP status code is safe and appropriate for retry.
     * Retries: 429 (Rate limit), 500, 502, 503, 504 (Server/Gateway errors).
     * NEVER retries: 400, 401, 403, 404, 422 (Client/Auth/Validation errors).
     */
    fun isRetryableStatusCode(code: Int): Boolean {
        return code == 429 || code == 500 || code == 502 || code == 503 || code == 504
    }

    /**
     * Determines if a thrown exception is a transient network/timeout failure.
     */
    fun isRetryableException(e: Throwable): Boolean {
        return when (e) {
            is SocketTimeoutException, is InterruptedIOException -> true
            is UnknownHostException, is ConnectException, is IOException -> true
            else -> false
        }
    }

    /**
     * Parses the Retry-After header (seconds or HTTP date).
     * Returns delay in milliseconds, or -1 if value is invalid or exceeds max allowable wait.
     */
    fun parseRetryAfter(header: String?): Long? {
        if (header.isNullOrBlank()) return null
        val trimmed = header.trim()
        // Try parsing as integer seconds
        trimmed.toLongOrNull()?.let { seconds ->
            if (seconds <= 0) return 0L
            if (seconds > maxRetryAfterSeconds) return -1L // Exceeds budget, signal abort to fallback
            return seconds * 1000L
        }

        // Try parsing as RFC 1123 HTTP date
        try {
            val format = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("GMT")
            }
            val date = format.parse(trimmed)
            if (date != null) {
                val delayMs = date.time - System.currentTimeMillis()
                if (delayMs <= 0) return 0L
                if (delayMs > maxRetryAfterSeconds * 1000L) return -1L
                return delayMs
            }
        } catch (_: Exception) {
            // Unparseable format, fallback to default exponential backoff
        }
        return null
    }

    /**
     * Calculates delay for retry attempt (0-indexed attempt count).
     */
    fun computeBackoffMs(attempt: Int, retryAfterHeader: String? = null): Long {
        val retryAfter = parseRetryAfter(retryAfterHeader)
        if (retryAfter != null) {
            return retryAfter
        }
        val exponential = (initialBackoffMs * backoffMultiplier.pow(attempt.toDouble())).toLong()
        return min(maxBackoffMs, exponential)
    }
}
