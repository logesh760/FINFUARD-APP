package com.example.security.logging

import android.util.Log
import java.util.regex.Pattern

/**
 * Secure logging utility for FinGuard Security.
 * Ensures zero secrets (API keys, session tokens, passwords) and zero PII (phone numbers, OTPs, card numbers)
 * are written into Android Logcat.
 */
object SecureLogger {

    private val SENSITIVE_PATTERNS = listOf(
        // Bearer tokens & auth headers
        Pattern.compile("(?i)(authorization\\s*[:=]\\s*Bearer\\s+)[a-zA-Z0-9_\\-\\.]+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(token\\s*[:=]\\s*)[a-zA-Z0-9_\\-\\.]+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(key\\s*[:=]\\s*)[a-zA-Z0-9_\\-\\.]+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(password\\s*[:=]\\s*)[^\\s,;]+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(secret\\s*[:=]\\s*)[^\\s,;]+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(nonce\\s*[:=]\\s*)[a-fA-F0-9]+", Pattern.CASE_INSENSITIVE),
        // Credit card patterns
        Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13})\\b"),
        // Phone numbers
        Pattern.compile("(?:\\+?\\d{1,3}[- ]?)?[6-9]\\d{9}\\b"),
        // OTPs
        Pattern.compile("(?i)\\b(?:otp|code|pin)\\s*[:=-]?\\s*([0-9]{4,8})\\b")
    )

    fun sanitize(message: String): String {
        var sanitized = message
        for (pattern in SENSITIVE_PATTERNS) {
            val matcher = pattern.matcher(sanitized)
            if (matcher.find()) {
                sanitized = matcher.replaceAll("[REDACTED]")
            }
        }
        return sanitized
    }

    fun d(tag: String, message: String) {
        Log.d(tag, sanitize(message))
    }

    fun i(tag: String, message: String) {
        Log.i(tag, sanitize(message))
    }

    fun w(tag: String, message: String) {
        Log.w(tag, sanitize(message))
    }

    fun e(tag: String, message: String, throwable: Throwable? = null) {
        val sanitizedMsg = sanitize(message)
        if (throwable != null) {
            // Log only safe exception class and sanitized message; avoid raw stack trace parameter dumps
            Log.e(tag, "$sanitizedMsg (${throwable.javaClass.simpleName}: ${sanitize(throwable.message ?: "")})")
        } else {
            Log.e(tag, sanitizedMsg)
        }
    }
}
