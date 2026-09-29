package com.example.security.network

/**
 * Client-Side Rate Limiter enforcing safe throughput boundaries.
 * Prevents runaway loops, accidental DoS, and excessive backend/Gemini API expenses.
 */
class ClientRateLimiter(
    val maxPermits: Int = 10,
    val windowDurationMs: Long = 60_000L,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    private val timestamps = ArrayDeque<Long>()

    /**
     * Checks if a request is permitted under the rate limit.
     * Returns true if request is allowed, false if rate limited.
     */
    @Synchronized
    fun tryAcquire(): Boolean {
        val now = clock()
        val windowStart = now - windowDurationMs

        // Evict expired timestamps outside the rolling window
        while (timestamps.isNotEmpty() && timestamps.first() < windowStart) {
            timestamps.removeFirst()
        }

        return if (timestamps.size < maxPermits) {
            timestamps.addLast(now)
            true
        } else {
            false
        }
    }

    @Synchronized
    fun reset() {
        timestamps.clear()
    }
}
