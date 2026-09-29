package com.example.security.ai

/**
 * Circuit Breaker pattern to protect the backend Gemini gateway and client battery/latency.
 *
 * States:
 * - CLOSED: Normal operation; network requests are permitted.
 * - OPEN: Gateway is experiencing persistent failures; requests fail fast to local deterministic fallback.
 * - HALF_OPEN: Probe state after reset timeout; a single request is allowed to test recovery.
 */
class GatewayCircuitBreaker(
    var failureThreshold: Int = 3,
    var resetTimeoutMs: Long = 30_000L,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    enum class State {
        CLOSED,
        OPEN,
        HALF_OPEN
    }

    private var _state = State.CLOSED
    val state: State get() = synchronized(this) { updateStateLocked() }

    private var consecutiveFailures = 0
    val failureCount: Int get() = synchronized(this) { consecutiveFailures }

    private var lastFailureTimeMs: Long = 0L

    @Synchronized
    fun canExecute(): Boolean {
        val current = updateStateLocked()
        return current == State.CLOSED || current == State.HALF_OPEN
    }

    @Synchronized
    fun recordSuccess() {
        consecutiveFailures = 0
        _state = State.CLOSED
    }

    @Synchronized
    fun recordFailure() {
        consecutiveFailures++
        lastFailureTimeMs = clock()
        if (consecutiveFailures >= failureThreshold) {
            _state = State.OPEN
        }
    }

    @Synchronized
    fun reset() {
        consecutiveFailures = 0
        lastFailureTimeMs = 0L
        _state = State.CLOSED
    }

    private fun updateStateLocked(): State {
        if (_state == State.OPEN) {
            val elapsed = clock() - lastFailureTimeMs
            if (elapsed >= resetTimeoutMs) {
                _state = State.HALF_OPEN
            }
        }
        return _state
    }
}
