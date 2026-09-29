package com.example.security

import com.example.data.model.IngestChannel
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * High-performance thread-safe event deduplication engine.
 * Prevents duplicate processing, duplicate database writes, and repeated alert
 * notifications caused by multi-part SMS delivery, carrier duplicate broadcasts,
 * or NotificationListenerService status updates.
 */
object EventDeduplicator {

    private const val DEFAULT_WINDOW_MS = 15_000L

    private val seenEvents = ConcurrentHashMap<String, Long>()
    private val duplicateCount = AtomicLong(0L)

    /**
     * Checks if the incoming message event is a duplicate within [windowMs].
     * If duplicate, returns true. If novel, records timestamp and returns false.
     */
    fun isDuplicate(
        sender: String,
        content: String,
        channel: IngestChannel,
        windowMs: Long = DEFAULT_WINDOW_MS
    ): Boolean {
        val now = System.currentTimeMillis()
        pruneExpired(now, windowMs)

        val key = generateKey(sender, content, channel)
        val lastSeen = seenEvents[key]

        if (lastSeen != null && (now - lastSeen) < windowMs) {
            duplicateCount.incrementAndGet()
            return true
        }

        seenEvents[key] = now
        return false
    }

    fun getDuplicateCount(): Long = duplicateCount.get()

    fun resetForTesting() {
        seenEvents.clear()
        duplicateCount.set(0L)
    }

    private fun pruneExpired(now: Long, windowMs: Long) {
        if (seenEvents.size > 200) {
            val iterator = seenEvents.entries.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                if (now - entry.value > windowMs) {
                    iterator.remove()
                }
            }
        }
    }

    private fun generateKey(sender: String, content: String, channel: IngestChannel): String {
        val cleanSender = sender.trim().lowercase()
        val cleanContent = content.trim().replace("\\s+".toRegex(), " ")
        val raw = "${channel.name}:$cleanSender:$cleanContent"
        return sha256(raw)
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }
}
