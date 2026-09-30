package com.example.service

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.example.data.local.FinGuardDatabase
import com.example.data.local.ThreatLogEntity
import com.example.data.model.IngestChannel
import com.example.security.EventDeduplicator
import com.example.security.ShieldStateManager
import com.example.security.classifier.ScamClassifier
import com.example.util.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class FinGuardNotificationListener : NotificationListenerService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val TAG = "FinGuardListener"

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i(TAG, "FIN_GUARD_LISTENER_CONNECTED")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        try {
            val packageName = sbn.packageName ?: "unknown.package"
            val key = sbn.key ?: "unknown_key"

            val notification = sbn.notification
            val extras = notification?.extras
            val title = extras?.getString(Notification.EXTRA_TITLE)
                ?: extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString()
                ?: "No Title"

            val text = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString()
                ?: extras?.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
                ?: ""

            // Logcat logging for all callbacks immediately before filtering
            Log.i(
                TAG,
                "FIN_GUARD_NOTIFICATION_POSTED\npackage=$packageName\ntitle=$title\ntext=$text\nkey=$key"
            )

            // Ignore empty content
            if (text.isBlank()) return

            // Determine ingestion channel for messaging apps or test callbacks
            val channel = when {
                packageName.contains("whatsapp", ignoreCase = true) -> IngestChannel.WHATSAPP
                packageName.contains("telegram", ignoreCase = true) -> IngestChannel.TELEGRAM
                packageName.contains("instagram", ignoreCase = true) -> IngestChannel.INSTAGRAM
                packageName.contains("messaging", ignoreCase = true) ||
                        packageName.contains("mms", ignoreCase = true) ||
                        packageName.contains("sms", ignoreCase = true) -> IngestChannel.SMS
                packageName == "com.android.shell" || title.contains("CALLBACK TEST", ignoreCase = true) -> IngestChannel.SMS
                else -> return // Ignore unrelated non-messaging system apps
            }

            // Check 1: Shield Master Switch
            if (!ShieldStateManager.isShieldActive(applicationContext)) {
                Log.d(TAG, "FinGuard Shield is OFF. Discarding incoming notification.")
                return
            }

            // Check 2: Event Deduplication
            if (EventDeduplicator.isDuplicate(title, text, channel)) {
                Log.d(TAG, "Duplicate notification event detected and deduplicated from sender: $title ($channel)")
                return
            }

            // Perform analysis on background coroutine to keep onNotificationPosted light
            serviceScope.launch {
                try {
                    val db = FinGuardDatabase.getInstance(applicationContext)
                    val scanResult = ScamClassifier.analyze(
                        sender = title,
                        rawContent = text,
                        channel = channel,
                        flaggedVpaDao = db.flaggedVpaDao()
                    )

                    val actionTaken = when {
                        scanResult.riskScore >= 75 -> "BLOCKED"
                        scanResult.riskScore >= 50 -> "WARNED"
                        else -> "VERIFIED_SAFE"
                    }

                    val logEntity = ThreatLogEntity(
                        sender = title,
                        channel = channel,
                        scrubbedContent = scanResult.piiResult.scrubbedText,
                        originalMasked = scanResult.piiResult.originalText,
                        piiItemsFound = scanResult.piiResult.redactedTokens,
                        riskScore = scanResult.riskScore,
                        severity = scanResult.severity,
                        category = scanResult.category,
                        threatSignals = scanResult.threatSignals,
                        aiAnalysis = scanResult.aiReasoning,
                        actionTaken = actionTaken,
                        timestamp = System.currentTimeMillis()
                    )

                    db.threatLogDao().insertLog(logEntity)

                    // If dangerous scam, trigger proactive threat alert
                    if (scanResult.riskScore >= 60) {
                        NotificationHelper.showThreatAlert(
                            context = applicationContext,
                            sender = title,
                            threatTitle = scanResult.threatSignals.firstOrNull() ?: "Potential Scam Intercepted",
                            severity = scanResult.severity
                        )
                    }

                } catch (e: Exception) {
                    Log.e(TAG, "Error evaluating incoming notification: ${e.message}", e)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in onNotificationPosted: ${e.message}", e)
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        super.onNotificationRemoved(sbn)
        if (sbn == null) return

        try {
            val packageName = sbn.packageName ?: "unknown.package"
            val key = sbn.key ?: "unknown_key"
            Log.i(TAG, "FIN_GUARD_NOTIFICATION_REMOVED\npackage=$packageName\nkey=$key")
        } catch (e: Exception) {
            Log.e(TAG, "Error in onNotificationRemoved: ${e.message}", e)
        }
    }
}
