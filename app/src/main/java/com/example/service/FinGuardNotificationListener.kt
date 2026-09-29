package com.example.service

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.example.data.local.FinGuardDatabase
import com.example.data.local.ThreatLogEntity
import com.example.data.model.IngestChannel
import com.example.security.classifier.ScamClassifier
import com.example.util.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class FinGuardNotificationListener : NotificationListenerService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val TAG = "FinGuardListener"

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName ?: return

        // Filter supported messaging apps
        val channel = when {
            packageName.contains("whatsapp") -> IngestChannel.WHATSAPP
            packageName.contains("telegram") -> IngestChannel.TELEGRAM
            packageName.contains("instagram") -> IngestChannel.INSTAGRAM
            packageName.contains("messaging") || packageName.contains("mms") || packageName.contains("sms") -> IngestChannel.SMS
            else -> return // Ignore unrelated system or app notifications
        }

        val extras = sbn.notification?.extras ?: return
        val title = extras.getString(Notification.EXTRA_TITLE) ?: "Unknown Contact"
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            ?: return

        if (text.isBlank()) return

        // Check 1: Shield Master Switch
        if (!com.example.security.ShieldStateManager.isShieldActive(applicationContext)) {
            Log.d(TAG, "FinGuard Shield is OFF. Discarding incoming notification.")
            return
        }

        // Check 2: Event Deduplication
        if (com.example.security.EventDeduplicator.isDuplicate(title, text, channel)) {
            Log.d(TAG, "Duplicate notification event detected and deduplicated from sender: $title ($channel)")
            return
        }

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
                Log.e(TAG, "Error processing incoming notification: ${e.message}", e)
            }
        }
    }
}
