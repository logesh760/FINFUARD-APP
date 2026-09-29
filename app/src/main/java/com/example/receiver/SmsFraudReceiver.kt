package com.example.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.example.data.local.FinGuardDatabase
import com.example.data.local.ThreatLogEntity
import com.example.data.model.IngestChannel
import com.example.security.classifier.ScamClassifier
import com.example.util.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SmsFraudReceiver : BroadcastReceiver() {

    private val TAG = "SmsFraudReceiver"

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val fullBody = StringBuilder()
        var sender = "SMS"

        for (sms in messages) {
            sender = sms.displayOriginatingAddress ?: sms.originatingAddress ?: "SMS"
            fullBody.append(sms.displayMessageBody ?: sms.messageBody ?: "")
        }

        val text = fullBody.toString()
        if (text.isBlank()) return

        // Check 1: Shield Master Switch
        if (!com.example.security.ShieldStateManager.isShieldActive(context)) {
            Log.d(TAG, "FinGuard Shield is OFF. Discarding incoming SMS event.")
            return
        }

        // Check 2: Event Deduplication
        if (com.example.security.EventDeduplicator.isDuplicate(sender, text, IngestChannel.SMS)) {
            Log.d(TAG, "Duplicate SMS event detected and deduplicated from sender: $sender")
            return
        }

        val pendingResult = goAsync()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val db = FinGuardDatabase.getInstance(context)
                val scanResult = ScamClassifier.analyze(
                    sender = sender,
                    rawContent = text,
                    channel = IngestChannel.SMS,
                    flaggedVpaDao = db.flaggedVpaDao()
                )

                val actionTaken = when {
                    scanResult.riskScore >= 75 -> "BLOCKED"
                    scanResult.riskScore >= 50 -> "WARNED"
                    else -> "VERIFIED_SAFE"
                }

                val logEntity = ThreatLogEntity(
                    sender = sender,
                    channel = IngestChannel.SMS,
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

                if (scanResult.riskScore >= 60) {
                    NotificationHelper.showThreatAlert(
                        context = context,
                        sender = sender,
                        threatTitle = scanResult.threatSignals.firstOrNull() ?: "Scam SMS Intercepted",
                        severity = scanResult.severity
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error evaluating incoming SMS: ${e.message}", e)
            } finally {
                pendingResult.finish()
            }
        }
    }
}
