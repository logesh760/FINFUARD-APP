package com.example.util

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.data.model.ThreatSeverity

object NotificationHelper {

    const val CHANNEL_ID = "finguard_security_alerts"
    private const val CHANNEL_NAME = "FinGuard Threat Alerts"

    fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Real-time alerts for intercepted financial scams, phishing, and fake UPI requests"
                enableVibration(true)
            }
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            manager?.createNotificationChannel(channel)
        }
    }

    fun showThreatAlert(
        context: Context,
        sender: String,
        threatTitle: String,
        severity: ThreatSeverity,
        notificationId: Int = System.currentTimeMillis().toInt()
    ) {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("NOTIFICATION_THREAT_ID", notificationId)
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val severityLabel = when (severity) {
            ThreatSeverity.CRITICAL -> "CRITICAL SCAM DETECTED"
            ThreatSeverity.HIGH_RISK -> "HIGH-RISK THREAT"
            ThreatSeverity.SUSPICIOUS -> "SUSPICIOUS MESSAGE"
            else -> "SECURITY ALERT"
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("🛡️ FinGuard: $severityLabel")
            .setContentText("From $sender: $threatTitle")
            .setStyle(NotificationCompat.BigTextStyle().bigText("From $sender: $threatTitle. FinGuard has quarantined this threat. Tap to inspect deep reasoning."))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        manager?.notify(notificationId, notification)
    }
}
