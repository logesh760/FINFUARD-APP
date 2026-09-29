package com.example.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.example.security.ShieldStateManager
import com.example.util.NotificationHelper

/**
 * Handles device boot events to ensure notification channels, security policies,
 * and background listeners are operational upon physical device reboot.
 */
class BootReceiver : BroadcastReceiver() {

    private val TAG = "FinGuardBootReceiver"

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        val action = intent.action
        if (action == Intent.ACTION_BOOT_COMPLETED || action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            Log.i(TAG, "Device booted / package updated ($action). Initializing FinGuard security subsystem.")
            NotificationHelper.createNotificationChannel(context)
            val isShieldOn = ShieldStateManager.isShieldActive(context)
            Log.i(TAG, "FinGuard Shield state on boot: ${if (isShieldOn) "ACTIVE" else "DISABLED"}")
        }
    }
}
