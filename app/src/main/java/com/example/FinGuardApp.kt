package com.example

import android.app.Application
import com.example.data.local.FinGuardDatabase
import com.example.util.NotificationHelper

class FinGuardApp : Application() {
    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createNotificationChannel(this)
        // Warm up Room DB
        FinGuardDatabase.getInstance(this)
    }
}
