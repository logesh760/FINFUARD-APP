package com.example.security

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Thread-safe persistent state manager for FinGuard Shield protection.
 * Persists the active/inactive state across app restarts and device reboots.
 */
object ShieldStateManager {

    private const val PREFS_NAME = "finguard_security_prefs"
    private const val KEY_SHIELD_ACTIVE = "shield_active"

    private val _shieldStateFlow = MutableStateFlow(true)
    val shieldStateFlow: StateFlow<Boolean> = _shieldStateFlow.asStateFlow()

    private var sharedPreferences: SharedPreferences? = null

    private fun getPrefs(context: Context): SharedPreferences {
        return sharedPreferences ?: synchronized(this) {
            sharedPreferences ?: context.applicationContext
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .also {
                    sharedPreferences = it
                    _shieldStateFlow.value = it.getBoolean(KEY_SHIELD_ACTIVE, true)
                }
        }
    }

    fun isShieldActive(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_SHIELD_ACTIVE, true)
    }

    fun setShieldActive(context: Context, active: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_SHIELD_ACTIVE, active).apply()
        _shieldStateFlow.value = active
    }

    /**
     * For testing purposes only to reset in-memory preferences reference.
     */
    fun resetForTesting(initialState: Boolean = true) {
        _shieldStateFlow.value = initialState
        sharedPreferences = null
    }
}
