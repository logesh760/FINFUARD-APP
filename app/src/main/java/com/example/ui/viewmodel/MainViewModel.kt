package com.example.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.FlaggedVpaEntity
import com.example.data.local.ThreatLogEntity
import com.example.data.model.IngestChannel
import com.example.data.model.ScamScanResult
import com.example.data.model.ThreatCategory
import com.example.data.model.ThreatSeverity
import com.example.data.repository.SecurityRepository
import com.example.security.banking.BankSmsParser
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class AppTab(val title: String) {
    DASHBOARD("Shield"),
    THREAT_FEED("Threat Feed"),
    UPI_BANKING("UPI Guard"),
    SIMULATOR("Ingest Test"),
    CONFIG("Production API")
}

sealed class VpaCheckState {
    object Idle : VpaCheckState()
    object Checking : VpaCheckState()
    data class FoundBlacklisted(val entity: FlaggedVpaEntity) : VpaCheckState()
    data class SafeOrUnreported(val vpa: String) : VpaCheckState()
}

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SecurityRepository(application)

    private val _selectedTab = MutableStateFlow(AppTab.DASHBOARD)
    val selectedTab: StateFlow<AppTab> = _selectedTab.asStateFlow()

    val threatLogs: StateFlow<List<ThreatLogEntity>> = repository.allThreatLogs
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val flaggedVpas: StateFlow<List<FlaggedVpaEntity>> = repository.allFlaggedVpas
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val totalScanned: StateFlow<Int> = repository.totalCount
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    val totalThreats: StateFlow<Int> = repository.threatCount
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    // Shield master switch persisted across reboots
    private val _shieldActive = MutableStateFlow(com.example.security.ShieldStateManager.isShieldActive(application))
    val shieldActive: StateFlow<Boolean> = _shieldActive.asStateFlow()

    // Threat feed search query & filter
    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _channelFilter = MutableStateFlow<IngestChannel?>(null)
    val channelFilter: StateFlow<IngestChannel?> = _channelFilter.asStateFlow()

    private val _severityFilter = MutableStateFlow<ThreatSeverity?>(null)
    val severityFilter: StateFlow<ThreatSeverity?> = _severityFilter.asStateFlow()

    // Selected log for deep-dive dialog
    private val _selectedLog = MutableStateFlow<ThreatLogEntity?>(null)
    val selectedLog: StateFlow<ThreatLogEntity?> = _selectedLog.asStateFlow()

    // Simulator / Scanner state
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _lastScanResult = MutableStateFlow<ScamScanResult?>(null)
    val lastScanResult: StateFlow<ScamScanResult?> = _lastScanResult.asStateFlow()

    // VPA checker state
    private val _vpaCheckState = MutableStateFlow<VpaCheckState>(VpaCheckState.Idle)
    val vpaCheckState: StateFlow<VpaCheckState> = _vpaCheckState.asStateFlow()

    // Bank SMS Parser state
    private val _bankSmsParsed = MutableStateFlow<com.example.data.model.BankTransactionInfo?>(null)
    val bankSmsParsed: StateFlow<com.example.data.model.BankTransactionInfo?> = _bankSmsParsed.asStateFlow()

    // Config settings
    val webhookUrl = MutableStateFlow("https://ingest.finguard.security/v1/telemetry")
    val selectedPaymentProvider = MutableStateFlow("Setu UPI SDK")
    val kafkaTopic = MutableStateFlow("finguard.production.sanitized.events")

    fun selectTab(tab: AppTab) {
        _selectedTab.value = tab
    }

    fun toggleShield(enabled: Boolean) {
        _shieldActive.value = enabled
        com.example.security.ShieldStateManager.setShieldActive(getApplication(), enabled)
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun setChannelFilter(channel: IngestChannel?) {
        _channelFilter.value = channel
    }

    fun setSeverityFilter(severity: ThreatSeverity?) {
        _severityFilter.value = severity
    }

    fun selectLogForDetails(log: ThreatLogEntity?) {
        _selectedLog.value = log
    }

    fun scanSimulatorPayload(
        sender: String,
        content: String,
        channel: IngestChannel
    ) {
        viewModelScope.launch {
            _isScanning.value = true
            try {
                val result = repository.scanAndRecord(sender, content, channel)
                _lastScanResult.value = result
            } finally {
                _isScanning.value = false
            }
        }
    }

    fun checkVpa(vpa: String) {
        if (vpa.isBlank()) {
            _vpaCheckState.value = VpaCheckState.Idle
            return
        }
        viewModelScope.launch {
            _vpaCheckState.value = VpaCheckState.Checking
            val found = repository.checkVpaDirect(vpa)
            if (found != null) {
                _vpaCheckState.value = VpaCheckState.FoundBlacklisted(found)
            } else {
                _vpaCheckState.value = VpaCheckState.SafeOrUnreported(vpa)
            }
        }
    }

    fun reportVpa(vpa: String, reason: String) {
        viewModelScope.launch {
            repository.reportVpa(vpa, reason)
            checkVpa(vpa)
        }
    }

    fun parseBankSms(sender: String, messageText: String) {
        val parsed = BankSmsParser.parse(sender, messageText)
        _bankSmsParsed.value = parsed
    }

    fun deleteLog(id: Long) {
        viewModelScope.launch {
            repository.deleteLog(id)
            if (_selectedLog.value?.id == id) {
                _selectedLog.value = null
            }
        }
    }

    fun clearAllLogs() {
        viewModelScope.launch {
            repository.clearAllLogs()
            _selectedLog.value = null
        }
    }
}
