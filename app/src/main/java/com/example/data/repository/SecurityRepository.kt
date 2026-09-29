package com.example.data.repository

import android.content.Context
import com.example.data.local.FinGuardDatabase
import com.example.data.local.FlaggedVpaEntity
import com.example.data.local.ThreatLogEntity
import com.example.data.model.IngestChannel
import com.example.data.model.ScamScanResult
import com.example.data.model.ThreatSeverity
import com.example.security.classifier.ScamClassifier
import kotlinx.coroutines.flow.Flow

class SecurityRepository(context: Context) {

    private val db = FinGuardDatabase.getInstance(context)
    private val threatLogDao = db.threatLogDao()
    private val flaggedVpaDao = db.flaggedVpaDao()

    val allThreatLogs: Flow<List<ThreatLogEntity>> = threatLogDao.getAllLogs()
    val allFlaggedVpas: Flow<List<FlaggedVpaEntity>> = flaggedVpaDao.getAllVpas()
    val totalCount: Flow<Int> = threatLogDao.getTotalCount()
    val threatCount: Flow<Int> = threatLogDao.getThreatCount()

    suspend fun scanAndRecord(
        sender: String,
        content: String,
        channel: IngestChannel
    ): ScamScanResult {
        val result = ScamClassifier.analyze(
            sender = sender,
            rawContent = content,
            channel = channel,
            flaggedVpaDao = flaggedVpaDao
        )

        val actionTaken = when {
            result.riskScore >= 75 -> "BLOCKED"
            result.riskScore >= 50 -> "WARNED"
            else -> "VERIFIED_SAFE"
        }

        val entity = ThreatLogEntity(
            sender = sender,
            channel = channel,
            scrubbedContent = result.piiResult.scrubbedText,
            originalMasked = result.piiResult.originalText,
            piiItemsFound = result.piiResult.redactedTokens,
            riskScore = result.riskScore,
            severity = result.severity,
            category = result.category,
            threatSignals = result.threatSignals,
            aiAnalysis = result.aiReasoning,
            actionTaken = actionTaken,
            timestamp = System.currentTimeMillis()
        )

        threatLogDao.insertLog(entity)
        return result
    }

    suspend fun checkVpaDirect(vpa: String): FlaggedVpaEntity? {
        return flaggedVpaDao.findByVpa(vpa.trim())
    }

    suspend fun reportVpa(vpa: String, reason: String) {
        val clean = vpa.trim().lowercase()
        val existing = flaggedVpaDao.findByVpa(clean)
        if (existing != null) {
            flaggedVpaDao.insert(
                existing.copy(
                    reportedCount = existing.reportedCount + 1,
                    reason = if (reason.isNotBlank()) reason else existing.reason
                )
            )
        } else {
            flaggedVpaDao.insert(
                FlaggedVpaEntity(
                    vpa = clean,
                    reason = if (reason.isNotBlank()) reason else "User reported fraud VPA",
                    reportedCount = 1,
                    riskLevel = ThreatSeverity.CRITICAL,
                    dateReported = System.currentTimeMillis()
                )
            )
        }
    }

    suspend fun deleteLog(id: Long) {
        threatLogDao.deleteById(id)
    }

    suspend fun clearAllLogs() {
        threatLogDao.clearAll()
    }
}
