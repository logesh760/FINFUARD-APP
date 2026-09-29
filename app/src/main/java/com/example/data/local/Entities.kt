package com.example.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.TypeConverter
import com.example.data.model.IngestChannel
import com.example.data.model.ThreatCategory
import com.example.data.model.ThreatSeverity

@Entity(tableName = "threat_logs")
data class ThreatLogEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val sender: String,
    val channel: IngestChannel,
    val scrubbedContent: String,
    val originalMasked: String,
    val piiItemsFound: List<String>,
    val riskScore: Int, // 0 to 100
    val severity: ThreatSeverity,
    val category: ThreatCategory,
    val threatSignals: List<String>,
    val aiAnalysis: String?,
    val actionTaken: String, // "BLOCKED", "WARNED", "VERIFIED_SAFE"
    val timestamp: Long = System.currentTimeMillis()
)

@Entity(tableName = "flagged_vpas")
data class FlaggedVpaEntity(
    @PrimaryKey
    val vpa: String, // e.g. "claim-reward@okaxis"
    val reason: String,
    val reportedCount: Int = 1,
    val riskLevel: ThreatSeverity = ThreatSeverity.CRITICAL,
    val dateReported: Long = System.currentTimeMillis()
)

class SecurityConverters {
    @TypeConverter
    fun fromChannel(value: IngestChannel): String = value.name

    @TypeConverter
    fun toChannel(value: String): IngestChannel = try {
        IngestChannel.valueOf(value)
    } catch (_: Exception) {
        IngestChannel.SMS
    }

    @TypeConverter
    fun fromSeverity(value: ThreatSeverity): String = value.name

    @TypeConverter
    fun toSeverity(value: String): ThreatSeverity = try {
        ThreatSeverity.valueOf(value)
    } catch (_: Exception) {
        ThreatSeverity.SAFE
    }

    @TypeConverter
    fun fromCategory(value: ThreatCategory): String = value.name

    @TypeConverter
    fun toCategory(value: String): ThreatCategory = try {
        ThreatCategory.valueOf(value)
    } catch (_: Exception) {
        ThreatCategory.SAFE_TRANSACTION
    }

    @TypeConverter
    fun fromStringList(list: List<String>): String = list.joinToString("|||")

    @TypeConverter
    fun toStringList(data: String): List<String> =
        if (data.isBlank()) emptyList() else data.split("|||")
}
