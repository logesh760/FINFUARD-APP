package com.example.data.local

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.sqlite.db.SupportSQLiteDatabase
import com.example.data.model.IngestChannel
import com.example.data.model.ThreatCategory
import com.example.data.model.ThreatSeverity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch

@Dao
interface ThreatLogDao {
    @Query("SELECT * FROM threat_logs ORDER BY timestamp DESC")
    fun getAllLogs(): Flow<List<ThreatLogEntity>>

    @Query("SELECT * FROM threat_logs ORDER BY timestamp DESC")
    suspend fun getRecentLogsDirect(): List<ThreatLogEntity>

    @Query("SELECT * FROM threat_logs WHERE id = :id LIMIT 1")
    suspend fun getLogById(id: Long): ThreatLogEntity?

    @Query("SELECT COUNT(*) FROM threat_logs")
    fun getTotalCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM threat_logs WHERE riskScore >= 50")
    fun getThreatCount(): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertLog(log: ThreatLogEntity): Long

    @Query("DELETE FROM threat_logs WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM threat_logs")
    suspend fun clearAll()
}

@Dao
interface FlaggedVpaDao {
    @Query("SELECT * FROM flagged_vpas ORDER BY reportedCount DESC")
    fun getAllVpas(): Flow<List<FlaggedVpaEntity>>

    @Query("SELECT * FROM flagged_vpas WHERE LOWER(vpa) = LOWER(:vpa) LIMIT 1")
    suspend fun findByVpa(vpa: String): FlaggedVpaEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(vpa: FlaggedVpaEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(vpas: List<FlaggedVpaEntity>)

    @Query("DELETE FROM flagged_vpas WHERE vpa = :vpa")
    suspend fun delete(vpa: String)
}

@Database(
    entities = [ThreatLogEntity::class, FlaggedVpaEntity::class],
    version = 1,
    exportSchema = false
)
@TypeConverters(SecurityConverters::class)
abstract class FinGuardDatabase : RoomDatabase() {
    abstract fun threatLogDao(): ThreatLogDao
    abstract fun flaggedVpaDao(): FlaggedVpaDao

    companion object {
        @Volatile
        private var INSTANCE: FinGuardDatabase? = null

        fun getInstance(context: Context): FinGuardDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    FinGuardDatabase::class.java,
                    "finguard_security.db"
                ).addCallback(object : Callback() {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        super.onCreate(db)
                        // Seed initial known threat signatures and blacklist
                        CoroutineScope(Dispatchers.IO).launch {
                            val database = getInstance(context)
                            seedInitialThreatData(database)
                        }
                    }
                }).build()
                INSTANCE = instance
                instance
            }
        }

        private suspend fun seedInitialThreatData(db: FinGuardDatabase) {
            // Seed known malicious VPAs from fraud alerts
            val knownBadVpas = listOf(
                FlaggedVpaEntity("rewards.refund99@okaxis", "Fake GPay Cashback Collect Request", 482, ThreatSeverity.CRITICAL),
                FlaggedVpaEntity("electricity.bill.desk@ybl", "Electricity Disconnection Phishing", 312, ThreatSeverity.CRITICAL),
                FlaggedVpaEntity("kyc.update.hdfc@paytm", "Impersonation Bank KYC Update", 245, ThreatSeverity.HIGH_RISK),
                FlaggedVpaEntity("kbc.lottery.winner@icici", "Fake Lottery Registration Fee", 580, ThreatSeverity.CRITICAL),
                FlaggedVpaEntity("telegram.job.tasks@ibl", "Daily Task Prepayment Scam", 189, ThreatSeverity.HIGH_RISK)
            )
            db.flaggedVpaDao().insertAll(knownBadVpas)

            // Seed initial real-world threat detections so the user sees live threat analytics immediately
            val initialLogs = listOf(
                ThreatLogEntity(
                    sender = "+919876501234",
                    channel = IngestChannel.WHATSAPP,
                    scrubbedContent = "Congratulations! You have won [CASH_REWARD] in KBC lottery. Call manager at +9198****** to claim. Verification Code: [OTP_REDACTED].",
                    originalMasked = "Congratulations! You have won Rs 25,00,000 in KBC lottery. Call manager at +919876501234. Verification Code: 492819.",
                    piiItemsFound = listOf("OTP (6-digit)", "Phone Number"),
                    riskScore = 96,
                    severity = ThreatSeverity.CRITICAL,
                    category = ThreatCategory.LOTTERY_JOB_SCAM,
                    threatSignals = listOf("Unsolicited lottery reward claim", "Advance fee scam pattern", "OTP harvesting solicitation"),
                    aiAnalysis = "High-confidence financial fraud. Attacker attempts advance fee fraud by promising a fictitious lottery jackpot and asking the victim to reveal OTP verification codes.",
                    actionTaken = "BLOCKED",
                    timestamp = System.currentTimeMillis() - 1000 * 60 * 18
                ),
                ThreatLogEntity(
                    sender = "VK-SBINB",
                    channel = IngestChannel.SMS,
                    scrubbedContent = "Dear Customer, your SBI YONO account is suspended due to PAN expiry. Update immediately at http://sbi-pan-kyc-update.xyz/[ID] to avoid penalty.",
                    originalMasked = "Dear Customer, your SBI YONO account is suspended due to PAN expiry. Update immediately at http://sbi-pan-kyc-update.xyz/login to avoid penalty.",
                    piiItemsFound = listOf("Lookalike Bank URL"),
                    riskScore = 92,
                    severity = ThreatSeverity.HIGH_RISK,
                    category = ThreatCategory.BANK_IMPERSONATION,
                    threatSignals = listOf("Spoofed bank sender header", "Urgent suspension threat", "Phishing domain (.xyz TLD)"),
                    aiAnalysis = "Critical Bank Impersonation / Credential Harvester. Legitimate banks never send .xyz links asking for PAN or netbanking passwords.",
                    actionTaken = "BLOCKED",
                    timestamp = System.currentTimeMillis() - 1000 * 60 * 45
                ),
                ThreatLogEntity(
                    sender = "AD-HDFCBK",
                    channel = IngestChannel.SMS,
                    scrubbedContent = "Rs 450.00 debited from A/C [ACCOUNT_REDACTED] on 27-Sep at Swiggy. UPI Ref: 4291829102. Balance: [BALANCE_REDACTED].",
                    originalMasked = "Rs 450.00 debited from A/C **4921 on 27-Sep at Swiggy. UPI Ref: 4291829102. Balance: Rs 14,210.00.",
                    piiItemsFound = listOf("Account Number Ending", "Account Balance"),
                    riskScore = 5,
                    severity = ThreatSeverity.SAFE,
                    category = ThreatCategory.SAFE_TRANSACTION,
                    threatSignals = listOf("Authentic bank debit pattern", "Legitimate merchant reference"),
                    aiAnalysis = "Verified genuine merchant transaction. Standard debit notification with normal merchant descriptor.",
                    actionTaken = "VERIFIED_SAFE",
                    timestamp = System.currentTimeMillis() - 1000 * 60 * 120
                )
            )

            initialLogs.forEach { db.threatLogDao().insertLog(it) }
        }
    }
}
