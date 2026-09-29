package com.example.security

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.local.FinGuardDatabase
import com.example.data.local.ThreatLogEntity
import com.example.data.model.IngestChannel
import com.example.data.model.ThreatCategory
import com.example.data.model.ThreatSeverity
import com.example.security.ai.GatewayCircuitBreaker
import com.example.security.ai.GeminiThreatAnalyzer
import com.example.security.classifier.ScamClassifier
import com.example.security.network.ClientRateLimiter
import com.example.security.pii.PiiScrubber
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Phase6RealDeviceQaTest {

    private lateinit var context: Context
    private lateinit var database: FinGuardDatabase

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        database = Room.inMemoryDatabaseBuilder(context, FinGuardDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        EventDeduplicator.resetForTesting()
        ShieldStateManager.resetForTesting(initialState = true)
        GeminiThreatAnalyzer.rateLimiter = ClientRateLimiter(maxPermits = 10_000, windowDurationMs = 60_000L)
        GeminiThreatAnalyzer.circuitBreaker.reset()
        GeminiThreatAnalyzer.delayProvider = { /* instantaneous in test */ }
    }

    @After
    fun tearDown() {
        database.close()
        EventDeduplicator.resetForTesting()
        ShieldStateManager.resetForTesting(initialState = true)
    }

    // -------------------------------------------------------------------------
    // Test 5: Shield ON
    // -------------------------------------------------------------------------
    @Test
    fun testShieldOnState() {
        ShieldStateManager.setShieldActive(context, true)
        assertTrue(ShieldStateManager.isShieldActive(context))
        assertTrue(ShieldStateManager.shieldStateFlow.value)
    }

    // -------------------------------------------------------------------------
    // Test 6: Shield OFF
    // -------------------------------------------------------------------------
    @Test
    fun testShieldOffState() {
        ShieldStateManager.setShieldActive(context, false)
        assertFalse(ShieldStateManager.isShieldActive(context))
        assertFalse(ShieldStateManager.shieldStateFlow.value)
    }

    // -------------------------------------------------------------------------
    // Test 10: Normal message
    // -------------------------------------------------------------------------
    @Test
    fun testNormalMessage() = runBlocking {
        val result = ScamClassifier.analyze(
            sender = "+919876543210",
            rawContent = "Hey, are you free for lunch tomorrow at 1 PM?",
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertEquals(0, result.riskScore)
        assertEquals(ThreatSeverity.SAFE, result.severity)
        assertEquals(ThreatCategory.SAFE_TRANSACTION, result.category)
        assertTrue(result.threatSignals.isEmpty())
    }

    // -------------------------------------------------------------------------
    // Test 11: Scam message
    // -------------------------------------------------------------------------
    @Test
    fun testGeneralScamMessage() = runBlocking {
        val result = ScamClassifier.analyze(
            sender = "DM-PROMO",
            rawContent = "Congratulations! You have won Rs 50,00,000 in KBC lottery. Claim immediately via http://kbc-winner.xyz/claim",
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore >= 75)
        assertTrue(result.severity == ThreatSeverity.HIGH_RISK || result.severity == ThreatSeverity.CRITICAL)
        assertTrue(result.threatSignals.isNotEmpty())
    }

    // -------------------------------------------------------------------------
    // Test 12: OTP message (Legitimate bank advisory vs OTP solicitation)
    // -------------------------------------------------------------------------
    @Test
    fun testLegitimateOtpMessage() = runBlocking {
        val legitimateOtp = "582910 is your secret OTP for transaction of Rs 1500.00 at AMAZON. Do not share OTP with anyone."
        val result = ScamClassifier.analyze(
            sender = "VM-HDFCBK",
            rawContent = legitimateOtp,
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertEquals(5, result.riskScore)
        assertEquals(ThreatSeverity.SAFE, result.severity)
        assertEquals(ThreatCategory.SAFE_TRANSACTION, result.category)
        assertTrue(result.threatSignals.any { it.contains("OTP verification alert") })
    }

    @Test
    fun testFraudulentOtpSolicitation() = runBlocking {
        val maliciousSolicitation = "Bank executive here. Please share OTP 582910 immediately to unblock your account."
        val result = ScamClassifier.analyze(
            sender = "+919988776655",
            rawContent = maliciousSolicitation,
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore >= 75)
        assertEquals(ThreatCategory.OTP_THEFT, result.category)
        assertTrue(result.threatSignals.any { it.contains("OTP theft vector") })
    }

    // -------------------------------------------------------------------------
    // Test 13: Phishing message
    // -------------------------------------------------------------------------
    @Test
    fun testPhishingMessage() = runBlocking {
        val phishing = "Dear customer, your card is blocked. Click here to verify credentials: http://secure-banking-login.xyz/portal"
        val result = ScamClassifier.analyze(
            sender = "+919123456789",
            rawContent = phishing,
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore >= 70)
        assertTrue(result.category == ThreatCategory.PHISHING_URL || result.category == ThreatCategory.BANK_IMPERSONATION)
        assertTrue(result.threatSignals.any { it.contains("shortened or spoofed link") })
    }

    // -------------------------------------------------------------------------
    // Test 14: Job scam
    // -------------------------------------------------------------------------
    @Test
    fun testJobScam() = runBlocking {
        val jobScam = "Part time job! Earn Rs 3000 to 5000 daily by just liking youtube videos. Join our telegram task group: t.me/fastcash"
        val result = ScamClassifier.analyze(
            sender = "TelegramPromo",
            rawContent = jobScam,
            channel = IngestChannel.TELEGRAM,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore >= 75)
        assertEquals(ThreatCategory.LOTTERY_JOB_SCAM, result.category)
        assertTrue(result.threatSignals.any { it.contains("task-based work-from-home") })
    }

    // -------------------------------------------------------------------------
    // Test 15: Electricity scam
    // -------------------------------------------------------------------------
    @Test
    fun testElectricityScam() = runBlocking {
        val electricityScam = "Dear consumer, your electricity power will be cut tonight at 9:30 PM because your previous month bill was not updated. Immediately contact our officer at 9876543210."
        val result = ScamClassifier.analyze(
            sender = "+919876543210",
            rawContent = electricityScam,
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore >= 80)
        assertEquals(ThreatCategory.EXTORTION_THREAT, result.category)
        assertTrue(result.threatSignals.any { it.contains("utility power cut-off scam") })
    }

    // -------------------------------------------------------------------------
    // Test 16: Reverse UPI collect trap
    // -------------------------------------------------------------------------
    @Test
    fun testReverseUpiCollectTrap() = runBlocking {
        val upiTrap = "Collect request of Rs 4,999.00 approved for cashback! Enter UPI PIN to receive money in your bank account."
        val result = ScamClassifier.analyze(
            sender = "PAYTM-REWARDS",
            rawContent = upiTrap,
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore >= 80)
        assertEquals(ThreatCategory.UPI_COLLECT_FRAUD, result.category)
        assertTrue(result.threatSignals.any { it.contains("Reverse UPI payment trap") })
    }

    // -------------------------------------------------------------------------
    // Test 17: Banking impersonation
    // -------------------------------------------------------------------------
    @Test
    fun testBankingImpersonation() = runBlocking {
        val bankFraud = "Dear SBI User, your NetBanking account has been suspended due to expired PAN card. Please update KYC immediately at http://sbi-kyc-verify.xyz"
        val result = ScamClassifier.analyze(
            sender = "SB-NOTIF",
            rawContent = bankFraud,
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore >= 80)
        assertEquals(ThreatCategory.BANK_IMPERSONATION, result.category)
        assertTrue(result.threatSignals.any { it.contains("impersonating") || it.contains("bank") })
    }

    // -------------------------------------------------------------------------
    // Test 18: Suspicious APK link
    // -------------------------------------------------------------------------
    @Test
    fun testSuspiciousApkLink() = runBlocking {
        val apkThreat = "Dear user, install our official security patch update: http://cdn.banking-patch.com/secure_bank_v2.apk to protect your funds."
        val result = ScamClassifier.analyze(
            sender = "WHATSAPP-MSG",
            rawContent = apkThreat,
            channel = IngestChannel.WHATSAPP,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore >= 85)
        assertEquals(ThreatCategory.MALICIOUS_APK, result.category)
        assertTrue(result.threatSignals.any { it.contains("APK") })
    }

    // -------------------------------------------------------------------------
    // Test 19: PII masking
    // -------------------------------------------------------------------------
    @Test
    fun testPiiMasking() {
        val sensitive = "User phone is +919876543210, VPA is merchant@okaxis, card is 4111222233334444, and OTP is 782109."
        val scrubbed = PiiScrubber.scrub(sensitive)

        assertFalse(scrubbed.scrubbedText.contains("9876543210"))
        assertFalse(scrubbed.scrubbedText.contains("4111222233334444"))
        assertFalse(scrubbed.scrubbedText.contains("782109"))
        assertTrue(scrubbed.scrubbedText.contains("[PHONE_REDACTED]"))
        assertTrue(scrubbed.scrubbedText.contains("[UPI_REDACTED]"))
        assertTrue(scrubbed.scrubbedText.contains("[CARD_REDACTED]"))
        assertTrue(scrubbed.scrubbedText.contains("[OTP_REDACTED]"))
        assertTrue(scrubbed.redactedCount >= 4)
    }

    // -------------------------------------------------------------------------
    // Test 20: Gemini analysis (Local fallback structured assessment)
    // -------------------------------------------------------------------------
    @Test
    fun testGeminiAnalysisStructure() = runBlocking {
        val structured = GeminiThreatAnalyzer.generateLocalExpertAssessmentStructured(
            text = "Electricity will be cut tonight at 9 PM. Call officer at [PHONE_REDACTED]",
            channel = "SMS",
            signals = listOf("Urgent power cutoff warning")
        )

        assertNotNull(structured)
        assertEquals("HIGH", structured.riskLevel)
        assertTrue(structured.riskScore >= 80)
        assertTrue(structured.confidence > 0.8)
        assertTrue(structured.isLocalFallback)
        assertFalse(structured.fraudVector.isBlank())
        assertFalse(structured.countermeasure.isBlank())
    }

    // -------------------------------------------------------------------------
    // Test 21 & 22: Gemini & Backend unavailable (Circuit Breaker)
    // -------------------------------------------------------------------------
    @Test
    fun testBackendUnavailableCircuitBreaker() = runBlocking {
        val breaker = GatewayCircuitBreaker(failureThreshold = 2, resetTimeoutMs = 5000L)
        assertEquals(GatewayCircuitBreaker.State.CLOSED, breaker.state)

        breaker.recordFailure()
        breaker.recordFailure()
        assertEquals(GatewayCircuitBreaker.State.OPEN, breaker.state)
        assertFalse(breaker.canExecute())

        val fallback = GeminiThreatAnalyzer.generateLocalExpertAssessmentStructured(
            text = "Collect request of Rs 5000 approved",
            channel = "SMS",
            signals = listOf("Reverse UPI trap")
        )
        assertNotNull(fallback)
        assertTrue(fallback.isLocalFallback)
    }

    // -------------------------------------------------------------------------
    // Test 23: Offline mode
    // -------------------------------------------------------------------------
    @Test
    fun testOfflineModeLocalReasoning() = runBlocking {
        // When completely offline, analyze operates cleanly using local regex & heuristics
        val result = ScamClassifier.analyze(
            sender = "+919876543210",
            rawContent = "Power will be cut tonight. Contact officer.",
            channel = IngestChannel.SMS,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertTrue(result.riskScore > 0)
        assertNotNull(result.aiReasoning)
        assertNotNull(result.structuredThreat)
        assertTrue(result.structuredThreat!!.isLocalFallback)
    }

    // -------------------------------------------------------------------------
    // Test 26: Database persistence
    // -------------------------------------------------------------------------
    @Test
    fun testDatabasePersistence() = runBlocking {
        val logDao = database.threatLogDao()
        val entity = ThreatLogEntity(
            sender = "DM-HDFCBK",
            channel = IngestChannel.SMS,
            scrubbedContent = "Debit Rs 500 from A/c [ACCOUNT_REDACTED]",
            originalMasked = "Debit Rs 500 from A/c XX1234",
            piiItemsFound = listOf("XX1234"),
            riskScore = 5,
            severity = ThreatSeverity.SAFE,
            category = ThreatCategory.SAFE_TRANSACTION,
            threatSignals = listOf("Legitimate bank SMS"),
            aiAnalysis = "Verified genuine",
            actionTaken = "VERIFIED_SAFE"
        )

        val id = logDao.insertLog(entity)
        assertTrue(id > 0)

        val retrieved = logDao.getLogById(id)
        assertNotNull(retrieved)
        assertEquals("DM-HDFCBK", retrieved!!.sender)
        assertEquals(ThreatSeverity.SAFE, retrieved.severity)
        assertEquals(5, retrieved.riskScore)
    }

    // -------------------------------------------------------------------------
    // Test 29: Filtering
    // -------------------------------------------------------------------------
    @Test
    fun testFilteringByChannelAndSeverity() = runBlocking {
        val logDao = database.threatLogDao()
        logDao.insertLog(ThreatLogEntity(sender = "Sender1", channel = IngestChannel.SMS, scrubbedContent = "SMS safe", originalMasked = "SMS safe", piiItemsFound = emptyList(), riskScore = 0, severity = ThreatSeverity.SAFE, category = ThreatCategory.SAFE_TRANSACTION, threatSignals = emptyList(), aiAnalysis = null, actionTaken = "VERIFIED_SAFE"))
        logDao.insertLog(ThreatLogEntity(sender = "Sender2", channel = IngestChannel.WHATSAPP, scrubbedContent = "WA dangerous", originalMasked = "WA dangerous", piiItemsFound = emptyList(), riskScore = 90, severity = ThreatSeverity.CRITICAL, category = ThreatCategory.MALICIOUS_APK, threatSignals = listOf("APK"), aiAnalysis = null, actionTaken = "BLOCKED"))

        val allLogs = logDao.getRecentLogsDirect()
        assertEquals(2, allLogs.size)

        val smsOnly = allLogs.filter { it.channel == IngestChannel.SMS }
        assertEquals(1, smsOnly.size)
        assertEquals("Sender1", smsOnly[0].sender)

        val criticalOnly = allLogs.filter { it.severity == ThreatSeverity.CRITICAL }
        assertEquals(1, criticalOnly.size)
        assertEquals("Sender2", criticalOnly[0].sender)
    }

    // -------------------------------------------------------------------------
    // Test 30: Search
    // -------------------------------------------------------------------------
    @Test
    fun testThreatFeedSearch() = runBlocking {
        val logDao = database.threatLogDao()
        logDao.insertLog(ThreatLogEntity(sender = "ElectricityOffice", channel = IngestChannel.SMS, scrubbedContent = "Electricity bill overdue power cut", originalMasked = "Electricity bill", piiItemsFound = emptyList(), riskScore = 85, severity = ThreatSeverity.HIGH_RISK, category = ThreatCategory.EXTORTION_THREAT, threatSignals = listOf("Power cut"), aiAnalysis = null, actionTaken = "WARNED"))
        logDao.insertLog(ThreatLogEntity(sender = "BankAlert", channel = IngestChannel.SMS, scrubbedContent = "Debit of Rs 100", originalMasked = "Debit", piiItemsFound = emptyList(), riskScore = 0, severity = ThreatSeverity.SAFE, category = ThreatCategory.SAFE_TRANSACTION, threatSignals = emptyList(), aiAnalysis = null, actionTaken = "VERIFIED_SAFE"))

        val allLogs = logDao.getRecentLogsDirect()
        val query = "power cut"
        val matched = allLogs.filter {
            it.sender.contains(query, ignoreCase = true) ||
            it.scrubbedContent.contains(query, ignoreCase = true) ||
            it.threatSignals.any { signal -> signal.contains(query, ignoreCase = true) }
        }

        assertEquals(1, matched.size)
        assertEquals("ElectricityOffice", matched[0].sender)
    }

    // -------------------------------------------------------------------------
    // Test 31: Simulator
    // -------------------------------------------------------------------------
    @Test
    fun testSimulatorPayloadExecution() = runBlocking {
        val scanResult = ScamClassifier.analyze(
            sender = "+919876543210",
            rawContent = "Part-time job! Earn daily 3000 rs by liking youtube videos.",
            channel = IngestChannel.TELEGRAM,
            flaggedVpaDao = database.flaggedVpaDao()
        )

        assertNotNull(scanResult)
        assertEquals(ThreatCategory.LOTTERY_JOB_SCAM, scanResult.category)
        assertTrue(scanResult.riskScore >= 75)
    }

    // -------------------------------------------------------------------------
    // Test 32: Duplicate event handling
    // -------------------------------------------------------------------------
    @Test
    fun testDuplicateEventDeduplication() {
        val sender = "VM-ALERT"
        val content = "Transaction OTP is 492018. Do not share with anyone."
        val channel = IngestChannel.SMS

        // First occurrence: novel event
        val isFirstDuplicate = EventDeduplicator.isDuplicate(sender, content, channel, windowMs = 5000L)
        assertFalse(isFirstDuplicate)

        // Second occurrence with identical sender and content within window: duplicate
        val isSecondDuplicate = EventDeduplicator.isDuplicate(sender, content, channel, windowMs = 5000L)
        assertTrue(isSecondDuplicate)
        assertEquals(1L, EventDeduplicator.getDuplicateCount())

        // Third occurrence with slight whitespace variance: still deduplicated
        val isThirdDuplicate = EventDeduplicator.isDuplicate(sender, "  Transaction OTP is 492018.  Do not share with anyone. ", channel, windowMs = 5000L)
        assertTrue(isThirdDuplicate)
        assertEquals(2L, EventDeduplicator.getDuplicateCount())

        // Different sender: novel event
        val differentSenderDuplicate = EventDeduplicator.isDuplicate("OTHER-SENDER", content, channel, windowMs = 5000L)
        assertFalse(differentSenderDuplicate)
    }
}
