package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.security.ai.GeminiThreatAnalyzer
import com.example.security.banking.BankSmsParser
import com.example.security.pii.PiiScrubber
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("FinGuard", appName)
  }

  @Test
  fun `test pii scrubber redacts otp and account numbers`() {
    val input = "Your OTP is 482910 for account 987654321098. Never share."
    val result = PiiScrubber.scrub(input)
    assertFalse(result.scrubbedText.contains("482910"))
    assertTrue(result.scrubbedText.contains("[OTP_REDACTED]"))
    assertTrue(result.redactedCount >= 1)
  }

  @Test
  fun `test pii scrubber redacts standalone otp and payment cards`() {
    val input = "Security alert: 849201 is valid for card 4532 1122 3344 5566."
    val result = PiiScrubber.scrub(input)
    assertFalse(result.scrubbedText.contains("849201"))
    assertFalse(result.scrubbedText.contains("4532 1122 3344 5566"))
    assertTrue(result.scrubbedText.contains("[OTP_REDACTED]"))
    assertTrue(result.scrubbedText.contains("[CARD_REDACTED]"))
  }

  @Test
  fun `test bank sms parser detects reverse collect request fraud`() {
    val sms = "Collect Request for Rs 4,999.00 received from cashback.rewards@upi. Approve to receive bonus."
    val parsed = BankSmsParser.parse("VK-HDFCBK", sms)
    assertEquals("HDFC Bank", parsed?.bankName)
    assertTrue(parsed?.isCollectRequest == true)
    assertTrue(parsed?.isSuspiciousCollect == true)
  }

  @Test
  fun `test offline deterministic local fallback returns structured analysis`() = runBlocking {
    // When backend gateway is offline/unreachable, client gracefully falls back to local expert engine
    val fallback = GeminiThreatAnalyzer.generateLocalExpertAssessment(
      text = "Collect Request for Rs 4,999.00 received from unknown. Enter UPI PIN to claim.",
      channel = "WHATSAPP",
      signals = listOf("Reverse UPI Trap")
    )
    assertTrue(fallback.contains("[FRAUD VECTOR]: Reverse UPI Collect Trap"))
    assertTrue(fallback.contains("[ACTIONABLE COUNTERMEASURE]: Decline the collect request"))
  }
}
