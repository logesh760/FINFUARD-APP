package com.example.security.pii

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class PiiScrubberTest {

    // === Core Mandatory Tests Required by Audit ===

    @Test
    fun `test standalone 6-digit OTP`() {
        val result = PiiScrubber.scrub("483921")
        assertEquals("[OTP_REDACTED]", result.scrubbedText)
        assertFalse(result.scrubbedText.contains("483921"))
    }

    @Test
    fun `test OTP with trigger keyword phrase Your OTP is`() {
        val result = PiiScrubber.scrub("Your OTP is 483921")
        assertEquals("Your OTP is [OTP_REDACTED]", result.scrubbedText)
        assertFalse(result.scrubbedText.contains("483921"))
    }

    @Test
    fun `test OTP with trigger keyword phrase Use code`() {
        val result = PiiScrubber.scrub("Use code 483921")
        assertEquals("Use code [OTP_REDACTED]", result.scrubbedText)
        assertFalse(result.scrubbedText.contains("483921"))
    }

    @Test
    fun `test unformatted payment card number`() {
        val result = PiiScrubber.scrub("Card 4111111111111111")
        assertEquals("Card [CARD_REDACTED]", result.scrubbedText)
        assertFalse(result.scrubbedText.contains("4111111111111111"))
    }

    @Test
    fun `test bank account number`() {
        val result = PiiScrubber.scrub("Account 123456789012")
        assertEquals("Account [ACCOUNT_REDACTED]", result.scrubbedText)
        assertFalse(result.scrubbedText.contains("123456789012"))
    }

    @Test
    fun `test phone number with call context`() {
        val result = PiiScrubber.scrub("Call 9876543210")
        assertEquals("Call [PHONE_REDACTED]", result.scrubbedText)
        assertFalse(result.scrubbedText.contains("9876543210"))
    }

    @Test
    fun `test UPI identifier with contextual prefix`() {
        val result = PiiScrubber.scrub("UPI test@bank")
        assertEquals("UPI [UPI_REDACTED]", result.scrubbedText)
        assertFalse(result.scrubbedText.contains("test@bank"))
    }

    @Test
    fun `test password credential with contextual indicator`() {
        val result = PiiScrubber.scrub("password: mySecret123")
        assertEquals("password: [CREDENTIAL_REDACTED]", result.scrubbedText)
        assertFalse(result.scrubbedText.contains("mySecret123"))
    }

    // === Legitimate Non-PII Numbers: Preventing Over-Redaction ===

    @Test
    fun `test legitimate order number is preserved without destruction`() {
        val result = PiiScrubber.scrub("Order number 483921")
        assertEquals("Order number 483921", result.scrubbedText)
        assertEquals(0, result.redactedCount)
    }

    @Test
    fun `test legitimate amount with rupee symbol is preserved`() {
        val result = PiiScrubber.scrub("Amount ₹500")
        assertEquals("Amount ₹500", result.scrubbedText)
        assertEquals(0, result.redactedCount)
    }

    @Test
    fun `test legitimate invoice number is preserved`() {
        val result = PiiScrubber.scrub("Invoice 123456")
        assertEquals("Invoice 123456", result.scrubbedText)
        assertEquals(0, result.redactedCount)
    }

    @Test
    fun `test additional legitimate reference and tracking codes are preserved`() {
        val res1 = PiiScrubber.scrub("Bill #123456")
        assertEquals("Bill #123456", res1.scrubbedText)

        val res2 = PiiScrubber.scrub("Tracking ID: 654321")
        assertEquals("Tracking ID: 654321", res2.scrubbedText)

        val res3 = PiiScrubber.scrub("Ticket 987654")
        assertEquals("Ticket 987654", res3.scrubbedText)
    }

    // === Extended Security Hardening: CVV, Tokens, Seed Phrases, Email, UPI Handles ===

    @Test
    fun `test CVV and CVC security codes redaction`() {
        val res1 = PiiScrubber.scrub("Your CVV is 789. Do not disclose.")
        assertTrue(res1.scrubbedText.contains("[CREDENTIAL_REDACTED]"))
        assertFalse(res1.scrubbedText.contains("789"))

        val res2 = PiiScrubber.scrub("Security code: 4567")
        assertTrue(res2.scrubbedText.contains("[CREDENTIAL_REDACTED]"))
        assertFalse(res2.scrubbedText.contains("4567"))
    }

    @Test
    fun `test OTP without requiring words OTP or code`() {
        val input = "Do not share 654321 with anyone to verify your login."
        val result = PiiScrubber.scrub(input)
        assertTrue(result.scrubbedText.contains("[OTP_REDACTED]"))
        assertFalse(result.scrubbedText.contains("654321"))
    }

    @Test
    fun `test known UPI PSP handles redaction`() {
        val res1 = PiiScrubber.scrub("Send payment to merchant.store@paytm")
        assertTrue(res1.scrubbedText.contains("[UPI_REDACTED]"))
        assertFalse(res1.scrubbedText.contains("merchant.store@paytm"))

        val res2 = PiiScrubber.scrub("Collect from user@okhdfcbank")
        assertTrue(res2.scrubbedText.contains("[UPI_REDACTED]"))
        assertFalse(res2.scrubbedText.contains("user@okhdfcbank"))
    }

    @Test
    fun `test standard email address redaction`() {
        val result = PiiScrubber.scrub("Contact support team at security@fintechbank.com for help.")
        assertTrue(result.scrubbedText.contains("[EMAIL_REDACTED]"))
        assertFalse(result.scrubbedText.contains("security@fintechbank.com"))
    }

    @Test
    fun `test API keys and secrets redaction`() {
        val input = "API Key: AIzaSyD9x8q7p6o5n4m3l2k1j0hgfEdcBaZyxWv"
        val result = PiiScrubber.scrub(input)
        assertTrue(result.scrubbedText.contains("[SECRET_REDACTED]"))
        assertFalse(result.scrubbedText.contains("AIzaSy"))
    }

    @Test
    fun `test seed and recovery phrases redaction`() {
        val input = "Seed phrase: apple banana cherry dog elephant fox grape horse igloo jaguar kite lemon"
        val result = PiiScrubber.scrub(input)
        assertTrue(result.scrubbedText.contains("[SECRET_REDACTED]"))
        assertFalse(result.scrubbedText.contains("banana cherry dog"))
    }

    @Test
    fun `test conservative human name privacy strategy`() {
        // Greeting recipient name is sanitized without using unsafe regex that would destroy brand or bank names
        val input = "Dear Rajesh Sharma, your OTP is 948201 for State Bank of India account."
        val result = PiiScrubber.scrub(input)
        assertFalse(result.scrubbedText.contains("Rajesh Sharma"))
        assertTrue(result.scrubbedText.contains("Dear Customer,"))
        // Crucial: Brand & bank names are NOT damaged
        assertTrue(result.scrubbedText.contains("State Bank of India"))
    }

    @Test
    fun `test comprehensive multi-token complex message scrubbing`() {
        val complex = "Dear John Doe, Call 9876543210. Card 4111111111111111 has OTP 482910 for Account 123456789012. Order number 994821 is ready."
        val result = PiiScrubber.scrub(complex)

        // Raw PII must be completely stripped
        assertFalse(result.scrubbedText.contains("9876543210"))
        assertFalse(result.scrubbedText.contains("4111111111111111"))
        assertFalse(result.scrubbedText.contains("482910"))
        assertFalse(result.scrubbedText.contains("123456789012"))

        // Placeholders must be present
        assertTrue(result.scrubbedText.contains("[PHONE_REDACTED]"))
        assertTrue(result.scrubbedText.contains("[CARD_REDACTED]"))
        assertTrue(result.scrubbedText.contains("[OTP_REDACTED]"))
        assertTrue(result.scrubbedText.contains("[ACCOUNT_REDACTED]"))

        // Legitimate order number must be preserved
        assertTrue(result.scrubbedText.contains("Order number 994821"))
    }
}
