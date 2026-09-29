package com.example.security.pii

import com.example.data.model.PiiScrubResult
import java.util.regex.Pattern

/**
 * Enterprise PII Scrubber for FinGuard Security (Phase 2 Hardened).
 * Sanitizes incoming text locally on device before storage, transmission, or AI evaluation.
 *
 * Strict Privacy Placeholders:
 * - [OTP_REDACTED]
 * - [CARD_REDACTED]
 * - [ACCOUNT_REDACTED]
 * - [PHONE_REDACTED]
 * - [EMAIL_REDACTED]
 * - [UPI_REDACTED]
 * - [CREDENTIAL_REDACTED]
 * - [SECRET_REDACTED]
 *
 * Conservative Privacy Strategy for Human Names:
 * Arbitrary dictionary matching or broad Capitalized regex (`[A-Z][a-z]+`) is explicitly
 * avoided as it causes catastrophic false-positives on bank names ('State Bank of India',
 * 'HDFC Bank'), brand entities ('Amazon', 'Flipkart'), and sentence starters. Instead, we
 * conservatively sanitize structured greeting recipient names while preserving contextual fraud signals.
 */
object PiiScrubber {

    // 1. Seed / Recovery phrases (12-24 words preceded by seed phrase context)
    private val SEED_PHRASE_PATTERN = Pattern.compile(
        "(?i)\\b(?:seed\\s*phrase|recovery\\s*phrase|backup\\s*phrase|mnemonic(?:\\s*phrase)?|secret\\s*recovery\\s*phrase)\\s*[:=\\-]\\s*([a-z]{3,12}(?:\\s+[a-z]{3,12}){11,23})\\b"
    )

    // 2. API Keys, Tokens & Secrets
    private val API_KEY_PATTERNS = listOf(
        Pattern.compile("\\bAIza[0-9A-Za-z\\-_]{35}\\b"),
        Pattern.compile("\\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\\b"),
        Pattern.compile("\\b(?:sk-[a-zA-Z0-9]{20,}|xox[baprs]-[0-9a-zA-Z]{10,})\\b"),
        Pattern.compile("(?i)\\b(?:api[\\-_\\s]?key|access[\\-_\\s]?token|auth[\\-_\\s]?token|secret[\\-_\\s]?key|bearer)\\s*[:=\\-]?\\s*([a-zA-Z0-9_\\-\\._]{16,})\\b")
    )

    // 3. Passwords & Login Credentials
    private val PASSWORD_PATTERN = Pattern.compile(
        "(?i)\\b(?:password|passwd|pwd|passcode|passphrase|netbanking\\s*password|login\\s*password)\\s*(?:is|:|=|-)?\\s*([^\\s,;]{3,})"
    )

    // 4. CVV / CVC Security Codes
    private val CVV_PATTERN = Pattern.compile(
        "(?i)\\b(?:cvv[2]?|cvc[2]?|cid|card\\s*security\\s*code|security\\s*code)\\s*(?:is|:|=|-)?\\s*([0-9]{3,4})\\b"
    )

    // 5. Payment Cards (13 to 19 digits formatted or unformatted)
    private val CARD_PATTERN = Pattern.compile(
        "(?i)(?:\\b(?:card(?:\\s*(?:no|number|#))?|debit\\s*card|credit\\s*card)\\s*[:=\\-]?\\s*)?(\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4})\\b)"
    )

    // 6. Bank Account Numbers
    private val BANK_ACCOUNT_PATTERN = Pattern.compile(
        "(?i)\\b(?:a/c|acct|account|acc\\s*no[.:]?|a/c\\s*no[.:]?|account\\s*(?:no|number|#)[.:]?)\\s*(?:is|:|-)?\\s*([X*]{2,12}[0-9]{3,4}|[0-9]{9,18})\\b"
    )

    // 7. UPI Identifiers (Preceded by UPI or known PSP handles)
    private val UPI_CONTEXT_PATTERN = Pattern.compile(
        "(?i)\\b(?:upi(?:\\s*(?:id|vpa|handle|address))?|vpa|pay\\s*to|send\\s*to|collect\\s*from)\\s*[:=\\-]?\\s*([a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-_]+)\\b"
    )

    private val UPI_KNOWN_PSP_PATTERN = Pattern.compile(
        "\\b[a-zA-Z0-9._%+\\-]+@(?:upi|paytm|okhdfcbank|okaxis|okicici|oksbi|ybl|axl|ibl|apl|postbank|federal|kotak|icici|sbi|hdfcbank|barodampay|pnb|indus|allbank|aubank|airtel|jupiteraxis|fbl|idfcbank|freecharge)\\b",
        Pattern.CASE_INSENSITIVE
    )

    // 8. Email Addresses
    private val EMAIL_PATTERN = Pattern.compile(
        "\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\\b"
    )

    // 9. Phone Numbers (Preceded by phone context OR Indian 10-digit mobile)
    private val PHONE_CONTEXT_PATTERN = Pattern.compile(
        "(?i)\\b(?:call|dial|phone|mobile|contact|tel|helpline|whatsapp|sms|ph|mob)\\s*(?:is|:|=|\\-)?\\s*(\\+?(?:91[\\-\\s]?)?[6-9]\\d{9}|(?:\\+?[1-9]\\d{0,3}[\\-\\s]?)?[0-9]{7,12})\\b"
    )

    private val INDIAN_MOBILE_STANDALONE = Pattern.compile(
        "(?<![0-9+])(?:\\+91[\\-\\s]?|0)?[6-9]\\d{9}(?!\\d)\\b"
    )

    // 10. OTP / Verification codes with trigger keywords
    private val OTP_TRIGGER_PATTERN = Pattern.compile(
        "(?i)\\b(?:otp|code|one[- ]?time[- ]?password|verification(?:[- ]?code)?|pin|secret|auth(?:[- ]?code)?|passcode)\\s*(?:is|:|-)?\\s*([0-9]{4,8})\\b"
    )

    // 11. Standalone 6-Digit Codes
    private val STANDALONE_6DIGIT = Pattern.compile(
        "\\b(?<!\\d)([0-9]{6})(?!\\d)\\b"
    )

    // Legitimate non-OTP transactional context pattern (Negative Context Check)
    private val LEGITIMATE_NUMBER_CONTEXT = Pattern.compile(
        "(?i)\\b(?:order(?:\\s*(?:number|no|id|#))?|invoice(?:\\s*(?:number|no|id|#))?|bill(?:\\s*(?:number|no|id|#))?|tracking(?:\\s*(?:id|number|no|#))?|ticket(?:\\s*(?:number|no|id|#))?|amount|amt|[₹$€£]|rs\\.?|inr|usd|pnr|postal|zip(?:\\s*code)?|ref(?:\\s*(?:no|number|#))?)\\s*[:#\\-]?\\s*$"
    )

    // Conservative salutation pattern for greeting recipient name
    private val CONSERVATIVE_SALUTATION = Pattern.compile(
        "(?i)^(?:dear|hi|hello)\\s+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+)?)\\s*[,:\n\r]"
    )

    private val GENERIC_GREETINGS = setOf(
        "customer", "user", "sir", "madam", "member", "client", "cardholder", "team", "all",
        "hdfc", "sbi", "icici", "axis", "bank", "manager"
    )

    /**
     * Sanitizes incoming text locally on device before storage, transmission, or AI evaluation.
     */
    fun scrub(input: String): PiiScrubResult {
        if (input.isBlank()) {
            return PiiScrubResult(input, input, emptyList(), 0)
        }

        // 0. Standalone exact OTP check (e.g. input is solely "483921")
        val trimmed = input.trim()
        if (trimmed.matches(Regex("^[0-9]{4,8}$"))) {
            return PiiScrubResult(
                originalText = input,
                scrubbedText = "[OTP_REDACTED]",
                redactedTokens = listOf("Standalone OTP"),
                redactedCount = 1
            )
        }

        var scrubbed = input
        val tokens = mutableListOf<String>()
        var count = 0

        // 1. Seed / Recovery phrases
        val seedMatcher = SEED_PHRASE_PATTERN.matcher(scrubbed)
        while (seedMatcher.find()) {
            val phrase = seedMatcher.group(1)
            if (phrase != null && !phrase.startsWith("[")) {
                scrubbed = scrubbed.replace(phrase, "[SECRET_REDACTED]")
                tokens.add("Seed/Recovery Phrase")
                count++
            }
        }

        // 2. API Keys, Tokens & Secrets
        for (apiPattern in API_KEY_PATTERNS) {
            val matcher = apiPattern.matcher(scrubbed)
            while (matcher.find()) {
                val secret = if (matcher.groupCount() >= 1) matcher.group(1) else matcher.group()
                if (secret != null && !secret.startsWith("[") && secret.length >= 10) {
                    scrubbed = scrubbed.replace(secret, "[SECRET_REDACTED]")
                    tokens.add("Secret API Key/Token")
                    count++
                }
            }
        }

        // 3. Passwords & Login Credentials
        val pwdMatcher = PASSWORD_PATTERN.matcher(scrubbed)
        while (pwdMatcher.find()) {
            val pwd = pwdMatcher.group(1)
            if (pwd != null && !pwd.startsWith("[")) {
                scrubbed = scrubbed.replace(pwd, "[CREDENTIAL_REDACTED]")
                tokens.add("User Password/Passcode")
                count++
            }
        }

        // 4. CVV / CVC Security Codes
        val cvvMatcher = CVV_PATTERN.matcher(scrubbed)
        while (cvvMatcher.find()) {
            val cvv = cvvMatcher.group(1)
            if (cvv != null && !cvv.startsWith("[")) {
                scrubbed = scrubbed.replace(cvv, "[CREDENTIAL_REDACTED]")
                tokens.add("Card CVV/CVC Code")
                count++
            }
        }

        // 5. Payment Card Numbers
        val cardMatcher = CARD_PATTERN.matcher(scrubbed)
        while (cardMatcher.find()) {
            val card = if (cardMatcher.groupCount() >= 1 && cardMatcher.group(1) != null) cardMatcher.group(1) else cardMatcher.group()
            if (card != null && !card.startsWith("[")) {
                scrubbed = scrubbed.replace(card, "[CARD_REDACTED]")
                tokens.add("Payment Card")
                count++
            }
        }

        // 6. Bank Account Numbers
        val bankMatcher = BANK_ACCOUNT_PATTERN.matcher(scrubbed)
        while (bankMatcher.find()) {
            val acc = bankMatcher.group(1)
            if (acc != null && !acc.contains("REDACTED")) {
                scrubbed = scrubbed.replace(acc, "[ACCOUNT_REDACTED]")
                tokens.add("Bank Account Number")
                count++
            }
        }

        // 7. UPI Identifiers (Contextual & Known PSP Handles)
        val upiContextMatcher = UPI_CONTEXT_PATTERN.matcher(scrubbed)
        while (upiContextMatcher.find()) {
            val upi = upiContextMatcher.group(1)
            if (upi != null && !upi.startsWith("[")) {
                scrubbed = scrubbed.replace(upi, "[UPI_REDACTED]")
                tokens.add("UPI VPA Identifier")
                count++
            }
        }

        val upiKnownMatcher = UPI_KNOWN_PSP_PATTERN.matcher(scrubbed)
        while (upiKnownMatcher.find()) {
            val upi = upiKnownMatcher.group()
            if (!upi.startsWith("[")) {
                scrubbed = scrubbed.replace(upi, "[UPI_REDACTED]")
                tokens.add("UPI Handle")
                count++
            }
        }

        // 8. Email Addresses
        val emailMatcher = EMAIL_PATTERN.matcher(scrubbed)
        while (emailMatcher.find()) {
            val email = emailMatcher.group()
            if (!email.startsWith("[")) {
                scrubbed = scrubbed.replace(email, "[EMAIL_REDACTED]")
                tokens.add("Email Address")
                count++
            }
        }

        // 9. Phone Numbers (Contextual and Standalone Mobile)
        val phoneContextMatcher = PHONE_CONTEXT_PATTERN.matcher(scrubbed)
        while (phoneContextMatcher.find()) {
            val phone = phoneContextMatcher.group(1)
            if (phone != null && !phone.startsWith("[")) {
                scrubbed = scrubbed.replace(phone, "[PHONE_REDACTED]")
                tokens.add("Phone Number")
                count++
            }
        }

        // Check standalone Indian mobile format if not preceded by order/ref/amount/account
        val mobileMatcher = INDIAN_MOBILE_STANDALONE.matcher(scrubbed)
        val mobileMatches = mutableListOf<Pair<Int, Int>>()
        while (mobileMatcher.find()) {
            val start = mobileMatcher.start()
            val end = mobileMatcher.end()
            val num = mobileMatcher.group()
            if (!num.startsWith("[")) {
                val preceding = scrubbed.substring(maxOf(0, start - 35), start)
                if (!LEGITIMATE_NUMBER_CONTEXT.matcher(preceding).find()) {
                    mobileMatches.add(Pair(start, end))
                }
            }
        }
        for (pair in mobileMatches.reversed()) {
            scrubbed = scrubbed.substring(0, pair.first) + "[PHONE_REDACTED]" + scrubbed.substring(pair.second)
            tokens.add("Mobile Phone Number")
            count++
        }

        // 10. OTP / Verification codes with trigger keywords
        val otpTriggerMatcher = OTP_TRIGGER_PATTERN.matcher(scrubbed)
        while (otpTriggerMatcher.find()) {
            val otp = otpTriggerMatcher.group(1)
            if (otp != null && !otp.startsWith("[") && !otp.startsWith("202")) {
                scrubbed = scrubbed.replace(otp, "[OTP_REDACTED]")
                tokens.add("One-Time Password")
                count++
            }
        }

        // 11. Standalone / Isolated 6-digit Codes without trigger words, PRESERVING legitimate context
        val standaloneMatcher = STANDALONE_6DIGIT.matcher(scrubbed)
        val standaloneMatches = mutableListOf<Pair<Int, Int>>()
        while (standaloneMatcher.find()) {
            val start = standaloneMatcher.start()
            val end = standaloneMatcher.end()
            val code = standaloneMatcher.group(1)
            if (code != null && !code.startsWith("[") && !code.startsWith("202")) {
                val preceding = scrubbed.substring(maxOf(0, start - 35), start)
                // If preceded by Order, Invoice, Bill, Tracking, Ticket, Amount, Rs, Ref, etc., PRESERVE it!
                if (!LEGITIMATE_NUMBER_CONTEXT.matcher(preceding).find()) {
                    standaloneMatches.add(Pair(start, end))
                }
            }
        }
        for (pair in standaloneMatches.reversed()) {
            scrubbed = scrubbed.substring(0, pair.first) + "[OTP_REDACTED]" + scrubbed.substring(pair.second)
            tokens.add("Isolated 6-Digit Code")
            count++
        }

        // 12. Conservative Salutation Name Privacy Strategy
        val salutationMatcher = CONSERVATIVE_SALUTATION.matcher(scrubbed)
        if (salutationMatcher.find()) {
            val name = salutationMatcher.group(1)
            if (name != null && !GENERIC_GREETINGS.contains(name.lowercase().trim())) {
                scrubbed = scrubbed.replace(name, "Customer")
                tokens.add("Recipient Greeting Salutation")
                count++
            }
        }

        return PiiScrubResult(
            originalText = input,
            scrubbedText = scrubbed,
            redactedTokens = tokens.distinct(),
            redactedCount = count
        )
    }
}
