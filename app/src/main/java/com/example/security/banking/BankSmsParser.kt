package com.example.security.banking

import com.example.data.model.BankTransactionInfo
import java.util.regex.Pattern

object BankSmsParser {

    private val AMOUNT_PATTERN = Pattern.compile(
        "(?i)(?:rs\\.?|inr|usd|\\$|eur)\\s*([0-9,]+\\.[0-9]{2}|[0-9,]+)"
    )

    private val ACCOUNT_PATTERN = Pattern.compile(
        "(?i)(?:a/c|account|acct|card)\\s*(?:no[.:]?)?\\s*([xX*]{2,8}[0-9]{3,4}|[0-9]{9,16})"
    )

    private val UPI_VPA_PATTERN = Pattern.compile(
        "[a-zA-Z0-9.\\-_]{2,50}@[a-zA-Z]{2,30}"
    )

    private val UTR_PATTERN = Pattern.compile(
        "(?i)(?:ref(?:erence)?|utr|txn|upi ref)[.: ]*([0-9a-zA-Z]{8,22})"
    )

    private val COLLECT_PATTERN = Pattern.compile(
        "(?i)(?:collect request|requested money|payment request|approval request|requested rs|pay to receive|claim refund)"
    )

    private val DEBIT_KEYWORDS = listOf("debited", "spent", "paid", "withdrawn", "purchase", "sent")
    private val CREDIT_KEYWORDS = listOf("credited", "received", "deposited", "refunded", "added")

    /**
     * Parses financial SMS payload and extracts structured transaction metadata.
     */
    fun parse(sender: String, messageText: String): BankTransactionInfo? {
        val lower = messageText.lowercase()

        // Check if message resembles a banking or UPI transaction alert
        val hasFinancialKeywords = lower.contains("rs") ||
                lower.contains("inr") ||
                lower.contains("debited") ||
                lower.contains("credited") ||
                lower.contains("upi") ||
                lower.contains("a/c") ||
                lower.contains("account") ||
                lower.contains("vpa") ||
                lower.contains("collect")

        if (!hasFinancialKeywords) {
            return null
        }

        // 1. Bank name detection from sender header or text
        val bankName = detectBankName(sender, messageText)

        // 2. Extract Amount
        val amountMatcher = AMOUNT_PATTERN.matcher(messageText)
        val amount = if (amountMatcher.find()) amountMatcher.group(1) else null

        // 3. Detect Debit / Credit / Collect
        val isDebit = DEBIT_KEYWORDS.any { lower.contains(it) }
        val isCredit = CREDIT_KEYWORDS.any { lower.contains(it) }
        val isCollect = COLLECT_PATTERN.matcher(messageText).find() || lower.contains("collect request")

        // 4. Extract Account / Card digits
        val accMatcher = ACCOUNT_PATTERN.matcher(messageText)
        val account = if (accMatcher.find()) accMatcher.group(1) else null

        // 5. Extract VPA
        val vpaMatcher = UPI_VPA_PATTERN.matcher(messageText)
        var vpa: String? = null
        while (vpaMatcher.find()) {
            val candidate = vpaMatcher.group()
            // Ignore generic email addresses if possible
            if (!candidate.endsWith(".com") && !candidate.endsWith(".org") && !candidate.endsWith(".in")) {
                vpa = candidate
                break
            } else if (vpa == null) {
                vpa = candidate
            }
        }

        // 6. Extract Reference No / UTR
        val utrMatcher = UTR_PATTERN.matcher(messageText)
        val referenceNo = if (utrMatcher.find()) utrMatcher.group(1) else null

        // 7. Check for dangerous UPI Collect Request scam
        // Common Scam: Attacker sends collect request pretending it is "Cashback", "Refund", or "Winner prize"
        // Legitimate rule: In UPI, YOU NEVER PAY OR ENTER PIN TO RECEIVE MONEY!
        val isSuspiciousCollect = isCollect && (
                lower.contains("refund") ||
                lower.contains("cashback") ||
                lower.contains("won") ||
                lower.contains("claim") ||
                lower.contains("lottery") ||
                lower.contains("prize") ||
                lower.contains("approve to receive")
        )

        return BankTransactionInfo(
            bankName = bankName,
            senderHeader = sender,
            amount = amount,
            isDebit = isDebit,
            isCredit = isCredit,
            isCollectRequest = isCollect,
            accountMasked = account,
            vpaId = vpa,
            referenceNo = referenceNo,
            isSuspiciousCollect = isSuspiciousCollect
        )
    }

    private fun detectBankName(sender: String, messageText: String): String {
        val s = sender.uppercase()
        val text = messageText.uppercase()

        return when {
            s.contains("HDFC") || text.contains("HDFC BANK") -> "HDFC Bank"
            s.contains("SBI") || text.contains("STATE BANK") || text.contains("YONO") -> "State Bank of India (SBI)"
            s.contains("ICICI") || text.contains("ICICI BANK") || text.contains("IMOBILE") -> "ICICI Bank"
            s.contains("AXIS") || text.contains("AXIS BANK") -> "Axis Bank"
            s.contains("KOTAK") || text.contains("KOTAK BANK") -> "Kotak Mahindra Bank"
            s.contains("PNB") || text.contains("PUNJAB NATIONAL") -> "Punjab National Bank"
            s.contains("PAYTM") || text.contains("PAYTM PAYMENTS") -> "Paytm Payments Bank"
            s.contains("GPAY") || text.contains("GOOGLE PAY") -> "Google Pay"
            s.contains("PHONEPE") || text.contains("PHONEPE") -> "PhonePe"
            s.contains("CANARA") || text.contains("CANARA BANK") -> "Canara Bank"
            s.contains("BOB") || text.contains("BANK OF BARODA") -> "Bank of Baroda"
            else -> if (sender.isNotBlank()) "Bank/UPI ($sender)" else "UPI Banking"
        }
    }
}
