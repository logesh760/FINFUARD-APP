package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.AddAlert
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Dangerous
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Report
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.ui.theme.FinAmber
import com.example.ui.theme.FinCrimson
import com.example.ui.theme.FinCyan
import com.example.ui.theme.FinEmerald
import com.example.ui.theme.FinNavyBorder
import com.example.ui.theme.FinNavyElevated
import com.example.ui.theme.FinNavySurface
import com.example.ui.theme.FinTextPrimary
import com.example.ui.theme.FinTextSecondary
import com.example.ui.viewmodel.MainViewModel
import com.example.ui.viewmodel.VpaCheckState

@Composable
fun UpiBankingGuardScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val vpaState by viewModel.vpaCheckState.collectAsStateWithLifecycle()
    val flaggedVpas by viewModel.flaggedVpas.collectAsStateWithLifecycle()
    val parsedBankSms by viewModel.bankSmsParsed.collectAsStateWithLifecycle()

    var vpaInput by remember { mutableStateOf("") }
    var reportReasonInput by remember { mutableStateOf("") }
    var showReportBox by remember { mutableStateOf(false) }

    var smsSenderInput by remember { mutableStateOf("VK-HDFCBK") }
    var smsBodyInput by remember {
        mutableStateOf("Dear Customer, Collect Request for Rs 4,999.00 received from rewards.refund99@okaxis. Approve payment to receive your cash reward.")
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Section 1: Header
        item {
            Spacer(modifier = Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(FinCyan.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.AccountBalance,
                        contentDescription = null,
                        tint = FinCyan,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column {
                    Text(
                        text = "UPI & BANKING FRAUD DEFENSE",
                        color = FinCyan,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "NPCI Blacklist Registry & Bank SMS Forensics",
                        color = FinTextSecondary,
                        fontSize = 11.sp
                    )
                }
            }
        }

        // Section 2: UPI VPA Validator Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "VERIFY UPI ID / VPA REPUTATION",
                        color = FinTextPrimary,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Check whether a payment address is tied to known scams, reverse collect traps, or malicious refund campaigns.",
                        color = FinTextSecondary,
                        fontSize = 11.sp,
                        lineHeight = 15.sp
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedTextField(
                        value = vpaInput,
                        onValueChange = { vpaInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("e.g. cashback.reward99@okaxis", color = FinTextSecondary, fontSize = 12.sp) },
                        leadingIcon = {
                            Icon(imageVector = Icons.Default.Search, contentDescription = null, tint = FinCyan)
                        },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = FinCyan,
                            unfocusedBorderColor = FinNavyBorder,
                            focusedTextColor = FinTextPrimary,
                            unfocusedTextColor = FinTextPrimary,
                            focusedContainerColor = FinNavyElevated,
                            unfocusedContainerColor = FinNavyElevated
                        ),
                        shape = RoundedCornerShape(10.dp),
                        singleLine = true
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { viewModel.checkVpa(vpaInput) },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = FinCyan, contentColor = Color(0xFF00363D)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Scan VPA Database", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }

                        Button(
                            onClick = {
                                vpaInput = "rewards.refund99@okaxis"
                                viewModel.checkVpa("rewards.refund99@okaxis")
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = FinNavyElevated, contentColor = FinCyan),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Load Bad Sample", fontSize = 11.sp)
                        }
                    }

                    // VPA Scan Result Display
                    when (val state = vpaState) {
                        is VpaCheckState.Checking -> {
                            Spacer(modifier = Modifier.height(12.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.size(16.dp), color = FinCyan, strokeWidth = 2.dp)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Querying NPCI threat registry...", color = FinTextSecondary, fontSize = 12.sp)
                            }
                        }
                        is VpaCheckState.FoundBlacklisted -> {
                            Spacer(modifier = Modifier.height(12.dp))
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color(0xFF380813))
                                    .border(1.dp, FinCrimson, RoundedCornerShape(10.dp))
                                    .padding(12.dp)
                            ) {
                                Column {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(imageVector = Icons.Default.Dangerous, contentDescription = null, tint = FinCrimson, modifier = Modifier.size(20.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = "CRITICAL: FLAGGED SCAM VPA",
                                            color = FinCrimson,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 12.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text(
                                        text = "Address: ${state.entity.vpa}",
                                        color = FinTextPrimary,
                                        fontSize = 12.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                    Text(
                                        text = "Threat Reason: ${state.entity.reason}",
                                        color = Color(0xFFFFB3B3),
                                        fontSize = 12.sp
                                    )
                                    Text(
                                        text = "Total Reports: ${state.entity.reportedCount} victims",
                                        color = FinAmber,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.SemiBold
                                    )
                                }
                            }
                        }
                        is VpaCheckState.SafeOrUnreported -> {
                            Spacer(modifier = Modifier.height(12.dp))
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color(0xFF072B18))
                                    .border(1.dp, FinEmerald, RoundedCornerShape(10.dp))
                                    .padding(12.dp)
                            ) {
                                Column {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(imageVector = Icons.Default.CheckCircle, contentDescription = null, tint = FinEmerald, modifier = Modifier.size(20.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = "NO NPCI BLACKLIST MATCH",
                                            color = FinEmerald,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 12.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = "${state.vpa} is not currently blacklisted. If this VPA attempted fraud, report it below.",
                                        color = FinTextSecondary,
                                        fontSize = 11.sp
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Button(
                                        onClick = { showReportBox = !showReportBox },
                                        colors = ButtonDefaults.buttonColors(containerColor = FinNavyElevated, contentColor = FinAmber),
                                        modifier = Modifier.height(30.dp),
                                        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 10.dp, vertical = 2.dp)
                                    ) {
                                        Icon(imageVector = Icons.Default.Report, contentDescription = null, modifier = Modifier.size(14.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Report this VPA as Scam", fontSize = 11.sp)
                                    }
                                }
                            }
                        }
                        VpaCheckState.Idle -> {}
                    }

                    // Report Form if expanded
                    if (showReportBox) {
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedTextField(
                            value = reportReasonInput,
                            onValueChange = { reportReasonInput = it },
                            modifier = Modifier.fillMaxWidth(),
                            placeholder = { Text("Reason (e.g. Sent fake lottery collect request)", color = FinTextSecondary, fontSize = 12.sp) },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = FinAmber,
                                unfocusedBorderColor = FinNavyBorder,
                                focusedTextColor = FinTextPrimary,
                                unfocusedTextColor = FinTextPrimary,
                                focusedContainerColor = FinNavyElevated,
                                unfocusedContainerColor = FinNavyElevated
                            ),
                            shape = RoundedCornerShape(10.dp)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                if (vpaInput.isNotBlank()) {
                                    viewModel.reportVpa(vpaInput, reportReasonInput)
                                    showReportBox = false
                                    reportReasonInput = ""
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = FinAmber, contentColor = Color(0xFF2E1C00)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Submit to NPCI Community Blacklist", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        // Section 3: Bank SMS Scraper Sandbox
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(imageVector = Icons.Default.Fingerprint, contentDescription = null, tint = FinCyan, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "BANK SMS SCRAPER & PARSER",
                            color = FinTextPrimary,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Parses transaction headers (AD-HDFCBK, VK-SBIPAY) to extract amount, VPA, ledger direction, and fake collect attacks.",
                        color = FinTextSecondary,
                        fontSize = 11.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = smsSenderInput,
                            onValueChange = { smsSenderInput = it },
                            modifier = Modifier.weight(0.45f),
                            label = { Text("Header", fontSize = 10.sp) },
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = FinCyan,
                                unfocusedBorderColor = FinNavyBorder,
                                focusedTextColor = FinTextPrimary,
                                unfocusedTextColor = FinTextPrimary,
                                focusedContainerColor = FinNavyElevated,
                                unfocusedContainerColor = FinNavyElevated
                            )
                        )

                        OutlinedTextField(
                            value = smsBodyInput,
                            onValueChange = { smsBodyInput = it },
                            modifier = Modifier.weight(0.55f),
                            label = { Text("SMS Content", fontSize = 10.sp) },
                            maxLines = 3,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = FinCyan,
                                unfocusedBorderColor = FinNavyBorder,
                                focusedTextColor = FinTextPrimary,
                                unfocusedTextColor = FinTextPrimary,
                                focusedContainerColor = FinNavyElevated,
                                unfocusedContainerColor = FinNavyElevated
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { viewModel.parseBankSms(smsSenderInput, smsBodyInput) },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = FinCyan, contentColor = Color(0xFF00363D)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Execute Forensic Parse", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }

                        Button(
                            onClick = {
                                smsSenderInput = "AD-SBIPAY"
                                smsBodyInput = "Rs 1,250.00 debited from A/C **8392 on 27-Sep to Zomato UPI Ref: 3928192831. Avl Bal Rs 28,400.00."
                                viewModel.parseBankSms(smsSenderInput, smsBodyInput)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = FinNavyElevated, contentColor = FinEmerald),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Legit Debit", fontSize = 11.sp)
                        }
                    }

                    // Parsed Output Card
                    parsedBankSms?.let { info ->
                        Spacer(modifier = Modifier.height(14.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(Color(0xFF0A1424))
                                .border(1.dp, if (info.isSuspiciousCollect) FinCrimson else FinEmerald, RoundedCornerShape(10.dp))
                                .padding(12.dp)
                        ) {
                            Column {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = info.bankName,
                                        color = FinCyan,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp
                                    )
                                    Text(
                                        text = if (info.isDebit) "DEBIT" else if (info.isCredit) "CREDIT" else "COLLECT REQ",
                                        color = if (info.isDebit) Color(0xFFFF8A80) else if (info.isCredit) FinEmerald else FinAmber,
                                        fontWeight = FontWeight.Bold,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp
                                    )
                                }

                                Spacer(modifier = Modifier.height(6.dp))
                                Text(text = "Amount: Rs ${info.amount ?: "N/A"}", color = FinTextPrimary, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                                Text(text = "Account: ${info.accountMasked ?: "N/A"}", color = FinTextSecondary, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                                Text(text = "VPA Target: ${info.vpaId ?: "N/A"}", color = FinTextSecondary, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                                Text(text = "UTR Ref: ${info.referenceNo ?: "N/A"}", color = FinTextSecondary, fontSize = 11.sp, fontFamily = FontFamily.Monospace)

                                if (info.isSuspiciousCollect) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(imageVector = Icons.Default.Warning, contentDescription = null, tint = FinCrimson, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = "CRITICAL WARNING: FAKE CASHBACK COLLECT TRAP! Never enter UPI PIN to receive money.",
                                            color = FinCrimson,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 11.sp
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Section 4: Known Scam VPA Registry Table
        item {
            Text(
                text = "COMMUNITY SCAM VPA REGISTRY (${flaggedVpas.size})",
                color = FinTextSecondary,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
        }

        items(flaggedVpas) { vpaItem ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = vpaItem.vpa,
                            color = FinTextPrimary,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = vpaItem.reason,
                            color = FinTextSecondary,
                            fontSize = 11.sp
                        )
                    }
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(Color(0xFF380813))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = "${vpaItem.reportedCount} Reports",
                            color = FinCrimson,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
