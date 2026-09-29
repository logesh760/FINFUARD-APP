package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.ReportProblem
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
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
import com.example.data.model.IngestChannel
import com.example.ui.components.RiskScoreMeter
import com.example.ui.components.SeverityBadge
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

@Composable
fun LiveSimulatorScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val isScanning by viewModel.isScanning.collectAsStateWithLifecycle()
    val lastScanResult by viewModel.lastScanResult.collectAsStateWithLifecycle()

    var senderInput by remember { mutableStateOf("+919876501234") }
    var channelSelected by remember { mutableStateOf(IngestChannel.WHATSAPP) }
    var contentInput by remember {
        mutableStateOf(
            "Hello! You are selected for part-time online job. Earn Rs 3,500 daily by rating hotels. Join telegram t.me/earn_daily_task. OTP for registration is 582910."
        )
    }

    val presetScenarios = listOf(
        Pair("WhatsApp Job Scam", Triple("+919876501234", IngestChannel.WHATSAPP, "Congratulations! Part-time work from home job. Earn Rs 4000/day liking YouTube videos. Click t.me/fast_income_tasks to join. Verification Code is 849201.")),
        Pair("Electricity Cutoff SMS", Triple("VK-POWERCUT", IngestChannel.SMS, "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the main grid office due to unpaid bill of Rs 1,420. Call power officer at 9876543210 immediately.")),
        Pair("Reverse UPI Collect Trap", Triple("AD-PAYTM", IngestChannel.SMS, "Collect Request received for Rs 4,999.00 from rewards.refund99@okaxis. Approve payment and enter UPI PIN in PayTM to receive your cashback bonus.")),
        Pair("Banking Trojan APK", Triple("VK-SBINB", IngestChannel.SMS, "Dear SBI Customer, your YONO access is blocked due to expired PAN card. Download updated security patch to unblock: http://sbi-kyc-verify.xyz/yono_patch.apk")),
        Pair("Legit Bank Debit", Triple("AD-HDFCBK", IngestChannel.SMS, "Rs 750.00 debited from A/C **4921 on 27-Sep at Apollo Pharmacy. UPI Ref: 482910291. Avl Balance: Rs 18,320.00."))
    )

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Bolt,
                    contentDescription = null,
                    tint = FinCyan,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Column {
                    Text(
                        text = "LIVE INGESTION SIMULATOR",
                        color = FinCyan,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Test real-time event pipeline, local PII scrubbing, & AI analysis",
                        color = FinTextSecondary,
                        fontSize = 11.sp
                    )
                }
            }
        }

        // Preset Test Scenarios
        item {
            Text(
                text = "SELECT REAL-WORLD ATTACK PRESET",
                color = FinTextSecondary,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(6.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                presetScenarios.forEach { (title, data) ->
                    Card(
                        modifier = Modifier
                            .clickable {
                                senderInput = data.first
                                channelSelected = data.second
                                contentInput = data.third
                            },
                        colors = CardDefaults.cardColors(containerColor = FinNavyElevated),
                        shape = RoundedCornerShape(10.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
                    ) {
                        Text(
                            text = title,
                            color = FinTextPrimary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp)
                        )
                    }
                }
            }
        }

        // Ingest Form
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "EVENT PAYLOAD PARAMETERS",
                        color = FinTextPrimary,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    // Channel selector
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        IngestChannel.values().forEach { channel ->
                            FilterChip(
                                selected = channelSelected == channel,
                                onClick = { channelSelected = channel },
                                label = { Text(channel.name, fontSize = 10.sp) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = FinCyan.copy(alpha = 0.2f),
                                    selectedLabelColor = FinCyan
                                )
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = senderInput,
                        onValueChange = { senderInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Sender ID / Originating Phone", fontSize = 11.sp) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = FinCyan,
                            unfocusedBorderColor = FinNavyBorder,
                            focusedTextColor = FinTextPrimary,
                            unfocusedTextColor = FinTextPrimary,
                            focusedContainerColor = FinNavyElevated,
                            unfocusedContainerColor = FinNavyElevated
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = contentInput,
                        onValueChange = { contentInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Raw Message Content", fontSize = 11.sp) },
                        maxLines = 4,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = FinCyan,
                            unfocusedBorderColor = FinNavyBorder,
                            focusedTextColor = FinTextPrimary,
                            unfocusedTextColor = FinTextPrimary,
                            focusedContainerColor = FinNavyElevated,
                            unfocusedContainerColor = FinNavyElevated
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = {
                            viewModel.scanSimulatorPayload(senderInput, contentInput, channelSelected)
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                        enabled = !isScanning && contentInput.isNotBlank(),
                        colors = ButtonDefaults.buttonColors(containerColor = FinCyan, contentColor = Color(0xFF00363D)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (isScanning) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), color = Color(0xFF00363D), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Running 3-Layer Pipeline...", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        } else {
                            Icon(imageVector = Icons.Default.Bolt, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Fire Real-Time Ingest Pipeline", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                    }
                }
            }
        }

        // Live Pipeline Execution Breakdown Output
        lastScanResult?.let { result ->
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0C192E)),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.5.dp, if (result.riskScore >= 60) FinCrimson else FinEmerald)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "PIPELINE INSPECTION TELEMETRY",
                                color = FinCyan,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                            SeverityBadge(severity = result.severity)
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        RiskScoreMeter(score = result.riskScore)

                        Spacer(modifier = Modifier.height(14.dp))

                        // Layer 1: Client-Side PII Scrubbing
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(FinNavyElevated)
                                .padding(10.dp)
                        ) {
                            Column {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(imageVector = Icons.Default.Lock, contentDescription = null, tint = FinEmerald, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "LAYER 0: ZERO-LEAKAGE PII REDACTION",
                                        color = FinEmerald,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = result.piiResult.scrubbedText,
                                    color = FinTextPrimary,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                                if (result.piiResult.redactedTokens.isNotEmpty()) {
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = "Sanitized on device: ${result.piiResult.redactedTokens.joinToString(", ")}",
                                        color = FinAmber,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        // Layer 2: Fast Regex & Heuristic Signals
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(FinNavyElevated)
                                .padding(10.dp)
                        ) {
                            Column {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(imageVector = Icons.Default.Speed, contentDescription = null, tint = FinCyan, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "LAYER 1 & 2: HEURISTICS & NPCI REGISTRY (<5ms)",
                                        color = FinCyan,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                if (result.threatSignals.isEmpty()) {
                                    Text(text = "No malicious patterns identified.", color = FinEmerald, fontSize = 11.sp)
                                } else {
                                    result.threatSignals.forEach { signal ->
                                        Row(verticalAlignment = Alignment.Top, modifier = Modifier.padding(vertical = 2.dp)) {
                                            Icon(imageVector = Icons.Default.ReportProblem, contentDescription = null, tint = FinAmber, modifier = Modifier.size(12.dp).padding(top = 2.dp))
                                            Spacer(modifier = Modifier.width(4.dp))
                                            Text(text = signal, color = FinTextPrimary, fontSize = 11.sp)
                                        }
                                    }
                                }
                            }
                        }

                        // Layer 3: AI Reasoning
                        result.aiReasoning?.let { reasoning ->
                            Spacer(modifier = Modifier.height(10.dp))
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(FinNavyElevated)
                                    .padding(10.dp)
                            ) {
                                Column {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(imageVector = Icons.Default.Psychology, contentDescription = null, tint = FinCyan, modifier = Modifier.size(14.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = "LAYER 3: GEMINI AI FRAUD REASONING",
                                            color = FinCyan,
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = reasoning,
                                        color = FinTextPrimary,
                                        fontSize = 11.sp,
                                        lineHeight = 15.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}
