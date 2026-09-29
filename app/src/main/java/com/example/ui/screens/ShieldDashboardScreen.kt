package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.automirrored.filled.Message
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.data.local.ThreatLogEntity
import com.example.ui.components.ChannelChip
import com.example.ui.components.MetricStatCard
import com.example.ui.components.RadarShieldGraphic
import com.example.ui.components.SeverityBadge
import com.example.ui.theme.FinAmber
import com.example.ui.theme.FinCrimson
import com.example.ui.theme.FinCyan
import com.example.ui.theme.FinCyanContainer
import com.example.ui.theme.FinEmerald
import com.example.ui.theme.FinNavyBorder
import com.example.ui.theme.FinNavyElevated
import com.example.ui.theme.FinNavySurface
import com.example.ui.theme.FinTextPrimary
import com.example.ui.theme.FinTextSecondary
import com.example.ui.viewmodel.AppTab
import com.example.ui.viewmodel.MainViewModel

@Composable
fun ShieldDashboardScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val shieldActive by viewModel.shieldActive.collectAsStateWithLifecycle()
    val threatLogs by viewModel.threatLogs.collectAsStateWithLifecycle()
    val totalScanned by viewModel.totalScanned.collectAsStateWithLifecycle()
    val totalThreats by viewModel.totalThreats.collectAsStateWithLifecycle()

    val piiScrubbedCount = threatLogs.sumOf { it.piiItemsFound.size }
    val safeCount = threatLogs.count { it.riskScore < 50 }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            // Radar & Shield Status Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                shape = RoundedCornerShape(20.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    RadarShieldGraphic(isActive = shieldActive)

                    Spacer(modifier = Modifier.height(14.dp))

                    Text(
                        text = if (shieldActive) "FINGUARD SHIELD ARMED" else "SHIELD INGESTION PAUSED",
                        color = if (shieldActive) FinCyan else FinCrimson,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = if (shieldActive)
                            "Real-time event ingest listening to SMS, WhatsApp, Telegram, & Banking streams."
                        else "Protection paused. Ingest pipeline will not inspect or sanitize incoming messages.",
                        color = FinTextSecondary,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    // Master Toggle Row
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(FinNavyElevated)
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = "Autonomous Ingestion",
                                color = FinTextPrimary,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = "Zero-latency local PII scrubber & AI detector",
                                color = FinTextSecondary,
                                fontSize = 11.sp
                            )
                        }

                        Switch(
                            checked = shieldActive,
                            onCheckedChange = { viewModel.toggleShield(it) },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = FinCyan,
                                checkedTrackColor = Color(0xFF033E4C),
                                uncheckedThumbColor = FinTextSecondary,
                                uncheckedTrackColor = FinNavyBorder
                            )
                        )
                    }
                }
            }
        }

        // Metrics Grid
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    MetricStatCard(
                        title = "MESSAGES SCANNED",
                        value = totalScanned.toString(),
                        icon = Icons.AutoMirrored.Filled.Message,
                        accentColor = FinCyan,
                        modifier = Modifier.weight(1f)
                    )
                    MetricStatCard(
                        title = "THREATS QUARANTINED",
                        value = totalThreats.toString(),
                        icon = Icons.Default.Block,
                        accentColor = FinCrimson,
                        modifier = Modifier.weight(1f)
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    MetricStatCard(
                        title = "PII DATA SCRUBBED",
                        value = piiScrubbedCount.toString(),
                        icon = Icons.Default.Lock,
                        accentColor = FinAmber,
                        modifier = Modifier.weight(1f)
                    )
                    MetricStatCard(
                        title = "SAFE TRANSACTIONS",
                        value = safeCount.toString(),
                        icon = Icons.Default.CheckCircle,
                        accentColor = FinEmerald,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        // Multi-Platform Ingest Channels Status
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "INGESTION PIPELINES",
                            color = FinCyan,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = "4 ACTIVE",
                            color = FinEmerald,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    val channels = listOf(
                        Triple("SMS Broadcast Receiver", "Native Telephony Parser", Color(0xFF64B5F6)),
                        Triple("WhatsApp Messenger", "Notification Ingest Hook", Color(0xFF25D366)),
                        Triple("Telegram MTProto/Bot", "Channel Stream Listener", Color(0xFF29B6F6)),
                        Triple("Banking / UPI Callbacks", "NPCI Regex & Collect Filter", FinAmber)
                    )

                    channels.forEach { (name, desc, color) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 5.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .clip(CircleShape)
                                    .background(color)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = name,
                                    color = FinTextPrimary,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Medium
                                )
                                Text(
                                    text = desc,
                                    color = FinTextSecondary,
                                    fontSize = 11.sp
                                )
                            }
                            Text(
                                text = "MONITORING",
                                color = FinEmerald,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }

        // Live Threat Intercept Stream Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "RECENT INTERCEPTED EVENTS",
                    color = FinTextSecondary,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "View All (${threatLogs.size})",
                    color = FinCyan,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.clickable { viewModel.selectTab(AppTab.THREAT_FEED) }
                )
            }
        }

        // Top 3 recent items
        val recentLogs = threatLogs.take(3)
        if (recentLogs.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(FinNavySurface)
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No intercepted events yet. All systems clean.",
                        color = FinTextSecondary,
                        fontSize = 13.sp
                    )
                }
            }
        } else {
            items(recentLogs) { log ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { viewModel.selectLogForDetails(log) },
                    colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                    shape = RoundedCornerShape(14.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                ChannelChip(channel = log.channel)
                                Spacer(modifier = Modifier.width(8.dp))
                                SeverityBadge(severity = log.severity)
                            }
                            Text(
                                text = "Risk: ${log.riskScore}%",
                                color = if (log.riskScore >= 60) FinCrimson else FinEmerald,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = log.scrubbedContent,
                            color = FinTextPrimary,
                            fontSize = 13.sp,
                            maxLines = 2,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            lineHeight = 17.sp
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "From: ${log.sender}",
                                color = FinTextSecondary,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "Inspect Details",
                                    color = FinCyan,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Medium
                                )
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                    contentDescription = null,
                                    tint = FinCyan,
                                    modifier = Modifier.size(13.dp)
                                )
                            }
                        }
                    }
                }
            }
        }

        // Live Ingest Sandbox quick card
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { viewModel.selectTab(AppTab.SIMULATOR) },
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0C1F38)),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, FinCyan.copy(alpha = 0.5f))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(CircleShape)
                            .background(FinCyanContainer),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.PlayArrow,
                            contentDescription = null,
                            tint = FinCyan,
                            modifier = Modifier.size(24.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(14.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Test Live Ingestion Simulator",
                            color = FinCyan,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Inject sample WhatsApp scams, reverse UPI traps & phishing links",
                            color = FinTextSecondary,
                            fontSize = 11.sp
                        )
                    }

                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                        contentDescription = null,
                        tint = FinCyan,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
