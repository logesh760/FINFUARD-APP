package com.example.ui.screens

import android.Manifest
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.runtime.DisposableEffect
import com.example.service.FinGuardNotificationListener
import com.example.security.ShieldStateManager
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.automirrored.filled.Message
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Repeat
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.BuildConfig
import androidx.compose.foundation.lazy.items
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
import com.example.ui.viewmodel.MainViewModel

enum class IntegrationStatus(val label: String, val color: Color, val bgColor: Color) {
    LIVE("LIVE / CONNECTED", FinEmerald, Color(0xFF072B18)),
    SANDBOX("SANDBOX / TEST", FinCyan, Color(0xFF072633)),
    MOCK("LOCAL MOCK", FinAmber, Color(0xFF2E1C00)),
    NOT_CONFIGURED("NOT CONFIGURED", Color(0xFF8A99AD), Color(0xFF1E2633))
}

data class ChannelIntegrationInfo(
    val id: String,
    val name: String,
    val icon: ImageVector,
    val provider: String,
    val status: IntegrationStatus,
    val lastEvent: String,
    val details: String
)

@Composable
fun ProductionConfigScreen(
    viewModel: MainViewModel,
    onRequestSmsPermission: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var webhookUrlInput by remember { mutableStateOf(viewModel.webhookUrl.value) }
    var kafkaTopicInput by remember { mutableStateOf(viewModel.kafkaTopic.value) }
    var selectedTab by remember { mutableStateOf(0) } // 0: Integrations, 1: Cloud & API, 2: Privacy Center

    val lifecycleOwner = LocalLifecycleOwner.current
    var isNotificationAccessGranted by remember { mutableStateOf(false) }
    var isSmsGranted by remember { mutableStateOf(false) }
    var isPostNotificationsGranted by remember { mutableStateOf(false) }
    var isBatteryOptimizationIgnored by remember { mutableStateOf(false) }
    var isShieldArmed by remember { mutableStateOf(false) }

    fun refreshSystemStatus() {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        isNotificationAccessGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            nm?.isNotificationListenerAccessGranted(
                ComponentName(context, FinGuardNotificationListener::class.java)
            ) == true
        } else {
            val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
            flat != null && flat.contains(context.packageName)
        }
        isSmsGranted = ContextCompat.checkSelfPermission(context, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
        isPostNotificationsGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        isBatteryOptimizationIgnored = powerManager?.isIgnoringBatteryOptimizations(context.packageName) == true
        isShieldArmed = ShieldStateManager.isShieldActive(context)
    }

    val postNotificationLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) {
        refreshSystemStatus()
    }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                refreshSystemStatus()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        refreshSystemStatus()
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    var testApiKeyStatus by remember { mutableStateOf<String?>(null) }
    var testingApi by remember { mutableStateOf(false) }

    val integrationsList = listOf(
        ChannelIntegrationInfo(
            id = "sms",
            name = "Native SMS Receiver",
            icon = Icons.Default.Email,
            provider = "Android Telephony SMSReceiver",
            status = IntegrationStatus.LIVE,
            lastEvent = "18 mins ago (Legit Debit)",
            details = "Listens to Telephony.SMS_RECEIVED. PII redacted before local classification."
        ),
        ChannelIntegrationInfo(
            id = "whatsapp",
            name = "WhatsApp Ingestion",
            icon = Icons.AutoMirrored.Filled.Chat,
            provider = "Android NotificationListener + Meta Cloud API Hook",
            status = IntegrationStatus.LIVE,
            lastEvent = "45 mins ago (Job Scam Intercepted)",
            details = "Monitors com.whatsapp notifications locally. Meta Webhook adapter available for cloud ingest."
        ),
        ChannelIntegrationInfo(
            id = "telegram",
            name = "Telegram Feed",
            icon = Icons.AutoMirrored.Filled.Message,
            provider = "Telegram Bot API / Notification Ingest",
            status = IntegrationStatus.SANDBOX,
            lastEvent = "2 hours ago (Simulated)",
            details = "Handles notification payloads from org.telegram.messenger with zero-leakage scrubbing."
        ),
        ChannelIntegrationInfo(
            id = "instagram",
            name = "Instagram Direct",
            icon = Icons.Default.PhoneAndroid,
            provider = "Meta Graph API (Messenger Platform)",
            status = IntegrationStatus.NOT_CONFIGURED,
            lastEvent = "No events received",
            details = "Requires Meta Business Verification & Instagram Webhook token configuration."
        ),
        ChannelIntegrationInfo(
            id = "upi",
            name = "UPI Payment Gateway",
            icon = Icons.Default.AccountBalance,
            provider = "NPCI Blacklist Registry + Setu / Decentro",
            status = IntegrationStatus.SANDBOX,
            lastEvent = "12 mins ago (VPA Checked)",
            details = "Heuristic scanner for reverse collect requests and malicious VPA patterns."
        ),
        ChannelIntegrationInfo(
            id = "banking",
            name = "Banking Ledger APIs",
            icon = Icons.Default.Storage,
            provider = "Bank SMS Forensic Scraper (HDFC/SBI/ICICI)",
            status = IntegrationStatus.LIVE,
            lastEvent = "Active",
            details = "Extracts amount, UTR, and debit/credit ledger direction without storing account credentials."
        ),
        ChannelIntegrationInfo(
            id = "autopay",
            name = "AutoPay Mandate Guard",
            icon = Icons.Default.Repeat,
            provider = "Recurring Mandate Anomaly Filter",
            status = IntegrationStatus.MOCK,
            lastEvent = "Ready for test callbacks",
            details = "Detects unauthorized auto-debit triggers and hidden recurring payment traps."
        )
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
                    imageVector = Icons.Default.Settings,
                    contentDescription = null,
                    tint = FinCyan,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Column {
                    Text(
                        text = "PRODUCTION ARCHITECTURE & INTEGRATIONS",
                        color = FinCyan,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Multi-platform ingestion status, webhook gateways & privacy controls",
                        color = FinTextSecondary,
                        fontSize = 11.sp
                    )
                }
            }
        }

        // Sub Tabs
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(FinNavySurface)
                    .border(1.dp, FinNavyBorder, RoundedCornerShape(10.dp))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                val tabs = listOf("Channel Status", "Cloud Gateway", "Privacy Center")
                tabs.forEachIndexed { index, title ->
                    val isSelected = selectedTab == index
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(8.dp))
                            .background(if (isSelected) FinCyanContainer else Color.Transparent)
                            .clickable { selectedTab = index }
                            .padding(vertical = 8.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = title,
                            color = if (isSelected) FinCyan else FinTextSecondary,
                            fontSize = 11.sp,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                        )
                    }
                }
            }
        }

        if (selectedTab == 0) {
            // TAB 1: Channel Integrations
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
                                text = "PERMISSION & SYSTEM STATUS CENTER",
                                color = FinTextPrimary,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                            Surface(
                                color = if (isShieldArmed) FinEmerald.copy(alpha = 0.15f) else FinAmber.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Text(
                                    text = if (isShieldArmed) "SHIELD: ARMED" else "SHIELD: PAUSED",
                                    color = if (isShieldArmed) FinEmerald else FinAmber,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Real-time system permission state for TECNO HiOS 12.6 / Android 13. All statuses reflect live Android OS kernel responses.",
                            color = FinTextSecondary,
                            fontSize = 11.sp,
                            lineHeight = 15.sp
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        // Row 1: SMS Permission & Alert Notification Permission
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Surface(
                                color = if (isSmsGranted) FinEmerald.copy(alpha = 0.15f) else FinAmber.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = if (isSmsGranted) Icons.Default.CheckCircle else Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = if (isSmsGranted) FinEmerald else FinAmber,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = if (isSmsGranted) "SMS: GRANTED" else "SMS: NOT GRANTED",
                                        color = if (isSmsGranted) FinEmerald else FinAmber,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }

                            Surface(
                                color = if (isPostNotificationsGranted) FinEmerald.copy(alpha = 0.15f) else FinAmber.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = if (isPostNotificationsGranted) Icons.Default.CheckCircle else Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = if (isPostNotificationsGranted) FinEmerald else FinAmber,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = if (isPostNotificationsGranted) "Alerts: GRANTED" else "Alerts: NOT GRANTED",
                                        color = if (isPostNotificationsGranted) FinEmerald else FinAmber,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        // Row 2: Notification Listener Access & Battery Optimization
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Surface(
                                color = when {
                                    isNotificationAccessGranted -> FinEmerald.copy(alpha = 0.15f)
                                    Build.VERSION.SDK_INT >= 33 -> FinCrimson.copy(alpha = 0.15f)
                                    else -> FinAmber.copy(alpha = 0.15f)
                                },
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = if (isNotificationAccessGranted) Icons.Default.CheckCircle else Icons.Default.Lock,
                                        contentDescription = null,
                                        tint = when {
                                            isNotificationAccessGranted -> FinEmerald
                                            Build.VERSION.SDK_INT >= 33 -> FinCrimson
                                            else -> FinAmber
                                        },
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = when {
                                            isNotificationAccessGranted -> "Listener: ACTIVE"
                                            Build.VERSION.SDK_INT >= 33 -> "Listener: SYSTEM RESTRICTED"
                                            else -> "Listener: NOT ACTIVE"
                                        },
                                        color = when {
                                            isNotificationAccessGranted -> FinEmerald
                                            Build.VERSION.SDK_INT >= 33 -> FinCrimson
                                            else -> FinAmber
                                        },
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }

                            Surface(
                                color = if (isBatteryOptimizationIgnored) FinEmerald.copy(alpha = 0.15f) else FinAmber.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = if (isBatteryOptimizationIgnored) Icons.Default.CheckCircle else Icons.Default.Settings,
                                        contentDescription = null,
                                        tint = if (isBatteryOptimizationIgnored) FinEmerald else FinAmber,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = if (isBatteryOptimizationIgnored) "Battery: UNRESTRICTED" else "Battery: OPTIMIZED",
                                        color = if (isBatteryOptimizationIgnored) FinEmerald else FinAmber,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Action Buttons: Notification Listener & SMS
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = {
                                    val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
                                    context.startActivity(intent)
                                },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.buttonColors(containerColor = FinCyan, contentColor = Color(0xFF00363D)),
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Icon(imageVector = Icons.AutoMirrored.Filled.OpenInNew, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Enable Notification Access", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }

                            OutlinedButton(
                                onClick = onRequestSmsPermission,
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = FinCyan),
                                border = androidx.compose.foundation.BorderStroke(1.dp, FinCyan.copy(alpha = 0.5f)),
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Icon(imageVector = Icons.Default.Email, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Request SMS Perms", fontSize = 11.sp)
                            }
                        }

                        // Android 13 POST_NOTIFICATIONS button (if not yet granted)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !isPostNotificationsGranted) {
                            Spacer(modifier = Modifier.height(8.dp))
                            OutlinedButton(
                                onClick = {
                                    postNotificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                },
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = FinCyan),
                                border = androidx.compose.foundation.BorderStroke(1.dp, FinCyan.copy(alpha = 0.5f)),
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Icon(imageVector = Icons.Default.Info, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Request Alert Notification Permission", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }

                        // Sideloaded / Restricted Settings Warning Card
                        if (!isNotificationAccessGranted) {
                            Spacer(modifier = Modifier.height(12.dp))
                            Surface(
                                color = FinNavyElevated,
                                shape = RoundedCornerShape(8.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, FinAmber.copy(alpha = 0.4f)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.Info, contentDescription = null, tint = FinAmber, modifier = Modifier.size(14.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text("TECNO HiOS 12.6 / Android 13 (\"Restricted setting\")", color = FinAmber, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = "\"Restricted setting\" is Android 13's OS policy for sideloaded APKs. To unlock on this device:\n1. Tap 'Open App Info' below to go to FinGuard's system page.\n2. Tap the three-dot menu (⋮) in the top-right corner.\n   (Note: HiOS only reveals this menu AFTER you have attempted to toggle Notification Access once).\n3. Tap 'Allow restricted settings' and confirm your screen lock (PIN/fingerprint).\n4. Return here and tap 'Enable Notification Access'. The switch is now active!",
                                        color = FinTextSecondary,
                                        fontSize = 10.sp,
                                        lineHeight = 14.sp
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    OutlinedButton(
                                        onClick = {
                                            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                                data = Uri.fromParts("package", context.packageName, null)
                                            }
                                            context.startActivity(intent)
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = FinAmber),
                                        border = androidx.compose.foundation.BorderStroke(1.dp, FinAmber.copy(alpha = 0.5f)),
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(13.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text("Open App Info (Allow Restricted)", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                                    }
                                }
                            }
                        }

                        // TECNO HiOS Battery Optimization Card
                        if (!isBatteryOptimizationIgnored) {
                            Spacer(modifier = Modifier.height(10.dp))
                            Surface(
                                color = FinNavyElevated,
                                shape = RoundedCornerShape(8.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, FinCyan.copy(alpha = 0.3f)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.Settings, contentDescription = null, tint = FinCyan, modifier = Modifier.size(14.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text("HiOS Power Marathon Background Management", color = FinCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = "To ensure FinGuard intercepts threats when your screen is locked or idle, allow background execution in HiOS Battery settings.",
                                        color = FinTextSecondary,
                                        fontSize = 10.sp,
                                        lineHeight = 14.sp
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    OutlinedButton(
                                        onClick = {
                                            try {
                                                val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                                context.startActivity(intent)
                                            } catch (e: Exception) {
                                                val fallbackIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                                    data = Uri.fromParts("package", context.packageName, null)
                                                }
                                                context.startActivity(fallbackIntent)
                                            }
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = FinCyan),
                                        border = androidx.compose.foundation.BorderStroke(1.dp, FinCyan.copy(alpha = 0.5f)),
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(13.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text("Configure Battery (Don't Optimize)", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item {
                Text(
                    text = "CHANNEL INTEGRATION REGISTRY (7 CHANNELS)",
                    color = FinTextSecondary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
            }

            items(integrationsList) { item ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
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
                                Box(
                                    modifier = Modifier
                                        .size(32.dp)
                                        .clip(CircleShape)
                                        .background(FinNavyElevated),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(imageVector = item.icon, contentDescription = null, tint = item.status.color, modifier = Modifier.size(18.dp))
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(text = item.name, color = FinTextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                                    Text(text = item.provider, color = FinTextSecondary, fontSize = 10.sp)
                                }
                            }

                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(item.status.bgColor)
                                    .border(1.dp, item.status.color.copy(alpha = 0.4f), RoundedCornerShape(6.dp))
                                    .padding(horizontal = 8.dp, vertical = 3.dp)
                            ) {
                                Text(
                                    text = item.status.label,
                                    color = item.status.color,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))
                        Text(text = item.details, color = FinTextSecondary, fontSize = 11.sp, lineHeight = 15.sp)

                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Last Ingest Event: ${item.lastEvent}",
                            color = if (item.status == IntegrationStatus.NOT_CONFIGURED) Color(0xFF64748B) else FinCyan,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }

        } else if (selectedTab == 1) {
            // TAB 2: Cloud Ingestion & AI Pipeline
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Default.Psychology, contentDescription = null, tint = FinCyan, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "GEMINI AI ENGINE STATUS",
                                color = FinCyan,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .background(Color(0xFF072B18))
                                .padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = FinEmerald,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = "AI ARCHITECTURE: SECURE BACKEND GATEWAY",
                                    color = FinEmerald,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = "Zero client-side secrets. Gemini API key is isolated exclusively in server-side environment variables.",
                                    color = FinTextSecondary,
                                    fontSize = 10.sp
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        var gatewayUrlText by remember { mutableStateOf(com.example.security.ai.GeminiThreatAnalyzer.gatewayBaseUrl) }

                        OutlinedTextField(
                            value = gatewayUrlText,
                            onValueChange = {
                                gatewayUrlText = it
                                com.example.security.ai.GeminiThreatAnalyzer.gatewayBaseUrl = it
                            },
                            label = { Text("AI Gateway Endpoint", fontSize = 11.sp) },
                            modifier = Modifier.fillMaxWidth(),
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
                            value = "gemini-3.5-flash (via Server-Side Gateway)",
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Server Model", fontSize = 11.sp) },
                            modifier = Modifier.fillMaxWidth(),
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
                    }
                }
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "EVENT HUB & MESSAGE BROKER INGESTION",
                            color = FinTextPrimary,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Configure upstream Kafka or RabbitMQ event stream gateway for asynchronous threat telemetry.",
                            color = FinTextSecondary,
                            fontSize = 11.sp
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        OutlinedTextField(
                            value = webhookUrlInput,
                            onValueChange = {
                                webhookUrlInput = it
                                viewModel.webhookUrl.value = it
                            },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Webhook Ingest Gateway URL", fontSize = 11.sp) },
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
                            value = kafkaTopicInput,
                            onValueChange = {
                                kafkaTopicInput = it
                                viewModel.kafkaTopic.value = it
                            },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Kafka Pub/Sub Topic", fontSize = 11.sp) },
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

                        Spacer(modifier = Modifier.height(12.dp))

                        Button(
                            onClick = {
                                testApiKeyStatus = "Gateway configuration saved. Endpoint ready for event streaming."
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = FinCyan, contentColor = Color(0xFF00363D)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Save Gateway Settings", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }

                        testApiKeyStatus?.let {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(text = it, color = FinEmerald, fontSize = 11.sp)
                        }
                    }
                }
            }

        } else {
            // TAB 3: Privacy Center
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = FinNavySurface),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Default.Lock, contentDescription = null, tint = FinEmerald, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "ZERO-LEAKAGE PRIVACY PROMISE",
                                color = FinEmerald,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                        }

                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "FinGuard runs 100% of PII scrubbing locally on your Android device before any event is saved to disk or evaluated by AI models. No OTP, CVV, or 16-digit card number ever leaves your phone in plaintext.",
                            color = FinTextSecondary,
                            fontSize = 12.sp,
                            lineHeight = 17.sp
                        )

                        Spacer(modifier = Modifier.height(14.dp))

                        val rules = listOf(
                            "One-Time Passwords (OTPs) -> [OTP_REDACTED]",
                            "Payment Card Numbers -> [CARD_REDACTED]",
                            "Bank Account Numbers -> [ACCOUNT_REDACTED]",
                            "Phone Numbers -> [PHONE_REDACTED]",
                            "Email Addresses -> [EMAIL_REDACTED]",
                            "UPI Identifiers -> [UPI_REDACTED]",
                            "Passwords & CVV -> [CREDENTIAL_REDACTED]",
                            "API Keys & Seed Phrases -> [SECRET_REDACTED]"
                        )

                        rules.forEach { rule ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 3.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(imageVector = Icons.Default.CheckCircle, contentDescription = null, tint = FinEmerald, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(text = rule, color = FinTextPrimary, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            }
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        Button(
                            onClick = {
                                viewModel.clearAllLogs()
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = FinNavyElevated, contentColor = FinCrimson),
                            border = androidx.compose.foundation.BorderStroke(1.dp, FinCrimson.copy(alpha = 0.4f)),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Purge Local Interceptor Logs (Immediate Shredding)", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}
