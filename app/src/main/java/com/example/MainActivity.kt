package com.example

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.ui.components.ThreatDetailDialog
import com.example.ui.screens.LiveSimulatorScreen
import com.example.ui.screens.ProductionConfigScreen
import com.example.ui.screens.ShieldDashboardScreen
import com.example.ui.screens.ThreatFeedScreen
import com.example.ui.screens.UpiBankingGuardScreen
import com.example.ui.theme.FinAmber
import com.example.ui.theme.FinCrimson
import com.example.ui.theme.FinCyan
import com.example.ui.theme.FinEmerald
import com.example.ui.theme.FinNavyBorder
import com.example.ui.theme.FinNavyElevated
import com.example.ui.theme.FinNavySurface
import com.example.ui.theme.FinTextPrimary
import com.example.ui.theme.FinTextSecondary
import com.example.ui.theme.MyApplicationTheme
import com.example.ui.viewmodel.AppTab
import com.example.ui.viewmodel.MainViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            MyApplicationTheme {
                val selectedTab by viewModel.selectedTab.collectAsStateWithLifecycle()
                val selectedLog by viewModel.selectedLog.collectAsStateWithLifecycle()
                val shieldActive by viewModel.shieldActive.collectAsStateWithLifecycle()
                val totalThreats by viewModel.totalThreats.collectAsStateWithLifecycle()

                // Request SMS and Notification permissions at runtime
                val permissionLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.RequestMultiplePermissions()
                ) { /* Handle result gracefully */ }

                LaunchedEffect(Unit) {
                    val permissions = mutableListOf(
                        Manifest.permission.RECEIVE_SMS,
                        Manifest.permission.READ_SMS
                    )
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        permissions.add(Manifest.permission.POST_NOTIFICATIONS)
                    }
                    permissionLauncher.launch(permissions.toTypedArray())
                }

                // Handle back navigation
                BackHandler(enabled = selectedLog != null || selectedTab != AppTab.DASHBOARD) {
                    if (selectedLog != null) {
                        viewModel.selectLogForDetails(null)
                    } else if (selectedTab != AppTab.DASHBOARD) {
                        viewModel.selectTab(AppTab.DASHBOARD)
                    }
                }

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    containerColor = MaterialTheme.colorScheme.background,
                    topBar = {
                        TopAppBar(
                            title = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Box(
                                        modifier = Modifier
                                            .size(28.dp)
                                            .clip(CircleShape)
                                            .background(FinCyan.copy(alpha = 0.2f)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Security,
                                            contentDescription = null,
                                            tint = FinCyan,
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "FINGUARD",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 16.sp,
                                        fontFamily = FontFamily.Monospace,
                                        letterSpacing = 1.sp,
                                        color = FinTextPrimary
                                    )
                                }
                            },
                            actions = {
                                // Live Threat Status Badge in Top App Bar
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(if (shieldActive) Color(0xFF072B18) else Color(0xFF380813))
                                        .border(
                                            1.dp,
                                            if (shieldActive) FinEmerald.copy(alpha = 0.5f) else FinCrimson.copy(alpha = 0.5f),
                                            RoundedCornerShape(8.dp)
                                        )
                                        .padding(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Box(
                                            modifier = Modifier
                                                .size(6.dp)
                                                .clip(CircleShape)
                                                .background(if (shieldActive) FinEmerald else FinCrimson)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = if (shieldActive) "PROTECTED" else "PAUSED",
                                            color = if (shieldActive) FinEmerald else FinCrimson,
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                }
                                Spacer(modifier = Modifier.width(12.dp))
                            },
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = FinNavySurface,
                                titleContentColor = FinTextPrimary
                            )
                        )
                    },
                    bottomBar = {
                        FinGuardBottomNavigation(
                            currentTab = selectedTab,
                            onTabSelected = { viewModel.selectTab(it) },
                            threatBadgeCount = totalThreats
                        )
                    }
                ) { innerPadding ->
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding)
                    ) {
                        when (selectedTab) {
                            AppTab.DASHBOARD -> ShieldDashboardScreen(viewModel = viewModel)
                            AppTab.THREAT_FEED -> ThreatFeedScreen(viewModel = viewModel)
                            AppTab.UPI_BANKING -> UpiBankingGuardScreen(viewModel = viewModel)
                            AppTab.SIMULATOR -> LiveSimulatorScreen(viewModel = viewModel)
                            AppTab.CONFIG -> ProductionConfigScreen(
                                viewModel = viewModel,
                                onRequestSmsPermission = {
                                    permissionLauncher.launch(
                                        arrayOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS)
                                    )
                                }
                            )
                        }

                        // Inspect Threat Details Dialog
                        selectedLog?.let { log ->
                            ThreatDetailDialog(
                                log = log,
                                onDismiss = { viewModel.selectLogForDetails(null) },
                                onDelete = { id -> viewModel.deleteLog(id) }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun FinGuardBottomNavigation(
    currentTab: AppTab,
    onTabSelected: (AppTab) -> Unit,
    threatBadgeCount: Int,
    modifier: Modifier = Modifier
) {
    NavigationBar(
        modifier = modifier,
        containerColor = FinNavySurface,
        tonalElevation = 8.dp
    ) {
        val items = listOf(
            Triple(AppTab.DASHBOARD, Icons.Default.Security, "Shield"),
            Triple(AppTab.THREAT_FEED, Icons.Default.Warning, "Feed"),
            Triple(AppTab.UPI_BANKING, Icons.Default.AccountBalance, "UPI"),
            Triple(AppTab.SIMULATOR, Icons.Default.Bolt, "Simulator"),
            Triple(AppTab.CONFIG, Icons.Default.Settings, "Config")
        )

        items.forEach { (tab, icon, label) ->
            val isSelected = currentTab == tab
            NavigationBarItem(
                selected = isSelected,
                onClick = { onTabSelected(tab) },
                icon = {
                    Icon(
                        imageVector = icon,
                        contentDescription = label,
                        modifier = Modifier.size(20.dp)
                    )
                },
                label = {
                    Text(
                        text = label,
                        fontSize = 10.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                    )
                },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Color(0xFF00363D),
                    selectedTextColor = FinCyan,
                    indicatorColor = FinCyan,
                    unselectedIconColor = FinTextSecondary,
                    unselectedTextColor = FinTextSecondary
                )
            )
        }
    }
}
