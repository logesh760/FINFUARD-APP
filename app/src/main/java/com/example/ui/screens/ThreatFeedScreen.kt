package com.example.ui.screens

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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.data.model.IngestChannel
import com.example.data.model.ThreatSeverity
import com.example.ui.components.ChannelChip
import com.example.ui.components.RiskScoreMeter
import com.example.ui.components.SeverityBadge
import com.example.ui.theme.FinAmber
import com.example.ui.theme.FinCrimson
import com.example.ui.theme.FinCyan
import com.example.ui.theme.FinEmerald
import com.example.ui.theme.FinNavyBorder
import com.example.ui.theme.FinNavySurface
import com.example.ui.theme.FinTextPrimary
import com.example.ui.theme.FinTextSecondary
import com.example.ui.viewmodel.MainViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ThreatFeedScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val logs by viewModel.threatLogs.collectAsStateWithLifecycle()
    val searchQuery by viewModel.searchQuery.collectAsStateWithLifecycle()
    val channelFilter by viewModel.channelFilter.collectAsStateWithLifecycle()
    val severityFilter by viewModel.severityFilter.collectAsStateWithLifecycle()

    val filteredLogs = remember(logs, channelFilter, severityFilter, searchQuery) {
        logs.filter { log ->
            val matchesChannel = channelFilter == null || log.channel == channelFilter
            val matchesSeverity = severityFilter == null || when (severityFilter) {
                ThreatSeverity.CRITICAL -> log.severity == ThreatSeverity.CRITICAL || log.severity == ThreatSeverity.HIGH_RISK
                ThreatSeverity.SUSPICIOUS -> log.severity == ThreatSeverity.SUSPICIOUS
                ThreatSeverity.SAFE -> log.severity == ThreatSeverity.SAFE
                else -> true
            }
            val matchesSearch = if (searchQuery.isBlank()) true else {
                val q = searchQuery.trim().lowercase()
                log.sender.lowercase().contains(q) ||
                log.scrubbedContent.lowercase().contains(q) ||
                log.category.name.lowercase().contains(q) ||
                log.threatSignals.any { it.lowercase().contains(q) }
            }
            matchesChannel && matchesSeverity && matchesSearch
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
    ) {
        // Top Filter & Action Bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "INTERCEPTED LOGS",
                    color = FinCyan,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "Showing ${filteredLogs.size} of ${logs.size} events",
                    color = FinTextSecondary,
                    fontSize = 11.sp
                )
            }

            if (logs.isNotEmpty()) {
                IconButton(onClick = { viewModel.clearAllLogs() }) {
                    Icon(
                        imageVector = Icons.Default.DeleteSweep,
                        contentDescription = "Clear All Logs",
                        tint = FinTextSecondary
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Search Input Bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { viewModel.setSearchQuery(it) },
            modifier = Modifier.fillMaxWidth(),
            placeholder = {
                Text("Search sender, content, threat vector...", color = FinTextSecondary, fontSize = 12.sp)
            },
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Search,
                    contentDescription = "Search Threats",
                    tint = FinCyan,
                    modifier = Modifier.size(18.dp)
                )
            },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { viewModel.setSearchQuery("") }) {
                        Icon(
                            imageVector = Icons.Default.Clear,
                            contentDescription = "Clear Search",
                            tint = FinTextSecondary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            },
            singleLine = true,
            shape = RoundedCornerShape(10.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = FinNavySurface,
                unfocusedContainerColor = FinNavySurface,
                focusedBorderColor = FinCyan,
                unfocusedBorderColor = FinNavyBorder,
                focusedTextColor = FinTextPrimary,
                unfocusedTextColor = FinTextPrimary
            )
        )

        Spacer(modifier = Modifier.height(10.dp))

        // Channel Filter Chips
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = channelFilter == null,
                onClick = { viewModel.setChannelFilter(null) },
                label = { Text("All Channels", fontSize = 11.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = FinCyan.copy(alpha = 0.2f),
                    selectedLabelColor = FinCyan
                )
            )

            IngestChannel.values().forEach { channel ->
                FilterChip(
                    selected = channelFilter == channel,
                    onClick = {
                        viewModel.setChannelFilter(if (channelFilter == channel) null else channel)
                    },
                    label = { Text(channel.name, fontSize = 11.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = FinCyan.copy(alpha = 0.2f),
                        selectedLabelColor = FinCyan
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        // Severity Filter Chips
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = severityFilter == null,
                onClick = { viewModel.setSeverityFilter(null) },
                label = { Text("All Risk Levels", fontSize = 11.sp) }
            )
            FilterChip(
                selected = severityFilter == ThreatSeverity.CRITICAL,
                onClick = {
                    viewModel.setSeverityFilter(
                        if (severityFilter == ThreatSeverity.CRITICAL) null else ThreatSeverity.CRITICAL
                    )
                },
                label = { Text("High / Critical", fontSize = 11.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = FinCrimson.copy(alpha = 0.2f),
                    selectedLabelColor = FinCrimson
                )
            )
            FilterChip(
                selected = severityFilter == ThreatSeverity.SUSPICIOUS,
                onClick = {
                    viewModel.setSeverityFilter(
                        if (severityFilter == ThreatSeverity.SUSPICIOUS) null else ThreatSeverity.SUSPICIOUS
                    )
                },
                label = { Text("Suspicious", fontSize = 11.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = FinAmber.copy(alpha = 0.2f),
                    selectedLabelColor = FinAmber
                )
            )
            FilterChip(
                selected = severityFilter == ThreatSeverity.SAFE,
                onClick = {
                    viewModel.setSeverityFilter(
                        if (severityFilter == ThreatSeverity.SAFE) null else ThreatSeverity.SAFE
                    )
                },
                label = { Text("Verified Safe", fontSize = 11.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = FinEmerald.copy(alpha = 0.2f),
                    selectedLabelColor = FinEmerald
                )
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        // List
        if (filteredLogs.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = FinTextSecondary,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "No events match current filter",
                        color = FinTextSecondary,
                        fontSize = 14.sp
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(filteredLogs, key = { it.id }) { log ->
                    val dateStr = SimpleDateFormat("dd MMM, HH:mm", Locale.getDefault()).format(Date(log.timestamp))

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
                                    text = dateStr,
                                    color = FinTextSecondary,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                text = "Sender: ${log.sender}",
                                color = FinTextPrimary,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                fontFamily = FontFamily.Monospace
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = log.scrubbedContent,
                                color = FinTextSecondary,
                                fontSize = 12.sp,
                                lineHeight = 16.sp,
                                maxLines = 3,
                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                            )

                            Spacer(modifier = Modifier.height(10.dp))

                            RiskScoreMeter(score = log.riskScore)

                            if (log.piiItemsFound.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Lock,
                                        contentDescription = null,
                                        tint = FinCyan,
                                        modifier = Modifier.size(12.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = "${log.piiItemsFound.size} PII fields sanitized",
                                        color = FinCyan,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                    }
                }
                item {
                    Spacer(modifier = Modifier.height(16.dp))
                }
            }
        }
    }
}
