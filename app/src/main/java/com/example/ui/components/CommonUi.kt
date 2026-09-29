package com.example.ui.components

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.automirrored.filled.Message
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.IngestChannel
import com.example.data.model.ThreatCategory
import com.example.data.model.ThreatSeverity
import com.example.ui.theme.FinAmber
import com.example.ui.theme.FinCrimson
import com.example.ui.theme.FinCyan
import com.example.ui.theme.FinEmerald
import com.example.ui.theme.FinNavyBorder
import com.example.ui.theme.FinNavyElevated
import com.example.ui.theme.FinNavySurface
import com.example.ui.theme.FinTextPrimary
import com.example.ui.theme.FinTextSecondary

@Composable
fun SeverityBadge(severity: ThreatSeverity, modifier: Modifier = Modifier) {
    val (bgColor, textColor, label) = when (severity) {
        ThreatSeverity.CRITICAL -> Triple(Color(0xFF450A18), FinCrimson, "CRITICAL")
        ThreatSeverity.HIGH_RISK -> Triple(Color(0xFF381219), Color(0xFFFF5252), "HIGH RISK")
        ThreatSeverity.SUSPICIOUS -> Triple(Color(0xFF3D2C04), FinAmber, "SUSPICIOUS")
        ThreatSeverity.LOW_RISK -> Triple(Color(0xFF0F2B33), FinCyan, "LOW RISK")
        ThreatSeverity.SAFE -> Triple(Color(0xFF063319), FinEmerald, "VERIFIED SAFE")
    }

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bgColor)
            .border(1.dp, textColor.copy(alpha = 0.5f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(
            text = label,
            color = textColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
fun ChannelChip(channel: IngestChannel, modifier: Modifier = Modifier) {
    val (icon, label, color) = when (channel) {
        IngestChannel.SMS -> Triple(Icons.Default.Email, "SMS", Color(0xFF64B5F6))
        IngestChannel.WHATSAPP -> Triple(Icons.AutoMirrored.Filled.Chat, "WhatsApp", Color(0xFF25D366))
        IngestChannel.TELEGRAM -> Triple(Icons.AutoMirrored.Filled.Message, "Telegram", Color(0xFF29B6F6))
        IngestChannel.INSTAGRAM -> Triple(Icons.Default.PhoneAndroid, "Instagram", Color(0xFFE040FB))
        IngestChannel.MANUAL_SCAN -> Triple(Icons.Default.Security, "Manual Scan", FinCyan)
    }

    Row(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(FinNavyElevated)
            .border(1.dp, FinNavyBorder, RoundedCornerShape(12.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = color,
            modifier = Modifier.size(13.dp)
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(
            text = label,
            color = FinTextSecondary,
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
fun RiskScoreMeter(score: Int, modifier: Modifier = Modifier) {
    val color = when {
        score >= 85 -> FinCrimson
        score >= 60 -> Color(0xFFFF7043)
        score >= 40 -> FinAmber
        else -> FinEmerald
    }

    Column(modifier = modifier) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "THREAT PROBABILITY",
                color = FinTextSecondary,
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "$score / 100",
                color = color,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { score / 100f },
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp)),
            color = color,
            trackColor = FinNavyElevated
        )
    }
}

@Composable
fun RadarShieldGraphic(
    isActive: Boolean,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "RadarTransition")
    val pulseRadius by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(2200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "PulseRadius"
    )
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 0.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(2200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "PulseAlpha"
    )

    Box(
        modifier = modifier.size(140.dp),
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.size(130.dp)) {
            val center = this.center
            val maxRadius = size.minDimension / 2

            // Static background radar rings
            drawCircle(
                color = Color(0xFF132A4A),
                radius = maxRadius * 0.95f,
                style = Stroke(width = 1.5.dp.toPx())
            )
            drawCircle(
                color = Color(0xFF10233D),
                radius = maxRadius * 0.65f,
                style = Stroke(width = 1.2.dp.toPx())
            )
            drawCircle(
                color = Color(0xFF0F1E33),
                radius = maxRadius * 0.35f,
                style = Stroke(width = 1.dp.toPx())
            )

            // Animated radiating pulse if active
            if (isActive) {
                drawCircle(
                    color = FinCyan.copy(alpha = pulseAlpha),
                    radius = maxRadius * pulseRadius,
                    style = Stroke(width = 2.dp.toPx())
                )
            }
        }

        // Central Shield Icon
        Box(
            modifier = Modifier
                .size(62.dp)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        colors = if (isActive) listOf(FinCyan.copy(alpha = 0.25f), Color(0xFF0E223D))
                        else listOf(Color(0xFF2B1B20), Color(0xFF191419))
                    )
                )
                .border(
                    1.5.dp,
                    if (isActive) FinCyan else FinCrimson.copy(alpha = 0.6f),
                    CircleShape
                ),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = "Shield Radar Status",
                tint = if (isActive) FinCyan else FinCrimson,
                modifier = Modifier.size(34.dp)
            )
        }
    }
}

@Composable
fun MetricStatCard(
    title: String,
    value: String,
    icon: ImageVector,
    accentColor: Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = FinNavySurface),
        shape = RoundedCornerShape(14.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, FinNavyBorder)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    color = FinTextSecondary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium
                )
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(18.dp)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = value,
                color = FinTextPrimary,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}
