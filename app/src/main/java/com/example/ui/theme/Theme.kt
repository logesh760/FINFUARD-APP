package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val FinGuardDarkColorScheme = darkColorScheme(
    primary = FinCyan,
    onPrimary = Color(0xFF00363D),
    primaryContainer = FinCyanContainer,
    onPrimaryContainer = Color(0xFF80F0FF),

    secondary = FinEmerald,
    onSecondary = Color(0xFF00381B),
    secondaryContainer = FinEmeraldContainer,
    onSecondaryContainer = Color(0xFF6BFFB0),

    tertiary = FinAmber,
    onTertiary = Color(0xFF3B2500),
    tertiaryContainer = FinAmberContainer,
    onTertiaryContainer = Color(0xFFFFDE99),

    error = FinCrimson,
    onError = Color.White,
    errorContainer = FinCrimsonContainer,
    onErrorContainer = Color(0xFFFFB3C2),

    background = FinNavyDark,
    onBackground = FinTextPrimary,
    surface = FinNavySurface,
    onSurface = FinTextPrimary,
    surfaceVariant = FinNavyElevated,
    onSurfaceVariant = FinTextSecondary,
    outline = FinNavyBorder
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false, // Enforce consistent sleek cyber dark theme
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = FinGuardDarkColorScheme,
        typography = Typography,
        content = content
    )
}
