package io.github.abboodan.topalencryption.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

/** The colours of the desktop app (gui/ui/style.css). */
object Palette {
    val Background = Color(0xFF0B101C)
    val Panel = Color(0xFF131A2B)
    val PanelHover = Color(0xFF18213A)
    val Line = Color(0xFF243049)
    val Text = Color(0xFFE6EBF5)
    val Muted = Color(0xFF8B97B0)
    val Accent = Color(0xFF5EEAD4)
    val Accent2 = Color(0xFF38BDF8)
    val OnAccent = Color(0xFF06202A)
    val Danger = Color(0xFFF87171)
    val Warn = Color(0xFFFBBF24)

    val AccentBrush = Brush.linearGradient(listOf(Accent, Accent2))
}

private val Colors = darkColorScheme(
    primary = Palette.Accent,
    onPrimary = Palette.OnAccent,
    secondary = Palette.Accent2,
    onSecondary = Palette.OnAccent,
    background = Palette.Background,
    onBackground = Palette.Text,
    surface = Palette.Panel,
    onSurface = Palette.Text,
    surfaceVariant = Palette.PanelHover,
    onSurfaceVariant = Palette.Muted,
    outline = Palette.Line,
    outlineVariant = Palette.Line,
    error = Palette.Danger,
)

/** Always dark, like the desktop app. */
@Composable
fun TopalTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Colors, content = content)
}
