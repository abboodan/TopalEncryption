package io.github.abboodan.topalencryption.ui

import android.content.Context
import io.github.abboodan.topalencryption.R
import io.github.abboodan.topalencryption.engine.Mode
import java.util.Locale

/** Digits stay Western in both languages, so sizes and counts read the same. */
fun number(n: Long): String = String.format(Locale.US, "%,d", n)

fun Context.files(count: Int): String = resources.getQuantityString(R.plurals.files, count, number(count.toLong()))

fun Context.bytes(bytes: Long): String {
    val units = resources.getStringArray(R.array.units)
    var value = bytes.toDouble()
    var unit = 0
    while (value >= 1024 && unit < units.size - 1) {
        value /= 1024
        unit++
    }
    val text = when {
        unit == 0 -> bytes.toString()
        value < 10 -> String.format(Locale.US, "%.2f", value)
        else -> String.format(Locale.US, "%.1f", value)
    }
    return "$text ${units[unit]}"
}

fun Context.duration(millis: Long): String {
    val seconds = millis / 1000.0
    return if (seconds < 60) {
        getString(R.string.seconds, String.format(Locale.US, if (seconds < 10) "%.1f" else "%.0f", seconds))
    } else {
        getString(R.string.minutes, String.format(Locale.US, "%d:%02d", (seconds / 60).toInt(), (seconds % 60).toInt()))
    }
}

fun Context.working(mode: Mode): String = getString(
    when (mode) {
        Mode.ENCRYPT -> R.string.working_encrypt
        Mode.DECRYPT -> R.string.working_decrypt
        Mode.VERIFY -> R.string.working_verify
    },
)

/** The translated message for an error code from the native library. */
fun Context.errorText(code: String): String = getString(
    when (code) {
        "wrong_password" -> R.string.err_wrong_password
        "wrong_recovery_key" -> R.string.err_wrong_recovery_key
        "no_recovery_slot" -> R.string.err_no_recovery_slot
        "invalid_recovery_key" -> R.string.err_invalid_recovery_key
        "not_topal" -> R.string.err_not_topal
        "corrupted" -> R.string.err_corrupted
        "unsafe_path" -> R.string.err_unsafe_path
        "output_exists" -> R.string.err_output_exists
        "unsupported_version" -> R.string.err_unsupported_version
        "invalid_kdf_params" -> R.string.err_invalid_kdf_params
        "io" -> R.string.err_io
        else -> R.string.err_internal
    },
)

/** Rough strength estimate, 1 (weak) to 4 (strong): length matters most. Same as the desktop app. */
fun strength(password: String): Int {
    val classes = listOf(Regex("[a-z]"), Regex("[A-Z]"), Regex("\\d"), Regex("[^A-Za-z0-9]"))
        .count { it.containsMatchIn(password) }
    // Repeating a character adds little: each distinct one counts at most twice.
    val length = minOf(password.length, password.toSet().size * 2)
    // The first things anyone tries. Containing one halves the estimate.
    val common = Regex("pass|qwert|asdf|1234|4321|abcd|admin|letmein|welcome|iloveyou|0000|1111", RegexOption.IGNORE_CASE)
        .containsMatchIn(password)
    val bits = length * doubleArrayOf(0.0, 4.7, 5.7, 5.95, 6.5)[classes] * (if (common) 0.5 else 1.0)
    return when {
        bits < 40 -> 1
        bits < 60 -> 2
        bits < 80 -> 3
        else -> 4
    }
}

/**
 * A name as it really is: characters that change the direction text is drawn in are
 * replaced by a visible mark, so a name cannot be displayed as something else.
 */
fun plainName(text: String): String = text.replace(Regex("[‪-‮⁦-⁩]"), "�")
