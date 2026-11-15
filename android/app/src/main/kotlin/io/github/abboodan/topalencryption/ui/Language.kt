package io.github.abboodan.topalencryption.ui

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

/**
 * The interface language is the app's own setting, not the phone's: English unless the
 * user switches to Arabic, as in the desktop app.
 */
object Language {
    private const val PREFS = "settings"
    private const val KEY = "language"

    fun current(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, "en") ?: "en"

    fun set(context: Context, language: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, language).apply()
    }

    /** [base] with the chosen language and its text direction. */
    fun wrap(base: Context): Context {
        val locale = Locale.forLanguageTag(current(base))
        val config = Configuration(base.resources.configuration)
        config.setLocale(locale)
        config.setLayoutDirection(locale)
        return base.createConfigurationContext(config)
    }
}
