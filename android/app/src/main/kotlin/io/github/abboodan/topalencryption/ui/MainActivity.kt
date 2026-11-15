package io.github.abboodan.topalencryption.ui

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import io.github.abboodan.topalencryption.R
import io.github.abboodan.topalencryption.engine.JobService
import io.github.abboodan.topalencryption.engine.JobState
import io.github.abboodan.topalencryption.engine.Jobs

class MainActivity : ComponentActivity() {
    private val model: AppViewModel by viewModels()

    override fun attachBaseContext(newBase: Context) = super.attachBaseContext(Language.wrap(newBase))

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
        )
        super.onCreate(savedInstanceState)
        secure(!model.allowScreenshots)
        // Only a fresh start carries new files: a recreated activity sees the old Intent again.
        if (savedInstanceState == null) receive(intent)
        setContent {
            TopalTheme {
                App(
                    model,
                    onLanguage = ::switchLanguage,
                    onScreenshots = { allowed ->
                        model.allowScreenshots(allowed)
                        secure(!allowed)
                    },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        receive(intent)
    }

    override fun onStart() {
        super.onStart()
        Jobs.visible = true
        getSystemService(NotificationManager::class.java).cancel(JobService.NOTIFICATION_FINISHED)
        model.dailyCheck()
    }

    /**
     * Passwords and recovery keys are on this screen: unless the user allows screenshots in
     * the settings, it is kept out of them, out of screen recordings and out of the previews
     * of the recent apps list.
     */
    private fun secure(on: Boolean) {
        if (on) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    override fun onStop() {
        Jobs.visible = false
        super.onStop()
    }

    private fun switchLanguage(tag: String) {
        Language.set(this, tag)
        recreate()
    }

    /** Takes the files another app shared, or the one that was tapped in a file manager. */
    private fun receive(intent: Intent?) {
        val uris: List<Uri> = when (intent?.action) {
            Intent.ACTION_SEND -> listOfNotNull(intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java))
            Intent.ACTION_SEND_MULTIPLE -> intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
            Intent.ACTION_VIEW -> listOfNotNull(intent.data)
            else -> return
        }
        if (uris.isEmpty()) return
        when (Jobs.state.value) {
            is JobState.Running -> {
                Toast.makeText(this, R.string.err_busy, Toast.LENGTH_LONG).show()
                return
            }
            is JobState.Finished -> model.finish()
            JobState.Idle -> {}
        }
        model.receive(uris)
    }
}
