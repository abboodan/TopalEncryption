package io.github.abboodan.topalencryption.ui

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
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
        // Only a fresh start carries a new share: a recreated activity sees the old Intent again.
        if (savedInstanceState == null) receive(intent)
        setContent {
            TopalTheme {
                App(model, onLanguage = ::switchLanguage)
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
    }

    override fun onStop() {
        Jobs.visible = false
        super.onStop()
    }

    private fun switchLanguage(tag: String) {
        Language.set(this, tag)
        recreate()
    }

    /** Takes the files of a "Share" from another app. */
    private fun receive(intent: Intent?) {
        val uris: List<Uri> = when (intent?.action) {
            Intent.ACTION_SEND -> listOfNotNull(intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java))
            Intent.ACTION_SEND_MULTIPLE -> intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
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
