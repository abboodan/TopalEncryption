package io.github.abboodan.topalencryption.engine

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import io.github.abboodan.topalencryption.R
import io.github.abboodan.topalencryption.core.TopalException
import io.github.abboodan.topalencryption.ui.Language
import io.github.abboodan.topalencryption.ui.MainActivity
import io.github.abboodan.topalencryption.ui.bytes
import io.github.abboodan.topalencryption.ui.number
import io.github.abboodan.topalencryption.ui.working
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Runs the job while the app is not on screen. A foreground service with a progress
 * notification keeps Android from stopping the app in the middle of a large file.
 */
class JobService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val notifications by lazy { getSystemService(NotificationManager::class.java) }

    override fun attachBaseContext(base: Context) = super.attachBaseContext(Language.wrap(base))

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        notifications.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.channel_progress), NotificationManager.IMPORTANCE_LOW),
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_CANCEL) {
            Jobs.cancel()
            return START_NOT_STICKY
        }
        val request = Jobs.takePending()
        val mode = request?.mode ?: Mode.ENCRYPT
        // Android requires this within seconds of the service being started, job or no job.
        startForeground(
            NOTIFICATION_PROGRESS,
            progressNotification(working(mode), getString(R.string.preparing), 0, 0),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
        )
        if (request == null) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(startId)
            return START_NOT_STICKY
        }
        notifications.cancel(NOTIFICATION_FINISHED)
        scope.launch { run(request) }
        return START_NOT_STICKY
    }

    private suspend fun run(request: JobRequest) {
        val wakeLock = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TopalEncryption:job")
        wakeLock.acquire(MAX_JOB_MILLIS)
        val runner = Runner(applicationContext, request)
        Jobs.attach(runner)
        val totalFiles = request.items.size
        val totalBytes = request.items.sumOf { it.size }
        var lastNotified = 0L
        val summary = try {
            runner.run { progress ->
                Jobs.progress(progress)
                val now = SystemClock.elapsedRealtime()
                if (now - lastNotified >= NOTIFY_EVERY_MILLIS) {
                    lastNotified = now
                    val text = if (progress.preparing) {
                        getString(R.string.preparing)
                    } else {
                        getString(
                            R.string.working_detail,
                            number(progress.files.toLong()), number(totalFiles.toLong()),
                            bytes(progress.bytes), bytes(totalBytes),
                        )
                    }
                    notifications.notify(
                        NOTIFICATION_PROGRESS,
                        progressNotification(working(request.mode), text, progress.bytes, totalBytes),
                    )
                }
            }
        } catch (err: Throwable) {
            // The key could not be prepared (a mistyped recovery key, for one).
            val failure = if (err is TopalException) Failure("", err.code, err.detail) else Failure("", "internal", err.toString())
            Summary(request.mode, 0, 0, listOf(failure), false, request.recoveryKey != null, 0, 0, request.targetLabel)
        } finally {
            Jobs.attach(null)
            if (wakeLock.isHeld) wakeLock.release()
        }
        // Counts and timing only: never names, never secrets.
        Log.i(
            TAG,
            "${request.mode}: done=${summary.done} skipped=${summary.skipped} failed=${summary.failures.size} " +
                "cancelled=${summary.cancelled} bytes=${summary.bytes} ms=${summary.millis}",
        )
        Jobs.finish(summary)
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (!Jobs.visible) notifications.notify(NOTIFICATION_FINISHED, finishedNotification(summary))
        stopSelf()
    }

    /** Android 15 and later stop a long-running data service after six hours in a day. */
    override fun onTimeout(startId: Int, fgsType: Int) {
        Jobs.cancel()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun openApp(): PendingIntent = PendingIntent.getActivity(
        this, 0,
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun progressNotification(title: String, text: String, bytes: Long, totalBytes: Long): Notification {
        val cancel = PendingIntent.getService(
            this, 1,
            Intent(this, JobService::class.java).setAction(ACTION_CANCEL),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val known = totalBytes > 0 && bytes > 0
        val permille = if (known) (bytes * 1000 / totalBytes).toInt().coerceIn(0, 1000) else 0
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setProgress(1000, permille, !known)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_PROGRESS)
            .setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(openApp())
            .addAction(Notification.Action.Builder(null, getString(R.string.cancel), cancel).build())
            .build()
    }

    private fun finishedNotification(summary: Summary): Notification {
        val title = getString(
            when {
                summary.cancelled -> R.string.result_cancelled
                summary.allFailedWith("wrong_password") -> R.string.result_wrong_password
                summary.allFailedWith("wrong_recovery_key") -> R.string.result_wrong_recovery_key
                summary.failures.isNotEmpty() -> R.string.result_problems
                else -> R.string.result_all_done
            },
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(getString(R.string.app_name))
            .setAutoCancel(true)
            .setContentIntent(openApp())
            .build()
    }

    companion object {
        private const val TAG = "TopalEncryption"
        private const val CHANNEL = "progress"
        private const val ACTION_CANCEL = "io.github.abboodan.topalencryption.CANCEL"
        private const val NOTIFICATION_PROGRESS = 1
        const val NOTIFICATION_FINISHED = 2
        private const val NOTIFY_EVERY_MILLIS = 500L
        private const val MAX_JOB_MILLIS = 6 * 60 * 60 * 1000L
    }
}
