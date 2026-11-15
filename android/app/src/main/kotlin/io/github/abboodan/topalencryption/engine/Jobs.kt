package io.github.abboodan.topalencryption.engine

import android.content.ClipData
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

sealed interface JobState {
    data object Idle : JobState

    data class Running(
        val mode: Mode,
        val files: Int,
        val totalFiles: Int,
        val bytes: Long,
        val totalBytes: Long,
        /** The key is being derived; nothing has been read yet. */
        val preparing: Boolean,
        val cancelling: Boolean,
    ) : JobState

    data class Finished(val summary: Summary) : JobState
}

/**
 * The one job the app runs at a time. It lives in the process, not in an activity, so
 * the screen can be rotated or left and found again in the state the job is in.
 */
object Jobs {
    private val mutableState = MutableStateFlow<JobState>(JobState.Idle)
    val state: StateFlow<JobState> = mutableState

    /** Handed to [JobService] when it starts. Never put in an Intent: it holds the password. */
    private var pending: JobRequest? = null

    @Volatile
    private var runner: Runner? = null

    /** Whether the app's screen is in front; decides if a "finished" notification is needed. */
    @Volatile
    var visible = false

    /**
     * Starts [request] in the foreground service. [granted] are documents this app was
     * given temporary access to (shared from another app); the access is passed on to
     * the service so that it lasts as long as the job. Returns `false` if a job is running.
     */
    @Synchronized
    fun start(context: Context, request: JobRequest, granted: List<Uri> = emptyList()): Boolean {
        if (mutableState.value is JobState.Running) return false
        pending = request
        mutableState.value = JobState.Running(
            request.mode, 0, request.items.size, 0, request.items.sumOf { it.size }, preparing = true, cancelling = false,
        )
        val intent = Intent(context, JobService::class.java)
        val content = granted.filter { it.scheme == ContentResolver.SCHEME_CONTENT }.take(MAX_GRANTS)
        try {
            if (content.isEmpty()) {
                context.startForegroundService(intent)
            } else {
                val clip = ClipData.newRawUri(null, content.first())
                content.drop(1).forEach { clip.addItem(ClipData.Item(it)) }
                val granting = Intent(intent).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                granting.clipData = clip
                try {
                    context.startForegroundService(granting)
                } catch (_: SecurityException) {
                    // Access to one of them is already gone. The job reports that file by
                    // name; the others are read through the activity's own access.
                    context.startForegroundService(intent)
                }
            }
        } catch (err: Exception) {
            pending = null
            mutableState.value = JobState.Idle
            throw err
        }
        return true
    }

    @Synchronized
    internal fun takePending(): JobRequest? = pending.also { pending = null }

    internal fun attach(runner: Runner?) {
        this.runner = runner
        // Cancel may have been pressed before the service got as far as this.
        if ((mutableState.value as? JobState.Running)?.cancelling == true) runner?.cancel()
    }

    internal fun progress(progress: Progress) = mutableState.update { current ->
        if (current is JobState.Running) {
            current.copy(files = progress.files, bytes = progress.bytes, preparing = progress.preparing)
        } else {
            current
        }
    }

    internal fun finish(summary: Summary) {
        mutableState.value = JobState.Finished(summary)
    }

    fun cancel() {
        mutableState.update { if (it is JobState.Running) it.copy(cancelling = true) else it }
        runner?.cancel()
    }

    /** Leaves the results screen. */
    fun dismiss() = mutableState.update { if (it is JobState.Finished) JobState.Idle else it }

    /** More than this many documents would not fit in one Intent. */
    private const val MAX_GRANTS = 500
}
