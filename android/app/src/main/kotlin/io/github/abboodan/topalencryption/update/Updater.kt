package io.github.abboodan.topalencryption.update

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.util.Log
import io.github.abboodan.topalencryption.BuildConfig
import io.github.abboodan.topalencryption.engine.JobState
import io.github.abboodan.topalencryption.engine.Jobs
import java.io.File
import java.io.IOException
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** A published version newer than the one running. */
data class Release(
    /** `0.4.0` */
    val version: String,
    val url: String,
    /** The size of the download in bytes, or 0 if GitHub did not say. */
    val size: Long,
)

/** Why an update could not be found, downloaded, accepted or installed. */
enum class Problem {
    /** GitHub could not be reached, or the connection broke. */
    NETWORK,

    /** GitHub answered with something this version does not understand. */
    UNEXPECTED,

    /** The newest release has no Android download. */
    NO_DOWNLOAD,
    TOO_LARGE,
    STORAGE,

    /** The download is not an installable app at all. */
    NOT_AN_APP,

    /** It is another app. */
    WRONG_APP,

    /** It is not newer than the version running. */
    NOT_NEWER,

    /** It is not signed with the key this app is signed with. */
    WRONG_SIGNATURE,

    /** Android's installer refused it; the detail is its own message. */
    INSTALL,
}

sealed interface UpdateState {
    data object Idle : UpdateState
    data object Checking : UpdateState
    data class UpToDate(val latest: String) : UpdateState
    data class Available(val release: Release) : UpdateState
    data class Downloading(val release: Release, val bytes: Long, val total: Long) : UpdateState
    data class Verifying(val release: Release) : UpdateState

    /** Downloaded, and checked to be this app, newer, and signed with the same key. */
    data class Ready(val release: Release, val problem: Problem? = null, val detail: String = "") : UpdateState

    /** Handed to Android's installer, which asks the user to confirm. */
    data class Installing(val release: Release) : UpdateState
    data class Failed(val problem: Problem, val detail: String = "") : UpdateState
}

private class Refused(val problem: Problem, val detail: String = "") : Exception(problem.name)

/**
 * Looks for a newer version on GitHub, downloads it and hands it to Android's installer.
 *
 * It is the only part of the app that uses the network, and it does so only when asked:
 * by the button on the About screen, or once a day when the app is opened if the user
 * turned that on. Every request is an HTTPS request to GitHub that carries nothing about
 * the user or the phone: no account, no identifier, not even the version in use.
 *
 * What comes back is not trusted. Before Android's installer sees the download, it must
 * be this app, newer than the one running, and signed with the same certificate; Android
 * then checks the signature again and asks the user to confirm.
 */
object Updater {
    private const val TAG = "TopalEncryption"
    private const val REPOSITORY = "https://github.com/abboodan/TopalEncryption"
    private const val USER_AGENT = "TopalEncryption"
    private const val FOLDER = "updates"
    private const val PART = ".part"
    private const val MAX_REDIRECTS = 5

    /** Eight times the size of the app today. Anything larger is not this app. */
    private const val MAX_BYTES = 200L * 1024 * 1024
    private const val ACTION_INSTALL_STATUS = "io.github.abboodan.topalencryption.INSTALL_STATUS"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutableState = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val state: StateFlow<UpdateState> = mutableState

    private var work: Job? = null

    @Volatile
    private var connection: HttpsURLConnection? = null

    /** The version code of the app that is running. */
    fun ownVersionCode(context: Context): Long =
        // A test build can pretend to be older, so that the release already published
        // counts as an update. Never set in a build that is published.
        if (BuildConfig.PRETEND_VERSION_CODE > 0) {
            BuildConfig.PRETEND_VERSION_CODE.toLong()
        } else {
            context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode
        }

    /** `1.2.3` as the version code the build gives it, or `null` if it is not a version. */
    fun versionCode(version: String): Long? {
        val parts = Regex("""(\d{1,3})\.(\d{1,2})\.(\d{1,2})""").matchEntire(version)?.groupValues ?: return null
        return parts[1].toLong() * 10000 + parts[2].toLong() * 100 + parts[3].toLong()
    }

    private fun apkName(version: String) = "TopalEncryption_${version}_android.apk"

    private fun folder(context: Context) = File(context.cacheDir, FOLDER)

    private fun busy(): Boolean = when (mutableState.value) {
        UpdateState.Checking, is UpdateState.Downloading, is UpdateState.Verifying, is UpdateState.Installing -> true
        else -> false
    }

    /**
     * Asks GitHub for the newest release. With [quiet], for the daily check, a failure is
     * not reported: the next day tries again.
     */
    @Synchronized
    fun check(context: Context, quiet: Boolean = false) {
        if (busy() || mutableState.value is UpdateState.Ready) return
        val app = context.applicationContext
        val before = mutableState.value
        mutableState.value = UpdateState.Checking
        work = scope.launch {
            mutableState.value = try {
                val latest = latestVersion()
                val code = versionCode(latest) ?: throw Refused(Problem.UNEXPECTED, latest)
                if (code <= ownVersionCode(app)) {
                    UpdateState.UpToDate(latest)
                } else {
                    val url = "$REPOSITORY/releases/download/v$latest/${apkName(latest)}"
                    UpdateState.Available(Release(latest, url, sizeOf(url)))
                }
            } catch (err: Exception) {
                Log.i(TAG, "update check failed: ${err.javaClass.simpleName}")
                if (quiet) before else failure(err)
            }
        }
    }

    /** Downloads the release found by [check], then checks what arrived. */
    @Synchronized
    fun download(context: Context) {
        val release = (mutableState.value as? UpdateState.Available)?.release ?: return
        // An update restarts the app: never while files are being processed.
        if (Jobs.state.value is JobState.Running) return
        val app = context.applicationContext
        mutableState.value = UpdateState.Downloading(release, 0, release.size)
        work = scope.launch {
            val dir = folder(app)
            val part = File(dir, apkName(release.version) + PART)
            try {
                dir.deleteRecursively()
                if (!dir.mkdirs()) throw Refused(Problem.STORAGE)
                fetch(release, part)
                mutableState.value = UpdateState.Verifying(release)
                verify(app, part)
                if (!part.renameTo(File(dir, apkName(release.version)))) throw Refused(Problem.STORAGE)
                mutableState.value = UpdateState.Ready(release)
            } catch (err: Exception) {
                part.delete()
                // Cancelled by the user: the release is still there to download.
                mutableState.value = if (err is CancellationException) UpdateState.Available(release) else failure(err)
                if (err is CancellationException) throw err
            }
        }
    }

    /** Stops a download; what was received is deleted. */
    @Synchronized
    fun cancel() {
        if (mutableState.value !is UpdateState.Downloading) return
        work?.cancel()
        // Closing the connection is what ends a read that is waiting for the network.
        val open = connection
        scope.launch { runCatching { open?.disconnect() } }
    }

    /** Back to the start after a result has been read. */
    @Synchronized
    fun dismiss() {
        when (mutableState.value) {
            is UpdateState.Failed, is UpdateState.UpToDate -> mutableState.value = UpdateState.Idle
            else -> {}
        }
    }

    /**
     * Run when the app starts. A download that was complete and checked is offered again:
     * Android may restart the app when the user allows it to install apps. Anything else
     * in the folder is a leftover and is deleted, as is the download of the version that
     * is now installed.
     */
    @Synchronized
    fun restore(context: Context) {
        if (busy() || mutableState.value is UpdateState.Ready) return
        val app = context.applicationContext
        scope.launch {
            val files = folder(app).listFiles().orEmpty()
            var kept: UpdateState? = null
            for (file in files) {
                val version = Regex("""TopalEncryption_(.+)_android\.apk""").matchEntire(file.name)?.groupValues?.get(1)
                val good = kept == null && version != null && versionCode(version) != null &&
                    runCatching { verify(app, file) }.isSuccess
                if (good) {
                    kept = UpdateState.Ready(Release(version!!, "", file.length()))
                } else {
                    file.delete()
                }
            }
            synchronized(this@Updater) {
                if (kept != null && mutableState.value == UpdateState.Idle) mutableState.value = kept
            }
        }
    }

    /**
     * Hands the checked download to Android's installer, which asks the user to confirm.
     * The caller has made sure the app is allowed to ask (`canRequestPackageInstalls`).
     */
    @Synchronized
    fun install(context: Context) {
        val release = (mutableState.value as? UpdateState.Ready)?.release ?: return
        if (Jobs.state.value is JobState.Running) return
        val app = context.applicationContext
        mutableState.value = UpdateState.Installing(release)
        work = scope.launch {
            val installer = app.packageManager.packageInstaller
            var id = -1
            try {
                val file = File(folder(app), apkName(release.version))
                // Checked again: this is the file the installer gets, byte for byte.
                verify(app, file)
                val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                    setAppPackageName(app.packageName)
                    setSize(file.length())
                    setInstallReason(PackageManager.INSTALL_REASON_USER)
                    setPackageSource(PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE)
                }
                id = installer.createSession(params)
                installer.openSession(id).use { session ->
                    session.openWrite("update.apk", 0, file.length()).use { out ->
                        file.inputStream().use { it.copyTo(out, 1 shl 16) }
                        session.fsync(out)
                    }
                    val status = Intent(app, InstallReceiver::class.java).setAction(ACTION_INSTALL_STATUS)
                    val pending = PendingIntent.getBroadcast(
                        app, id, status, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                    )
                    session.commit(pending.intentSender)
                }
            } catch (err: Exception) {
                if (id >= 0) runCatching { installer.abandonSession(id) }
                val failed = failure(err)
                mutableState.value = if (err is Refused) failed else UpdateState.Ready(release, Problem.INSTALL, failed.detail)
                if (err is Refused) File(folder(app), apkName(release.version)).delete()
            }
        }
    }

    /** What Android's installer reported about the session started by [install]. */
    internal fun installStatus(context: Context, intent: Intent) {
        val release = (mutableState.value as? UpdateState.Installing)?.release
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) ?: return
                try {
                    context.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                } catch (err: Exception) {
                    if (release != null) mutableState.value = UpdateState.Ready(release, Problem.INSTALL, err.javaClass.simpleName)
                }
            }
            // The app is replaced and restarted: this is rarely seen.
            PackageInstaller.STATUS_SUCCESS -> mutableState.value = UpdateState.Idle
            // The user said no.
            PackageInstaller.STATUS_FAILURE_ABORTED -> if (release != null) mutableState.value = UpdateState.Ready(release)
            else -> if (release != null) {
                val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()
                mutableState.value = UpdateState.Ready(release, Problem.INSTALL, message)
            }
        }
    }

    private fun failure(err: Exception): UpdateState.Failed = when (err) {
        is Refused -> UpdateState.Failed(err.problem, err.detail)
        is IOException -> UpdateState.Failed(Problem.NETWORK, err.message.orEmpty())
        else -> UpdateState.Failed(Problem.UNEXPECTED, err.javaClass.simpleName)
    }

    /** Only GitHub, and only over HTTPS: its site, and the hosts its downloads are served from. */
    private fun requireGitHub(url: URL) {
        val host = url.host.lowercase()
        val known = host == "github.com" || host.endsWith(".githubusercontent.com")
        if (url.protocol != "https" || !known) throw Refused(Problem.UNEXPECTED, host)
    }

    /** One request, with redirects not followed: each hop is checked by the caller first. */
    private fun request(url: URL, method: String): HttpsURLConnection {
        requireGitHub(url)
        val open = url.openConnection() as HttpsURLConnection
        open.requestMethod = method
        open.instanceFollowRedirects = false
        open.useCaches = false
        open.connectTimeout = 15_000
        open.readTimeout = 30_000
        // Android would otherwise name the phone's model and system version here.
        open.setRequestProperty("User-Agent", USER_AGENT)
        return open
    }

    private fun isRedirect(status: Int) = status in setOf(301, 302, 303, 307, 308)

    /** Follows redirects, within GitHub, to the response that is not one. */
    private fun follow(start: String, method: String): HttpsURLConnection {
        var url = URL(start)
        repeat(MAX_REDIRECTS) {
            val open = request(url, method)
            connection = open
            val status = open.responseCode
            if (!isRedirect(status)) return open
            val location = open.getHeaderField("Location")
            open.disconnect()
            url = URL(url, location ?: throw Refused(Problem.UNEXPECTED, "redirect"))
        }
        throw Refused(Problem.UNEXPECTED, "redirect")
    }

    /**
     * The version of the newest release: GitHub redirects `releases/latest` to the page
     * of that release, whose address ends with its tag.
     */
    private fun latestVersion(): String {
        val open = request(URL("$REPOSITORY/releases/latest"), "HEAD")
        try {
            val status = open.responseCode
            if (!isRedirect(status)) throw Refused(Problem.UNEXPECTED, "HTTP $status")
            val target = URL(open.url, open.getHeaderField("Location") ?: throw Refused(Problem.UNEXPECTED, "redirect"))
            val prefix = "/abboodan/TopalEncryption/releases/tag/v"
            if (target.host != "github.com" || !target.path.startsWith(prefix)) throw Refused(Problem.UNEXPECTED, "no release")
            return target.path.removePrefix(prefix)
        } finally {
            open.disconnect()
        }
    }

    /** The size of the download, which also tells that the release has one for Android. */
    private fun sizeOf(url: String): Long {
        val open = follow(url, "HEAD")
        try {
            return when (val status = open.responseCode) {
                200 -> open.contentLengthLong.coerceAtLeast(0)
                404 -> throw Refused(Problem.NO_DOWNLOAD)
                else -> throw Refused(Problem.UNEXPECTED, "HTTP $status")
            }
        } finally {
            open.disconnect()
        }
    }

    private suspend fun fetch(release: Release, into: File) {
        val open = follow(release.url, "GET")
        try {
            when (val status = open.responseCode) {
                200 -> {}
                404 -> throw Refused(Problem.NO_DOWNLOAD)
                else -> throw Refused(Problem.UNEXPECTED, "HTTP $status")
            }
            val total = open.contentLengthLong.takeIf { it > 0 } ?: release.size
            if (total > MAX_BYTES) throw Refused(Problem.TOO_LARGE)
            var received = 0L
            var shown = 0L
            val buffer = ByteArray(1 shl 16)
            open.inputStream.use { input ->
                val output = try {
                    into.outputStream()
                } catch (_: IOException) {
                    throw Refused(Problem.STORAGE)
                }
                output.use {
                    while (true) {
                        kotlin.coroutines.coroutineContext.ensureActive()
                        val n = input.read(buffer)
                        if (n < 0) break
                        received += n
                        if (received > MAX_BYTES) throw Refused(Problem.TOO_LARGE)
                        try {
                            output.write(buffer, 0, n)
                        } catch (_: IOException) {
                            throw Refused(Problem.STORAGE)
                        }
                        if (received - shown >= 256 * 1024) {
                            shown = received
                            mutableState.value = UpdateState.Downloading(release, received, total)
                        }
                    }
                    output.fd.sync()
                }
            }
            if (total > 0 && received != total) throw IOException("the download ended early")
        } catch (err: IOException) {
            // A read cut off by Cancel arrives as a network error.
            kotlin.coroutines.coroutineContext.ensureActive()
            throw err
        } finally {
            connection = null
            open.disconnect()
        }
    }

    private fun signers(info: PackageInfo?): Set<String> =
        info?.signingInfo?.apkContentsSigners.orEmpty().map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
        }.toSet()

    /**
     * Accepts [file] only if it is an update of this very app: the same package, a higher
     * version, and signed by exactly the certificate this app is signed with. Android
     * verifies the signature over the whole file while reading the certificate from it.
     */
    private fun verify(context: Context, file: File) {
        val packages = context.packageManager
        val flags = PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
        val theirs = packages.getPackageArchiveInfo(file.path, flags) ?: throw Refused(Problem.NOT_AN_APP)
        if (theirs.packageName != context.packageName) throw Refused(Problem.WRONG_APP)
        if (theirs.longVersionCode <= ownVersionCode(context)) throw Refused(Problem.NOT_NEWER)
        val ours = signers(packages.getPackageInfo(context.packageName, flags))
        if (ours.isEmpty() || signers(theirs) != ours) throw Refused(Problem.WRONG_SIGNATURE)
    }
}

/** Receives what Android's installer has to say about an update handed to it. */
class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = Updater.installStatus(context, intent)
}
