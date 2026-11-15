package io.github.abboodan.topalencryption.engine

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import io.github.abboodan.topalencryption.core.DecryptSink
import io.github.abboodan.topalencryption.core.Native
import io.github.abboodan.topalencryption.core.TopalException
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** What to do, with the secrets it needs. Lives in memory only. */
class JobRequest(
    val mode: Mode,
    val items: List<Item>,
    /** Encrypts, or opens. When changing a password, the current one. */
    val password: String,
    /** Opens files instead of the password when set. Not used when encrypting. */
    val recoveryKey: String? = null,
    /** The password files get when changing it. */
    val newPassword: String? = null,
    /** The public half of the recovery key files are also sealed to when encrypting. */
    val recoveryPublic: RecoveryPublic? = null,
    /** `null` for Verify and Change password, which write no new file. */
    val target: Target? = null,
    /** Shown in the results: where the outputs went. */
    val targetLabel: String? = null,
)

data class Failure(val name: String, val code: String, val detail: String)

/** Something this job wrote. */
data class Output(
    /** Its name, with the folders it sits in below the output folder. */
    val name: String,
    /** What other apps can be handed to read it; `null` for a folder. */
    val uri: Uri?,
)

data class Summary(
    val mode: Mode,
    val done: Int,
    /** Outputs that already existed and were left alone. */
    val skipped: Int,
    val failures: List<Failure>,
    val cancelled: Boolean,
    val usedRecoveryKey: Boolean,
    /** Source bytes read, and how long the whole job took. */
    val bytes: Long,
    val millis: Long,
    val savedTo: String?,
    /**
     * Files decrypted to an app installer (`.apk`...) under a name the encrypted file did
     * not show. The real name is stored inside an encrypted file, so `photo.jpg.topal` from
     * someone else can produce `update.apk`; the results point these out.
     */
    val installers: List<String> = emptyList(),
    /** What was written, in the order of the selection. */
    val outputs: List<Output> = emptyList(),
    /** The folder the outputs are under, for a file manager to show. */
    val folder: Uri? = null,
    /** The ID of the recovery key the encrypted files can also be opened with. */
    val recoveryId: String? = null,
) {
    /** Every file was refused for the same reason, [code]: nothing was opened at all. */
    fun allFailedWith(code: String): Boolean =
        done == 0 && skipped == 0 && failures.isNotEmpty() && failures.all { it.code == code }
}

data class Progress(val files: Int, val bytes: Long, val preparing: Boolean)

private sealed interface Outcome {
    data class Done(val output: Output? = null) : Outcome
    data object Skipped : Outcome
    data object Cancelled : Outcome
    data class Failed(val code: String, val detail: String) : Outcome
}

/**
 * Runs one batch. The key is derived once (256 MiB of memory), then a few files are
 * processed at a time; each needs about two megabytes whatever its size. One file failing
 * does not stop the others.
 */
class Runner(private val context: Context, private val request: JobRequest) {
    private val resolver = context.contentResolver
    private val lock = Any()
    private var control = 0L
    private var cancelled = false

    /** Outputs taken by this run, so that two sources never fight over one name. */
    private val claimed = HashSet<String>()

    /** See [Summary.installers]. */
    private val installers = ArrayList<String>()

    fun cancel() = synchronized(lock) {
        cancelled = true
        if (control != 0L) Native.controlCancel(control)
    }

    private fun isCancelled(): Boolean = synchronized(lock) { cancelled }

    private fun key(relDir: List<String>, name: String): String = (relDir + name).joinToString("/").lowercase()

    private fun claim(relDir: List<String>, name: String): Boolean =
        synchronized(claimed) { claimed.add(key(relDir, name)) }

    /** Gives a name back when nothing was written under it, so that a later file may still use it. */
    private fun release(relDir: List<String>, name: String) {
        synchronized(claimed) { claimed.remove(key(relDir, name)) }
    }

    suspend fun run(onProgress: (Progress) -> Unit): Summary = withContext(Dispatchers.Default) {
        val started = SystemClock.elapsedRealtime()
        val handle = synchronized(lock) {
            control = Native.newControl()
            if (cancelled) Native.controlCancel(control)
            control
        }
        var encryptor = 0L
        var decryptor = 0L
        val files = AtomicInteger()
        val extraBytes = AtomicLong()
        try {
            onProgress(Progress(0, 0, preparing = true))
            when (request.mode) {
                Mode.ENCRYPT -> encryptor = Native.newEncryptor(request.password, request.recoveryPublic?.text)
                Mode.CHANGE -> {
                    // A recovery slot is carried over as it is: the new header needs no key for it.
                    encryptor = Native.newEncryptor(request.newPassword!!, null)
                    decryptor = Native.newDecryptor(request.password, request.recoveryKey)
                }
                // The key is derived when the first file is opened, and kept for the rest.
                Mode.DECRYPT, Mode.VERIFY -> decryptor = Native.newDecryptor(request.password, request.recoveryKey)
            }
            val outcomes = coroutineScope {
                val ticker = launch {
                    while (isActive) {
                        val bytes = Native.controlBytes(handle) + extraBytes.get()
                        onProgress(Progress(files.get(), bytes, preparing = bytes == 0L && files.get() == 0))
                        delay(100)
                    }
                }
                val workers = Dispatchers.IO.limitedParallelism(WORKERS)
                val results = request.items.map { item ->
                    async(workers) {
                        if (isCancelled()) return@async Outcome.Cancelled
                        val outcome = process(item, handle, encryptor, decryptor, extraBytes)
                        files.incrementAndGet()
                        outcome
                    }
                }.awaitAll()
                ticker.cancel()
                results
            }
            val failures = request.items.zip(outcomes).mapNotNull { (item, outcome) ->
                (outcome as? Outcome.Failed)?.let { Failure(item.name, it.code, it.detail) }
            }
            Summary(
                mode = request.mode,
                done = outcomes.count { it is Outcome.Done },
                skipped = outcomes.count { it is Outcome.Skipped },
                failures = failures,
                cancelled = isCancelled(),
                usedRecoveryKey = request.recoveryKey != null,
                bytes = Native.controlBytes(handle) + extraBytes.get(),
                millis = SystemClock.elapsedRealtime() - started,
                savedTo = request.targetLabel,
                installers = synchronized(installers) { installers.toList() },
                outputs = outcomes.mapNotNull { (it as? Outcome.Done)?.output },
                folder = request.target?.folder,
                recoveryId = request.recoveryPublic?.id.takeIf { request.mode == Mode.ENCRYPT },
            )
        } finally {
            synchronized(lock) {
                Native.freeControl(control)
                control = 0L
            }
            if (encryptor != 0L) Native.freeEncryptor(encryptor)
            if (decryptor != 0L) Native.freeDecryptor(decryptor)
        }
    }

    private fun process(item: Item, control: Long, encryptor: Long, decryptor: Long, extraBytes: AtomicLong): Outcome =
        try {
            when (request.mode) {
                Mode.ENCRYPT -> encrypt(item, control, encryptor, extraBytes)
                Mode.DECRYPT -> decrypt(item, control, decryptor)
                Mode.VERIFY -> {
                    Native.verify(decryptor, control, open(item).detachFd(), item.size)
                    Outcome.Done()
                }
                Mode.CHANGE -> change(item, control, encryptor, decryptor, extraBytes)
            }
        } catch (err: TopalException) {
            if (err.code == "cancelled") Outcome.Cancelled else Outcome.Failed(err.code, err.detail)
        } catch (err: Exception) {
            // The document provider refused, the storage is full, a file went away...
            if (isCancelled()) Outcome.Cancelled else Outcome.Failed("io", err.message ?: err.javaClass.simpleName)
        }

    private fun open(item: Item): ParcelFileDescriptor =
        resolver.openFileDescriptor(item.uri, "r") ?: throw IOException("Could not open ${item.name}")

    /** How an output is listed: with the folders it sits in below the output folder. */
    private fun shown(relDir: List<String>, name: String): String = (relDir + name).joinToString("/")

    private fun encrypt(item: Item, control: Long, encryptor: Long, extraBytes: AtomicLong): Outcome {
        val target = request.target!!
        val name = "${item.name}.$EXTENSION"
        if (!claim(item.relDir, name)) {
            extraBytes.addAndGet(item.size)
            return Outcome.Failed("output_exists", "")
        }
        if (target.exists(item.relDir, name)) {
            extraBytes.addAndGet(item.size)
            return Outcome.Skipped
        }
        val input = open(item)
        val pending = try {
            target.newFile(item.relDir, name)
        } catch (err: Exception) {
            input.close()
            throw err
        }
        try {
            val output = try {
                pending.detachFd()
            } catch (err: Exception) {
                input.close()
                throw err
            }
            Native.encrypt(encryptor, control, input.detachFd(), output, item.name, item.size)
            return Outcome.Done(Output(shown(item.relDir, name), pending.commit()))
        } catch (err: Exception) {
            pending.discard()
            release(item.relDir, name)
            throw err
        }
    }

    /** The name a decrypted file takes when the encrypted one does not carry a usable name. */
    private fun fallbackName(item: Item): String {
        val name = if (isTopal(item.name)) item.name.dropLast(EXTENSION.length + 1) else "${item.name}.decrypted"
        return if (Native.isSafeName(name)) name else "decrypted file"
    }

    private fun decrypt(item: Item, control: Long, decryptor: Long): Outcome {
        val target = request.target!!
        var file: PendingFile? = null
        var folder: PendingFolder? = null
        var claimedName: String? = null
        var installer: String? = null
        val sink = object : DecryptSink {
            override fun beginFile(name: String?): Int {
                val shown = fallbackName(item)
                val final = name ?: shown
                if (!claim(item.relDir, final)) throw TopalException("output_exists|")
                claimedName = final
                if (target.exists(item.relDir, final)) return -1
                if (!final.equals(shown, ignoreCase = true) && isInstaller(final)) installer = final
                return target.newFile(item.relDir, final).also { file = it }.detachFd()
            }

            override fun beginFolder(name: String?): Boolean {
                val final = name ?: fallbackName(item)
                if (!claim(item.relDir, final)) throw TopalException("output_exists|")
                claimedName = final
                // A folder is only ever unpacked into a new folder, never into an existing one.
                if (target.exists(item.relDir, final)) return false
                folder = target.newFolder(item.relDir, final)
                return true
            }

            override fun dir(rel: String) = folder!!.dir(rel)

            override fun file(rel: String): Int = folder!!.file(rel)
        }
        try {
            val written = Native.decrypt(decryptor, control, open(item).detachFd(), item.size, sink)
            if (!written) return Outcome.Skipped
            val address = file?.commit()
            folder?.commit()
            installer?.let { synchronized(installers) { installers += it } }
            val name = shown(item.relDir, claimedName!!)
            // A folder has no address of its own to share: it is listed, with a mark that tells it apart.
            return Outcome.Done(if (folder != null) Output("$name/", null) else Output(name, address))
        } catch (err: Throwable) {
            file?.discard()
            folder?.discard()
            claimedName?.let { release(item.relDir, it) }
            throw err
        }
    }

    /**
     * Rewrites the header of [item] in place. That needs the document open for writing,
     * which a shared file, or one from a provider that only lends copies, does not allow:
     * those are reported, and never touched.
     */
    private fun change(item: Item, control: Long, encryptor: Long, decryptor: Long, extraBytes: AtomicLong): Outcome {
        val file = try {
            resolver.openFileDescriptor(item.uri, "rw")
        } catch (_: Exception) {
            null
        }
        if (file == null) {
            extraBytes.addAndGet(item.size)
            // Tell a file that cannot be changed from one that cannot be reached at all.
            open(item).close()
            return Outcome.Failed("read_only", "")
        }
        val saved = File(context.filesDir, SAVED_HEADERS)
        Native.changePassword(encryptor, decryptor, control, file.detachFd(), item.size, saved.path, savedName(item.uri))
        return Outcome.Done()
    }

    private fun isInstaller(name: String): Boolean =
        name.substringAfterLast('.', "").lowercase() in INSTALLER_EXTENSIONS

    private companion object {
        /** What Android, or a common installer app, installs when the file is opened. */
        val INSTALLER_EXTENSIONS = setOf("apk", "apks", "apkm", "xapk")

        /** Files in flight at once. Storage, not the cipher, is what limits the speed. */
        val WORKERS = Runtime.getRuntime().availableProcessors().coerceIn(1, 4)

        /** Where the header of a file is kept while its password is being changed. */
        const val SAVED_HEADERS = "header-backups"

        /** A file name for the header saved for [uri]: its address says nothing once hashed. */
        fun savedName(uri: Uri): String =
            MessageDigest.getInstance("SHA-256").digest(uri.toString().toByteArray())
                .joinToString("") { "%02x".format(it) }
    }
}
