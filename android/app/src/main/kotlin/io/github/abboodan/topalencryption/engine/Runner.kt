package io.github.abboodan.topalencryption.engine

import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import io.github.abboodan.topalencryption.core.DecryptSink
import io.github.abboodan.topalencryption.core.Native
import io.github.abboodan.topalencryption.core.TopalException
import java.io.IOException
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
    val password: String,
    /** Opens files instead of the password when set. Decrypt and Verify only. */
    val recoveryKey: String?,
    /** `null` for Verify, which writes nothing. */
    val target: Target?,
    /** Shown in the results: where the outputs went. */
    val targetLabel: String?,
)

data class Failure(val name: String, val code: String, val detail: String)

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
) {
    /** Every file was refused for the same reason, [code]: nothing was opened at all. */
    fun allFailedWith(code: String): Boolean =
        done == 0 && skipped == 0 && failures.isNotEmpty() && failures.all { it.code == code }
}

data class Progress(val files: Int, val bytes: Long, val preparing: Boolean)

private sealed interface Outcome {
    data object Done : Outcome
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
            if (request.mode == Mode.ENCRYPT) {
                encryptor = Native.newEncryptor(request.password)
            } else {
                // The key is derived when the first file is opened, and kept for the rest.
                decryptor = Native.newDecryptor(request.password, request.recoveryKey)
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
                    Outcome.Done
                }
            }
        } catch (err: TopalException) {
            if (err.code == "cancelled") Outcome.Cancelled else Outcome.Failed(err.code, err.detail)
        } catch (err: Exception) {
            // The document provider refused, the storage is full, a file went away...
            if (isCancelled()) Outcome.Cancelled else Outcome.Failed("io", err.message ?: err.javaClass.simpleName)
        }

    private fun open(item: Item): ParcelFileDescriptor =
        resolver.openFileDescriptor(item.uri, "r") ?: throw IOException("Could not open ${item.name}")

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
            pending.commit()
        } catch (err: Exception) {
            pending.discard()
            release(item.relDir, name)
            throw err
        }
        return Outcome.Done
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
        val sink = object : DecryptSink {
            override fun beginFile(name: String?): Int {
                val final = name ?: fallbackName(item)
                if (!claim(item.relDir, final)) throw TopalException("output_exists|")
                claimedName = final
                if (target.exists(item.relDir, final)) return -1
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
            file?.commit()
            folder?.commit()
        } catch (err: Throwable) {
            file?.discard()
            folder?.discard()
            claimedName?.let { release(item.relDir, it) }
            throw err
        }
        return Outcome.Done
    }

    private companion object {
        /** Files in flight at once. Storage, not the cipher, is what limits the speed. */
        val WORKERS = Runtime.getRuntime().availableProcessors().coerceIn(1, 4)
    }
}
