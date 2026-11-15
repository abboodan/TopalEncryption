package io.github.abboodan.topalencryption.engine

import android.content.Context
import io.github.abboodan.topalencryption.core.Native
import java.io.File

/**
 * The public half of a recovery key: enough to add a recovery slot to the files that are
 * encrypted, and unable to open anything.
 */
data class RecoveryPublic(
    /** `XXXX-XXXX-XXXX-XXXX`, the ID the desktop app shows for the same key. */
    val id: String,
    /** `TOPAL-PUB-...` */
    val text: String,
)

/**
 * The recovery key in use, brought over from the PC. Only the public half is ever on the
 * phone, in the app's own storage, which other apps cannot read or replace; the secret
 * half stays wherever the user keeps it.
 */
object RecoveryStore {
    /** The same name as on the PC. */
    private const val FILE = "recovery-public.txt"

    private fun file(context: Context) = File(context.filesDir, FILE)

    /**
     * Checks a key, pasted or read from `recovery-public.txt`, and returns it with its ID.
     * Throws a `TopalException` with the code `invalid_recovery_key` for anything else.
     */
    fun parse(text: String): RecoveryPublic {
        val lines = Native.importRecoveryPublic(text).lines()
        return RecoveryPublic(lines[0], lines[1])
    }

    /** The key in use, or `null` if there is none. A stored key that no longer checks out counts as none. */
    fun load(context: Context): RecoveryPublic? = try {
        val file = file(context)
        if (file.isFile) parse(file.readText()) else null
    } catch (_: Exception) {
        null
    }

    fun save(context: Context, key: RecoveryPublic) {
        val file = file(context)
        val part = File(file.path + ".part")
        part.writeText(key.text + "\n")
        if (!part.renameTo(file)) {
            part.delete()
            throw java.io.IOException("Could not store the recovery key")
        }
    }

    /** Stops adding a recovery slot to new files. Files already encrypted keep theirs. */
    fun clear(context: Context) {
        file(context).delete()
    }
}
