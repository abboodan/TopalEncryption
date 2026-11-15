package io.github.abboodan.topalencryption.core

/**
 * An error from the native library. [code] is a short stable name (`wrong_password`,
 * `corrupted`, `not_topal`, `cancelled`, `io`...), the same ones the desktop app uses;
 * [detail] is the English text of the error, useful for `io`.
 */
class TopalException(raw: String) : Exception(raw) {
    val code: String = raw.substringBefore('|')
    val detail: String = raw.substringAfter('|', "")
}

/**
 * Where decrypted content goes. Called by the native library on the decrypting thread,
 * after the password has been accepted and before anything is written.
 *
 * Names come out of the encrypted file: they are passed only if they are safe to use as
 * a single file name, and are `null` otherwise or when the file records none. Paths given
 * to [dir] and [file] are `/` separated and every part has passed the same check.
 *
 * Descriptors returned must be detached: the native library closes them.
 */
interface DecryptSink {
    /** The encrypted file holds one file. Returns a descriptor to write it to, or -1 to skip. */
    fun beginFile(name: String?): Int

    /** The encrypted file holds a whole folder. Returns `false` to skip it. */
    fun beginFolder(name: String?): Boolean

    /** Creates a folder inside the folder being unpacked. */
    fun dir(rel: String)

    /** Creates a file inside the folder being unpacked, and returns a descriptor to write it to. */
    fun file(rel: String): Int
}

/**
 * `topal-core`, through the bridge in `android/rust`. Every function blocks; none may be
 * called on the main thread except the last four.
 *
 * Handles are freed exactly once, after every call using them has returned. Descriptors
 * passed in must be detached (`ParcelFileDescriptor.detachFd`): the call closes them.
 */
object Native {
    init {
        System.loadLibrary("topal_android")
    }

    /**
     * Derives the key for a batch: about a second and 256 MiB. With [recoveryPublic], the
     * public half of a recovery key, every file encrypted also gets a recovery slot.
     */
    external fun newEncryptor(password: String, recoveryPublic: String?): Long
    external fun freeEncryptor(handle: Long)

    /** With [recoveryKey], files are opened with it and [password] is ignored. */
    external fun newDecryptor(password: String, recoveryKey: String?): Long
    external fun freeDecryptor(handle: Long)

    /** A byte counter and a cancel switch shared by the items of one batch. */
    external fun newControl(): Long
    external fun controlBytes(handle: Long): Long
    external fun controlCancel(handle: Long)
    external fun freeControl(handle: Long)

    /** Returns the number of plaintext bytes. [size] is the input's size, 0 if unknown. */
    external fun encrypt(encryptor: Long, control: Long, input: Int, output: Int, name: String, size: Long): Long

    /** Returns `false` if [sink] chose to skip the file. */
    external fun decrypt(decryptor: Long, control: Long, input: Int, size: Long, sink: DecryptSink): Boolean

    external fun verify(decryptor: Long, control: Long, input: Int, size: Long)

    /**
     * Gives the document behind [file], open for reading and writing, the password of
     * [encryptor]; [decryptor] holds what opens it now. Only its header is rewritten. The
     * header being replaced is kept in [savedDir] under [key] until the new one is in place.
     */
    external fun changePassword(encryptor: Long, decryptor: Long, control: Long, file: Int, size: Long, savedDir: String, key: String)

    external fun generatePassphrase(): String
    external fun isRecoveryKey(text: String): Boolean

    /**
     * Checks the public half of a recovery key, pasted or read from `recovery-public.txt`.
     * Returns its ID and its canonical text on two lines; throws `invalid_recovery_key`.
     */
    external fun importRecoveryPublic(text: String): String
    external fun isSafeName(name: String): Boolean
}
