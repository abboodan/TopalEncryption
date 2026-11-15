package io.github.abboodan.topalencryption.engine

import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.MediaStore
import android.provider.MediaStore.MediaColumns
import android.webkit.MimeTypeMap
import java.io.File
import java.io.IOException

/**
 * Where results are written. Nothing is ever replaced: a name that is taken is either
 * reported through [exists] before writing (the item is then skipped), or, if it appears
 * in between or belongs to another app, Android gives the new file a numbered name.
 *
 * An output only gets its real name when it is committed. Until then it is hidden
 * (MediaStore) or carries a `.topal-part` name (a picked folder), so that a cancelled or
 * failed item, or a killed app, never leaves something that looks complete.
 */
interface Target {
    /** Whether something called [name] is already in [relDir]. */
    fun exists(relDir: List<String>, name: String): Boolean

    fun newFile(relDir: List<String>, name: String): PendingFile

    /** A new folder for the content of a folder container. */
    fun newFolder(relDir: List<String>, name: String): PendingFolder
}

interface PendingFile {
    /** A detached descriptor to write the content to. */
    fun detachFd(): Int
    fun commit()
    fun discard()
}

interface PendingFolder {
    /** Creates the folder at the `/` separated path [rel]. */
    fun dir(rel: String)

    /** Creates the file at [rel] and returns a detached descriptor to write it to. */
    fun file(rel: String): Int
    fun commit()
    fun discard()
}

/** The type Android expects for [name], so that it leaves the extension alone. */
internal fun mimeOf(name: String): String {
    val extension = name.substringAfterLast('.', "").lowercase()
    return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension) ?: "application/octet-stream"
}

private fun detach(resolver: ContentResolver, uri: Uri): Int =
    (resolver.openFileDescriptor(uri, "w") ?: throw IOException("Could not open the output")).detachFd()

/** The default: `Download/Topal Encryption` on the shared storage, through MediaStore. */
class MediaStoreTarget(context: Context) : Target {
    private val resolver = context.contentResolver
    private val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)

    private fun relativePath(relDir: List<String>): String =
        (listOf(Environment.DIRECTORY_DOWNLOADS, FOLDER) + relDir).joinToString("/", postfix = "/")

    private fun directory(relDir: List<String>): File =
        File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), (listOf(FOLDER) + relDir).joinToString("/"))

    override fun exists(relDir: List<String>, name: String): Boolean {
        if (File(directory(relDir), name).exists()) return true
        val selection = "${MediaColumns.RELATIVE_PATH}=? AND ${MediaColumns.DISPLAY_NAME}=?"
        return resolver.query(collection, arrayOf(MediaColumns._ID), selection, arrayOf(relativePath(relDir), name), null)
            ?.use { it.count > 0 } ?: false
    }

    private fun insertPending(relDir: List<String>, name: String): Uri {
        val values = ContentValues().apply {
            put(MediaColumns.DISPLAY_NAME, name)
            put(MediaColumns.MIME_TYPE, mimeOf(name))
            put(MediaColumns.RELATIVE_PATH, relativePath(relDir))
            put(MediaColumns.IS_PENDING, 1)
        }
        return resolver.insert(collection, values) ?: throw IOException("Could not create $name")
    }

    /**
     * Removes the folders MediaStore created for an output that was then discarded, as
     * long as they are empty, so that a failed item leaves nothing at all behind.
     */
    private fun pruneEmpty(relDir: List<String>) {
        for (depth in relDir.size downTo 1) {
            // Deleting a folder only succeeds when nothing is in it.
            if (!directory(relDir.subList(0, depth)).delete()) return
        }
    }

    private fun publish(uri: Uri) {
        val values = ContentValues().apply { put(MediaColumns.IS_PENDING, 0) }
        if (resolver.update(uri, values, null, null) != 1) throw IOException("Could not finish the output")
    }

    override fun newFile(relDir: List<String>, name: String): PendingFile {
        val uri = insertPending(relDir, name)
        return object : PendingFile {
            override fun detachFd(): Int = detach(resolver, uri)
            override fun commit() = publish(uri)
            override fun discard() {
                runCatching { resolver.delete(uri, null, null) }
                runCatching { pruneEmpty(relDir) }
            }
        }
    }

    override fun newFolder(relDir: List<String>, name: String): PendingFolder {
        val base = relDir + name
        val root = directory(base)
        // Creating it first is what takes the name: it fails if anything is already there.
        if (!root.mkdirs()) throw IOException("Could not create the folder $name")
        val files = ArrayList<Uri>()
        return object : PendingFolder {
            override fun dir(rel: String) {
                val dir = File(root, rel)
                if (!dir.isDirectory && !dir.mkdirs()) throw IOException("Could not create a folder")
            }

            override fun file(rel: String): Int {
                val parts = rel.split('/')
                val uri = insertPending(base + parts.dropLast(1), parts.last())
                files += uri
                return detach(resolver, uri)
            }

            override fun commit() = files.forEach(::publish)

            override fun discard() {
                for (uri in files) runCatching { resolver.delete(uri, null, null) }
                runCatching { root.deleteRecursively() }
                runCatching { pruneEmpty(relDir) }
            }
        }
    }

    /**
     * Removes hidden, unfinished outputs that a killed run left behind: when decrypting
     * they hold plaintext. Only this app's own files are visible to it.
     */
    fun removeLeftovers() {
        runCatching {
            val args = android.os.Bundle().apply {
                putString(ContentResolver.QUERY_ARG_SQL_SELECTION, "${MediaColumns.IS_PENDING}=1 AND ${MediaColumns.RELATIVE_PATH} LIKE ?")
                putStringArray(ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS, arrayOf(relativePath(emptyList()) + "%"))
                putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_ONLY)
            }
            val stale = ArrayList<Uri>()
            resolver.query(collection, arrayOf(MediaColumns._ID), args, null)?.use { cursor ->
                while (cursor.moveToNext()) stale += android.content.ContentUris.withAppendedId(collection, cursor.getLong(0))
            }
            for (uri in stale) runCatching { resolver.delete(uri, null, null) }
        }
    }

    companion object {
        const val FOLDER = "Topal Encryption"
    }
}

/** A folder the user picked with the system folder picker. */
class TreeTarget(context: Context, private val tree: Uri) : Target {
    private val resolver = context.contentResolver
    private val rootId = DocumentsContract.getTreeDocumentId(tree)

    /** Folders of the tree that have been looked up or created, by path. */
    private val dirs = HashMap<List<String>, String>()

    /** The names inside folders that have been listed, lower-cased, kept up to date with what is created here. */
    private val listings = HashMap<String, MutableMap<String, String>>()

    /** Folders this run created, as opposed to ones that were already there. */
    private val createdDirs = HashSet<String>()

    private fun uriOf(id: String): Uri = DocumentsContract.buildDocumentUriUsingTree(tree, id)

    /** Lower-cased names to document IDs of what is inside the folder [dirId]. */
    private fun listing(dirId: String): MutableMap<String, String> = listings.getOrPut(dirId) {
        val names = HashMap<String, String>()
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, dirId)
        resolver.query(children, arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                val name = cursor.getString(1) ?: continue
                names[name.lowercase()] = cursor.getString(0)
            }
        }
        names
    }

    private fun create(dirId: String, mime: String, name: String): Uri {
        val uri = DocumentsContract.createDocument(resolver, uriOf(dirId), mime, name)
            ?: throw IOException("Could not create $name")
        listing(dirId)[name.lowercase()] = DocumentsContract.getDocumentId(uri)
        return uri
    }

    /** The document ID of the folder at [relDir], created if [create] is set, else `null` if missing. */
    private fun dir(relDir: List<String>, create: Boolean, from: String = rootId, cache: MutableMap<List<String>, String> = dirs): String? {
        var id = from
        for (depth in relDir.indices) {
            val path = relDir.subList(0, depth + 1)
            id = cache[path] ?: run {
                val found = listing(id)[relDir[depth].lowercase()]
                    ?: if (create) {
                        DocumentsContract.getDocumentId(create(id, Document.MIME_TYPE_DIR, relDir[depth])).also { createdDirs += it }
                    } else {
                        return null
                    }
                cache[path.toList()] = found
                found
            }
        }
        return id
    }

    /**
     * Removes the folders this run created for an output that was then discarded, as
     * long as they are empty, so that a failed item leaves nothing behind. Folders that
     * existed before are never touched.
     */
    @Synchronized
    private fun pruneEmpty(relDir: List<String>) {
        for (depth in relDir.size downTo 1) {
            val path = relDir.subList(0, depth).toList()
            val id = dirs[path] ?: return
            if (id !in createdDirs) return
            val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, id)
            val empty = resolver.query(children, arrayOf(Document.COLUMN_DOCUMENT_ID), null, null, null)?.use { it.count == 0 }
            if (empty != true) return
            if (!DocumentsContract.deleteDocument(resolver, uriOf(id))) return
            createdDirs -= id
            dirs.remove(path)
            listings.remove(id)
            val parent = if (depth == 1) rootId else dirs[relDir.subList(0, depth - 1)] ?: return
            listings[parent]?.remove(relDir[depth - 1].lowercase())
        }
    }

    private fun canRename(uri: Uri): Boolean = runCatching {
        resolver.query(uri, arrayOf(Document.COLUMN_FLAGS), null, null, null)?.use { cursor ->
            cursor.moveToFirst() && cursor.getInt(0) and Document.FLAG_SUPPORTS_RENAME != 0
        }
    }.getOrNull() ?: false

    /**
     * Creates [name] in [dirId] under a temporary name, to be renamed by [rename] when it
     * is complete. Providers that cannot rename get the final name straight away.
     */
    private fun createPart(dirId: String, mime: String, name: String): Pair<Uri, Boolean> {
        val partMime = if (mime == Document.MIME_TYPE_DIR) mime else "application/octet-stream"
        val part = create(dirId, partMime, name + PART_SUFFIX)
        if (canRename(part)) return part to true
        DocumentsContract.deleteDocument(resolver, part)
        return create(dirId, mime, name) to false
    }

    private fun rename(dirId: String, part: Uri, name: String) {
        DocumentsContract.renameDocument(resolver, part, name) ?: throw IOException("Could not finish the output")
        synchronized(this) { listing(dirId)[name.lowercase()] = "" }
    }

    @Synchronized
    override fun exists(relDir: List<String>, name: String): Boolean {
        val dirId = dir(relDir, create = false) ?: return false
        return listing(dirId).containsKey(name.lowercase())
    }

    @Synchronized
    override fun newFile(relDir: List<String>, name: String): PendingFile {
        val dirId = dir(relDir, create = true)!!
        val (uri, part) = createPart(dirId, mimeOf(name), name)
        return object : PendingFile {
            override fun detachFd(): Int = detach(resolver, uri)
            override fun commit() {
                if (part) rename(dirId, uri, name)
            }

            override fun discard() {
                runCatching { DocumentsContract.deleteDocument(resolver, uri) }
                runCatching { pruneEmpty(relDir) }
            }
        }
    }

    @Synchronized
    override fun newFolder(relDir: List<String>, name: String): PendingFolder {
        val parentId = dir(relDir, create = true)!!
        val (top, part) = createPart(parentId, Document.MIME_TYPE_DIR, name)
        val topId = DocumentsContract.getDocumentId(top)
        val inside = HashMap<List<String>, String>()
        return object : PendingFolder {
            private fun folder(parts: List<String>): String =
                synchronized(this@TreeTarget) { dir(parts, create = true, from = topId, cache = inside)!! }

            override fun dir(rel: String) {
                folder(rel.split('/'))
            }

            override fun file(rel: String): Int {
                val parts = rel.split('/')
                val dirId = folder(parts.dropLast(1))
                val uri = synchronized(this@TreeTarget) { create(dirId, mimeOf(parts.last()), parts.last()) }
                return detach(resolver, uri)
            }

            override fun commit() {
                if (part) rename(parentId, top, name)
            }

            override fun discard() {
                runCatching { DocumentsContract.deleteDocument(resolver, top) }
                runCatching { pruneEmpty(relDir) }
            }
        }
    }

    companion object {
        const val PART_SUFFIX = ".topal-part"
    }
}
