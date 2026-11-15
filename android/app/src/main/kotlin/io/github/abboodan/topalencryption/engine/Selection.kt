package io.github.abboodan.topalencryption.engine

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.OpenableColumns
import java.io.File

enum class Mode { ENCRYPT, DECRYPT, VERIFY }

const val EXTENSION = "topal"

fun isTopal(name: String): Boolean = name.endsWith(".$EXTENSION", ignoreCase = true)

/** Something the user picked or shared: a single document, or a folder tree. */
sealed interface Root {
    val uri: Uri

    data class Document(override val uri: Uri) : Root
    data class Tree(override val uri: Uri) : Root
}

/** One file to process. */
data class Item(
    val uri: Uri,
    val name: String,
    /** In bytes; 0 when the provider does not say. */
    val size: Long,
    /** Where the file sits inside a picked folder, starting with that folder's name. Empty for a picked file. */
    val relDir: List<String>,
)

data class Scan(val items: List<Item>, val unreadable: Int) {
    val totalBytes: Long get() = items.sumOf { it.size }
}

object Scanner {
    /** Folders nested deeper than this are not walked, as on the desktop. */
    private const val MAX_DEPTH = 128
    private const val TEMP_PREFIX = ".topal-tmp-"

    /**
     * Expands [roots] into the work list. A file picked directly is always taken; inside
     * folders, encryption skips `.topal` files and the other modes take only them.
     */
    fun scan(context: Context, mode: Mode, roots: List<Root>): Scan {
        val resolver = context.contentResolver
        val items = ArrayList<Item>()
        var unreadable = 0
        for (root in roots) {
            when (root) {
                is Root.Document -> {
                    val described = describe(resolver, root.uri)
                    if (described == null) unreadable++ else items += Item(root.uri, described.first, described.second, emptyList())
                }
                is Root.Tree -> try {
                    val rootId = DocumentsContract.getTreeDocumentId(root.uri)
                    val top = treeName(resolver, root.uri)
                    unreadable += walk(resolver, mode, root.uri, rootId, listOf(top), items, 0)
                } catch (_: Exception) {
                    unreadable++
                }
            }
        }
        return Scan(items, unreadable)
    }

    /** The display name and size of a document, or `null` if it cannot be read. */
    fun describe(resolver: ContentResolver, uri: Uri): Pair<String, Long>? {
        if (uri.scheme == ContentResolver.SCHEME_FILE) {
            val file = File(uri.path ?: return null)
            return if (file.isFile) file.name to file.length() else null
        }
        return try {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                if (!cursor.moveToFirst()) return null
                val nameAt = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeAt = cursor.getColumnIndex(OpenableColumns.SIZE)
                val name = (if (nameAt >= 0) cursor.getString(nameAt) else null)
                    ?: uri.lastPathSegment?.substringAfterLast('/')
                    ?: return null
                val size = if (sizeAt >= 0 && !cursor.isNull(sizeAt)) cursor.getLong(sizeAt) else 0L
                name to size.coerceAtLeast(0)
            }
        } catch (_: Exception) {
            null
        }
    }

    /** The name of the folder a tree URI stands for. */
    fun treeName(resolver: ContentResolver, tree: Uri): String {
        val rootId = DocumentsContract.getTreeDocumentId(tree)
        val fallback = rootId.substringAfterLast('/').substringAfterLast(':').ifEmpty { rootId }
        return try {
            val uri = DocumentsContract.buildDocumentUriUsingTree(tree, rootId)
            resolver.query(uri, arrayOf(Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            } ?: fallback
        } catch (_: Exception) {
            fallback
        }
    }

    /** Returns how many folders could not be listed. */
    private fun walk(
        resolver: ContentResolver,
        mode: Mode,
        tree: Uri,
        dirId: String,
        relDir: List<String>,
        into: MutableList<Item>,
        depth: Int,
    ): Int {
        if (depth > MAX_DEPTH) return 1
        var unreadable = 0
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, dirId)
        val columns = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_SIZE,
        )
        val folders = ArrayList<Pair<String, String>>()
        try {
            resolver.query(children, columns, null, null, null)?.use { cursor ->
                while (cursor.moveToNext()) {
                    val id = cursor.getString(0) ?: continue
                    val name = cursor.getString(1) ?: continue
                    if (cursor.getString(2) == Document.MIME_TYPE_DIR) {
                        folders += id to name
                        continue
                    }
                    val wanted = if (mode == Mode.ENCRYPT) !isTopal(name) else isTopal(name)
                    if (!wanted || name.startsWith(TEMP_PREFIX)) continue
                    val size = if (cursor.isNull(3)) 0L else cursor.getLong(3)
                    into += Item(DocumentsContract.buildDocumentUriUsingTree(tree, id), name, size.coerceAtLeast(0), relDir)
                }
            } ?: return 1
        } catch (_: Exception) {
            return 1
        }
        for ((id, name) in folders) {
            unreadable += walk(resolver, mode, tree, id, relDir + name, into, depth + 1)
        }
        return unreadable
    }
}
