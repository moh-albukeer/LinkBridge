package com.linkbridge.app.files

import android.content.Context
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Environment
import android.provider.OpenableColumns
import androidx.documentfile.provider.DocumentFile
import com.linkbridge.app.data.LinkBridgeDatabase
import com.linkbridge.app.protocol.ProtocolConstants
import com.linkbridge.app.protocol.TransportAdapter
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.SecureRandom

class SafFileTransferController(
    private val context: Context,
    private val db: LinkBridgeDatabase
) {
    private val random = SecureRandom()

    fun sanitizeFileName(rawName: String): String {
        if (rawName.isBlank() || rawName.contains("\u0000") || rawName.contains("..")) {
            throw SecurityException("اسم ملف غير آمن تم رفضه: $rawName")
        }
        val clean = rawName.substringAfterLast('/').substringAfterLast('\\')
            .replace(Regex("[<>:\"|?*\\x00-\\x1F]"), "_")
        if (clean.isBlank() || clean == "." || clean == "..") {
            throw SecurityException("اسم ملف غير صالح بعد التنظيف")
        }
        return clean
    }

    fun getDefaultReceiveFolder(): File {
        return try {
            @Suppress("DEPRECATION")
            val pubDl = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "LinkBridge")
            if (pubDl.exists() || pubDl.mkdirs()) {
                pubDl
            } else {
                val appDl = File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: context.filesDir, "LinkBridge")
                appDl.mkdirs()
                appDl
            }
        } catch (_: Exception) {
            val fallback = File(context.getExternalFilesDir(null) ?: context.filesDir, "LinkBridge")
            fallback.mkdirs()
            fallback
        }
    }

    fun queryUriMetadata(uri: Uri): Pair<String, Long> {
        var name = "shared_file.bin"
        var size = 0L
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (cursor.moveToFirst()) {
                if (nameIdx >= 0) name = cursor.getString(nameIdx) ?: name
                if (sizeIdx >= 0) size = cursor.getLong(sizeIdx)
            }
        }
        return Pair(sanitizeFileName(name), size)
    }

    fun computeUriSha256(uri: Uri, chunkSize: Int): String {
        val md = MessageDigest.getInstance("SHA-256")
        context.contentResolver.openInputStream(uri)?.use { input ->
            val buf = ByteArray(chunkSize)
            while (true) {
                val read = input.read(buf)
                if (read <= 0) break
                md.update(buf, 0, read)
            }
        } ?: throw IllegalArgumentException("تعذر فتح الملف لحساب البصمة SHA-256")
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun sendUriFile(
        transport: TransportAdapter,
        uri: Uri,
        existingTransferId: Long? = null,
        onProgress: ((Long, Long) -> Unit)? = null
    ): Boolean {
        val (fileName, totalBytes) = queryUriMetadata(uri)
        val sha256 = computeUriSha256(uri, transport.chunkSize)
        val transferId = existingTransferId ?: (Math.abs(random.nextLong()) shr 16)

        val offer = JSONObject().apply {
            put("transfer_id", transferId)
            put("file_name", fileName)
            put("rel_path", fileName)
            put("total_bytes", totalBytes)
            put("sha256", sha256)
            put("chunk_size", transport.chunkSize)
        }
        transport.sendControl(ProtocolConstants.MSG_FILE_OFFER, offer, transferId = transferId)

        val resp = transport.receiveReplyFrame()
        if (resp.header.msgType == ProtocolConstants.MSG_FILE_REJECT) {
            return false
        }
        if (resp.header.msgType != ProtocolConstants.MSG_FILE_ACCEPT) {
            throw IllegalStateException("Expected FILE_ACCEPT from peer")
        }
        val resumeOffset = resp.jsonBody().optLong("resume_offset", 0L).coerceAtLeast(0L)

        var sentBytes = resumeOffset
        context.contentResolver.openInputStream(uri)?.use { input ->
            if (resumeOffset > 0) {
                input.skip(resumeOffset)
            }
            val buf = ByteArray(transport.chunkSize)
            while (sentBytes < totalBytes) {
                val n = input.read(buf)
                if (n <= 0) break
                val slice = if (n == buf.size) buf else buf.copyOf(n)
                transport.sendChunk(slice, transferId = transferId)
                sentBytes += n
                onProgress?.invoke(sentBytes, totalBytes)
            }
        }

        val complete = JSONObject().apply {
            put("transfer_id", transferId)
            put("total_bytes", totalBytes)
            put("sha256", sha256)
        }
        transport.sendControl(ProtocolConstants.MSG_FILE_COMPLETE, complete, transferId = transferId)

        val verifyResp = transport.receiveReplyFrame()
        return verifyResp.header.msgType == ProtocolConstants.MSG_FILE_VERIFY_RESULT &&
            verifyResp.jsonBody().optBoolean("verified", false)
    }

    /**
     * Receives an incoming file directly into `Download/LinkBridge` (or optional SAF folder),
     * verifies full SHA-256 and byte size, resolves duplicate filenames safely (`file (1).ext`),
     * and notifies Android MediaScanner so the file appears immediately in Downloads & Gallery!
     */
    fun receiveFile(
        transport: TransportAdapter,
        offerBody: JSONObject,
        transferId: Long,
        targetSafDirectory: DocumentFile? = null,
        onProgress: ((Long, Long) -> Unit)? = null
    ): String? {
        val rawName = offerBody.optString("file_name", "")
        val safeName = try {
            sanitizeFileName(rawName)
        } catch (e: SecurityException) {
            val rej = JSONObject().put("transfer_id", transferId).put("reason", e.message)
            transport.sendControl(ProtocolConstants.MSG_FILE_REJECT, rej, transferId)
            return null
        }

        val totalBytes = offerBody.optLong("total_bytes", -1L)
        val expectedSha256 = offerBody.optString("sha256", "").lowercase()
        val tempFile = File(context.cacheDir, ".lb_${transferId}_${safeName}.lbpart")
        val resumeOffset = if (tempFile.exists() && tempFile.length() in 1..totalBytes) tempFile.length() else 0L
        if (resumeOffset == 0L && tempFile.exists()) tempFile.delete()

        val accept = JSONObject().put("transfer_id", transferId).put("resume_offset", resumeOffset)
        transport.sendControl(ProtocolConstants.MSG_FILE_ACCEPT, accept, transferId)

        var received = resumeOffset
        FileOutputStream(tempFile, resumeOffset > 0).use { fos ->
            while (true) {
                val frame = transport.receiveFrame(maxPayloadBytes = maxOf(transport.chunkSize * 2, 131072))
                when (frame.header.msgType) {
                    ProtocolConstants.MSG_FILE_CHUNK -> {
                        fos.write(frame.payload)
                        received += frame.payload.size
                        onProgress?.invoke(received, totalBytes)
                    }
                    ProtocolConstants.MSG_FILE_COMPLETE -> break
                    ProtocolConstants.MSG_FILE_CANCEL -> {
                        fos.close()
                        tempFile.delete()
                        return null
                    }
                    else -> throw IllegalStateException("Unexpected frame during receive: ${frame.header.msgType}")
                }
            }
        }

        val md = MessageDigest.getInstance("SHA-256")
        FileInputStream(tempFile).use { fis ->
            val buf = ByteArray(65536)
            while (true) {
                val n = fis.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        val actualSha256 = md.digest().joinToString("") { "%02x".format(it) }
        if (tempFile.length() != totalBytes || actualSha256 != expectedSha256) {
            tempFile.delete()
            val vFail = JSONObject().put("transfer_id", transferId).put("verified", false)
                .put("reason", "SHA-256 or byte size mismatch")
            transport.sendControl(ProtocolConstants.MSG_FILE_VERIFY_RESULT, vFail, transferId)
            return null
        }

        val dotIdx = safeName.lastIndexOf('.')
        val stem = if (dotIdx > 0) safeName.substring(0, dotIdx) else safeName
        val ext = if (dotIdx > 0) safeName.substring(dotIdx) else ""

        var finalSavedPath = safeName
        if (targetSafDirectory != null && targetSafDirectory.uri.scheme == "content") {
            var finalName = safeName
            var counter = 1
            while (targetSafDirectory.findFile(finalName) != null) {
                finalName = "$stem ($counter)$ext"
                counter++
            }
            val docFile = targetSafDirectory.createFile("application/octet-stream", finalName)
                ?: throw IllegalStateException("تعذر إنشاء الملف داخل مجلد SAF")
            context.contentResolver.openOutputStream(docFile.uri)?.use { out ->
                FileInputStream(tempFile).use { fis -> fis.copyTo(out, bufferSize = 65536) }
            }
            finalSavedPath = finalName
        } else {
            val destFolder = getDefaultReceiveFolder()
            var destFile = File(destFolder, safeName)
            var counter = 1
            while (destFile.exists()) {
                destFile = File(destFolder, "$stem ($counter)$ext")
                counter++
            }
            FileInputStream(tempFile).use { fis ->
                FileOutputStream(destFile).use { fos ->
                    fis.copyTo(fos, bufferSize = 65536)
                }
            }
            finalSavedPath = destFile.absolutePath
            try {
                MediaScannerConnection.scanFile(context, arrayOf(destFile.absolutePath), null, null)
            } catch (_: Exception) {
            }
        }
        tempFile.delete()

        val vOk = JSONObject().put("transfer_id", transferId).put("verified", true).put("saved_name", finalSavedPath)
        transport.sendControl(ProtocolConstants.MSG_FILE_VERIFY_RESULT, vOk, transferId)
        return finalSavedPath
    }
}
