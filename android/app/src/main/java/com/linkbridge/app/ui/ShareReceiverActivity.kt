package com.linkbridge.app.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.linkbridge.app.clipboard.AndroidClipboardController
import com.linkbridge.app.data.LinkBridgeDatabase
import com.linkbridge.app.files.SafFileTransferController
import kotlin.concurrent.thread

/**
 * Native Android System Share Target (`ShareReceiverActivity.kt`).
 * Receives `ACTION_SEND` (text, URLs, code snippets, notes, or single file) and `ACTION_SEND_MULTIPLE` (multiple files)
 * from any Android app and transmits them over the active LinkBridge connection immediately.
 */
class ShareReceiverActivity : AppCompatActivity() {

    @Suppress("DEPRECATION")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val transport = MainActivity.activeTransport
        if (transport == null || !transport.isConnected) {
            Toast.makeText(this, "LinkBridge غير متصل حاليًا؛ يرجى فتح التطبيق للاتصال بالكمبيوتر أولًا", Toast.LENGTH_LONG).show()
            finish()
            return
        }

        val db = LinkBridgeDatabase(this)
        val deviceId = db.getSetting("device_id", "lb-android")
        val clipCtrl = AndroidClipboardController(this, deviceId, db)
        val fileCtrl = SafFileTransferController(this, db)

        when (intent?.action) {
            Intent.ACTION_SEND -> {
                val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
                val sharedStream = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
                thread {
                    try {
                        if (!sharedText.isNullOrBlank()) {
                            clipCtrl.sendTextNow(transport, sharedText, mode = "MANUAL")
                        } else if (sharedStream != null) {
                            fileCtrl.sendUriFile(transport, sharedStream)
                        }
                        runOnUiThread {
                            Toast.makeText(this, "تم الإرسال عبر LinkBridge بنجاح", Toast.LENGTH_SHORT).show()
                            finish()
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            Toast.makeText(this, "فشل الإرسال: ${e.message}", Toast.LENGTH_LONG).show()
                            finish()
                        }
                    }
                }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val uris = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM) ?: emptyList()
                thread {
                    try {
                        for (u in uris) {
                            fileCtrl.sendUriFile(transport, u)
                        }
                        runOnUiThread {
                            Toast.makeText(this, "تم إرسال ${uris.size} ملفات عبر LinkBridge", Toast.LENGTH_SHORT).show()
                            finish()
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            Toast.makeText(this, "فشل إرسال الملفات: ${e.message}", Toast.LENGTH_LONG).show()
                            finish()
                        }
                    }
                }
            }
            else -> finish()
        }
    }
}
