package com.linkbridge.app.clipboard

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import com.linkbridge.app.data.LinkBridgeDatabase
import com.linkbridge.app.protocol.CryptoUtils
import com.linkbridge.app.protocol.ProtocolConstants
import com.linkbridge.app.protocol.TransportAdapter
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Android 9+ Clipboard Bridge Controller (`AndroidClipboardController.kt`).
 *
 * Respects Android 9 (API 28) & Android 10+ (API 29+) Clipboard Constraints:
 * - On Android 9 (API 28), `OnPrimaryClipChangedListener` works while the app or its foreground service is active,
 *   unless aggressive OEM battery savers freeze the process.
 * - On Android 10+ (API 29+), background apps cannot read the clipboard unless they are the default IME or have window focus.
 * - Therefore, LinkBridge NEVER uses AccessibilityService hacks. Instead, it provides three primary, rock-solid flows:
 *   1. Native System Share Sheet (`ACTION_SEND` text/links/code from any app directly to LinkBridge).
 *   2. Quick-Send button inside the persistent Foreground Notification & Main App screen (reads clipboard when tapped/focused).
 *   3. Optional automatic `OnPrimaryClipChangedListener` when supported by Android 9 or when window focus is gained.
 * - Implements strict loop prevention (`remoteOriginHashes`) and duplicate suppression (`seenItemIds`).
 */
class AndroidClipboardController(
    private val context: Context,
    private val localDeviceId: String,
    private val db: LinkBridgeDatabase
) {
    private val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val seenItemIds = ConcurrentHashMap.newKeySet<String>()
    private val remoteOriginHashes = ConcurrentHashMap<String, String>()
    @Volatile
    private var lastSentHash: String? = null

    fun computeTextHash(text: String): String {
        val normalized = text.replace("\r\n", "\n")
        return CryptoUtils.sha256Hex(normalized.toByteArray(StandardCharsets.UTF_8))
    }

    fun readCurrentClipboardText(): String? {
        if (!clipboardManager.hasPrimaryClip()) return null
        val item = clipboardManager.primaryClip?.getItemAt(0) ?: return null
        return item.coerceToText(context)?.toString()
    }

    fun sendTextNow(transport: TransportAdapter, text: String, mode: String = "MANUAL"): Boolean {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return false
        val maxKb = db.getSetting("max_text_size_kb", "512").toIntOrNull() ?: 512
        val rawBytes = trimmed.toByteArray(StandardCharsets.UTF_8)
        if (rawBytes.size > maxKb * 1024) {
            throw IllegalArgumentException("حجم النص يتجاوز الحد الأقصى المسموح به ($maxKb كيلوبايت)")
        }

        val contentHash = computeTextHash(trimmed)
        if (mode == "AUTO") {
            if (remoteOriginHashes.containsKey(contentHash) || contentHash == lastSentHash) {
                return false
            }
        }

        val itemId = "clip-" + UUID.randomUUID().toString().replace("-", "").take(16)
        val payload = JSONObject().apply {
            put("item_id", itemId)
            put("content_hash", contentHash)
            put("text", trimmed)
            put("origin_device_id", localDeviceId)
            put("timestamp", System.currentTimeMillis() / 1000.0)
            put("mode", mode)
        }
        transport.sendControl(ProtocolConstants.MSG_CLIPBOARD_PUSH, payload)
        transport.receiveReplyFrame()
        seenItemIds.add(itemId)
        lastSentHash = contentHash
        db.addClipboardItem(itemId, contentHash, trimmed, localDeviceId, "OUTGOING", transport.route.name)
        return true
    }

    fun handleIncomingClipboardPush(transport: TransportAdapter, body: JSONObject): Boolean {
        val itemId = body.optString("item_id", "")
        val text = body.optString("text", "")
        val expectedHash = body.optString("content_hash", "")
        val originDeviceId = body.optString("origin_device_id", "")

        if (itemId.isEmpty() || text.isEmpty() || originDeviceId == localDeviceId) {
            val ack = JSONObject().put("item_id", itemId).put("accepted", false)
            transport.sendControl(ProtocolConstants.MSG_CLIPBOARD_ACK, ack)
            return false
        }

        if (seenItemIds.contains(itemId)) {
            val ack = JSONObject().put("item_id", itemId).put("accepted", true).put("duplicate", true)
            transport.sendControl(ProtocolConstants.MSG_CLIPBOARD_ACK, ack)
            return true
        }

        val actualHash = computeTextHash(text)
        if (expectedHash.isNotEmpty() && !actualHash.equals(expectedHash, ignoreCase = true)) {
            val ack = JSONObject().put("item_id", itemId).put("accepted", false).put("reason", "SHA-256 mismatch")
            transport.sendControl(ProtocolConstants.MSG_CLIPBOARD_ACK, ack)
            return false
        }

        seenItemIds.add(itemId)
        remoteOriginHashes[actualHash] = originDeviceId

        val autoCopy = db.getSetting("auto_copy_received_to_clipboard", "false") == "true"
        if (autoCopy) {
            val clip = ClipData.newPlainText("LinkBridge", text)
            clipboardManager.setPrimaryClip(clip)
        }

        db.addClipboardItem(itemId, actualHash, text, originDeviceId, "INCOMING", transport.route.name)
        val ack = JSONObject()
            .put("item_id", itemId)
            .put("accepted", true)
            .put("duplicate", false)
            .put("copied_to_clipboard", autoCopy)
        transport.sendControl(ProtocolConstants.MSG_CLIPBOARD_ACK, ack)
        return true
    }

    fun getAndroidClipboardPlatformNote(): String {
        return if (Build.VERSION.SDK_INT == Build.VERSION_CODES.P) {
            "يعمل على Android 9 (API 28): المزامنة التلقائية متاحة أثناء تشغيل الخدمة، مع توفر المشاركة المباشرة وزر الإرسال السريع كمسارات أساسية موثوقة."
        } else {
            "يعمل على Android 10+: بسبب قيود الخصوصية في النظام، تُقرأ الحافظة عند فتح التطبيق أو الضغط على زر الإرسال السريع أو عبر قائمة المشاركة (Share)."
        }
    }
}
