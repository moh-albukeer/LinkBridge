package com.linkbridge.app.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class LinkBridgeDatabase(context: Context) :
    SQLiteOpenHelper(context, "linkbridge_android.db", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS paired_devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                link_key_hex TEXT NOT NULL,
                last_ip TEXT DEFAULT '',
                bt_mac TEXT DEFAULT '',
                updated_at INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS clipboard_history (
                item_id TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                text_content TEXT NOT NULL,
                origin_device_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                transport TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS file_transfers (
                transfer_id INTEGER PRIMARY KEY,
                file_name TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                transferred_bytes INTEGER NOT NULL,
                expected_sha256 TEXT NOT NULL,
                direction TEXT NOT NULL,
                transport TEXT NOT NULL,
                status TEXT NOT NULL,
                temp_path TEXT DEFAULT '',
                saved_uri TEXT DEFAULT '',
                updated_at INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {}

    fun getSetting(key: String, defaultVal: String): String {
        readableDatabase.rawQuery("SELECT value FROM settings WHERE key = ?", arrayOf(key)).use { c ->
            return if (c.moveToFirst()) c.getString(0) else defaultVal
        }
    }

    fun setSetting(key: String, value: String) {
        val cv = ContentValues().apply {
            put("key", key)
            put("value", value)
        }
        writableDatabase.insertWithOnConflict("settings", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun savePairedDevice(deviceId: String, deviceName: String, fingerprint: String, linkKeyHex: String) {
        val cv = ContentValues().apply {
            put("device_id", deviceId)
            put("device_name", deviceName)
            put("fingerprint", fingerprint)
            put("link_key_hex", linkKeyHex)
            put("updated_at", System.currentTimeMillis())
        }
        writableDatabase.insertWithOnConflict("paired_devices", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun getPairedDeviceLinkKeyHex(deviceId: String, expectedFingerprint: String): String? {
        readableDatabase.rawQuery(
            "SELECT fingerprint, link_key_hex FROM paired_devices WHERE device_id = ?",
            arrayOf(deviceId)
        ).use { c ->
            if (!c.moveToFirst()) return null
            val savedFp = c.getString(0)
            val keyHex = c.getString(1)
            if (!savedFp.equals(expectedFingerprint, ignoreCase = true)) {
                throw SecurityException("تحذير أمني: تغيرت بصمة شهادة الكمبيوتر المقترن!")
            }
            return keyHex
        }
    }

    fun addClipboardItem(
        itemId: String,
        contentHash: String,
        text: String,
        originDeviceId: String,
        direction: String,
        transport: String
    ) {
        if (getSetting("save_clipboard_history", "true") != "true") return
        val cv = ContentValues().apply {
            put("item_id", itemId)
            put("content_hash", contentHash)
            put("text_content", text)
            put("origin_device_id", originDeviceId)
            put("direction", direction)
            put("transport", transport)
            put("created_at", System.currentTimeMillis())
        }
        writableDatabase.insertWithOnConflict("clipboard_history", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun listRecentClipboardItems(limit: Int = 30): List<String> {
        val list = mutableListOf<String>()
        readableDatabase.rawQuery(
            "SELECT direction, text_content FROM clipboard_history ORDER BY created_at DESC LIMIT ?",
            arrayOf(limit.toString())
        ).use { c ->
            while (c.moveToNext()) {
                val dir = if (c.getString(0) == "INCOMING") "⬅ وارد" else "➡ مرسل"
                val txt = c.getString(1).replace("\n", " ").take(80)
                list.add("[$dir] $txt")
            }
        }
        return list
    }

    fun clearClipboardHistory() {
        writableDatabase.delete("clipboard_history", null, null)
    }
}
