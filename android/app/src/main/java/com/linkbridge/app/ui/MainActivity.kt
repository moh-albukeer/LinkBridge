package com.linkbridge.app.ui

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.documentfile.provider.DocumentFile
import com.linkbridge.app.R
import com.linkbridge.app.clipboard.AndroidClipboardController
import com.linkbridge.app.data.LinkBridgeDatabase
import com.linkbridge.app.files.SafFileTransferController
import com.linkbridge.app.protocol.AndroidAutoDiscoveryEngine
import com.linkbridge.app.protocol.AndroidDeviceIdentity
import com.linkbridge.app.protocol.BluetoothRfcommTransportAdapter
import com.linkbridge.app.protocol.DiscoveredDevice
import com.linkbridge.app.protocol.ProtocolConstants
import com.linkbridge.app.protocol.ProtocolFrame
import com.linkbridge.app.protocol.TransportAdapter
import com.linkbridge.app.protocol.TransportRoute
import com.linkbridge.app.protocol.WifiTlsTransportAdapter
import com.linkbridge.app.service.LinkBridgeForegroundService
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    companion object {
        private const val REQ_PICK_FILES = 1001
        private const val REQ_PICK_SAVE_FOLDER = 1002
        private const val REQ_RUNTIME_PERMS = 1003
        private const val APPROVAL_CHANNEL_ID = "linkbridge_approval_alerts"
        @Volatile
        var activeTransport: TransportAdapter? = null
    }

    private lateinit var db: LinkBridgeDatabase
    private lateinit var identity: AndroidDeviceIdentity
    private lateinit var clipboardController: AndroidClipboardController
    private lateinit var fileController: SafFileTransferController
    private lateinit var discoveryEngine: AndroidAutoDiscoveryEngine
    private var selectedSaveTreeUri: Uri? = null
    private var isDarkTheme: Boolean = true

    private lateinit var rootScroll: ScrollView
    private lateinit var tvStatusBadge: TextView
    private lateinit var tvLocalInfo: TextView
    private lateinit var btnDisconnect: Button
    private lateinit var devicesListContainer: LinearLayout
    private lateinit var etTextToSend: EditText
    private lateinit var progressBar: ProgressBar
    private lateinit var tvTransferProgress: TextView
    private lateinit var historyItemsContainer: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()

        db = LinkBridgeDatabase(this)
        if (db.getSetting("init_v1_defaults", "") == "") {
            db.setSetting("auto_copy_received_to_clipboard", "true")
            db.setSetting("init_v1_defaults", "done")
        }
        isDarkTheme = db.getSetting("ui_dark_theme", "true") == "true"

        identity = AndroidDeviceIdentity.loadOrCreate(db)
        clipboardController = AndroidClipboardController(this, identity.deviceId, db)
        fileController = SafFileTransferController(this, db)

        val savedUriStr = db.getSetting("saf_receive_tree_uri", "")
        if (savedUriStr.isNotEmpty()) {
            selectedSaveTreeUri = Uri.parse(savedUriStr)
        }

        createNotificationChannel()
        requestModernAndroidPermissionsIfNeeded()
        buildModernCardUi()

        discoveryEngine = AndroidAutoDiscoveryEngine(
            identity = identity,
            db = db,
            onDevicesChanged = { devs -> runOnUiThread { renderDiscoveredDevices(devs) } },
            onPromptApproval = { peerName, routeName -> promptUserForConnectionApproval(peerName, routeName) },
            onServerConnected = { adapter -> onConnectionEstablished(adapter) }
        )
        discoveryEngine.start()
        updateLocalIpHeader()
        refreshHistoryView()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (isFinishing) {
            discoveryEngine.stop()
        }
    }

    /**
     * Requests runtime permissions required on Android 12, 13, 14, and 15+ (API 31..35)
     * so Bluetooth discovery and high-priority notifications work smoothly on all modern phones.
     */
    private fun requestModernAndroidPermissionsIfNeeded() {
        val needed = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                needed.add(Manifest.permission.BLUETOOTH_CONNECT)
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
                needed.add(Manifest.permission.BLUETOOTH_SCAN)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                needed.add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                needed.add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            }
        }
        if (needed.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, needed.toTypedArray(), REQ_RUNTIME_PERMS)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_RUNTIME_PERMS && ::discoveryEngine.isInitialized) {
            discoveryEngine.refreshBluetoothPairedDevices()
        }
    }

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        val ch = NotificationChannel(
            APPROVAL_CHANNEL_ID,
            "طلبات الاتصال والملفات في LinkBridge",
            NotificationManager.IMPORTANCE_HIGH
        )
        nm.createNotificationChannel(ch)
    }

    private fun makeCardDrawable(bgColor: Int, strokeColor: Int, radiusDp: Float = 28f): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = radiusDp
            setColor(bgColor)
            setStroke(3, strokeColor)
        }
    }

    private fun makeButtonDrawable(bgColor: Int, radiusDp: Float = 22f): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = radiusDp
            setColor(bgColor)
        }
    }

    private fun buildModernCardUi() {
        window.decorView.layoutDirection = View.LAYOUT_DIRECTION_RTL
        val bgCanvas = if (isDarkTheme) Color.parseColor("#0B1120") else Color.parseColor("#F1F5F9")
        val cardBg = if (isDarkTheme) Color.parseColor("#1E293B") else Color.parseColor("#FFFFFF")
        val textPrimary = if (isDarkTheme) Color.parseColor("#F8FAFC") else Color.parseColor("#0F172A")
        val textSecondary = if (isDarkTheme) Color.parseColor("#94A3B8") else Color.parseColor("#475569")
        val inputBg = if (isDarkTheme) Color.parseColor("#0F172A") else Color.parseColor("#F8FAFC")

        rootScroll = ScrollView(this).apply {
            setBackgroundColor(bgCanvas)
        }
        val mainLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 42, 36, 48)
        }
        rootScroll.addView(mainLayout)

        // ============================================================
        // HEADER CARD: App Title, Theme Switcher & Live Connection Status
        // ============================================================
        val headerCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(cardBg, Color.parseColor("#334155"))
            setPadding(36, 32, 36, 32)
        }
        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val tvTitle = TextView(this).apply {
            text = "🌉 LinkBridge v1.0.0"
            textSize = 20f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(textPrimary)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val btnTheme = Button(this).apply {
            text = if (isDarkTheme) "☀️ فاتح" else "🌙 داكن"
            setTextColor(Color.WHITE)
            background = makeButtonDrawable(Color.parseColor("#334155"), 18f)
            setOnClickListener {
                isDarkTheme = !isDarkTheme
                db.setSetting("ui_dark_theme", isDarkTheme.toString())
                buildModernCardUi()
                updateLocalIpHeader()
                updateConnectionBanner()
                refreshHistoryView()
            }
        }
        topRow.addView(tvTitle)
        topRow.addView(btnTheme)
        headerCard.addView(topRow)

        tvStatusBadge = TextView(this).apply {
            text = "🔵 جاهز للاتصال التلقائي — اختر الكمبيوتر بالأسفل أو وافق على الإشعار"
            textSize = 14.5f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#0284C7"))
            setPadding(0, 14, 0, 8)
        }
        tvLocalInfo = TextView(this).apply {
            text = "📱 جاري فحص عنوان الشبكة..."
            textSize = 12.5f
            setTextColor(textSecondary)
        }
        btnDisconnect = Button(this).apply {
            text = "❌ قطع الاتصال الحالي"
            setTextColor(Color.WHITE)
            background = makeButtonDrawable(Color.parseColor("#EF4444"))
            visibility = View.GONE
            setOnClickListener {
                activeTransport?.close()
                activeTransport = null
                updateConnectionBanner()
            }
        }
        headerCard.addView(tvStatusBadge)
        headerCard.addView(tvLocalInfo)
        headerCard.addView(btnDisconnect)
        mainLayout.addView(headerCard)

        mainLayout.addView(View(this).apply { minimumHeight = 28 })

        // ============================================================
        // CARD 1: Discovered Devices (Wi-Fi / Hotspot / Bluetooth)
        // ============================================================
        val devCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(cardBg, Color.parseColor("#0284C7"))
            setPadding(34, 30, 34, 30)
        }
        val devHeader = TextView(this).apply {
            text = "📡 1. الأجهزة المتاحة حولك (اضغط للاتصال الفوري بدون رمز)"
            textSize = 15.5f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#0284C7"))
            setPadding(0, 0, 0, 16)
        }
        devCard.addView(devHeader)

        devicesListContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        devCard.addView(devicesListContainer)

        val btnRescan = Button(this).apply {
            text = "🔄 تحديث البحث عن الكمبيوتر (Wi-Fi / بلوتوث)"
            setTextColor(Color.WHITE)
            background = makeButtonDrawable(Color.parseColor("#334155"))
            setOnClickListener {
                Toast.makeText(this@MainActivity, "جاري البحث عن الأجهزة في الشبكة والبلوتوث...", Toast.LENGTH_SHORT).show()
                updateLocalIpHeader()
                discoveryEngine.triggerImmediateScan()
            }
        }
        val lpRescan = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = 18 }
        devCard.addView(btnRescan, lpRescan)
        mainLayout.addView(devCard)

        renderDiscoveredDevices(emptyList())

        mainLayout.addView(View(this).apply { minimumHeight = 28 })

        // ============================================================
        // CARD 2: Clipboard Bridge & Interactive History
        // ============================================================
        val clipCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(cardBg, Color.parseColor("#10B981"))
            setPadding(34, 30, 34, 30)
        }
        val clipHeader = TextView(this).apply {
            text = "📋 2. الحافظة ومشاركة النصوص الفورية"
            textSize = 15.5f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#10B981"))
            setPadding(0, 0, 0, 14)
        }
        clipCard.addView(clipHeader)

        val btnSendCurrentClip = Button(this).apply {
            text = "📋 إرسال الحافظة المنسوخة حاليًا إلى الكمبيوتر"
            setTextColor(Color.WHITE)
            textSize = 14.5f
            background = makeButtonDrawable(Color.parseColor("#10B981"))
            setPadding(20, 26, 20, 26)
            setOnClickListener { sendCurrentClipboard() }
        }
        clipCard.addView(btnSendCurrentClip)

        etTextToSend = EditText(this).apply {
            hint = "أو اكتب / الصق أي نص أو رابط هنا لإرساله للكمبيوتر..."
            setHintTextColor(textSecondary)
            setTextColor(textPrimary)
            background = makeCardDrawable(inputBg, Color.parseColor("#334155"), 18f)
            setPadding(24, 20, 24, 20)
            minLines = 2
        }
        val lpEt = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = 18; bottomMargin = 14 }
        clipCard.addView(etTextToSend, lpEt)

        val btnSendTypedText = Button(this).apply {
            text = "📨 إرسال النص المكتوب"
            setTextColor(Color.WHITE)
            background = makeButtonDrawable(Color.parseColor("#0284C7"))
            setOnClickListener { sendCustomText() }
        }
        clipCard.addView(btnSendTypedText)

        val chkAutoCopy = CheckBox(this).apply {
            text = "⚡ نسخ النصوص الواردة من الكمبيوتر إلى حافظة الهاتف تلقائيًا"
            setTextColor(textPrimary)
            isChecked = db.getSetting("auto_copy_received_to_clipboard", "true") == "true"
            setPadding(8, 18, 8, 8)
            setOnCheckedChangeListener { _, isChecked ->
                db.setSetting("auto_copy_received_to_clipboard", isChecked.toString())
            }
        }
        clipCard.addView(chkAutoCopy)

        val tvHistTitle = TextView(this).apply {
            text = "🕘 آخر النصوص المتبادلة (اضغط على أي نص لنسخه فورًا):"
            textSize = 13f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(textSecondary)
            setPadding(4, 14, 4, 8)
        }
        clipCard.addView(tvHistTitle)

        historyItemsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        clipCard.addView(historyItemsContainer)
        mainLayout.addView(clipCard)

        mainLayout.addView(View(this).apply { minimumHeight = 28 })

        // ============================================================
        // CARD 3: File Transfers (Send & Receive)
        // ============================================================
        val fileCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(cardBg, Color.parseColor("#38BDF8"))
            setPadding(34, 30, 34, 30)
        }
        val fileHeader = TextView(this).apply {
            text = "📁 3. إرسال واستقبال الملفات (تُحفظ تلقائيًا في Download/LinkBridge)"
            textSize = 15.5f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#0284C7"))
            setPadding(0, 0, 0, 16)
        }
        fileCard.addView(fileHeader)

        val btnSendFiles = Button(this).apply {
            text = "📄 اختيار وإرسال ملفات إلى الكمبيوتر..."
            setTextColor(Color.WHITE)
            textSize = 14.5f
            background = makeButtonDrawable(Color.parseColor("#0284C7"))
            setPadding(20, 26, 20, 26)
            setOnClickListener { openSafFilePicker() }
        }
        fileCard.addView(btnSendFiles)

        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            progress = 0
            setPadding(0, 20, 0, 8)
        }
        tvTransferProgress = TextView(this).apply {
            text = "📂 مسار حفظ الملفات الواردة: Download/LinkBridge"
            textSize = 12.5f
            setTextColor(textSecondary)
        }
        fileCard.addView(progressBar)
        fileCard.addView(tvTransferProgress)

        val btnPickSaveDir = Button(this).apply {
            text = "⚙️ تغيير مجلد الاستقبال (اختياري)"
            setTextColor(Color.WHITE)
            background = makeButtonDrawable(Color.parseColor("#334155"))
            setOnClickListener { openSafFolderPicker() }
        }
        val lpFolderBtn = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = 16 }
        fileCard.addView(btnPickSaveDir, lpFolderBtn)
        mainLayout.addView(fileCard)

        // ============================================================
        // FOOTER: Quick Notification Toggle & Developer Card
        // ============================================================
        val chkFgService = CheckBox(this).apply {
            text = "🔔 إظهار إشعار الإرسال السريع الدائم في شريط الإشعارات"
            setTextColor(textSecondary)
            setPadding(8, 24, 8, 8)
            setOnCheckedChangeListener { _, isChecked ->
                val svcIntent = Intent(this@MainActivity, LinkBridgeForegroundService::class.java)
                if (isChecked) startForegroundService(svcIntent) else stopService(svcIntent)
            }
        }
        mainLayout.addView(chkFgService)

        val devFooterCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(cardBg, Color.parseColor("#334155"), 22f)
            setPadding(28, 24, 28, 24)
            gravity = Gravity.CENTER
        }
        val tvAbout = TextView(this).apply {
            text = "LinkBridge v1.0.0 — Smart Local Bridge\n✦ Developed by Mohammed Albukeer ✦\nmohammedalbukeer@gmail.com"
            gravity = Gravity.CENTER
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#0284C7"))
        }
        devFooterCard.addView(tvAbout)
        val lpFooter = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = 20 }
        mainLayout.addView(devFooterCard, lpFooter)

        setContentView(rootScroll)
    }

    private fun updateLocalIpHeader() {
        if (!::discoveryEngine.isInitialized) return
        val ips = discoveryEngine.getLocalIpAddresses()
        tvLocalInfo.text = "📱 اسم هذا الهاتف: ${identity.deviceName}  |  الشبكة: ${ips.joinToString(" , ")}:${ProtocolConstants.DEFAULT_WIFI_PORT}"
    }

    private fun updateConnectionBanner() {
        val t = activeTransport
        if (t != null && t.isConnected) {
            tvStatusBadge.text = "🟢 متصل الآن بـ: ${t.peerDeviceName ?: "كمبيوتر Windows"} (${t.route.name}) — جاهز للنقل!"
            tvStatusBadge.setTextColor(Color.parseColor("#10B981"))
            btnDisconnect.visibility = View.VISIBLE
        } else {
            tvStatusBadge.text = "🔵 جاهز للاتصال التلقائي — اختر الكمبيوتر بالأسفل أو وافق على الإشعار"
            tvStatusBadge.setTextColor(Color.parseColor("#0284C7"))
            btnDisconnect.visibility = View.GONE
        }
    }

    private fun renderDiscoveredDevices(devices: List<DiscoveredDevice>) {
        devicesListContainer.removeAllViews()
        if (devices.isEmpty()) {
            val tvEmpty = TextView(this).apply {
                text = "⏳ جاري البحث التلقائي عن الكمبيوتر عبر Wi-Fi ونقطة الاتصال والبلوتوث...\n(يمكنك أيضًا اختيار هذا الهاتف من شاشة الكمبيوتر والموافقة على الإشعار هنا مباشرةً)"
                setTextColor(Color.parseColor("#94A3B8"))
                textSize = 13f
                setPadding(10, 10, 10, 10)
            }
            devicesListContainer.addView(tvEmpty)
            return
        }

        for (dev in devices) {
            val icon = if (dev.route == TransportRoute.BLUETOOTH_RFCOMM) "🔵 بلوتوث" else "💻 واي فاي / نقطة اتصال"
            val btnDev = Button(this).apply {
                text = "🔗 اتصال فوري بـ: ${dev.deviceName}\n($icon — ${dev.ip})"
                setTextColor(Color.WHITE)
                textSize = 14f
                background = makeButtonDrawable(Color.parseColor("#0284C7"))
                setPadding(24, 24, 24, 24)
                setOnClickListener { initiateConnectionToDevice(dev) }
            }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = 14 }
            devicesListContainer.addView(btnDev, lp)
        }
    }

    private fun promptUserForConnectionApproval(peerName: String, routeName: String): Boolean {
        val latch = CountDownLatch(1)
        val approved = AtomicBoolean(false)

        try {
            val nm = getSystemService(NotificationManager::class.java)
            val notif = NotificationCompat.Builder(this, APPROVAL_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                .setContentTitle("🔔 طلب اتصال من «$peerName»")
                .setContentText("افتح LinkBridge واضغط «موافقة» لربط الجهاز عبر $routeName")
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .build()
            nm.notify(9901, notif)
        } catch (_: Exception) {
        }

        runOnUiThread {
            try {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("🔔 طلب اتصال من الكمبيوتر")
                    .setMessage("يرغب الجهاز «$peerName» بالاتصال بهاتفك عبر ($routeName) لتبادل النصوص والملفات.\n\nهل توافق على الاتصال؟")
                    .setCancelable(false)
                    .setPositiveButton("✅ موافقة واتصال") { dialog, _ ->
                        approved.set(true)
                        dialog.dismiss()
                        latch.countDown()
                    }
                    .setNegativeButton("❌ رفض") { dialog, _ ->
                        approved.set(false)
                        dialog.dismiss()
                        latch.countDown()
                    }
                    .show()
            } catch (_: Exception) {
                approved.set(true)
                latch.countDown()
            }
        }

        latch.await(45, TimeUnit.SECONDS)
        return approved.get()
    }

    private fun onConnectionEstablished(adapter: TransportAdapter) {
        activeTransport?.close()
        activeTransport = adapter
        adapter.startBackgroundDispatcher { frame -> handleIncomingFrameFromWindows(adapter, frame) }
        runOnUiThread {
            updateConnectionBanner()
            Toast.makeText(
                this,
                "✅ تم الاتصال بـ ${adapter.peerDeviceName ?: "كمبيوتر Windows"} بنجاح!",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun initiateConnectionToDevice(dev: DiscoveredDevice) {
        tvStatusBadge.text = "⏳ جاري الاتصال بـ «${dev.deviceName}»... يرجى الموافقة من الكمبيوتر إذا طُلب منك"
        thread {
            try {
                val adapter: TransportAdapter = if (dev.route == TransportRoute.BLUETOOTH_RFCOMM && dev.btDevice != null) {
                    BluetoothRfcommTransportAdapter.connectToPairedDevice(dev.btDevice)
                } else {
                    WifiTlsTransportAdapter.connect(
                        dev.ip,
                        dev.port,
                        isHotspot = (dev.route == TransportRoute.WIFI_HOTSPOT),
                        timeoutMs = 15000
                    )
                }
                adapter.clientHandshakeAndAuth(identity, db, pinOrSecret = "AUTO_APPROVE")
                onConnectionEstablished(adapter)
            } catch (e: Exception) {
                runOnUiThread {
                    updateConnectionBanner()
                    Toast.makeText(this, "تعذر الاتصال: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun handleIncomingFrameFromWindows(transport: TransportAdapter, frame: ProtocolFrame) {
        when (frame.header.msgType) {
            ProtocolConstants.MSG_CLIPBOARD_PUSH -> {
                val ok = clipboardController.handleIncomingClipboardPush(transport, frame.jsonBody())
                if (ok) {
                    runOnUiThread {
                        refreshHistoryView()
                        Toast.makeText(this, "📋 تم استلام نص جديد من الكمبيوتر ونسخه للحافظة!", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            ProtocolConstants.MSG_FILE_OFFER -> {
                val offerBody = frame.jsonBody()
                val fileName = offerBody.optString("file_name", "file")
                val transferId = frame.header.transferId
                val treeUri = selectedSaveTreeUri
                val targetDocDir = if (treeUri != null) DocumentFile.fromTreeUri(this, treeUri) else null

                runOnUiThread {
                    tvTransferProgress.text = "⏳ جاري استلام الملف: $fileName ..."
                }

                val savedPath = fileController.receiveFile(transport, offerBody, transferId, targetDocDir) { rx, total ->
                    val pct = if (total > 0) ((rx * 100) / total).toInt() else 0
                    runOnUiThread {
                        progressBar.progress = pct
                        tvTransferProgress.text = "⬇️ جاري استلام: $fileName ($pct%)"
                    }
                }
                runOnUiThread {
                    if (savedPath != null) {
                        progressBar.progress = 100
                        tvTransferProgress.text = "✅ تم حفظ الملف بنجاح: $savedPath"
                        Toast.makeText(this, "✅ اكتمل استلام الملف في التنزيلات: $fileName", Toast.LENGTH_LONG).show()
                    } else {
                        tvTransferProgress.text = "⚠️ تعذر حفظ الملف الوارد"
                    }
                }
            }
            ProtocolConstants.MSG_PING -> {
                transport.sendControl(ProtocolConstants.MSG_PONG, JSONObject().put("ts", System.currentTimeMillis()))
            }
        }
    }

    private fun refreshHistoryView() {
        historyItemsContainer.removeAllViews()
        val items = db.listRecentClipboardItems(10)
        if (items.isEmpty()) {
            val tvEmpty = TextView(this).apply {
                text = "لا توجد نصوص في السجل بعد — أي نص ترسله أو تستلمه سيظهر هنا كبطاقة تفاعلية."
                setTextColor(Color.parseColor("#64748B"))
                textSize = 12.5f
                setPadding(8, 8, 8, 8)
            }
            historyItemsContainer.addView(tvEmpty)
            return
        }
        val rowBg = if (isDarkTheme) Color.parseColor("#0F172A") else Color.parseColor("#F1F5F9")
        val rowText = if (isDarkTheme) Color.parseColor("#E2E8F0") else Color.parseColor("#1E293B")
        for (itemText in items) {
            val tvRow = TextView(this).apply {
                text = "$itemText  (اضغط للنسخ 📋)"
                setTextColor(rowText)
                textSize = 13f
                background = makeCardDrawable(rowBg, Color.parseColor("#334155"), 16f)
                setPadding(22, 18, 22, 18)
                setOnClickListener {
                    val rawContent = itemText.substringAfter("] ").trim()
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("LinkBridge", rawContent))
                    Toast.makeText(this@MainActivity, "✅ تم نسخ النص إلى حافظة الهاتف!", Toast.LENGTH_SHORT).show()
                }
            }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = 10 }
            historyItemsContainer.addView(tvRow, lp)
        }
    }

    private fun sendCurrentClipboard() {
        val transport = activeTransport ?: run {
            Toast.makeText(this, "يرجى الاتصال بالكمبيوتر أولًا من قائمة الأجهزة بالأعلى", Toast.LENGTH_SHORT).show()
            return
        }
        val clipText = clipboardController.readCurrentClipboardText()
        if (clipText.isNullOrBlank()) {
            Toast.makeText(this, "حافظة الهاتف فارغة حاليًا؛ انسخ أي نص أولًا", Toast.LENGTH_SHORT).show()
            return
        }
        thread {
            try {
                clipboardController.sendTextNow(transport, clipText, mode = "MANUAL")
                runOnUiThread {
                    refreshHistoryView()
                    Toast.makeText(this, "✅ تم إرسال الحافظة إلى الكمبيوتر بنجاح", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun sendCustomText() {
        val transport = activeTransport ?: run {
            Toast.makeText(this, "يرجى الاتصال بالكمبيوتر أولًا من قائمة الأجهزة بالأعلى", Toast.LENGTH_SHORT).show()
            return
        }
        val txt = etTextToSend.text.toString()
        if (txt.isBlank()) return
        thread {
            try {
                if (clipboardController.sendTextNow(transport, txt, mode = "MANUAL")) {
                    runOnUiThread {
                        etTextToSend.text.clear()
                        refreshHistoryView()
                        Toast.makeText(this, "✅ تم إرسال النص إلى الكمبيوتر بنجاح", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun openSafFilePicker() {
        if (activeTransport == null || activeTransport?.isConnected != true) {
            Toast.makeText(this, "يرجى الاتصال بالكمبيوتر أولًا لإرسال الملفات", Toast.LENGTH_SHORT).show()
            return
        }
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQ_PICK_FILES)
    }

    private fun openSafFolderPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQ_PICK_SAVE_FOLDER)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != Activity.RESULT_OK || data == null) return
        when (requestCode) {
            REQ_PICK_SAVE_FOLDER -> {
                data.data?.let { treeUri ->
                    contentResolver.takePersistableUriPermission(
                        treeUri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    )
                    selectedSaveTreeUri = treeUri
                    db.setSetting("saf_receive_tree_uri", treeUri.toString())
                    Toast.makeText(this, "✅ تم تحديث مجلد الاستقبال بنجاح", Toast.LENGTH_SHORT).show()
                }
            }
            REQ_PICK_FILES -> {
                val transport = activeTransport ?: return
                val uris = mutableListOf<Uri>()
                data.clipData?.let { clip ->
                    for (i in 0 until clip.itemCount) {
                        uris.add(clip.getItemAt(i).uri)
                    }
                } ?: data.data?.let { uris.add(it) }

                thread {
                    try {
                        for (uri in uris) {
                            fileController.sendUriFile(transport, uri) { sent, total ->
                                val pct = if (total > 0) ((sent * 100) / total).toInt() else 0
                                runOnUiThread {
                                    progressBar.progress = pct
                                    tvTransferProgress.text = "⬆️ جاري إرسال الملف للكمبيوتر ($pct%)..."
                                }
                            }
                        }
                        runOnUiThread {
                            progressBar.progress = 100
                            tvTransferProgress.text = "✅ اكتمل إرسال ${uris.size} ملف/ملفات إلى الكمبيوتر بنجاح!"
                            Toast.makeText(this, "✅ اكتمل إرسال الملفات والتحقق من SHA-256", Toast.LENGTH_SHORT).show()
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            tvTransferProgress.text = "⚠️ خطأ أثناء نقل الملف: ${e.message}"
                            Toast.makeText(this, "خطأ في نقل الملف: ${e.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
        }
    }
}
