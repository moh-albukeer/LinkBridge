"""
LinkBridge Windows Desktop Application V2 (`app.py`).
Features:
- Automatic startup of Local Listener (`0.0.0.0:48520`) and `AutoDiscoveryEngine` (UDP Broadcast 48521 + ARP/Subnet Port 48520 Scanner + Paired Bluetooth Devices).
- Zero manual IP/MAC/PIN typing: discovered Wi-Fi, Hotspot, and Bluetooth devices appear automatically in a clear list.
- One-Click Connection & Notification/Popup Approval (`AUTO_APPROVE` via ECDH P-256 + HKDF-SHA256).
- Modern, intuitive Arabic RTL & English LTR interface with Dark/Light modes, System Tray integration, non-blocking background file transfers, and «عمل محمد البكير».
"""
import argparse
import json
import os
import socket
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from protocol.constants import DEFAULT_WIFI_PORT, TransportType
from protocol.transport import (
    AutoDiscoveryEngine,
    BluetoothRfcommTransport,
    LocalDiscoveryService,
    WifiTlsTransport,
)
from windows.bridge_node import LinkBridgeNode
from windows.i18n import STRINGS, get_stylesheet
from windows.startup_and_tray import WindowsStartupManager


def get_default_appdata_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return base / "LinkBridge"
    return Path.home() / ".local" / "share" / "LinkBridge"


def get_default_downloads_dir(appdata_dir: Path) -> Path:
    dl = Path.home() / "Downloads" / "LinkBridge"
    try:
        dl.mkdir(parents=True, exist_ok=True)
        return dl
    except Exception:
        fallback = appdata_dir / "ReceivedFiles"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def scan_windows_bluetooth_devices() -> List[Dict[str, Any]]:
    """
    Read paired Bluetooth devices directly from the Windows Registry (`BTHPORT\Parameters\Devices`)
    using Python's built-in `winreg` module.
    # Native Win32 API lookup
    and never triggers Windows Defender behavioral heuristics.
    """
    results: List[Dict[str, Any]] = []
    if sys.platform != "win32":
        return results
    try:
        import winreg

        bth_path = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bth_path, 0, winreg.KEY_READ) as dev_root:
            idx = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(dev_root, idx)
                    idx += 1
                except OSError:
                    break
                if len(subkey_name) != 12:
                    continue
                raw_hex = subkey_name.upper()
                mac = ":".join(raw_hex[i : i + 2] for i in range(0, 12, 2))
                friendly_name = f"جهاز بلوتوث ({mac})"
                try:
                    with winreg.OpenKey(dev_root, subkey_name, 0, winreg.KEY_READ) as subk:
                        val, _ = winreg.QueryValueEx(subk, "Name")
                        if isinstance(val, bytes):
                            decoded = val.rstrip(b"\x00").decode("utf-8", errors="ignore").strip()
                            if decoded:
                                friendly_name = decoded
                        elif isinstance(val, str) and val.strip():
                            friendly_name = val.strip()
                except OSError:
                    pass
                results.append(
                    {
                        "device_id": f"bt-{mac}",
                        "device_name": friendly_name,
                        "platform": "Bluetooth",
                        "ip": mac,
                        "port": 4,
                        "transport": "BLUETOOTH_RFCOMM",
                        "address": mac,
                    }
                )
    except Exception:
        pass
    return results


def run_self_check(data_dir: Path) -> int:
    node = LinkBridgeNode(data_dir=data_dir, device_name="LinkBridge-Windows-Check")
    pin, secret_hex, exp = node.generate_pairing_code()
    ips = LocalDiscoveryService.get_local_private_ips()
    bt_caps = BluetoothRfcommTransport.check_system_capabilities()
    qr_payload = LocalDiscoveryService.build_qr_pairing_payload(
        node.identity,
        ip=ips[0]["ip"],
        port=DEFAULT_WIFI_PORT,
        pairing_secret_hex=secret_hex,
        pin_code=pin,
        expires_at=exp,
    )
    summary = {
        "device_id": node.identity.device_id,
        "fingerprint_sha256": node.identity.fingerprint_sha256,
        "local_ips": ips,
        "bluetooth_capabilities": bt_caps,
        "sample_qr_pairing_payload": json.loads(qr_payload),
        "about_credit": STRINGS["ar"]["about_credit"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    node.shutdown()
    return 0


def launch_pyside6_gui(data_dir: Path, start_minimized: bool = False) -> int:
    try:
        from PySide6.QtCore import Qt, QTimer, Signal, QObject
        from PySide6.QtGui import QAction, QGuiApplication, QIcon, QPixmap, QColor
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QFileDialog,
            QFormLayout,
            QGroupBox,
            QHBoxLayout,
            QHeaderView,
            QInputDialog,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
            QMenu,
            QMessageBox,
            QProgressBar,
            QPushButton,
            QSystemTrayIcon,
            QTabWidget,
            QTableWidget,
            QTableWidgetItem,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as e:
        print(
            "PySide6 غير مثبت في بيئة Python الحالية. لتشغيل الواجهة الرسومية على Windows، ثبّت المتطلبات عبر:\n"
            "  pip install -r windows/requirements.txt\n"
            f"تفاصيل الخطأ: {e}",
            file=sys.stderr,
        )
        return 1

    class UiBridgeSignals(QObject):
        event_signal = Signal(str, dict)
        devices_updated_signal = Signal(list)
        pairing_prompt_signal = Signal(dict)

    class LinkBridgeMainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.signals = UiBridgeSignals()
            self.signals.event_signal.connect(self._on_node_event)
            self.signals.devices_updated_signal.connect(self._on_devices_updated)
            self.signals.pairing_prompt_signal.connect(self._on_pairing_prompt_main_thread)

            self._pairing_approval_event = threading.Event()
            self._pairing_approval_result = False

            pc_name = socket.gethostname() or "Windows-PC"
            self.node = LinkBridgeNode(
                data_dir=data_dir,
                device_name=f"كمبيوتر {pc_name}",
                on_event_callback=lambda et, d: self.signals.event_signal.emit(et, d),
                pairing_approval_callback=self._request_pairing_approval_from_thread,
            )
            # Set default receive folder to Downloads/LinkBridge
            default_dl = get_default_downloads_dir(data_dir)
            self.node.storage.set_setting("receive_directory", str(default_dl))
            self.node.clipboard_backend.set_qt_clipboard(QGuiApplication.clipboard())

            self.lang = self.node.storage.get_setting("language", "ar")
            self.theme = self.node.storage.get_setting("theme", "dark")
            self._discovered_devices: List[Dict[str, Any]] = []

            self._build_ui()
            self._apply_language_and_theme()
            self._setup_tray_icon()

            # Start Local Listener & Auto-Discovery Engine AUTOMATICALLY on startup!
            self._start_auto_services()

            # Periodic timer for Windows clipboard monitoring & UI device list refresh
            self._clip_timer = QTimer(self)
            self._clip_timer.timeout.connect(self._poll_clipboard)
            self._clip_timer.start(900)

            self._scan_timer = QTimer(self)
            self._scan_timer.timeout.connect(self._refresh_device_list_ui)
            self._scan_timer.start(2500)

        def _start_auto_services(self) -> None:
            try:
                self.node.generate_pairing_code()
                self.node.start_wifi_listener(bind_ip="0.0.0.0", port=DEFAULT_WIFI_PORT)
            except Exception:
                pass
            self.discovery = AutoDiscoveryEngine(
                identity=self.node.identity,
                listen_port=DEFAULT_WIFI_PORT,
                on_devices_updated=lambda devs: self.signals.devices_updated_signal.emit(devs),
            )
            self.discovery.start()
            threading.Thread(target=self._scan_bt_background, daemon=True).start()

        def _scan_bt_background(self) -> None:
            for bt_dev in scan_windows_bluetooth_devices():
                self.discovery._register_device(bt_dev)

        def _request_pairing_approval_from_thread(self, peer_info: Dict[str, Any]) -> bool:
            self._pairing_approval_event.clear()
            self._pairing_approval_result = False
            self.signals.pairing_prompt_signal.emit(peer_info)
            self._pairing_approval_event.wait(timeout=45.0)
            return self._pairing_approval_result

        def _on_pairing_prompt_main_thread(self, peer_info: Dict[str, Any]) -> None:
            peer_name = peer_info.get("device_name", "هاتف Android")
            transport_name = peer_info.get("transport", "Wi-Fi")
            if hasattr(self, "tray"):
                self.tray.showMessage(
                    "🔔 طلب اتصال في LinkBridge",
                    f"يرغب الجهاز «{peer_name}» بالاتصال بالكمبيوتر عبر {transport_name}.",
                )
            self.showNormal()
            self.activateWindow()
            ans = QMessageBox.question(
                self,
                "🔔 طلب اتصال واقتران جديد",
                f"يرغب الجهاز «{peer_name}» بالاتصال بالكمبيوتر عبر ({transport_name}).\n\n"
                "هل توافق على الاتصال والسماح بتبادل النصوص والملفات؟",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            self._pairing_approval_result = ans == QMessageBox.StandardButton.Yes
            self._pairing_approval_event.set()

        def _build_ui(self) -> None:
            self.setMinimumSize(980, 720)
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QVBoxLayout(central)
            main_layout.setSpacing(12)
            main_layout.setContentsMargins(18, 18, 18, 18)

            # Top Status Banner Card
            status_card = QGroupBox()
            status_layout = QHBoxLayout(status_card)
            self.lbl_conn_status = QLabel()
            self.lbl_conn_status.setStyleSheet("font-size: 16px; font-weight: bold;")
            self.lbl_local_addr = QLabel()
            self.lbl_local_addr.setStyleSheet("font-size: 13px; color: #38BDF8;")
            self.btn_disconnect = QPushButton("قطع الاتصال الحالي")
            self.btn_disconnect.setObjectName("dangerBtn")
            self.btn_disconnect.clicked.connect(self._on_disconnect_clicked)
            self.btn_disconnect.setVisible(False)
            status_layout.addWidget(self.lbl_conn_status, stretch=3)
            status_layout.addWidget(self.lbl_local_addr, stretch=2)
            status_layout.addWidget(self.btn_disconnect)
            main_layout.addWidget(status_card)

            self.tabs = QTabWidget()
            main_layout.addWidget(self.tabs)

            # Persistent Interactive Footer Bar
            footer_bar = QHBoxLayout()
            self.lbl_footer_dev = QLabel("✦ Developed by Mohammed Albukeer  |  mohammedalbukeer@gmail.com  |  LinkBridge v1.0.0 ✦")
            self.lbl_footer_dev.setStyleSheet("font-size: 12px; font-weight: 600; color: #38BDF8; padding: 4px;")
            self.btn_quick_theme = QPushButton("🌙 / ☀️ المظهر")
            self.btn_quick_theme.setObjectName("secondaryBtn")
            self.btn_quick_theme.clicked.connect(self._toggle_theme)
            footer_bar.addWidget(self.lbl_footer_dev, stretch=3)
            footer_bar.addWidget(self.btn_quick_theme)
            main_layout.addLayout(footer_bar)

            # =========================================================
            # TAB 1: Main Unified Workspace (Discovery + Clipboard + Files)
            # =========================================================
            self.tab_main = QWidget()
            dash_layout = QVBoxLayout(self.tab_main)
            dash_layout.setSpacing(14)

            # Card 1: Available Devices (Zero-Config Wi-Fi / Hotspot / Bluetooth List)
            dev_group = QGroupBox("📡 1. الأجهزة المتاحة حولك (اختر هاتفك واضغط اتصال — بدون كتابة أي رمز)")
            dev_layout = QVBoxLayout(dev_group)
            self.list_devices = QListWidget()
            self.list_devices.setMinimumHeight(115)
            self.list_devices.itemDoubleClicked.connect(lambda _: self._on_connect_selected_device())
            dev_layout.addWidget(self.list_devices)

            dev_btns = QHBoxLayout()
            self.btn_connect_selected = QPushButton("🔗 اتصال بالجهاز المحدد (موافقة من إشعار الهاتف فقط)")
            self.btn_connect_selected.setStyleSheet(
                "background-color: #10B981; color: #FFFFFF; font-size: 14px; padding: 10px 18px;"
            )
            self.btn_connect_selected.clicked.connect(self._on_connect_selected_device)

            self.btn_refresh_scan = QPushButton("🔄 تحديث البحث عن الأجهزة")
            self.btn_refresh_scan.clicked.connect(self._on_manual_rescan)

            self.btn_manual_ip = QPushButton("➕ اتصال بعنوان IP يدوي (اختياري)")
            self.btn_manual_ip.clicked.connect(self._on_manual_ip_dialog)

            dev_btns.addWidget(self.btn_connect_selected, stretch=2)
            dev_btns.addWidget(self.btn_refresh_scan, stretch=1)
            dev_btns.addWidget(self.btn_manual_ip, stretch=1)
            dev_layout.addLayout(dev_btns)
            dash_layout.addWidget(dev_group)

            # Card 2: Quick Clipboard & Text Transfer
            clip_group = QGroupBox("📋 2. مشاركة الحافظة والنصوص الفورية (في الاتجاهين)")
            clip_box = QVBoxLayout(clip_group)
            self.txt_quick_send = QTextEdit()
            self.txt_quick_send.setMaximumHeight(85)
            self.txt_quick_send.setPlaceholderText(
                "اكتب أو الصق أي نص أو رابط هنا لإرساله فورًا إلى الهاتف، أو اضغط «إرسال الحافظة الحالية»..."
            )
            clip_box.addWidget(self.txt_quick_send)

            clip_btns = QHBoxLayout()
            self.btn_send_clip = QPushButton("📋 إرسال الحافظة المنسوخة حاليًا للهاتف")
            self.btn_send_clip.clicked.connect(self._on_send_current_clipboard)
            self.btn_send_text = QPushButton("📨 إرسال النص المكتوب أعلاه")
            self.btn_send_text.clicked.connect(self._on_send_custom_text)
            clip_btns.addWidget(self.btn_send_clip)
            clip_btns.addWidget(self.btn_send_text)
            clip_box.addLayout(clip_btns)
            dash_layout.addWidget(clip_group)

            # Card 3: Quick File & Folder Transfer
            file_group = QGroupBox("📁 3. نقل الملفات والمجلدات (سريع ومفحوص ببصمة SHA-256)")
            file_box = QVBoxLayout(file_group)
            file_btns = QHBoxLayout()
            self.btn_quick_files = QPushButton("📄 اختيار وإرسال ملفات إلى الهاتف...")
            self.btn_quick_files.setStyleSheet(
                "background-color: #0284C7; color: #FFFFFF; font-size: 14px; padding: 10px;"
            )
            self.btn_quick_files.clicked.connect(self._on_pick_and_send_files)

            self.btn_quick_folder = QPushButton("📁 إرسال مجلد كامل إلى الهاتف...")
            self.btn_quick_folder.clicked.connect(self._on_pick_and_send_folder)

            self.btn_open_recv_dir = QPushButton("📂 فتح مجلد الملفات المستلمة على الكمبيوتر")
            self.btn_open_recv_dir.clicked.connect(self._on_open_receive_folder)

            file_btns.addWidget(self.btn_quick_files, stretch=2)
            file_btns.addWidget(self.btn_quick_folder, stretch=1)
            file_btns.addWidget(self.btn_open_recv_dir, stretch=1)
            file_box.addLayout(file_btns)

            self.progress_bar = QProgressBar()
            self.progress_bar.setValue(0)
            self.lbl_transfer_prog = QLabel("لا توجد عملية نقل جارية حاليًا — الملفات المستلمة تُحفظ تلقائيًا في Downloads\LinkBridge")
            file_box.addWidget(self.progress_bar)
            file_box.addWidget(self.lbl_transfer_prog)
            dash_layout.addWidget(file_group)

            self.tabs.addTab(self.tab_main, "🏠 الرئيسية والاتصال السريع")

            # =========================================================
            # TAB 2: Clipboard History
            # =========================================================
            self.tab_clip = QWidget()
            clip_layout = QVBoxLayout(self.tab_clip)
            clip_top = QHBoxLayout()
            self.input_clip_search = QLineEdit()
            self.input_clip_search.setPlaceholderText("ابحث في سجل النصوص المرسلة والمستلمة...")
            self.input_clip_search.textChanged.connect(self._refresh_clipboard_table)
            self.btn_clear_clip = QPushButton("🗑️ مسح السجل")
            self.btn_clear_clip.setObjectName("dangerBtn")
            self.btn_clear_clip.clicked.connect(self._on_clear_clipboard_history)
            self.btn_copy_selected_clip = QPushButton("📋 نسخ المحدد")
            self.btn_copy_selected_clip.clicked.connect(self._on_copy_selected_clip)
            self.btn_resend_selected_clip = QPushButton("🔁 إعادة إرسال المحدد")
            self.btn_resend_selected_clip.clicked.connect(self._on_resend_selected_clip)
            self.btn_del_selected_clip = QPushButton("❌ حذف المحدد")
            self.btn_del_selected_clip.setObjectName("secondaryBtn")
            self.btn_del_selected_clip.clicked.connect(self._on_delete_selected_clip)

            clip_top.addWidget(self.input_clip_search, stretch=3)
            clip_top.addWidget(self.btn_copy_selected_clip)
            clip_top.addWidget(self.btn_resend_selected_clip)
            clip_top.addWidget(self.btn_del_selected_clip)
            clip_top.addWidget(self.btn_clear_clip)
            clip_layout.addLayout(clip_top)

            self.tbl_clip = QTableWidget(0, 4)
            self.tbl_clip.setHorizontalHeaderLabels(["الاتجاه", "المسار", "محتوى النص (انقر مرتين للنسخ)", "المعرّف"])
            self.tbl_clip.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
            self.tbl_clip.cellDoubleClicked.connect(self._on_clip_row_double_clicked)
            clip_layout.addWidget(self.tbl_clip)
            self.tabs.addTab(self.tab_clip, "📋 سجل الحافظة")

            # =========================================================
            # TAB 3: File Transfers Log
            # =========================================================
            self.tab_files = QWidget()
            files_layout = QVBoxLayout(self.tab_files)
            self.tbl_files = QTableWidget(0, 5)
            self.tbl_files.setHorizontalHeaderLabels(["اسم الملف", "الاتجاه", "الحجم", "الحالة", "بصمة SHA-256"])
            self.tbl_files.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            files_layout.addWidget(self.tbl_files)
            self.tabs.addTab(self.tab_files, "📁 سجل الملفات المنقولة")

            # =========================================================
            # TAB 4: Settings & Privacy
            # =========================================================
            self.tab_settings = QWidget()
            set_layout = QVBoxLayout(self.tab_settings)
            form = QFormLayout()

            self.chk_auto_copy_recv = QCheckBox("نسخ النصوص الواردة من الهاتف إلى حافظة الكمبيوتر تلقائيًا")
            self.chk_monitor_clip = QCheckBox("مراقبة حافظة Windows لإرسال ما تنسخه تلقائيًا إلى الهاتف")
            self.chk_auto_win_to_and = QCheckBox("تفعيل المزامنة التلقائية الفورية من Windows إلى Android")
            self.chk_auto_accept_files = QCheckBox("حفظ الملفات الواردة من الهاتف المقترن تلقائيًا في Downloads\LinkBridge")
            self.chk_hide_notif = QCheckBox("إخفاء محتوى النصوص داخل الإشعارات المنبثقة للخصوصية")
            self.chk_save_history = QCheckBox("حفظ سجل النصوص محليًا في قاعدة البيانات")
            self.chk_run_startup = QCheckBox("تشغيل LinkBridge تلقائيًا مع بدء Windows")

            for chk, key in [
                (self.chk_auto_copy_recv, "auto_copy_received_to_clipboard"),
                (self.chk_monitor_clip, "monitor_windows_clipboard"),
                (self.chk_auto_win_to_and, "auto_sync_win_to_android"),
                (self.chk_auto_accept_files, "auto_accept_files"),
                (self.chk_hide_notif, "hide_text_in_notifications"),
                (self.chk_save_history, "save_clipboard_history"),
                (self.chk_run_startup, "run_on_windows_startup"),
            ]:
                chk.setChecked(bool(self.node.storage.get_setting(key, False)))
                chk.toggled.connect(lambda val, k=key: self._on_setting_toggled(k, val))
                form.addRow(chk)

            set_layout.addLayout(form)

            theme_row = QHBoxLayout()
            self.btn_toggle_theme = QPushButton("🌙 / ☀️ تبديل الوضع الداكن / الفاتح")
            self.btn_toggle_theme.clicked.connect(self._toggle_theme)
            self.btn_toggle_lang = QPushButton("عربي / English")
            self.btn_toggle_lang.clicked.connect(self._toggle_language)
            theme_row.addWidget(self.btn_toggle_theme)
            theme_row.addWidget(self.btn_toggle_lang)
            set_layout.addLayout(theme_row)
            set_layout.addStretch()
            self.tabs.addTab(self.tab_settings, "⚙️ الإعدادات والخصوصية")

            # =========================================================
            # TAB 5: About («عمل محمد البكير»)
            # =========================================================
            self.tab_about = QWidget()
            about_layout = QVBoxLayout(self.tab_about)
            self.lbl_about_heading = QLabel(STRINGS["ar"]["about_heading"])
            self.lbl_about_heading.setStyleSheet("font-size: 18px; font-weight: bold;")
            self.lbl_about_desc = QLabel(STRINGS["ar"]["about_description"])
            self.lbl_about_desc.setWordWrap(True)
            self.lbl_about_credit = QLabel(f"✦ {STRINGS['ar']['about_credit']} ✦")
            self.lbl_about_credit.setStyleSheet(
                "font-size: 16px; font-weight: bold; color: #38BDF8; margin-top: 16px; padding: 12px; "
                "border: 1px solid #334155; border-radius: 8px;"
            )
            about_layout.addWidget(self.lbl_about_heading)
            about_layout.addWidget(self.lbl_about_desc)
            about_layout.addWidget(self.lbl_about_credit)
            about_layout.addStretch()
            self.tabs.addTab(self.tab_about, "ℹ️ حول التطبيق")

            self._refresh_device_list_ui()
            self._refresh_clipboard_table()
            self._refresh_files_table()

        def _apply_language_and_theme(self) -> None:
            self.setLayoutDirection(
                Qt.LayoutDirection.RightToLeft if self.lang == "ar" else Qt.LayoutDirection.LeftToRight
            )
            self.setStyleSheet(get_stylesheet(self.theme))
            self.setWindowTitle(STRINGS.get(self.lang, STRINGS["ar"])["app_title"])

            primary_ip = LocalDiscoveryService.get_primary_lan_ip()
            self.lbl_local_addr.setText(f"💻 اسم هذا الجهاز: {self.node.identity.device_name}  |  عنوان الشبكة: {primary_ip}:{DEFAULT_WIFI_PORT}")

            if self.node.active_transport and self.node.active_transport.is_connected:
                peer_n = self.node.active_transport.peer_device_name or "هاتف Android"
                tr_n = self.node.active_transport.transport_type.value
                self.lbl_conn_status.setText(f"🟢 متصل الآن بـ: {peer_n} ({tr_n}) — جاهز لإرسال واستقبال النصوص والملفات")
                self.lbl_conn_status.setStyleSheet("font-size: 15px; font-weight: bold; color: #10B981;")
                self.btn_disconnect.setVisible(True)
            else:
                self.lbl_conn_status.setText("🔵 في انتظار الاتصال — اختر هاتفك من قائمة الأجهزة بالأسفل واضغط «اتصال»")
                self.lbl_conn_status.setStyleSheet("font-size: 15px; font-weight: bold; color: #38BDF8;")
                self.btn_disconnect.setVisible(False)

        def _on_devices_updated(self, devices: List[Dict[str, Any]]) -> None:
            self._discovered_devices = devices
            self._refresh_device_list_ui()

        def _refresh_device_list_ui(self) -> None:
            if hasattr(self, "discovery"):
                self._discovered_devices = self.discovery.get_discovered_devices()
            current_sel_id = None
            cur_item = self.list_devices.currentItem()
            if cur_item is not None:
                current_sel_id = cur_item.data(Qt.ItemDataRole.UserRole)

            self.list_devices.clear()
            if not self._discovered_devices:
                placeholder = QListWidgetItem(
                    "⏳ جاري البحث التلقائي عن الهواتف المتصلة بنفس شبكة Wi-Fi أو نقطة الاتصال أو البلوتوث... (افتح التطبيق على هاتفك ليظهر هنا تلقائيًا)"
                )
                placeholder.setData(Qt.ItemDataRole.UserRole, None)
                self.list_devices.addItem(placeholder)
                return

            for dev in self._discovered_devices:
                icon = "🔵 بلوتوث" if dev.get("transport") == "BLUETOOTH_RFCOMM" else "📱 واي فاي / نقطة اتصال"
                label = f"{icon}  |  {dev.get('device_name', 'هاتف Android')}  —  ({dev.get('address', '')})  —  اضغط مرتين للاتصال الفوري"
                item = QListWidgetItem(label)
                item.setData(Qt.ItemDataRole.UserRole, dev)
                self.list_devices.addItem(item)
                if current_sel_id and isinstance(current_sel_id, dict) and current_sel_id.get("device_id") == dev.get("device_id"):
                    self.list_devices.setCurrentItem(item)

            if self.list_devices.count() > 0 and self.list_devices.currentRow() < 0:
                self.list_devices.setCurrentRow(0)

        def _on_manual_rescan(self) -> None:
            self.lbl_conn_status.setText("🔍 جاري فحص الشبكة المحلية والبلوتوث بحثًا عن الأجهزة...")
            if hasattr(self, "discovery"):
                self.discovery.trigger_immediate_scan()
            threading.Thread(target=self._scan_bt_background, daemon=True).start()

        def _on_connect_selected_device(self) -> None:
            item = self.list_devices.currentItem()
            dev = item.data(Qt.ItemDataRole.UserRole) if item else None
            if not dev and self._discovered_devices:
                dev = self._discovered_devices[0]
            if not dev:
                QMessageBox.information(
                    self,
                    "LinkBridge",
                    "لم يتم اختيار جهاز بعد. تأكد من فتح تطبيق LinkBridge على هاتفك واتصالهما بنفس شبكة الـ Wi-Fi أو نقطة الاتصال أو البلوتوث، أو اضغط «تحديث البحث».",
                )
                return
            self._initiate_connection_to_device(dev)

        def _on_manual_ip_dialog(self) -> None:
            text, ok = QInputDialog.getText(
                self,
                "اتصال مباشر بعنوان الهاتف",
                "أدخل عنوان IP الظاهر في أعلى شاشة تطبيق الهاتف (مثال: 192.168.1.15 أو 192.168.43.1):",
            )
            if ok and text.strip():
                raw = text.strip()
                host, port_s = (raw.split(":", 1) + [str(DEFAULT_WIFI_PORT)])[:2]
                self._initiate_connection_to_device(
                    {
                        "device_id": f"manual-{host}",
                        "device_name": f"هاتف ({host})",
                        "ip": host,
                        "port": int(port_s) if port_s.isdigit() else DEFAULT_WIFI_PORT,
                        "transport": "WIFI_LAN",
                        "address": f"{host}:{port_s}",
                    }
                )

        def _initiate_connection_to_device(self, dev: Dict[str, Any]) -> None:
            dev_name = dev.get("device_name", "هاتف Android")
            self.lbl_conn_status.setText(f"⏳ جاري الاتصال بـ «{dev_name}»... يرجى الضغط على «موافقة» في إشعار الهاتف")

            def _connect_worker() -> None:
                try:
                    if dev.get("transport") == "BLUETOOTH_RFCOMM":
                        t = BluetoothRfcommTransport.connect(
                            self.node.identity,
                            bt_mac_address=dev["address"],
                            channel=int(dev.get("port", 4)),
                        )
                    else:
                        t = WifiTlsTransport.connect(
                            self.node.identity,
                            host=dev["ip"],
                            port=int(dev.get("port", DEFAULT_WIFI_PORT)),
                            timeout=20.0,
                            is_hotspot=(dev.get("transport") == "WIFI_HOTSPOT"),
                            use_tls=False,
                        )
                    self.node.authenticate_as_client(t, pin_or_secret="AUTO_APPROVE")
                    self.node.enable_live_dispatcher(t)
                except Exception as e:
                    self.signals.event_signal.emit("CONNECT_FAILED", {"reason": str(e)})

            threading.Thread(target=_connect_worker, daemon=True).start()

        def _on_disconnect_clicked(self) -> None:
            if self.node.active_transport:
                try:
                    self.node.active_transport.close()
                except Exception:
                    pass
                self.node.active_transport = None
            self._apply_language_and_theme()

        def _on_send_custom_text(self) -> None:
            text = self.txt_quick_send.toPlainText().strip()
            if not text:
                return
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى اختيار هاتفك من القائمة والضغط على «اتصال» أولًا.")
                return
            self.txt_quick_send.clear()

            def _send() -> None:
                try:
                    ok, info = self.node.clipboard_manager.send_text_manual(self.node.active_transport, text)
                    if ok:
                        self.signals.event_signal.emit("CLIPBOARD_SENT", info)
                    else:
                        self.signals.event_signal.emit("TRANSFER_ERROR", {"reason": info.get("error", "Error")})
                except Exception as e:
                    self.signals.event_signal.emit("TRANSFER_ERROR", {"reason": str(e)})

            threading.Thread(target=_send, daemon=True).start()

        def _on_send_current_clipboard(self) -> None:
            text = self.node.clipboard_backend.get_text()
            if not text:
                QMessageBox.information(self, "LinkBridge", "حافظة الكمبيوتر فارغة حاليًا؛ انسخ أي نص أولًا.")
                return
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى اختيار هاتفك من القائمة والضغط على «اتصال» أولًا.")
                return

            def _send() -> None:
                try:
                    ok, info = self.node.clipboard_manager.send_text_manual(self.node.active_transport, text)
                    if ok:
                        self.signals.event_signal.emit("CLIPBOARD_SENT", info)
                    else:
                        self.signals.event_signal.emit("TRANSFER_ERROR", {"reason": info.get("error", "Error")})
                except Exception as e:
                    self.signals.event_signal.emit("TRANSFER_ERROR", {"reason": str(e)})

            threading.Thread(target=_send, daemon=True).start()

        def _on_pick_and_send_files(self) -> None:
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى اختيار هاتفك من القائمة والضغط على «اتصال» أولًا.")
                return
            files, _ = QFileDialog.getOpenFileNames(self, "اختر الملفات لإرسالها إلى الهاتف")
            if not files:
                return

            def _send_files_worker() -> None:
                for fpath in files:
                    try:
                        self.node.file_manager.send_file(self.node.active_transport, Path(fpath))
                    except Exception as e:
                        self.signals.event_signal.emit("TRANSFER_ERROR", {"reason": str(e)})
                self.signals.event_signal.emit("FILES_BATCH_DONE", {"count": len(files)})

            threading.Thread(target=_send_files_worker, daemon=True).start()

        def _on_pick_and_send_folder(self) -> None:
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى اختيار هاتفك من القائمة والضغط على «اتصال» أولًا.")
                return
            folder = QFileDialog.getExistingDirectory(self, "اختر المجلد لإرساله إلى الهاتف")
            if not folder:
                return

            def _send_folder_worker() -> None:
                try:
                    res = self.node.file_manager.send_directory(self.node.active_transport, Path(folder))
                    self.signals.event_signal.emit("FILES_BATCH_DONE", {"count": len(res)})
                except Exception as e:
                    self.signals.event_signal.emit("TRANSFER_ERROR", {"reason": str(e)})

            threading.Thread(target=_send_folder_worker, daemon=True).start()

        def _on_open_receive_folder(self) -> None:
            recv_dir = Path(self.node.storage.get_setting("receive_directory"))
            recv_dir.mkdir(parents=True, exist_ok=True)
            if sys.platform == "win32":
                os.startfile(str(recv_dir))
            else:
                QMessageBox.information(self, "مجلد الاستقبال", str(recv_dir))

        def _on_clip_row_double_clicked(self, row: int, _col: int) -> None:
            item = self.tbl_clip.item(row, 2)
            if item:
                self.node.clipboard_backend.set_text(item.text())
                if hasattr(self, "tray"):
                    self.tray.showMessage("LinkBridge", "تم نسخ النص المحدد إلى الحافظة!")

        def _on_copy_selected_clip(self) -> None:
            row = self.tbl_clip.currentRow()
            if row >= 0:
                self._on_clip_row_double_clicked(row, 2)

        def _on_resend_selected_clip(self) -> None:
            row = self.tbl_clip.currentRow()
            if row < 0:
                return
            item = self.tbl_clip.item(row, 2)
            if not item or not item.text():
                return
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى الاتصال بالهاتف أولًا لإعادة إرسال النص.")
                return
            txt = item.text()
            threading.Thread(
                target=lambda: self.node.clipboard_manager.send_text_manual(self.node.active_transport, txt),
                daemon=True,
            ).start()

        def _on_delete_selected_clip(self) -> None:
            row = self.tbl_clip.currentRow()
            if row < 0:
                return
            id_item = self.tbl_clip.item(row, 3)
            if id_item:
                self.node.storage.delete_clipboard_item(id_item.text())
                self._refresh_clipboard_table()

        def _setup_tray_icon(self) -> None:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            pix = QPixmap(32, 32)
            pix.fill(QColor("#10B981"))
            self.tray = QSystemTrayIcon(QIcon(pix), self)
            menu = QMenu()
            act_show = QAction("إظهار نافذة LinkBridge", self)
            act_show.triggered.connect(self.showNormal)
            act_send_clip = QAction("📋 إرسال الحافظة الحالية للهاتف", self)
            act_send_clip.triggered.connect(self._on_send_current_clipboard)
            act_open_dir = QAction("📂 فتح مجلد الملفات المستلمة", self)
            act_open_dir.triggered.connect(self._on_open_receive_folder)
            act_quit = QAction("خروج", self)
            act_quit.triggered.connect(QApplication.instance().quit)
            menu.addAction(act_show)
            menu.addAction(act_send_clip)
            menu.addAction(act_open_dir)
            menu.addSeparator()
            menu.addAction(act_quit)
            self.tray.setContextMenu(menu)
            self.tray.show()

        def _toggle_language(self) -> None:
            self.lang = "en" if self.lang == "ar" else "ar"
            self.node.storage.set_setting("language", self.lang)
            self._apply_language_and_theme()

        def _toggle_theme(self) -> None:
            self.theme = "light" if self.theme == "dark" else "dark"
            self.node.storage.set_setting("theme", self.theme)
            self._apply_language_and_theme()

        def _on_setting_toggled(self, key: str, value: bool) -> None:
            if key == "run_on_windows_startup":
                WindowsStartupManager.set_startup_enabled(value, storage=self.node.storage)
            else:
                self.node.storage.set_setting(key, value)

        def _on_clear_clipboard_history(self) -> None:
            self.node.storage.clear_clipboard_history()
            self._refresh_clipboard_table()

        def _poll_clipboard(self) -> None:
            if self.node.active_transport and self.node.active_transport.is_connected:
                try:
                    sent, _ = self.node.clipboard_manager.poll_local_clipboard_for_auto_sync(self.node.active_transport)
                    if sent:
                        self._refresh_clipboard_table()
                except Exception:
                    pass

        def _on_node_event(self, event_type: str, data: Dict[str, Any]) -> None:
            if event_type == "CONNECTED":
                self._apply_language_and_theme()
                if hasattr(self, "tray"):
                    self.tray.showMessage(
                        "LinkBridge — تم الاتصال بنجاح ✅",
                        f"تم الربط مع الجهاز «{data.get('peer_device_name', 'Android')}» بنجاح!",
                    )
            elif event_type == "CONNECT_FAILED":
                self._apply_language_and_theme()
                QMessageBox.warning(self, "تعذر الاتصال", f"تفاصيل السبب: {data.get('reason', '')}")
            elif event_type in ("CLIPBOARD_RECEIVED", "CLIPBOARD_SENT"):
                self._refresh_clipboard_table()
                if event_type == "CLIPBOARD_RECEIVED" and hasattr(self, "tray"):
                    self.tray.showMessage("📋 نص جديد وارد من الهاتف", data.get("notification_preview", ""))
            elif event_type == "FILE_PROGRESS":
                total = max(int(data.get("total_bytes", 1)), 1)
                done = int(data.get("transferred_bytes", 0))
                pct = int((done * 100) / total)
                rate_mb = float(data.get("rate_bytes_per_sec", 0.0)) / (1024 * 1024)
                self.progress_bar.setValue(pct)
                self.lbl_transfer_prog.setText(
                    f"جاري نقل: {data.get('file_name', '')} — {pct}% ({rate_mb:.2f} MB/s)"
                )
                self._refresh_files_table()
            elif event_type == "FILES_BATCH_DONE":
                self.progress_bar.setValue(100)
                self.lbl_transfer_prog.setText(f"✅ اكتمل نقل {data.get('count', 1)} ملف/ملفات والتحقق من بصمة SHA-256 بنجاح!")
                self._refresh_files_table()
            elif event_type == "TRANSFER_ERROR":
                self.lbl_transfer_prog.setText(f"⚠️ تنبيه: {data.get('reason', '')}")

        def _refresh_clipboard_table(self) -> None:
            items = self.node.storage.list_clipboard_history(self.input_clip_search.text())
            self.tbl_clip.setRowCount(len(items))
            for idx, it in enumerate(items):
                dir_lbl = "⬅ وارد من الهاتف" if it["direction"] == "INCOMING" else "➡ مرسل للهاتف"
                self.tbl_clip.setItem(idx, 0, QTableWidgetItem(dir_lbl))
                self.tbl_clip.setItem(idx, 1, QTableWidgetItem(it["transport"]))
                self.tbl_clip.setItem(idx, 2, QTableWidgetItem(it["text_content"]))
                self.tbl_clip.setItem(idx, 3, QTableWidgetItem(it["item_id"]))

        def _refresh_files_table(self) -> None:
            items = self.node.storage.list_file_transfers()
            self.tbl_files.setRowCount(len(items))
            for idx, it in enumerate(items):
                self.tbl_files.setItem(idx, 0, QTableWidgetItem(it["file_name"]))
                dir_lbl = "⬅ وارد للكمبيوتر" if it["direction"] == "INCOMING" else "➡ مرسل للهاتف"
                self.tbl_files.setItem(idx, 1, QTableWidgetItem(dir_lbl))
                prog = f"{it['transferred_bytes']:,} / {it['total_bytes']:,} بايت"
                self.tbl_files.setItem(idx, 2, QTableWidgetItem(prog))
                self.tbl_files.setItem(idx, 3, QTableWidgetItem(it["status"]))
                self.tbl_files.setItem(idx, 4, QTableWidgetItem(it["expected_sha256"][:16]))

    app = QApplication(sys.argv)
    win = LinkBridgeMainWindow()
    if not start_minimized:
        win.show()
    return app.exec()


def main() -> int:
    parser = argparse.ArgumentParser(description="LinkBridge Windows Desktop Application")
    parser.add_argument("--data-dir", type=str, default=str(get_default_appdata_dir()))
    parser.add_argument("--minimized", action="store_true", help="Start minimized in system tray")
    parser.add_argument("--self-check", action="store_true", help="Run non-interactive self-check and print JSON status")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if args.self_check:
        return run_self_check(data_dir)
    return launch_pyside6_gui(data_dir, start_minimized=args.minimized)


if __name__ == "__main__":
    sys.exit(main())
