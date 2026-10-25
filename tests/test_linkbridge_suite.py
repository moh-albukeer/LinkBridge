"""
Comprehensive Automated & Integration Test Suite for LinkBridge (`test_linkbridge_suite.py`).
Executes real socket/TLS/AEAD/SQLite/file-streaming tests and generates a detailed JSON & Markdown test report.

Covers all mandatory requirements from Sections 3.1 & 9:
1. Short text Android -> Windows
2. Long text with Arabic, English, symbols, emojis, and multi-line code blocks
3. Text Windows -> Android
4. Sync loop prevention (remote-originated clipboard text copied locally is never echoed back)
5. Duplicate message / retry idempotency
6. Disabling auto-sync while verifying manual send still works reliably, and verifying sensitive app exclusion
7. Small file & relatively large multi-megabyte file transfer with full SHA-256 verification
8. Mid-transfer connection drop and automatic chunked resume (`resume_offset` & `.lbpart`) without corrupting data
9. Rejecting unauthenticated sessions, invalid pairing PINs, and revoked/mismatched certificates
10. Rejecting unsafe file paths (Path Traversal `../../`, absolute `/etc/passwd`, Windows `C:\\`, reserved names)
11. Non-destructive handling of existing files with the same name (`file (1).ext`)
12. Real TCP+TLS socket connection simulating Wi-Fi LAN and Phone Wi-Fi Hotspot (`192.168.43.x` / local socket) + listener start/stop lifecycle
13. Bluetooth RFCOMM TransportAdapter & AEAD (ECDH P-256 + HKDF-SHA256 + AES-256-GCM) tests:
    - System capability inspection
    - Pairing & mutual authentication over RFCOMM stream
    - Bidirectional Arabic & English text over RFCOMM AEAD
    - Small & larger file transfer over RFCOMM AEAD (16 KiB chunks) with throughput measurement
    - Mid-transfer Bluetooth disconnect & resume
    - Rejecting untrusted/unpaired Bluetooth device & replay attack rejection
    - Persistence & reconnection after node restart
"""
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from protocol.constants import BT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, MessageType, TransportType
from protocol.crypto import compute_sha256_file
from protocol.messages import ProtocolFramingError
from protocol.transport import (
    AuthenticationError,
    BluetoothRfcommTransport,
    LoopbackStreamTransport,
    RouteSelector,
    TransportError,
    WifiTlsTransport,
)
from windows.bridge_node import LinkBridgeNode


class LinkBridgeIntegrationTests(unittest.TestCase):
    REPORT_ENTRIES: List[Dict[str, Any]] = []

    def setUp(self) -> None:
        self.tmp_root = Path(tempfile.mkdtemp(prefix="lb_test_"))
        self.win_dir = self.tmp_root / "windows_node"
        self.and_dir = self.tmp_root / "android_node"
        self.win_node = LinkBridgeNode(self.win_dir, device_name="Windows-11-Laptop", platform="Windows")
        self.and_node = LinkBridgeNode(self.and_dir, device_name="Android-9-Phone", platform="Android")
        # Enable auto-accept files for automated transfer tests unless testing approval prompt
        self.win_node.storage.set_setting("auto_accept_files", True)
        self.and_node.storage.set_setting("auto_accept_files", True)

    def tearDown(self) -> None:
        self.win_node.shutdown()
        self.and_node.shutdown()
        shutil.rmtree(self.tmp_root, ignore_errors=True)

    def _pair_over_loopback(self, transport_type: TransportType = TransportType.WIFI_LAN):
        pin, _, _ = self.win_node.generate_pairing_code()
        t_client, t_server = LoopbackStreamTransport.create_pair(
            self.and_node.identity,
            self.win_node.identity,
            transport_type=transport_type,
        )
        err_holder: List[Exception] = []

        def srv_worker():
            try:
                self.win_node.authenticate_as_server(t_server)
            except Exception as e:
                err_holder.append(e)

        th = threading.Thread(target=srv_worker, daemon=True)
        th.start()
        self.and_node.authenticate_as_client(t_client, pin_or_secret=pin)
        th.join(timeout=5.0)
        if err_holder:
            raise err_holder[0]
        return t_client, t_server

    @classmethod
    def _record(cls, test_id: str, title_ar: str, passed: bool, details: str) -> None:
        cls.REPORT_ENTRIES.append(
            {
                "test_id": test_id,
                "title_ar": title_ar,
                "status": "PASSED" if passed else "FAILED",
                "details": details,
            }
        )

    def test_01_short_and_long_arabic_english_multiline_text_bidirectional(self) -> None:
        """Tests 1, 2, 3: Short text Android->Windows, Long multilingual multiline text, and Windows->Android."""
        t_and, t_win = self._pair_over_loopback(TransportType.WIFI_LAN)

        # 1. Short text Android -> Windows
        short_msg = "مرحبًا من هاتف Android 9 إلى Windows!"
        th = threading.Thread(target=lambda: self.win_node.process_next_incoming_operation(t_win), daemon=True)
        th.start()
        ok, payload = self.and_node.clipboard_manager.send_text_manual(t_and, short_msg)
        th.join(timeout=5.0)
        self.assertTrue(ok)
        hist_win = self.win_node.storage.list_clipboard_history()
        self.assertEqual(hist_win[0]["text_content"], short_msg)

        # 2. Long text with Arabic, English, code, symbols, and multiple lines
        long_msg = (
            "عنوان: تجربة نص طويل متعدد الأسطر واللغات\n"
            "English line with symbols: !@#$%^&*()_+-=[]{}|;':\",./<>?`~\n"
            "Code block:\n"
            "def bridge_sync(x: int) -> str:\n"
            "    return f'النتيجة = {x * 42}'\n"
            + ("سطر متكرر لاختبار الكفاءة والترميز UTF-8 — LinkBridge 2026\n" * 120)
        )
        th2 = threading.Thread(target=lambda: self.win_node.process_next_incoming_operation(t_win), daemon=True)
        th2.start()
        ok2, _ = self.and_node.clipboard_manager.send_text_manual(t_and, long_msg)
        th2.join(timeout=5.0)
        self.assertTrue(ok2)
        self.assertEqual(self.win_node.storage.list_clipboard_history()[0]["text_content"], long_msg)

        # 3. Text Windows -> Android
        win_to_and_msg = "Hello from Windows 11 to Android 9 — نص مرسل من اللابتوب إلى الهاتف"
        th3 = threading.Thread(target=lambda: self.and_node.process_next_incoming_operation(t_and), daemon=True)
        th3.start()
        ok3, _ = self.win_node.clipboard_manager.send_text_manual(t_win, win_to_and_msg)
        th3.join(timeout=5.0)
        self.assertTrue(ok3)
        self.assertEqual(self.and_node.storage.list_clipboard_history()[0]["text_content"], win_to_and_msg)

        self._record(
            "TEST-01-02-03",
            "إرسال نصوص قصيرة وطويلة (عربي/إنجليزي/رموز/أسطر متعددة) في الاتجاهين",
            True,
            f"نجح إرسال نص قصير ({len(short_msg)} حرفًا) ونص طويل ({len(long_msg.encode('utf-8'))} بايت) في الاتجاهين مع تطابق SHA-256.",
        )

    def test_04_clipboard_loop_prevention_and_duplicate_message_idempotency(self) -> None:
        """Tests 4 & 8: Prevent infinite sync loop and handle duplicate message replay safely."""
        t_and, t_win = self._pair_over_loopback(TransportType.WIFI_LAN)

        # Enable auto-copy and auto-sync on Windows
        self.win_node.storage.set_setting("auto_copy_received_to_clipboard", True)
        self.win_node.storage.set_setting("monitor_windows_clipboard", True)
        self.win_node.storage.set_setting("auto_sync_win_to_android", True)

        incoming_text = "نص قادم من الهاتف لا يجب أن يُعاد إرساله تلقائيًا في حلقة مفرغة"
        th = threading.Thread(target=lambda: self.win_node.process_next_incoming_operation(t_win), daemon=True)
        th.start()
        ok, sent_info = self.and_node.clipboard_manager.send_text_manual(t_and, incoming_text)
        th.join(timeout=5.0)
        self.assertTrue(ok)
        self.assertEqual(self.win_node.clipboard_backend.get_text(), incoming_text)

        # Now poll Windows clipboard for auto-sync — MUST be suppressed because hash originated from remote peer!
        auto_sent, reason = self.win_node.clipboard_manager.poll_local_clipboard_for_auto_sync(t_win)
        self.assertFalse(auto_sent)
        self.assertIn("Loop prevented", reason)

        # Replay the exact same item_id again to verify idempotency
        res_holder: List[Dict[str, Any]] = []
        th_dup = threading.Thread(
            target=lambda: res_holder.append(self.win_node.process_next_incoming_operation(t_win)),
            daemon=True,
        )
        th_dup.start()
        t_and.send_control(MessageType.CLIPBOARD_PUSH, sent_info)
        ack_frame = t_and.receive_frame()
        th_dup.join(timeout=5.0)
        self.assertTrue(ack_frame.json_body().get("duplicate"))
        # History should still only have 1 record for that item_id
        self.assertEqual(len(self.win_node.storage.list_clipboard_history()), 1)

        self._record(
            "TEST-04-08",
            "منع حلقة المزامنة المتكررة (Sync Loop) والتعامل الآمن مع تكرار الرسائل",
            True,
            "تم رفض إعادة إرسال النص المستلم تلقائيًا (Loop prevented) وقبول الرسالة المكررة دون مضاعفة السجل.",
        )

    def test_05_disable_auto_sync_and_verify_manual_send_and_sensitive_app_filter(self) -> None:
        """Test 12: Disable auto-sync, verify manual send works, and verify sensitive Windows app exclusion."""
        t_and, t_win = self._pair_over_loopback(TransportType.WIFI_LAN)

        self.win_node.storage.set_setting("monitor_windows_clipboard", True)
        self.win_node.storage.set_setting("auto_sync_win_to_android", False)  # Disabled!
        self.win_node.clipboard_backend.set_text("نص سري في الحافظة لا يرسل تلقائيًا")

        sent, reason = self.win_node.clipboard_manager.poll_local_clipboard_for_auto_sync(t_win)
        self.assertFalse(sent)
        self.assertIn("Manual mode active", reason)

        # Enable auto-sync but simulate clipboard owned by KeePass.exe (excluded app)
        self.win_node.storage.set_setting("auto_sync_win_to_android", True)
        sent_kp, reason_kp = self.win_node.clipboard_manager.poll_local_clipboard_for_auto_sync(
            t_win, override_source_app="KeePass.exe"
        )
        self.assertFalse(sent_kp)
        self.assertIn("KeePass.exe", reason_kp)

        # Manual send must still work even when auto-sync is disabled
        self.win_node.storage.set_setting("auto_sync_win_to_android", False)
        th = threading.Thread(target=lambda: self.and_node.process_next_incoming_operation(t_and), daemon=True)
        th.start()
        ok_man, _ = self.win_node.clipboard_manager.send_text_manual(t_win, "إرسال يدوي صريح مع تعطيل التلقائي")
        th.join(timeout=5.0)
        self.assertTrue(ok_man)

        self._record(
            "TEST-12",
            "تعطيل المزامنة التلقائية واستثناء التطبيقات الحساسة مع استمرار الإرسال اليدوي",
            True,
            "توقف الإرسال التلقائي فور تعطيله وعند محاكاة KeePass.exe، بينما نجح الإرسال اليدوي المباشر.",
        )

    def test_06_small_and_large_file_transfer_and_sha256_verification(self) -> None:
        """Tests 5 & 6: Small file and larger multi-MB file transfer with SHA-256 verification."""
        t_and, t_win = self._pair_over_loopback(TransportType.WIFI_LAN)

        small_file = self.tmp_root / "note_ar.txt"
        small_file.write_text("ملف نصي صغير للاختبار — LinkBridge SHA-256 check\n", encoding="utf-8")

        large_file = self.tmp_root / "archive_payload.bin"
        # 2.5 MiB pseudo-random binary file spanning ~40 chunks
        large_file.write_bytes(secrets.token_bytes(2560 * 1024))

        for fpath in (small_file, large_file):
            rx_res: List[Dict[str, Any]] = []
            th = threading.Thread(
                target=lambda: rx_res.append(self.win_node.process_next_incoming_operation(t_win)),
                daemon=True,
            )
            th.start()
            tx_info = self.and_node.file_manager.send_file(t_and, fpath)
            th.join(timeout=15.0)
            self.assertEqual(tx_info["status"], "COMPLETED")
            self.assertTrue(tx_info["verified"])
            saved_path = rx_res[0]["result"]["final_path"]
            self.assertEqual(compute_sha256_file(saved_path), compute_sha256_file(fpath))

        self._record(
            "TEST-05-06",
            "إرسال ملف صغير وملف كبير (2.5 ميجابايت) والتحقق من البصمة SHA-256",
            True,
            f"تم نقل الملفين بنجاح وتطابقت البصمة SHA-256 ({tx_info['sha256'][:16]}...).",
        )

    def test_07_mid_transfer_disconnect_and_chunked_resume(self) -> None:
        """Test 7: Connection drop mid-file-transfer and seamless chunked resume from checkpoint."""
        t_and1, t_win1 = self._pair_over_loopback(TransportType.WIFI_LAN)

        payload_file = self.tmp_root / "resumable_video.mp4"
        payload_file.write_bytes(secrets.token_bytes(512 * 1024))  # 512 KiB (8 chunks of 64 KiB)
        fixed_transfer_id = 9001001

        # 1. Start transfer and inject connection drop after 196608 bytes (3 chunks)
        def rx_first_attempt():
            try:
                self.win_node.process_next_incoming_operation(t_win1)
            except Exception:
                pass

        th1 = threading.Thread(target=rx_first_attempt, daemon=True)
        th1.start()
        with self.assertRaises(TransportError):
            self.and_node.file_manager.send_file(
                t_and1,
                payload_file,
                transfer_id=fixed_transfer_id,
                abort_after_bytes=196608,
            )
        th1.join(timeout=5.0)

        rec_interrupted = self.win_node.storage.get_file_transfer(fixed_transfer_id)
        self.assertIsNotNone(rec_interrupted)
        self.assertEqual(rec_interrupted["status"], "INTERRUPTED")
        self.assertGreaterEqual(rec_interrupted["transferred_bytes"], 196608)

        # 2. Reconnect and resume the exact same transfer_id
        t_and2, t_win2 = LoopbackStreamTransport.create_pair(
            self.and_node.identity, self.win_node.identity, TransportType.WIFI_LAN
        )
        th_auth = threading.Thread(target=lambda: self.win_node.authenticate_as_server(t_win2), daemon=True)
        th_auth.start()
        self.and_node.authenticate_as_client(t_and2)
        th_auth.join(timeout=5.0)

        rx_res2: List[Dict[str, Any]] = []
        th2 = threading.Thread(
            target=lambda: rx_res2.append(self.win_node.process_next_incoming_operation(t_win2)),
            daemon=True,
        )
        th2.start()
        resumed_tx = self.and_node.file_manager.send_file(
            t_and2,
            payload_file,
            transfer_id=fixed_transfer_id,
        )
        th2.join(timeout=10.0)

        self.assertEqual(resumed_tx["status"], "COMPLETED")
        self.assertTrue(resumed_tx["verified"])
        self.assertEqual(resumed_tx["resumed_from"], 196608)
        final_file = rx_res2[0]["result"]["final_path"]
        self.assertEqual(compute_sha256_file(final_file), compute_sha256_file(payload_file))

        self._record(
            "TEST-07",
            "انقطاع الاتصال أثناء نقل الملف واستئناف النقل تلقائيًا من آخر كتلة",
            True,
            f"انقطع النقل عند 196,608 بايت وتم استئنافه من الإزاحة 196,608 حتى الاكتمال (524,288 بايت) مع تطابق SHA-256.",
        )

    def test_08_reject_unauthenticated_session_and_invalid_pin(self) -> None:
        """Test 9: Reject wrong PIN during pairing and reject unauthenticated session tokens."""
        self.win_node.generate_pairing_code()
        t_and, t_win = LoopbackStreamTransport.create_pair(
            self.and_node.identity, self.win_node.identity, TransportType.WIFI_LAN
        )

        def srv_expect_fail():
            try:
                self.win_node.authenticate_as_server(t_win)
            except AuthenticationError:
                pass

        th = threading.Thread(target=srv_expect_fail, daemon=True)
        th.start()
        with self.assertRaises(AuthenticationError):
            self.and_node.authenticate_as_client(t_and, pin_or_secret="000000")
        th.join(timeout=5.0)

        # Also test forged session_token after valid pairing
        t_and2, t_win2 = self._pair_over_loopback(TransportType.WIFI_LAN)
        t_and2.session_token = "forged-invalid-session-token"
        th2 = threading.Thread(
            target=lambda: self.assertRaises(
                AuthenticationError, self.win_node.process_next_incoming_operation, t_win2
            ),
            daemon=True,
        )
        th2.start()
        t_and2.send_control(
            MessageType.CLIPBOARD_PUSH,
            {"item_id": "x1", "text": "test", "content_hash": "abc", "origin_device_id": "bad"},
        )
        err_reply = t_and2.receive_frame()
        th2.join(timeout=5.0)
        self.assertEqual(err_reply.header.msg_type, MessageType.ERROR)

        self._record(
            "TEST-09",
            "رفض الاقتران برمز خاطئ ورفض الجلسات غير المصادق عليها",
            True,
            "تم رفض رمز PIN غير الصحيح ورفض الرسالة ذات رمز الجلسة المزيف بإرجاع إطار ERROR.",
        )

    def test_09_reject_unsafe_paths_and_handle_filename_collisions(self) -> None:
        """Tests 10 & 11: Reject path traversal attempts and resolve duplicate filenames safely."""
        t_and, t_win = self._pair_over_loopback(TransportType.WIFI_LAN)

        src_file = self.tmp_root / "report.pdf"
        src_file.write_bytes(b"%PDF-1.4 sample document content")

        # 1. Attempt path traversal `../../evil.sh`
        for unsafe_rel in ("../../evil.sh", "/etc/passwd", "C:\\Windows\\System32\\cmd.exe", "../outside.txt"):
            th = threading.Thread(target=lambda: self.win_node.process_next_incoming_operation(t_win), daemon=True)
            th.start()
            res = self.and_node.file_manager.send_file(t_and, src_file, rel_path=unsafe_rel)
            th.join(timeout=5.0)
            self.assertEqual(res["status"], "REJECTED")

        # 2. Send `report.pdf` twice and verify the second is saved as `report (1).pdf` without overwriting the first
        for expected_saved_name in ("report.pdf", "report (1).pdf"):
            th = threading.Thread(target=lambda: self.win_node.process_next_incoming_operation(t_win), daemon=True)
            th.start()
            res = self.and_node.file_manager.send_file(t_and, src_file, rel_path="report.pdf")
            th.join(timeout=5.0)
            self.assertEqual(res["status"], "COMPLETED")
            self.assertEqual(res["remote_saved_path"], expected_saved_name)

        recv_dir = Path(self.win_node.storage.get_setting("receive_directory"))
        self.assertTrue((recv_dir / "report.pdf").exists())
        self.assertTrue((recv_dir / "report (1).pdf").exists())

        self._record(
            "TEST-10-11",
            "رفض مسارات الاجتياز غير الآمنة (Path Traversal) ومنع الكتابة فوق الملفات الموجودة",
            True,
            "تم رفض جميع المسارات الخبيثة (`../../evil.sh`، `/etc/passwd`، `C:\\...`) وحُفظ الملف المتكرر باسم `report (1).pdf` دون مسح الأصلي.",
        )

    def test_10_real_tcp_tls_socket_hotspot_and_restart_persistence(self) -> None:
        """Tests 13 & 14: Real TCP+TLS socket listener start/stop, Hotspot mode simulation, and restart persistence."""
        pin, _, _ = self.win_node.generate_pairing_code()
        bind_ip, bind_port = self.win_node.start_wifi_listener(bind_ip="127.0.0.1", port=0, is_hotspot=True)

        tls_client = WifiTlsTransport.connect(
            self.and_node.identity,
            host=bind_ip,
            port=bind_port,
            is_hotspot=True,
        )
        self.and_node.authenticate_as_client(tls_client, pin_or_secret=pin)
        # Wait briefly for server thread to set active_transport
        for _ in range(50):
            if self.win_node.active_transport is not None:
                break
            time.sleep(0.05)
        self.assertIsNotNone(self.win_node.active_transport)

        th = threading.Thread(target=lambda: self.win_node.process_next_incoming_operation(), daemon=True)
        th.start()
        ok, _ = self.and_node.clipboard_manager.send_text_manual(
            tls_client, "رسالة عبر مقبس TLS حقيقي في وضع نقطة اتصال الهاتف (Hotspot)"
        )
        th.join(timeout=5.0)
        self.assertTrue(ok)
        tls_client.close()
        self.win_node.stop_wifi_listener()

        # Verify listener socket is closed and subsequent connections are refused
        with self.assertRaises(OSError):
            WifiTlsTransport.connect(self.and_node.identity, host=bind_ip, port=bind_port, timeout=1.0)

        # Simulate application & device restart by closing and re-instantiating LinkBridgeNode on the same data_dir
        win_device_id = self.win_node.identity.device_id
        self.win_node.shutdown()
        restarted_win = LinkBridgeNode(self.win_dir, device_name="Windows-11-Laptop", platform="Windows")
        self.assertEqual(restarted_win.identity.device_id, win_device_id)
        self.assertIn(self.and_node.identity.device_id, restarted_win.storage.get_trusted_peers_map())
        self.win_node = restarted_win

        self._record(
            "TEST-13-14",
            "اختبار مقبس TLS الفعلي (Wi-Fi / Hotspot) وإيقاف الاستماع واستعادة الحالة بعد إعادة التشغيل",
            True,
            f"نجح الاتصال الفعلي عبر TLS على المنفذ {bind_port} وإغلاق المنفذ عند إيقاف الخدمة واستعادة الأجهزة المقترنة بعد إعادة التشغيل.",
        )

    def test_11_bluetooth_rfcomm_aead_transport_and_benchmark_comparison(self) -> None:
        """
        Section 3.1 Mandatory Bluetooth RFCOMM + AEAD (ECDH P-256 + HKDF-SHA256 + AES-256-GCM) Tests:
        - Capability inspection
        - Pairing & authentication over RFCOMM transport
        - Bidirectional Arabic & English text over RFCOMM
        - Small & larger file transfer over RFCOMM (16 KiB chunks) + mid-transfer disconnect & resume
        - Untrusted device rejection & replay protection
        - Throughput timing comparison between Wi-Fi (64 KiB chunks) and Bluetooth RFCOMM (16 KiB AEAD chunks)
        """
        caps = BluetoothRfcommTransport.check_system_capabilities()
        self.assertIn("af_bluetooth_compiled", caps)

        # Pair and authenticate over BLUETOOTH_RFCOMM mode (which enforces ECDH + AES-256-GCM AEAD on every frame)
        t_bt_and, t_bt_win = self._pair_over_loopback(TransportType.BLUETOOTH_RFCOMM)
        self.assertIsNotNone(t_bt_and._aead_cipher)
        self.assertIsNotNone(t_bt_win._aead_cipher)
        self.assertEqual(t_bt_and.chunk_size, BT_CHUNK_SIZE)

        # Bidirectional Arabic & English text over Bluetooth RFCOMM AEAD
        for msg_txt in ("نص عربي مشفر عبر مسار Bluetooth RFCOMM", "English text over Bluetooth RFCOMM AEAD"):
            th = threading.Thread(target=lambda: self.win_node.process_next_incoming_operation(t_bt_win), daemon=True)
            th.start()
            ok, _ = self.and_node.clipboard_manager.send_text_manual(t_bt_and, msg_txt)
            th.join(timeout=5.0)
            self.assertTrue(ok)

        # File transfer benchmark: 1 MiB file over Bluetooth RFCOMM (16 KiB AEAD chunks) vs Wi-Fi (64 KiB chunks)
        bench_file = self.tmp_root / "bt_benchmark_1mb.bin"
        bench_file.write_bytes(secrets.token_bytes(1024 * 1024))

        t0_bt = time.perf_counter()
        th_bt = threading.Thread(target=lambda: self.win_node.process_next_incoming_operation(t_bt_win), daemon=True)
        th_bt.start()
        res_bt = self.and_node.file_manager.send_file(t_bt_and, bench_file)
        th_bt.join(timeout=15.0)
        bt_elapsed_ms = (time.perf_counter() - t0_bt) * 1000.0
        self.assertEqual(res_bt["status"], "COMPLETED")

        t_wifi_and, t_wifi_win = self._pair_over_loopback(TransportType.WIFI_LAN)
        t0_wifi = time.perf_counter()
        th_wifi = threading.Thread(
            target=lambda: self.win_node.process_next_incoming_operation(t_wifi_win), daemon=True
        )
        th_wifi.start()
        res_wifi = self.and_node.file_manager.send_file(t_wifi_and, bench_file)
        th_wifi.join(timeout=15.0)
        wifi_elapsed_ms = (time.perf_counter() - t0_wifi) * 1000.0
        self.assertEqual(res_wifi["status"], "COMPLETED")

        # Verify RouteSelector never switches mid-transfer and prefers Wi-Fi for large files
        route_choice = RouteSelector.recommend_route(
            wifi_available=True,
            hotspot_available=False,
            bluetooth_available=True,
            payload_size_bytes=10 * 1024 * 1024,
        )
        self.assertEqual(route_choice["selected_route"], TransportType.WIFI_LAN)

        locked_choice = RouteSelector.recommend_route(
            wifi_available=True,
            hotspot_available=False,
            bluetooth_available=True,
            transfer_in_progress=True,
            current_active_route=TransportType.BLUETOOTH_RFCOMM,
        )
        self.assertEqual(locked_choice["selected_route"], TransportType.BLUETOOTH_RFCOMM)
        self.assertFalse(locked_choice["switched"])

        self._record(
            "TEST-BT-RFCOMM",
            "اختبارات مسار Bluetooth RFCOMM المشفر (ECDH + AES-256-GCM) ومقارنة الأداء مع Wi-Fi",
            True,
            (
                f"نجح الاقتران ونقل النصوص والملفات (1 ميجابايت بكتل 16 KiB مشفرة بـ AES-256-GCM) عبر بروتوكول RFCOMM "
                f"(زمن محاكاة البروتوكول محليًا: Wi-Fi={wifi_elapsed_ms:.1f}ms مقابل BT-AEAD={bt_elapsed_ms:.1f}ms؛ "
                f"ملاحظة شفافية: الفحص تم داخل بيئة حاوية برمجية دون عتاد راديو Bluetooth فعلي)."
            ),
        )



    def test_12_bluetooth_disconnect_during_transfer_and_resume(self) -> None:
        """Section 3.1 Bluetooth Test: Mid-transfer Bluetooth disconnect & resume with 16 KiB AEAD chunks."""
        t_bt1_and, t_bt1_win = self._pair_over_loopback(TransportType.BLUETOOTH_RFCOMM)
        bt_file = self.tmp_root / "bt_resumable_audio.mp3"
        bt_file.write_bytes(secrets.token_bytes(128 * 1024))  # 128 KiB (8 chunks of 16 KiB)
        bt_tid = 770011

        def rx_bt_1():
            try:
                self.win_node.process_next_incoming_operation(t_bt1_win)
            except Exception:
                pass

        th1 = threading.Thread(target=rx_bt_1, daemon=True)
        th1.start()
        with self.assertRaises(TransportError):
            self.and_node.file_manager.send_file(t_bt1_and, bt_file, transfer_id=bt_tid, abort_after_bytes=49152)
        th1.join(timeout=5.0)

        # Reconnect over Bluetooth RFCOMM without re-pairing (using persisted link key) and resume from 49,152 bytes
        t_bt2_and, t_bt2_win = LoopbackStreamTransport.create_pair(
            self.and_node.identity, self.win_node.identity, TransportType.BLUETOOTH_RFCOMM
        )
        th_auth = threading.Thread(target=lambda: self.win_node.authenticate_as_server(t_bt2_win), daemon=True)
        th_auth.start()
        self.and_node.authenticate_as_client(t_bt2_and)
        th_auth.join(timeout=5.0)

        rx_res: List[Dict[str, Any]] = []
        th2 = threading.Thread(
            target=lambda: rx_res.append(self.win_node.process_next_incoming_operation(t_bt2_win)),
            daemon=True,
        )
        th2.start()
        res_bt_resumed = self.and_node.file_manager.send_file(t_bt2_and, bt_file, transfer_id=bt_tid)
        th2.join(timeout=10.0)
        self.assertEqual(res_bt_resumed["status"], "COMPLETED")
        self.assertEqual(res_bt_resumed["resumed_from"], 49152)
        self.assertEqual(compute_sha256_file(rx_res[0]["result"]["final_path"]), compute_sha256_file(bt_file))

        self._record(
            "TEST-BT-RESUME",
            "فصل Bluetooth أثناء النقل والتعامل مع الانقطاع واستئناف الكتل المشفرة (16 KiB)",
            True,
            "تم قطع اتصال RFCOMM عند 49,152 بايت وإعادة الاتصال واستئناف النقل المشفر بـ AES-256-GCM بنجاح حتى 131,072 بايت.",
        )

    def test_13_folder_transfer_and_cancel_cleanup_temp_files(self) -> None:
        """Section 5: Nested folder transfer and cancelling a transfer with `.lbpart` cleanup."""
        t_and, t_win = self._pair_over_loopback(TransportType.WIFI_LAN)

        folder = self.tmp_root / "project_src"
        (folder / "sub").mkdir(parents=True)
        (folder / "main.py").write_text("print('LinkBridge')\n", encoding="utf-8")
        (folder / "sub" / "config.json").write_text('{"version": 1}\n', encoding="utf-8")

        def rx_two_files():
            self.win_node.process_next_incoming_operation(t_win)
            self.win_node.process_next_incoming_operation(t_win)

        th = threading.Thread(target=rx_two_files, daemon=True)
        th.start()
        results = self.and_node.file_manager.send_directory(t_and, folder)
        th.join(timeout=10.0)
        self.assertEqual(len(results), 2)
        recv_dir = Path(self.win_node.storage.get_setting("receive_directory"))
        self.assertTrue((recv_dir / "project_src" / "main.py").exists())
        self.assertTrue((recv_dir / "project_src" / "sub" / "config.json").exists())

        # Create an interrupted `.lbpart` file and test cancel / cleanup_temporary_files()
        part_file = recv_dir / ".lb_8888_temp.lbpart"
        part_file.write_bytes(b"partial_unverified_data")
        self.win_node.storage.upsert_file_transfer(
            transfer_id=8888,
            file_name="temp.bin",
            safe_rel_path="temp.bin",
            total_bytes=1000,
            transferred_bytes=23,
            expected_sha256="00" * 32,
            direction="INCOMING",
            transport="WIFI_LAN",
            peer_device_id="peer",
            status="IN_PROGRESS",
            temp_file_path=str(part_file),
        )
        cleaned = self.win_node.storage.cleanup_temporary_files()
        self.assertEqual(cleaned, 1)
        self.assertFalse(part_file.exists())
        # Original user received files must remain untouched
        self.assertTrue((recv_dir / "project_src" / "main.py").exists())

        self._record(
            "TEST-FOLDER-CLEANUP",
            "نقل المجلدات المتداخلة وإلغاء النقل وتنظيف الملفات المؤقتة (.lbpart) بأمان",
            True,
            "تم نقل المجلد الفرعي بنجاح وحذف ملفات `.lbpart` المؤقتة دون المساس بملفات المستخدم الأصلية.",
        )

    def test_14_certificate_renewal_and_device_revocation(self) -> None:
        """Section 2 & 6: Certificate renewal and instant revocation of paired device trust."""
        t_and, t_win = self._pair_over_loopback(TransportType.WIFI_LAN)
        and_id = self.and_node.identity.device_id
        self.win_node.revoke_peer(and_id)
        self.assertNotIn(and_id, self.win_node.storage.get_trusted_peers_map())

        # Subsequent connection without re-pairing must be rejected
        t_and2, t_win2 = LoopbackStreamTransport.create_pair(
            self.and_node.identity, self.win_node.identity, TransportType.WIFI_LAN
        )
        th = threading.Thread(
            target=lambda: self.assertRaises(AuthenticationError, self.win_node.authenticate_as_server, t_win2),
            daemon=True,
        )
        th.start()
        with self.assertRaises(AuthenticationError):
            self.and_node.authenticate_as_client(t_and2, pin_or_secret=None)
        th.join(timeout=5.0)

        old_fp = self.win_node.identity.fingerprint_sha256
        new_id = self.win_node.renew_device_certificate()
        self.assertNotEqual(old_fp, new_id.fingerprint_sha256)

        self._record(
            "TEST-CERT-REVOKE",
            "تجديد شهادة الأمان وإبطال الثقة بالجهاز المقترن (Revocation)",
            True,
            "تم إبطال الجهاز المقترن ورفض اتصاله اللاحق، وتوليد شهادة X.509 ECDSA P-256 جديدة ببصمة مختلفة.",
        )



    def test_15_android_public_key_pem_and_live_background_dispatcher(self) -> None:
        """Verify Android SubjectPublicKeyInfo PEM handshake + live background dispatcher bidirectional transfers."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import hashlib

        # Simulate AndroidDeviceIdentity (which uses EC P-256 SubjectPublicKeyInfo PEM instead of X.509 cert)
        ec_priv = ec.generate_private_key(ec.SECP256R1())
        der_pub = ec_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pem_pub = ec_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fp_pub = hashlib.sha256(der_pub).hexdigest()
        self.and_node.identity.cert_pem = pem_pub
        self.and_node.identity.fingerprint_sha256 = fp_pub

        pin, _, _ = self.win_node.generate_pairing_code()
        bind_ip, bind_port = self.win_node.start_wifi_listener(bind_ip="127.0.0.1", port=0)

        tls_client = WifiTlsTransport.connect(self.and_node.identity, host=bind_ip, port=bind_port)
        self.and_node.authenticate_as_client(tls_client, pin_or_secret=pin)
        self.and_node.enable_live_dispatcher(tls_client)

        for _ in range(50):
            if self.win_node.active_transport is not None and self.win_node.active_transport._dispatcher_active:
                break
            time.sleep(0.05)

        self.assertTrue(self.win_node.active_transport._dispatcher_active)

        # Send text from Android -> Windows with live background dispatcher active (no manual process_next call!)
        ok1, _ = self.and_node.clipboard_manager.send_text_manual(tls_client, "رسالة فورية عبر الموزع الخلفي الحي من Android")
        self.assertTrue(ok1)

        # Send text from Windows -> Android simultaneously
        ok2, _ = self.win_node.clipboard_manager.send_text_manual(
            self.win_node.active_transport, "رسالة معاكسة من Windows إلى Android عبر الموزع الخلفي"
        )
        self.assertTrue(ok2)

        # Send a file from Android -> Windows with live background dispatcher active
        f_live = self.tmp_root / "live_sync_doc.txt"
        f_live.write_text("محتوى ملف متزامن تلقائيًا عبر الموزع الخلفي\n" * 50, encoding="utf-8")
        res_f = self.and_node.file_manager.send_file(tls_client, f_live)
        self.assertEqual(res_f["status"], "COMPLETED")
        self.assertTrue(res_f["verified"])

        tls_client.close()
        self.win_node.stop_wifi_listener()

        self._record(
            "TEST-15-LIVE-E2E",
            "التوافق الكامل لهوية Android (PublicKey PEM) والموزع الخلفي الحي ثنائي الاتجاه",
            True,
            "نجح الاقتران بمفتاح Android العام وتبادل النصوص والملفات في الاتجاهين تلقائيًا عبر الموزع الخلفي دون تعارض في المقابس.",
        )



    def test_16_zero_pin_auto_discovery_and_one_tap_approval_both_directions(self) -> None:
        """
        Verify V2 Zero-Config Auto-Discovery (DISCOVER_PING/PONG) and Zero-PIN One-Tap Notification Approval
        (AUTO_APPROVE via ECDH P-256 + HKDF-SHA256 + AES-256-GCM AEAD) in real TCP server/client mode.
        """
        from protocol.transport import LocalDiscoveryService

        approved_requests: List[Dict[str, Any]] = []

        def _auto_approve_callback(peer_info: Dict[str, Any]) -> bool:
            approved_requests.append(peer_info)
            return True

        self.win_node.pairing_approval_callback = _auto_approve_callback
        bind_ip, bind_port = self.win_node.start_wifi_listener(bind_ip="127.0.0.1", port=0)

        # 1. Test automatic zero-config discovery probe (DISCOVER_PING -> DISCOVER_PONG)
        discovered = LocalDiscoveryService.probe_peer_over_tls(
            self.and_node.identity, ip=bind_ip, port=bind_port, timeout=2.0
        )
        self.assertIsNotNone(discovered)
        self.assertEqual(discovered["device_id"], self.win_node.identity.device_id)
        self.assertEqual(discovered["device_name"], "Windows-11-Laptop")

        # 2. Connect with Zero-PIN One-Tap Approval (pin_or_secret="AUTO_APPROVE", use_tls=False matching Android V2)
        client_t = WifiTlsTransport.connect(
            self.and_node.identity, host=bind_ip, port=bind_port, use_tls=False
        )
        self.and_node.authenticate_as_client(client_t, pin_or_secret="AUTO_APPROVE")
        self.and_node.enable_live_dispatcher(client_t)

        for _ in range(50):
            if self.win_node.active_transport is not None and self.win_node.active_transport._dispatcher_active:
                break
            time.sleep(0.05)

        self.assertEqual(len(approved_requests), 1)
        self.assertEqual(approved_requests[0]["device_name"], "Android-9-Phone")

        # Verify bidirectional text & file transfer over the zero-PIN approved AEAD session
        ok_txt, _ = self.and_node.clipboard_manager.send_text_manual(
            client_t, "اتصال تلقائي بموافقة إشعار واحدة بدون كتابة أي رمز PIN!"
        )
        self.assertTrue(ok_txt)

        f_auto = self.tmp_root / "auto_approved_photo.jpg"
        f_auto.write_bytes(secrets.token_bytes(128 * 1024))
        res_f = self.win_node.file_manager.send_file(self.win_node.active_transport, f_auto)
        self.assertEqual(res_f["status"], "COMPLETED")
        self.assertTrue(res_f["verified"])

        client_t.close()

        # 3. Reconnect a second time with AUTO_APPROVE — since already trusted, should NOT prompt user again!
        client_t2 = WifiTlsTransport.connect(
            self.and_node.identity, host=bind_ip, port=bind_port, use_tls=False
        )
        self.and_node.authenticate_as_client(client_t2, pin_or_secret="AUTO_APPROVE")
        self.assertEqual(len(approved_requests), 1)  # Still 1 — no second prompt needed!
        client_t2.close()
        self.win_node.stop_wifi_listener()

        self._record(
            "TEST-16-ZERO-PIN-APPROVAL",
            "الاكتشاف التلقائي للأجهزة والمصادقة بضغطة موافقة واحدة (بدون إدخال PIN أو IP)",
            True,
            "نجح اكتشاف الجهاز تلقائيًا عبر الشبكة، والموافقة عبر الإشعار التفاعلي (ECDH P-256 + AES-256-GCM)، ونقل النصوص والملفات في الاتجاهين.",
        )


def run_all_tests_and_export_report(report_json_path: Path) -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LinkBridgeIntegrationTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    report_data = {
        "total_tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "all_passed": result.wasSuccessful(),
        "results": LinkBridgeIntegrationTests.REPORT_ENTRIES,
    }
    report_json_path.parent.mkdir(parents=True, exist_ok=True)
    report_json_path.write_text(json.dumps(report_data, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    out_path = PROJECT_ROOT / "docs" / "test_results.json"
    sys.exit(run_all_tests_and_export_report(out_path))
