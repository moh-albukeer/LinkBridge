"""
Clipboard Bridge & Smart Sync Engine for LinkBridge Windows (`clipboard_manager.py`).
Features:
- Unique item_id (UUID/hex) and SHA-256 content hash (`content_hash`) for every clipboard item.
- Strict echo/loop prevention: tracks hashes and IDs originating from the remote peer so receiving
  an item and copying it to the local clipboard never triggers a re-send back to the peer.
- Duplicate suppression and idempotent message replay handling (`seen_item_ids`).
- Independent auto-sync toggles for Windows->Android and Android->Windows, plus explicit manual send.
- Never overwrites local clipboard silently when user settings require confirmation (`auto_copy_received_to_clipboard=False`).
- Optional sensitive Windows application exclusion using Win32 `GetClipboardOwner` / `GetForegroundWindow` process inspection.
"""
import ctypes
import hashlib
import os
import sys
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from protocol.constants import MessageType
from protocol.transport import TransportAdapter
from .storage import LocalStorage


class SystemClipboardBackend:
    """
    OS Clipboard abstraction supporting:
    1. PySide6 `QGuiApplication.clipboard()` when running inside the Qt GUI loop.
    2. Native Win32 API (`user32.OpenClipboard`, `GetClipboardData(CF_UNICODETEXT)`, `SetClipboardData`) on Windows.
    3. In-memory fallback for headless automated testing.
    """

    def __init__(self) -> None:
        self._memory_clipboard: str = ""
        self._qt_clipboard: Any = None

    def set_qt_clipboard(self, qt_clipboard: Any) -> None:
        self._qt_clipboard = qt_clipboard

    def get_text(self) -> str:
        if self._qt_clipboard is not None:
            try:
                return self._qt_clipboard.text() or ""
            except Exception:
                pass
        if sys.platform == "win32":
            return self._win32_get_text()
        return self._memory_clipboard

    def set_text(self, text: str) -> None:
        self._memory_clipboard = text
        if self._qt_clipboard is not None:
            try:
                self._qt_clipboard.setText(text)
                return
            except Exception:
                pass
        if sys.platform == "win32":
            self._win32_set_text(text)

    def get_owner_process_name(self) -> str:
        """
        Best-effort inspection of the Windows process that currently owns the clipboard or foreground window.
        Note: As documented in LinkBridge privacy guidelines, Windows does not guarantee source attribution
        for every clipboard operation, so this is an optional defense-in-depth filter rather than an absolute guarantee.
        """
        if sys.platform != "win32":
            return ""
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            hwnd = user32.GetClipboardOwner() or user32.GetForegroundWindow()
            if not hwnd:
                return ""
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if not pid.value:
                return ""
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            PROCESS_VM_READ = 0x0010
            hproc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid.value)
            if not hproc:
                return ""
            try:
                buf = ctypes.create_unicode_buffer(260)
                if psapi.GetModuleBaseNameW(hproc, None, buf, 260) > 0:
                    return buf.value
            finally:
                kernel32.CloseHandle(hproc)
        except Exception:
            pass
        return ""

    def _win32_get_text(self) -> str:
        try:
            CF_UNICODETEXT = 13
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            user32.OpenClipboard.argtypes = [ctypes.c_void_p]
            user32.OpenClipboard.restype = ctypes.c_int
            user32.GetClipboardData.argtypes = [ctypes.c_uint]
            user32.GetClipboardData.restype = ctypes.c_void_p
            user32.CloseClipboard.argtypes = []
            user32.CloseClipboard.restype = ctypes.c_int
            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalUnlock.restype = ctypes.c_int

            if not user32.OpenClipboard(None):
                return self._memory_clipboard
            try:
                handle = user32.GetClipboardData(CF_UNICODETEXT)
                if not handle:
                    return self._memory_clipboard
                ptr = kernel32.GlobalLock(handle)
                if not ptr:
                    return self._memory_clipboard
                try:
                    val = ctypes.wstring_at(ptr)
                    return val if val else self._memory_clipboard
                finally:
                    kernel32.GlobalUnlock(handle)
            finally:
                user32.CloseClipboard()
        except Exception:
            return self._memory_clipboard

    def _win32_set_text(self, text: str) -> None:
        try:
            CF_UNICODETEXT = 13
            GMEM_MOVEABLE = 0x0002
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            user32.OpenClipboard.argtypes = [ctypes.c_void_p]
            user32.OpenClipboard.restype = ctypes.c_int
            user32.EmptyClipboard.argtypes = []
            user32.EmptyClipboard.restype = ctypes.c_int
            user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
            user32.SetClipboardData.restype = ctypes.c_void_p
            user32.CloseClipboard.argtypes = []
            user32.CloseClipboard.restype = ctypes.c_int
            kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
            kernel32.GlobalAlloc.restype = ctypes.c_void_p
            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalUnlock.restype = ctypes.c_int

            if not user32.OpenClipboard(None):
                return
            try:
                user32.EmptyClipboard()
                encoded = (text + "\0").encode("utf-16-le")
                hmem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
                if not hmem:
                    return
                ptr = kernel32.GlobalLock(hmem)
                if ptr:
                    ctypes.memmove(ptr, encoded, len(encoded))
                    kernel32.GlobalUnlock(hmem)
                    user32.SetClipboardData(CF_UNICODETEXT, hmem)
            finally:
                user32.CloseClipboard()
        except Exception:
            pass


class ClipboardBridgeManager:
    """
    Manages bidirectional clipboard synchronization, manual sends, deduplication,
    anti-loop tracking, and privacy filtering.
    """

    def __init__(
        self,
        local_device_id: str,
        storage: LocalStorage,
        clipboard_backend: Optional[SystemClipboardBackend] = None,
        on_item_received_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.local_device_id = local_device_id
        self.storage = storage
        self.backend = clipboard_backend or SystemClipboardBackend()
        self.on_item_received_callback = on_item_received_callback

        # Track seen item IDs to guarantee idempotency on message retry/duplication
        self._seen_item_ids: Set[str] = set()
        # Track content hashes recently received from a remote device to prevent sync loops
        self._remote_origin_hashes: Dict[str, str] = {}  # content_hash -> origin_device_id
        self._last_sent_hash: Optional[str] = None
        self._last_observed_local_hash: Optional[str] = None

    @staticmethod
    def compute_text_hash(text: str) -> str:
        normalized = text.replace("\r\n", "\n")
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _check_size_limit(self, text: str) -> Tuple[bool, str]:
        raw_len = len(text.encode("utf-8"))
        max_kb = int(self.storage.get_setting("max_text_size_kb", 512))
        max_bytes = max_kb * 1024
        if raw_len == 0:
            return False, "النص فارغ ولا يمكن إرساله (Cannot send empty text)"
        if raw_len > max_bytes:
            return (
                False,
                f"حجم النص ({raw_len} بايت) يتجاوز الحد الأقصى المسموح به ({max_bytes} بايت)",
            )
        return True, "OK"

    def send_text_manual(
        self,
        transport: TransportAdapter,
        text: str,
        item_id: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Explicitly send text to the connected peer (works even when auto-sync is disabled).
        """
        ok, reason = self._check_size_limit(text)
        if not ok:
            return False, {"error": reason}

        content_hash = self.compute_text_hash(text)
        item_id = item_id or f"clip-{uuid.uuid4().hex[:16]}"
        payload = {
            "item_id": item_id,
            "content_hash": content_hash,
            "text": text,
            "origin_device_id": self.local_device_id,
            "timestamp": time.time(),
            "mode": "MANUAL",
        }
        transport.send_control(MessageType.CLIPBOARD_PUSH, payload)
        ack_frame = transport.receive_reply_frame()
        ack_body = ack_frame.json_body() if ack_frame.header.msg_type == MessageType.CLIPBOARD_ACK else {}
        payload["ack"] = ack_body
        self._seen_item_ids.add(item_id)
        self._last_sent_hash = content_hash

        self.storage.add_clipboard_item(
            item_id=item_id,
            content_hash=content_hash,
            text_content=text,
            origin_device_id=self.local_device_id,
            direction="OUTGOING",
            transport=transport.transport_type.value,
        )
        return True, payload

    def poll_local_clipboard_for_auto_sync(
        self,
        transport: Optional[TransportAdapter],
        override_source_app: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Polled by the Windows clipboard listener when `monitor_windows_clipboard` and
        `auto_sync_win_to_android` are enabled.
        Strictly prevents:
        - Sending when manual mode is active (`auto_sync_win_to_android=False`)
        - Sending empty or oversized text
        - Sending text from excluded sensitive Windows apps
        - Re-sending text that arrived from the remote device (sync loop prevention)
        - Sending duplicate consecutive clipboard content
        """
        if not self.storage.get_setting("monitor_windows_clipboard", False):
            return False, "مراقبة الحافظة معطلة (Clipboard monitoring disabled)"
        if not self.storage.get_setting("auto_sync_win_to_android", False):
            return False, "المزامنة التلقائية من Windows إلى Android معطلة (Manual mode active)"
        if transport is None or not transport.is_connected:
            return False, "لا يوجد اتصال نشط (No active connection)"

        text = self.backend.get_text()
        if not text:
            return False, "الحافظة فارغة"

        content_hash = self.compute_text_hash(text)

        # Prevent sync loop: if this exact content hash came from the remote device, do not echo it back!
        if content_hash in self._remote_origin_hashes:
            self._last_observed_local_hash = content_hash
            return False, "تم تجاهل النص لأنه مستلم من الجهاز المقابل لمنع حلقة التكرار (Loop prevented)"

        # Prevent duplicate consecutive sends
        if content_hash == self._last_observed_local_hash or content_hash == self._last_sent_hash:
            return False, "تم تجاهل النص المكرر (Duplicate content suppressed)"

        # Check excluded sensitive apps
        source_app = override_source_app if override_source_app is not None else self.backend.get_owner_process_name()
        excluded = [a.lower() for a in self.storage.get_setting("excluded_windows_apps", [])]
        if source_app and source_app.lower() in excluded:
            self._last_observed_local_hash = content_hash
            return False, f"تم استثناء النص لصدوره من تطبيق حساس مستثنى ({source_app})"

        ok, reason = self._check_size_limit(text)
        if not ok:
            return False, reason

        self._last_observed_local_hash = content_hash
        item_id = f"clip-{uuid.uuid4().hex[:16]}"
        payload = {
            "item_id": item_id,
            "content_hash": content_hash,
            "text": text,
            "origin_device_id": self.local_device_id,
            "timestamp": time.time(),
            "mode": "AUTO",
        }
        transport.send_control(MessageType.CLIPBOARD_PUSH, payload)
        ack_frame = transport.receive_reply_frame()
        ack_body = ack_frame.json_body() if ack_frame.header.msg_type == MessageType.CLIPBOARD_ACK else {}
        payload["ack"] = ack_body
        self._seen_item_ids.add(item_id)
        self._last_sent_hash = content_hash

        self.storage.add_clipboard_item(
            item_id=item_id,
            content_hash=content_hash,
            text_content=text,
            origin_device_id=self.local_device_id,
            direction="OUTGOING",
            transport=transport.transport_type.value,
        )
        return True, item_id

    def handle_incoming_clipboard_push(
        self,
        transport: TransportAdapter,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Process an incoming CLIPBOARD_PUSH frame from the remote device.
        - Rejects payloads exceeding `max_text_size_kb`.
        - Verifies SHA-256 `content_hash`.
        - Suppresses duplicate `item_id` (safe retry/idempotency).
        - Suppresses echo if `origin_device_id == self.local_device_id`.
        - Copies to local OS clipboard ONLY if `auto_copy_received_to_clipboard` is True.
        """
        item_id = str(body.get("item_id", ""))
        text = str(body.get("text", ""))
        expected_hash = str(body.get("content_hash", ""))
        origin_device_id = str(body.get("origin_device_id", ""))

        if not item_id or not text:
            transport.send_control(
                MessageType.CLIPBOARD_ACK,
                {"item_id": item_id, "accepted": False, "reason": "Empty item_id or text"},
            )
            return {"accepted": False, "reason": "Empty item_id or text"}

        # Prevent self-originated loop
        if origin_device_id == self.local_device_id:
            transport.send_control(
                MessageType.CLIPBOARD_ACK,
                {"item_id": item_id, "accepted": False, "reason": "Loop prevention: self origin"},
            )
            return {"accepted": False, "reason": "Loop prevention: self origin"}

        # Idempotent handling of duplicate/retried messages
        if item_id in self._seen_item_ids:
            transport.send_control(
                MessageType.CLIPBOARD_ACK,
                {"item_id": item_id, "accepted": True, "duplicate": True, "reason": "Already processed"},
            )
            return {"accepted": True, "duplicate": True, "item_id": item_id}

        ok, reason = self._check_size_limit(text)
        if not ok:
            transport.send_control(
                MessageType.CLIPBOARD_ACK,
                {"item_id": item_id, "accepted": False, "reason": reason},
            )
            return {"accepted": False, "reason": reason}

        actual_hash = self.compute_text_hash(text)
        if expected_hash and actual_hash != expected_hash:
            transport.send_control(
                MessageType.CLIPBOARD_ACK,
                {"item_id": item_id, "accepted": False, "reason": "SHA-256 content_hash mismatch"},
            )
            return {"accepted": False, "reason": "SHA-256 content_hash mismatch"}

        self._seen_item_ids.add(item_id)
        # Record remote origin hash BEFORE touching local clipboard so auto-sync monitor never echoes it back
        self._remote_origin_hashes[actual_hash] = origin_device_id

        copied_to_os = False
        if self.storage.get_setting("auto_copy_received_to_clipboard", False):
            self.backend.set_text(text)
            self._last_observed_local_hash = actual_hash
            copied_to_os = True

        self.storage.add_clipboard_item(
            item_id=item_id,
            content_hash=actual_hash,
            text_content=text,
            origin_device_id=origin_device_id,
            direction="INCOMING",
            transport=transport.transport_type.value,
        )

        ack_payload = {
            "item_id": item_id,
            "accepted": True,
            "duplicate": False,
            "copied_to_clipboard": copied_to_os,
        }
        transport.send_control(MessageType.CLIPBOARD_ACK, ack_payload)

        result = {
            "accepted": True,
            "duplicate": False,
            "item_id": item_id,
            "content_hash": actual_hash,
            "text": text,
            "origin_device_id": origin_device_id,
            "copied_to_clipboard": copied_to_os,
            "notification_preview": (
                "تم استلام نص جديد من الجهاز المقترن (محتوى النص مخفي للخصوصية)"
                if self.storage.get_setting("hide_text_in_notifications", True)
                else f"تم استلام نص: {text[:60]}"
            ),
        }
        if self.on_item_received_callback:
            self.on_item_received_callback(result)
        return result
