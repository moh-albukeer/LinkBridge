"""
SQLite Local Storage Engine for LinkBridge Windows (`storage.py`).
Stores:
- User settings (auto-sync per direction, privacy options, receive directory, retention period, size limits, startup toggle)
- Paired & trusted devices (device_id, name, platform, pinned X.509 certificate fingerprint, derived link key, last connected)
- Clipboard history metadata & text (with SHA-256 content hash, origin device, deduplication, search, and configurable retention/disable)
- File transfer state & chunk checkpoint metadata (separating metadata from actual files on disk, supporting resume after disconnect)
"""
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_SETTINGS: Dict[str, Any] = {
    "device_name": "LinkBridge-Windows-PC",
    "language": "ar",                      # "ar" (RTL) or "en" (LTR)
    "theme": "dark",                       # "dark" or "light"
    "wifi_port": 48520,
    "preferred_transport": "AUTO",         # "AUTO", "WIFI_LAN", "WIFI_HOTSPOT", "BLUETOOTH_RFCOMM"
    "auto_sync_win_to_android": False,     # Privacy first: disabled until user enables it
    "auto_sync_android_to_win": False,     # Require confirmation or explicit enable before overwriting local clipboard
    "auto_copy_received_to_clipboard": True,
    "monitor_windows_clipboard": False,
    "hide_text_in_notifications": True,
    "save_clipboard_history": True,
    "history_retention_days": 7,
    "max_text_size_kb": 512,
    "max_file_size_mb": 4096,
    "auto_accept_files": True,            # Prompt per file unless user enables auto-accept
    "excluded_windows_apps": ["KeePass.exe", "1Password.exe", "Bitwarden.exe"],
    "run_on_windows_startup": False,
    "receive_directory": "",               # Populated on init
}


class LocalStorage:
    """Thread-safe SQLite storage manager for LinkBridge."""

    def __init__(self, db_path: Path, default_receive_dir: Optional[Path] = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        if default_receive_dir:
            default_receive_dir.mkdir(parents=True, exist_ok=True)
            if not self.get_setting("receive_directory"):
                self.set_setting("receive_directory", str(default_receive_dir.resolve()))

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS paired_devices (
                    device_id TEXT PRIMARY KEY,
                    device_name TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    link_key_hex TEXT NOT NULL,
                    bt_mac_address TEXT DEFAULT '',
                    last_ip TEXT DEFAULT '',
                    last_seen REAL NOT NULL,
                    is_revoked INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS clipboard_history (
                    item_id TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    text_content TEXT NOT NULL,
                    origin_device_id TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_clip_hash ON clipboard_history(content_hash);
                CREATE INDEX IF NOT EXISTS idx_clip_time ON clipboard_history(created_at DESC);

                CREATE TABLE IF NOT EXISTS file_transfers (
                    transfer_id INTEGER PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    safe_rel_path TEXT NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    transferred_bytes INTEGER NOT NULL,
                    expected_sha256 TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    peer_device_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    temp_file_path TEXT DEFAULT '',
                    final_file_path TEXT DEFAULT '',
                    error_message TEXT DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            now = time.time()
            for k, v in DEFAULT_SETTINGS.items():
                self._conn.execute(
                    "INSERT OR IGNORE INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)",
                    (k, json.dumps(v, ensure_ascii=False), now),
                )

    # ------------------------------------------------------------------
    # Settings Management
    # ------------------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
            if not row:
                return DEFAULT_SETTINGS.get(key, default)
            return json.loads(row["value_json"])

    def set_setting(self, key: str, value: Any) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)",
                (key, json.dumps(value, ensure_ascii=False), time.time()),
            )

    def get_all_settings(self) -> Dict[str, Any]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value_json FROM settings").fetchall()
            result = dict(DEFAULT_SETTINGS)
            for r in rows:
                result[r["key"]] = json.loads(r["value_json"])
            return result

    # ------------------------------------------------------------------
    # Paired Devices Management
    # ------------------------------------------------------------------
    def save_paired_device(self, record: Dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO paired_devices
                (device_id, device_name, platform, fingerprint, cert_pem, link_key_hex, bt_mac_address, last_ip, last_seen, is_revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    record["device_id"],
                    record.get("device_name", "Android Device"),
                    record.get("platform", "Android"),
                    record["fingerprint"],
                    record["cert_pem"],
                    record["link_key_hex"],
                    record.get("bt_mac_address", ""),
                    record.get("last_ip", ""),
                    time.time(),
                ),
            )

    def get_trusted_peers_map(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM paired_devices WHERE is_revoked = 0"
            ).fetchall()
            return {r["device_id"]: dict(r) for r in rows}

    def revoke_paired_device(self, device_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE paired_devices SET is_revoked = 1 WHERE device_id = ?",
                (device_id,),
            )

    # ------------------------------------------------------------------
    # Clipboard History Management
    # ------------------------------------------------------------------
    def add_clipboard_item(
        self,
        item_id: str,
        content_hash: str,
        text_content: str,
        origin_device_id: str,
        direction: str,
        transport: str,
    ) -> bool:
        """
        Save clipboard item if `save_clipboard_history` is enabled.
        Automatically prunes expired items based on `history_retention_days`.
        """
        self.prune_expired_clipboard_history()
        if not self.get_setting("save_clipboard_history", True):
            return False
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO clipboard_history
                (item_id, content_hash, text_content, origin_device_id, direction, transport, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (item_id, content_hash, text_content, origin_device_id, direction, transport, time.time()),
            )
        return True

    def list_clipboard_history(self, search_query: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        self.prune_expired_clipboard_history()
        with self._lock:
            if search_query.strip():
                q = f"%{search_query.strip()}%"
                rows = self._conn.execute(
                    "SELECT * FROM clipboard_history WHERE text_content LIKE ? ORDER BY created_at DESC LIMIT ?",
                    (q, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM clipboard_history ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def delete_clipboard_item(self, item_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM clipboard_history WHERE item_id = ?", (item_id,))

    def clear_clipboard_history(self) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM clipboard_history")
            return cur.rowcount

    def prune_expired_clipboard_history(self) -> int:
        days = int(self.get_setting("history_retention_days", 7))
        if days <= 0:
            return 0
        cutoff = time.time() - (days * 86400)
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM clipboard_history WHERE created_at < ?", (cutoff,))
            return cur.rowcount

    # ------------------------------------------------------------------
    # File Transfer Metadata & Resume Tracking
    # ------------------------------------------------------------------
    def upsert_file_transfer(
        self,
        transfer_id: int,
        file_name: str,
        safe_rel_path: str,
        total_bytes: int,
        transferred_bytes: int,
        expected_sha256: str,
        direction: str,
        transport: str,
        peer_device_id: str,
        status: str,
        temp_file_path: str = "",
        final_file_path: str = "",
        error_message: str = "",
    ) -> None:
        now = time.time()
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT created_at FROM file_transfers WHERE transfer_id = ?",
                (transfer_id,),
            ).fetchone()
            created_at = existing["created_at"] if existing else now
            self._conn.execute(
                """
                INSERT OR REPLACE INTO file_transfers
                (transfer_id, file_name, safe_rel_path, total_bytes, transferred_bytes, expected_sha256,
                 direction, transport, peer_device_id, status, temp_file_path, final_file_path, error_message,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transfer_id,
                    file_name,
                    safe_rel_path,
                    total_bytes,
                    transferred_bytes,
                    expected_sha256,
                    direction,
                    transport,
                    peer_device_id,
                    status,
                    temp_file_path,
                    final_file_path,
                    error_message,
                    created_at,
                    now,
                ),
            )

    def get_file_transfer(self, transfer_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM file_transfers WHERE transfer_id = ?",
                (transfer_id,),
            ).fetchone()
            return dict(row) if row else None

    def list_file_transfers(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM file_transfers ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def cleanup_temporary_files(self) -> int:
        """Delete orphaned temporary `.lbpart` files without ever touching final user files."""
        removed = 0
        with self._lock:
            rows = self._conn.execute(
                "SELECT transfer_id, temp_file_path, status FROM file_transfers WHERE temp_file_path != ''"
            ).fetchall()
            for r in rows:
                p = Path(r["temp_file_path"])
                if p.exists() and p.suffix == ".lbpart":
                    try:
                        p.unlink()
                        removed += 1
                    except OSError:
                        pass
                with self._conn:
                    self._conn.execute(
                        "UPDATE file_transfers SET temp_file_path = '', status = CASE WHEN status = 'IN_PROGRESS' THEN 'CANCELLED' ELSE status END WHERE transfer_id = ?",
                        (r["transfer_id"],),
                    )
        return removed

    def close(self) -> None:
        with self._lock:
            self._conn.close()
