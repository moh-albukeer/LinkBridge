"""
Windows Startup & Permanent App Installation Helper (`startup_and_tray.py`).
- Installs a permanent copy of `LinkBridge-Windows.exe` into `%LOCALAPPDATA%\Programs\LinkBridge\LinkBridge-Windows.exe`
  when startup is enabled, so Windows Defender and Windows Firewall see a stable, trusted application path across reboots.
- Manages user-level Windows startup entry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) without requiring Administrator rights.
"""
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

from .storage import LocalStorage

RUN_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_KEY = "LinkBridge"


class WindowsStartupManager:
    """Manages optional Windows login auto-start under HKCU (no Administrator rights required)."""

    @staticmethod
    def get_permanent_exe_path() -> Path:
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        install_dir = base / "Programs" / "LinkBridge"
        install_dir.mkdir(parents=True, exist_ok=True)
        return install_dir / "LinkBridge-Windows.exe"

    @classmethod
    def get_launch_command(cls, app_entry_path: Optional[Path] = None) -> str:
        if getattr(sys, "frozen", False):
            current_exe = Path(sys.executable).resolve()
            perm_exe = cls.get_permanent_exe_path()
            try:
                if current_exe != perm_exe:
                    shutil.copy2(current_exe, perm_exe)
                return f'"{perm_exe}" --minimized'
            except Exception:
                return f'"{current_exe}" --minimized'
        entry = app_entry_path or (Path(__file__).resolve().parent / "app.py")
        return f'"{sys.executable}" "{entry}" --minimized'

    @classmethod
    def is_startup_enabled(cls, storage: Optional[LocalStorage] = None) -> bool:
        if sys.platform == "win32":
            try:
                import winreg

                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_READ) as key:
                    val, _ = winreg.QueryValueEx(key, APP_REG_KEY)
                    return bool(val)
            except OSError:
                return False
        if storage is not None:
            return bool(storage.get_setting("run_on_windows_startup", False))
        return False

    @classmethod
    def set_startup_enabled(
        cls,
        enabled: bool,
        storage: Optional[LocalStorage] = None,
        app_entry_path: Optional[Path] = None,
    ) -> bool:
        if storage is not None:
            storage.set_setting("run_on_windows_startup", enabled)

        if sys.platform != "win32":
            return True

        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                RUN_REG_PATH,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                if enabled:
                    launch_cmd = cls.get_launch_command(app_entry_path)
                    winreg.SetValueEx(key, APP_REG_KEY, 0, winreg.REG_SZ, launch_cmd)
                else:
                    try:
                        winreg.DeleteValue(key, APP_REG_KEY)
                    except FileNotFoundError:
                        pass
            return True
        except OSError:
            return False
