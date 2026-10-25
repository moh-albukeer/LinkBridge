"""
Bilingual Localization & Theme Palettes for LinkBridge Windows (`i18n.py`).
Supports Arabic (RTL) and English (LTR), plus Dark and Light themes.
"""
from typing import Dict

STRINGS: Dict[str, Dict[str, str]] = {
    "ar": {
        "app_title": "LinkBridge v1.0.0 — جسر محلي آمن بين Android وWindows",
        "status_connected": "متصل بـ: {peer} ({transport})",
        "status_disconnected": "غير متصل — في انتظار الربط المحلي",
        "status_listening": "الخدمة المحلية تستمع على {ip}:{port}",
        "about_heading": "LinkBridge v1.0.0 — جسر محلي آمن لنقل النصوص والملفات",
        "about_credit": "Developed by Mohammed Albukeer | mohammedalbukeer@gmail.com",
        "about_description": (
            "نظام متكامل لنقل النصوص ومحتويات الحافظة والملفات بين هاتف Android 9+ ولابتوب Windows 10/11 "
            "عبر الشبكة المحلية Wi-Fi أو نقطة اتصال الهاتف أو Bluetooth RFCOMM، بتشفير ومصادقة كاملة "
            "ودون أي اعتماد على الإنترنت أو الخدمات السحابية."
        ),
    },
    "en": {
        "app_title": "LinkBridge v1.0.0 — Secure Local Bridge for Android & Windows",
        "status_connected": "Connected to: {peer} ({transport})",
        "status_disconnected": "Disconnected — Waiting for local link",
        "status_listening": "Local service listening on {ip}:{port}",
        "about_heading": "LinkBridge v1.0.0 — Secure Local Text & File Bridge",
        "about_credit": "Developed by Mohammed Albukeer | mohammedalbukeer@gmail.com",
        "about_description": (
            "Integrated local bridge for transferring clipboard text and files between Android 9+ and Windows 10/11 "
            "over Local Wi-Fi, Phone Hotspot, or Bluetooth RFCOMM with end-to-end authentication and zero cloud dependencies."
        ),
    },
}


def get_stylesheet(theme: str = "dark") -> str:
    if theme == "light":
        return """
        QMainWindow, QWidget {
            background-color: #F8FAFC;
            color: #0F172A;
            font-family: "Segoe UI", "Noto Sans Arabic", Tahoma, sans-serif;
            font-size: 13px;
        }
        QTabWidget::pane {
            border: 1px solid #CBD5E1;
            border-radius: 8px;
            background: #FFFFFF;
        }
        QTabBar::tab {
            background: #E2E8F0;
            color: #334155;
            padding: 9px 18px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 4px;
            font-weight: 600;
        }
        QTabBar::tab:selected {
            background: #0284C7;
            color: #FFFFFF;
        }
        QPushButton {
            background-color: #0284C7;
            color: #FFFFFF;
            border: none;
            border-radius: 6px;
            padding: 8px 14px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #0369A1;
        }
        QPushButton#dangerBtn {
            background-color: #DC2626;
        }
        QLineEdit, QTextEdit, QComboBox, QSpinBox, QListWidget, QTableWidget {
            background-color: #FFFFFF;
            color: #0F172A;
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            padding: 6px;
        }
        QProgressBar {
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            text-align: center;
            background: #E2E8F0;
        }
        QProgressBar::chunk {
            background-color: #0284C7;
            border-radius: 5px;
        }
        """
    return """
    QMainWindow, QWidget {
        background-color: #0F172A;
        color: #F1F5F9;
        font-family: "Segoe UI", "Noto Sans Arabic", Tahoma, sans-serif;
        font-size: 13px;
    }
    QTabWidget::pane {
        border: 1px solid #334155;
        border-radius: 8px;
        background: #1E293B;
    }
    QTabBar::tab {
        background: #1E293B;
        color: #94A3B8;
        padding: 9px 18px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        margin-right: 4px;
        font-weight: 600;
    }
    QTabBar::tab:selected {
        background: #0EA5E9;
        color: #0F172A;
    }
    QPushButton {
        background-color: #0EA5E9;
        color: #0F172A;
        border: none;
        border-radius: 6px;
        padding: 8px 14px;
        font-weight: 600;
    }
    QPushButton:hover {
        background-color: #38BDF8;
    }
    QPushButton#dangerBtn {
        background-color: #EF4444;
        color: #FFFFFF;
    }
    QLineEdit, QTextEdit, QComboBox, QSpinBox, QListWidget, QTableWidget {
        background-color: #0F172A;
        color: #F1F5F9;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 6px;
    }
    QProgressBar {
        border: 1px solid #334155;
        border-radius: 6px;
        text-align: center;
        background: #0F172A;
        color: #F1F5F9;
    }
    QProgressBar::chunk {
        background-color: #10B981;
        border-radius: 5px;
    }
    """
