"""
Bilingual Localization & Interactive Modern Theme Palettes for LinkBridge v1.0.0 (`i18n.py`).
Supports Arabic (RTL) and English (LTR), plus Dark and Light themes.
"""
from typing import Dict

STRINGS: Dict[str, Dict[str, str]] = {
    "ar": {
        "app_title": "LinkBridge v1.0.0 — جسر محلي ذكي وآمن بين Android وWindows",
        "status_connected": "🟢 متصل الآن بـ: {peer} ({transport})",
        "status_disconnected": "🔵 جاهز للاتصال التلقائي — اختر جهازك من القائمة بالأسفل",
        "status_listening": "الخدمة المحلية نشطة على {ip}:{port}",
        "about_heading": "LinkBridge v1.0.0 — نظام الربط المحلي الآمن لنقل النصوص والملفات",
        "about_credit": "Developed by Mohammed Albukeer | mohammedalbukeer@gmail.com",
        "about_description": (
            "الإصدار الأول (v1.0.0): نظام متكامل لنقل النصوص ومحتويات الحافظة والملفات والمجلدات بين هواتف Android (من Android 9 حتى أحدث إصدار) "
            "وأجهزة Windows 10/11 عبر الشبكة المحلية Wi-Fi أو نقطة اتصال الهاتف أو البلوتوث، مع اكتشاف تلقائي للأجهزة وموافقة فورية عبر الإشعار "
            "وتشفير قياسي (ECDH P-256 + AES-256-GCM) دون أي اعتماد على الإنترنت أو السحابة."
        ),
    },
    "en": {
        "app_title": "LinkBridge v1.0.0 — Smart & Secure Local Bridge for Android & Windows",
        "status_connected": "🟢 Connected to: {peer} ({transport})",
        "status_disconnected": "🔵 Auto-Discovery Active — Select your device below to connect",
        "status_listening": "Local service active on {ip}:{port}",
        "about_heading": "LinkBridge v1.0.0 — Secure Local Clipboard & File Bridge",
        "about_credit": "Developed by Mohammed Albukeer | mohammedalbukeer@gmail.com",
        "about_description": (
            "First Release (v1.0.0): Complete offline local bridge for instant clipboard sync and resumable file & folder transfers "
            "between Android (Android 9 up to the latest Android release) and Windows 10/11 over Local Wi-Fi, Phone Hotspot, or Bluetooth "
            "with zero-config auto-discovery, one-tap notification approval, and end-to-end ECDH P-256 + AES-256-GCM encryption."
        ),
    },
}


def get_stylesheet(theme: str = "dark") -> str:
    if theme == "light":
        return """
        QMainWindow, QWidget {
            background-color: #F1F5F9;
            color: #0F172A;
            font-family: "Segoe UI", "Noto Sans Arabic", Tahoma, sans-serif;
            font-size: 13px;
        }
        QGroupBox {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-radius: 10px;
            margin-top: 10px;
            padding: 12px;
            font-weight: bold;
            color: #0284C7;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top right;
            padding: 2px 10px;
        }
        QTabWidget::pane {
            border: 1px solid #CBD5E1;
            border-radius: 10px;
            background: #FFFFFF;
        }
        QTabBar::tab {
            background: #E2E8F0;
            color: #334155;
            padding: 10px 20px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
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
            border-radius: 8px;
            padding: 9px 16px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #0369A1;
        }
        QPushButton:pressed {
            background-color: #075985;
        }
        QPushButton#dangerBtn {
            background-color: #DC2626;
            color: #FFFFFF;
        }
        QPushButton#dangerBtn:hover {
            background-color: #B91C1C;
        }
        QPushButton#secondaryBtn {
            background-color: #E2E8F0;
            color: #0F172A;
            border: 1px solid #CBD5E1;
        }
        QPushButton#secondaryBtn:hover {
            background-color: #CBD5E1;
        }
        QLineEdit, QTextEdit, QListWidget, QTableWidget {
            background-color: #F8FAFC;
            color: #0F172A;
            border: 1px solid #CBD5E1;
            border-radius: 8px;
            padding: 8px;
        }
        QListWidget::item {
            padding: 10px;
            border-bottom: 1px solid #E2E8F0;
            border-radius: 6px;
        }
        QListWidget::item:selected {
            background-color: #E0F2FE;
            color: #0369A1;
            font-weight: bold;
        }
        QProgressBar {
            border: 1px solid #CBD5E1;
            border-radius: 8px;
            text-align: center;
            height: 22px;
            background: #E2E8F0;
            color: #0F172A;
            font-weight: bold;
        }
        QProgressBar::chunk {
            background-color: #10B981;
            border-radius: 7px;
        }
        """
    return """
    QMainWindow, QWidget {
        background-color: #0B1120;
        color: #F1F5F9;
        font-family: "Segoe UI", "Noto Sans Arabic", Tahoma, sans-serif;
        font-size: 13px;
    }
    QGroupBox {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        margin-top: 10px;
        padding: 12px;
        font-weight: bold;
        color: #38BDF8;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top right;
        padding: 2px 10px;
    }
    QTabWidget::pane {
        border: 1px solid #334155;
        border-radius: 10px;
        background: #111827;
    }
    QTabBar::tab {
        background: #1E293B;
        color: #94A3B8;
        padding: 10px 20px;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
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
        border-radius: 8px;
        padding: 9px 16px;
        font-weight: 600;
    }
    QPushButton:hover {
        background-color: #38BDF8;
    }
    QPushButton:pressed {
        background-color: #0284C7;
        color: #FFFFFF;
    }
    QPushButton#dangerBtn {
        background-color: #EF4444;
        color: #FFFFFF;
    }
    QPushButton#dangerBtn:hover {
        background-color: #DC2626;
    }
    QPushButton#secondaryBtn {
        background-color: #334155;
        color: #F8FAFC;
    }
    QPushButton#secondaryBtn:hover {
        background-color: #475569;
    }
    QLineEdit, QTextEdit, QListWidget, QTableWidget {
        background-color: #0F172A;
        color: #F1F5F9;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 8px;
    }
    QListWidget::item {
        padding: 10px;
        border-bottom: 1px solid #1E293B;
        border-radius: 6px;
    }
    QListWidget::item:selected {
        background-color: #0284C7;
        color: #FFFFFF;
        font-weight: bold;
    }
    QProgressBar {
        border: 1px solid #334155;
        border-radius: 8px;
        text-align: center;
        height: 22px;
        background: #0F172A;
        color: #F8FAFC;
        font-weight: bold;
    }
    QProgressBar::chunk {
        background-color: #10B981;
        border-radius: 7px;
    }
    """
