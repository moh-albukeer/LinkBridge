# 🌉 LinkBridge v1.0.0 — Smart & Secure Local Clipboard and File Bridge

[![Version](https://img.shields.io/badge/Release-v1.0.0-0EA5E9?style=for-the-badge)](CHANGELOG.md)
[![Android](https://img.shields.io/badge/Android-9.0%2B%20(API%2028--34%2B)-10B981?style=for-the-badge&logo=android&logoColor=white)](android/)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20(64--bit)-0284C7?style=for-the-badge&logo=windows&logoColor=white)](windows/)
[![License](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)](LICENSE)

> **🌍 للنسخة العربية من التوثيق:** [**اقرأ الدليل الكامل باللغة العربية (README_AR.md)**](README_AR.md)

**LinkBridge (v1.0.0)** is a native, offline-first local bridge engineered to transfer clipboard text, links, code snippets, files, and folders between **Android phones (Android 9 Pie up to the latest Android 14/15+ releases)** and **Windows 10/11 PCs**. It operates entirely over your local network (**Wi-Fi LAN**, **Phone Wi-Fi Hotspot**, or **Bluetooth Classic RFCOMM**) with zero cloud servers, zero external accounts, and zero internet dependency.

**Author & Lead Engineer:** **Mohammed Albukeer** ([mohammedalbukeer@gmail.com](mailto:mohammedalbukeer@gmail.com))

---

## ✨ Key Highlights in v1.0.0

| Capability | Engineering Implementation |
| :--- | :--- |
| **📡 Zero-Config Automatic Discovery** | Automatically discovers nearby devices using a triple-path engine: **UDP Broadcast/Multicast Beacons (`Port 48521`)**, **Native Win32 IP Neighbor Table Lookup (`iphlpapi.GetIpNetTable` + Subnet Probe on `Port 48520`)**, and **Bluetooth Paired Device Registry Inspection (`BTHPORT`)** — requiring zero manual IP, port, or MAC address entry. |
| **🔔 One-Tap Notification Approval** | Eliminates manual PIN typing. Select your target device from the discovered list and tap **Connect**; the receiving device displays a high-priority system notification and confirmation dialog (**Approve / Reject**). Once approved, both devices derive a persistent 256-bit link key and reconnect automatically on future sessions. |
| **🔐 End-to-End Authenticated Encryption** | Every connection uses unique per-device **ECDSA / ECDH P-256** keypairs, **SHA-256 public key fingerprint pinning**, **HKDF-SHA256** key derivation, and **AES-256-GCM (`AeadChannelCipher`)** authenticated frame encryption with monotonic sequence numbers to prevent replay and tampering attacks. |
| **📋 Bidirectional Smart Clipboard Bridge** | Instant clipboard synchronization and one-tap manual send in both directions. Features SHA-256 content hashing, **Sync Loop Prevention** (prevents remote clipboard items from echoing back), duplicate suppression, optional exclusion for sensitive Windows password managers (`KeePass.exe`, `1Password.exe`, `Bitwarden.exe`), and a searchable local SQLite history. |
| **📁 Resumable Chunked File & Folder Streaming** | Streams arbitrary files and nested folders in binary chunks (`64 KiB` on Wi-Fi/Hotspot, `16 KiB` on Bluetooth) without loading entire files into RAM. Tracks byte offsets via `.lbpart` checkpoints for automatic resume after disconnects, verifies full-file **SHA-256** digests, blocks path traversal (`..`), and resolves filename collisions non-destructively (`file (1).ext`). |
| **🎨 Modern Interactive UI (RTL & LTR)** | Clean, card-based desktop and mobile interfaces supporting **Arabic (RTL)** and **English (LTR)**, **Dark & Light themes**, Windows System Tray integration (`QSystemTrayIcon`), optional user-level Windows startup (`HKCU`), and direct file saving into `Downloads/LinkBridge`. |

---

## 🏗️ System Architecture & Repository Structure

```text
LinkBridge/
├── android/                  # Native Android Application (Kotlin, minSdk 28 -> targetSdk 34+)
│   ├── app/
│   │   ├── build.gradle.kts  # Android 9+ Compatible Build Configuration (v1.0.0)
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/com/linkbridge/app/
│   │       │   ├── protocol/LinkBridgeProtocol.kt        # LB01 Binary Framing, ECDH + AES-256-GCM, Auto-Discovery
│   │       │   ├── data/LinkBridgeDatabase.kt            # Local SQLite Storage for Peers, History & Settings
│   │       │   ├── clipboard/AndroidClipboardController.kt # Clipboard Bridge, Share Sheet & Anti-Loop Engine
│   │       │   ├── files/SafFileTransferController.kt    # Streaming File Receiver/Sender & SHA-256 Verifier
│   │       │   ├── service/LinkBridgeForegroundService.kt # Quick-Send Notification Service (Android 9..15+)
│   │       │   └── ui/{MainActivity.kt, ShareReceiverActivity.kt}
│   │       └── res/{values,values-ar}/strings.xml
├── windows/                  # Native Windows 10/11 Desktop Application (Python 3.11 + PySide6 + SQLite)
│   ├── app.py                # Main Interactive Desktop GUI, System Tray & Self-Check CLI
│   ├── bridge_node.py        # Unified Session, Discovery & Background Frame Dispatcher
│   ├── clipboard_manager.py  # 64-bit Win32/Qt Clipboard Monitor, Smart Sync & Loop Prevention
│   ├── file_manager.py       # Resumable Chunked File/Folder Streamer & Path Traversal Guard
│   ├── storage.py            # Thread-Safe SQLite Persistence Engine
│   ├── startup_and_tray.py   # User-Level HKCU Startup Registration & Permanent Path Installer
│   ├── i18n.py               # Arabic (RTL) / English (LTR) Localization & Dark/Light Stylesheets
│   └── version_info.txt      # Windows PE Version Metadata Resource
├── protocol/                 # Shared Binary Protocol & Cryptographic Core (LB01 v1.0.0)
│   ├── constants.py          # Frame Flags, Message Types & Chunk Constants
│   ├── crypto.py             # EC P-256 Identity, ECDH + HKDF-SHA256 & AES-256-GCM Cipher
│   ├── messages.py           # 64-Byte Binary Header Serializer & SHA-256 Frame Verifier
│   └── transport.py          # TransportAdapter, WifiTlsTransport, BluetoothRfcommTransport & AutoDiscoveryEngine
├── tests/                    # Automated Unit & End-to-End Integration Test Suite (14 Tests)
│   └── test_linkbridge_suite.py
├── docs/                     # Technical Specifications, Security Audit & Actual Test Reports
│   ├── PROTOCOL.md
│   ├── SECURITY_AND_PERMISSIONS.md
│   ├── TROUBLESHOOTING.md
│   └── TEST_REPORT.md
├── .github/workflows/        # Automated Cloud CI/CD Pipeline (Publishes directly to GitHub Releases)
│   └── build_releases.yml
├── README.md                 # Primary English Documentation (GitHub Front Page)
├── README_AR.md              # Full Arabic Documentation
├── CHANGELOG.md              # Release History (v1.0.0)
└── LICENSE                   # MIT License
```

---

## 🚀 Getting Started (Direct Download from GitHub Releases)

### Option 1: Download Directly from GitHub Releases (`v1.0.0`)
The automated GitHub Actions pipeline (`.github/workflows/build_releases.yml`) compiles both apps and automatically publishes them directly to your repository's **Releases** section (`v1.0.0`):
1. Open your repository on GitHub and click on **Releases** (on the right sidebar of the repository home page).
2. Under **LinkBridge v1.0.0 — Ready-to-Run Windows EXE & Android APK** (`Assets`), click to download directly without needing to unzip any artifact archives:
   - 💻 **`LinkBridge-Windows.exe`**: Standalone, single-file Windows 10/11 application (bundled with Python 3.11, PySide6, SQLite, and OpenSSL/cryptography, built with `--noupx`, PE VersionInfo metadata, and SHA-256 Authenticode signature — no Python installation required).
   - 📱 **`LinkBridge-Android.apk`**: Ready-to-install Android application package compatible with **Android 9.0 (API 28) through Android 14/15+**.

### Option 2: How to Connect & Transfer in 3 Seconds
1. **Launch Both Apps**: Open `LinkBridge-Windows.exe` on your PC and **LinkBridge** on your Android phone (connected to the same Wi-Fi router, or with your PC connected to your phone's Wi-Fi Hotspot without internet, or paired via Bluetooth).
2. **Select & Approve (No IP or PIN Required)**:
   - Both devices automatically appear in the **📡 Available Devices** card on screen.
   - Click your phone's name on the PC (or tap your PC's name on the phone) and press **🔗 Connect**.
   - Tap **✅ Approve (موافقة واتصال)** on the notification/dialog that pops up on the other device.
3. **Transfer Texts & Files Instantly**:
   - **Clipboard & Text**: Click **📋 Send Current Clipboard** (or share any text/link from any Android app via the native Android **Share Sheet -> Send to PC via LinkBridge**). Received texts are automatically copied to your clipboard ready to paste.
   - **Files & Folders**: Click **📄 Pick & Send Files** (or **📁 Send Folder** on Windows). Incoming files are verified with **SHA-256** and saved directly into **`Downloads/LinkBridge`** on both Windows and Android.

---

## 🧪 Automated Verification Suite (14 / 14 Passed)

Run the complete integration test suite locally at any time:

```bash
bash scripts/run_tests.sh
```

All **14 end-to-end integration tests** verify:
- Bidirectional short and long multilingual text transfers (Arabic RTL, English LTR, symbols, multi-line code).
- Clipboard sync loop prevention (`remoteOriginHashes`) and duplicate message replay idempotency.
- Sensitive Windows application exclusion (`KeePass.exe`, `1Password.exe`, `Bitwarden.exe`) and manual send override when auto-sync is disabled.
- Small and multi-megabyte chunked file transfers and nested folder transfers with full **SHA-256** verification.
- Mid-transfer connection drop injection and automatic byte-offset resume (`.lbpart`) over both Wi-Fi and Bluetooth RFCOMM.
- Path traversal rejection (`../../`, `/etc/passwd`, `C:\...`) and non-destructive duplicate filename resolution (`report (1).pdf`).
- Zero-config `DISCOVER_PING` / `DISCOVER_PONG` discovery and one-tap `AUTO_APPROVE` ECDH P-256 key agreement.

---

## 👨‍💻 Author & Contact

- **Developer:** **Mohammed Albukeer**
- **Email:** [mohammedalbukeer@gmail.com](mailto:mohammedalbukeer@gmail.com)
- **Version:** `v1.0.0` (First Official Release)
- **License:** [MIT License](LICENSE)
