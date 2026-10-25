# Changelog — LinkBridge

## [1.0.0] - 2026-10-25 (First Official Release — الإصدار الأول)

**Author:** Mohammed Albukeer (mohammedalbukeer@gmail.com)

### Added & Engineered
- **Unified Binary Protocol (`LB01 v1.0.0`)**: 64-byte framing header supporting Local Wi-Fi LAN (`WIFI_LAN`), Phone Wi-Fi Hotspot (`WIFI_HOTSPOT`), and Bluetooth Classic (`BLUETOOTH_RFCOMM`).
- **Zero-Config Automatic Discovery (`AutoDiscoveryEngine`)**: Simultaneous UDP broadcast/multicast beacons (`Port 48521`), native Win32 IP neighbor table inspection (`iphlpapi.GetIpNetTable`), `/24` subnet probing (`Port 48520`), and Windows Registry / Android bonded Bluetooth discovery without spawning external console processes.
- **One-Tap Notification & Dialog Approval (`PROMPT_APPROVAL`)**: Seamless device pairing and connection approval via system notifications and confirmation dialogs without requiring manual IP, MAC, or PIN typing.
- **End-to-End Authenticated Encryption**: Per-device EC P-256 identities, SHA-256 fingerprint pinning, ephemeral ECDH P-256 key exchange, HKDF-SHA256 key derivation, and AES-256-GCM (`AeadChannelCipher`) encryption.
- **Bidirectional Smart Clipboard Bridge**: One-tap clipboard send, Android System Share Sheet target (`ACTION_SEND` / `ACTION_SEND_MULTIPLE`), automatic copy option, SHA-256 anti-loop filtering, sensitive Windows app exclusion, and interactive SQLite history.
- **Resumable Chunked File & Folder Streaming**: Streaming transfers with `.lbpart` byte-offset resume, full-file SHA-256 verification, path traversal protection, non-destructive duplicate filename resolution (`file (1).ext`), and automatic saving to `Downloads/LinkBridge`.
- **Cross-Version Android & Windows Compatibility**: Signed Android Release APK (`v1 + v2 + v3` signature schemes, Android 9 API 28 through Android 14/15+ runtime permissions) and Defender-friendly Windows standalone executable (`--noupx`, PE VersionInfo metadata, SHA-256 Authenticode signature).
