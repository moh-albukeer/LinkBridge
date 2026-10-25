"""
Protocol constants, message types, and limits for LinkBridge v1.0.
"""
from enum import IntEnum, Enum

PROTOCOL_MAGIC = b"LB01"
PROTOCOL_VERSION = 1

# Default network & chunking parameters
DEFAULT_WIFI_PORT = 48520
DEFAULT_DISCOVERY_PORT = 48521
BT_SERVICE_UUID = "8c9b4f10-5d32-4e8a-b129-7f4e90c31a2b"

# Chunk sizes: 64 KiB for Wi-Fi/Hotspot, 16 KiB for Bluetooth RFCOMM
DEFAULT_CHUNK_SIZE = 65536
BT_CHUNK_SIZE = 16384

# Safety & privacy limits (configurable in user settings)
MAX_CONTROL_FRAME_BYTES = 1 * 1024 * 1024      # 1 MiB max control JSON
MAX_TEXT_BYTES = 512 * 1024                    # 512 KiB max clipboard text payload by default
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024       # 10 GiB max single file size by default

# Session and pairing token lifetimes
PAIRING_TOKEN_TTL_SECONDS = 300                # 5 minutes for one-time pairing code/QR
SESSION_TTL_SECONDS = 3600                     # 1 hour short-lived session token


class TransportType(str, Enum):
    WIFI_LAN = "WIFI_LAN"
    WIFI_HOTSPOT = "WIFI_HOTSPOT"
    BLUETOOTH_RFCOMM = "BLUETOOTH_RFCOMM"
    LOOPBACK = "LOOPBACK"


class MessageType(IntEnum):
    # Handshake, Pairing & Session Management (0x01 - 0x0F)
    HELLO = 0x01
    HELLO_ACK = 0x02
    PAIR_REQUEST = 0x03
    PAIR_RESPONSE = 0x04
    AUTH_SESSION = 0x05
    AUTH_RESULT = 0x06
    PING = 0x07
    PONG = 0x08
    DISCONNECT = 0x09
    REVOKE_PAIRING = 0x0A
    DISCOVER_PING = 0x0B
    DISCOVER_PONG = 0x0C

    # Clipboard Bridge Operations (0x10 - 0x1F)
    CLIPBOARD_PUSH = 0x10
    CLIPBOARD_ACK = 0x11

    # File Transfer Control & Streaming Operations (0x20 - 0x2F)
    FILE_OFFER = 0x20
    FILE_ACCEPT = 0x21
    FILE_REJECT = 0x22
    FILE_CHUNK = 0x23
    FILE_CHUNK_ACK = 0x24
    FILE_COMPLETE = 0x25
    FILE_VERIFY_RESULT = 0x26
    FILE_CANCEL = 0x27
    FILE_RESUME_QUERY = 0x28
    FILE_RESUME_INFO = 0x29

    # Error reporting (0xF0)
    ERROR = 0xF0


class FrameFlags(IntEnum):
    NONE = 0x00
    ENCRYPTED_AEAD = 0x01   # Used when transport is RFCOMM or raw stream (payload is AES-256-GCM encrypted)
    REQUIRE_ACK = 0x02
    IS_BINARY_CHUNK = 0x04
