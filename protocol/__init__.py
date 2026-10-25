"""
LinkBridge Unified Transport & Security Protocol Package (v1.0)
Provides:
- Cryptographic identity (X.509 ECDSA P-256 certificates, SHA-256 fingerprints, pairing tokens, HKDF/AES-256-GCM AEAD for RFCOMM)
- Framing protocol (LB01 magic header, version, flags, msg_type, transfer_id, msg_id, length, SHA-256 payload digest)
- TransportAdapter abstraction with WifiTlsTransport and BluetoothRfcommTransport implementations
"""

from .constants import (
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    MessageType,
    TransportType,
    DEFAULT_WIFI_PORT,
    DEFAULT_CHUNK_SIZE,
    BT_CHUNK_SIZE,
    MAX_TEXT_BYTES,
    MAX_FILE_BYTES,
    SESSION_TTL_SECONDS,
    PAIRING_TOKEN_TTL_SECONDS,
)
from .crypto import (
    DeviceIdentity,
    PairingManager,
    SessionManager,
    AeadChannelCipher,
    compute_sha256_bytes,
    compute_sha256_file,
)
from .messages import (
    FrameHeader,
    ProtocolFrame,
    encode_frame,
    read_frame_from_stream,
    make_control_frame,
    make_chunk_frame,
)
from .transport import (
    TransportAdapter,
    WifiTlsTransport,
    BluetoothRfcommTransport,
    LoopbackStreamTransport,
    TransportError,
    AuthenticationError,
)

__all__ = [
    "PROTOCOL_MAGIC",
    "PROTOCOL_VERSION",
    "MessageType",
    "TransportType",
    "DEFAULT_WIFI_PORT",
    "DEFAULT_CHUNK_SIZE",
    "BT_CHUNK_SIZE",
    "MAX_TEXT_BYTES",
    "MAX_FILE_BYTES",
    "SESSION_TTL_SECONDS",
    "PAIRING_TOKEN_TTL_SECONDS",
    "DeviceIdentity",
    "PairingManager",
    "SessionManager",
    "AeadChannelCipher",
    "compute_sha256_bytes",
    "compute_sha256_file",
    "FrameHeader",
    "ProtocolFrame",
    "encode_frame",
    "read_frame_from_stream",
    "make_control_frame",
    "make_chunk_frame",
    "TransportAdapter",
    "WifiTlsTransport",
    "BluetoothRfcommTransport",
    "LoopbackStreamTransport",
    "TransportError",
    "AuthenticationError",
]
