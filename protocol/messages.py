"""
Binary framing and message serialization for LinkBridge v1.0.

Unified Frame Format (Header = 64 bytes fixed):
- Offset 0..4   (4B)  : Magic bytes b"LB01"
- Offset 4      (1B)  : Protocol version (1)
- Offset 5      (1B)  : FrameFlags bitmask
- Offset 6      (2B)  : MessageType (uint16 big-endian)
- Offset 8..16  (8B)  : msg_id (uint64 big-endian)
- Offset 16..24 (8B)  : transfer_id (uint64 big-endian; 0 for control/clipboard messages)
- Offset 24..32 (8B)  : payload_length (uint64 big-endian)
- Offset 32..64 (32B) : sha256_digest (32 raw bytes of SHA-256 of the unencrypted payload)

Followed immediately by `payload_length` bytes of payload (or AEAD-encrypted payload when ENCRYPTED_AEAD flag is set).
Separating `transfer_id` and `IS_BINARY_CHUNK` allows binary file chunks to stream without base64 bloat while control frames use compact UTF-8 JSON.
"""
import hashlib
import io
import json
import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .constants import (
    FrameFlags,
    MAX_CONTROL_FRAME_BYTES,
    MessageType,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
)
from .crypto import AeadChannelCipher

HEADER_STRUCT = struct.Struct("!4sBBHQQQ32s")
HEADER_SIZE = HEADER_STRUCT.size  # 64 bytes


class ProtocolFramingError(Exception):
    """Raised when a frame violates LinkBridge framing, size limits, or SHA-256 integrity."""


@dataclass
class FrameHeader:
    magic: bytes
    version: int
    flags: int
    msg_type: MessageType
    msg_id: int
    transfer_id: int
    payload_length: int
    sha256_digest: bytes

    def pack(self) -> bytes:
        return HEADER_STRUCT.pack(
            self.magic,
            self.version,
            self.flags,
            int(self.msg_type),
            self.msg_id,
            self.transfer_id,
            self.payload_length,
            self.sha256_digest,
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "FrameHeader":
        if len(raw) != HEADER_SIZE:
            raise ProtocolFramingError(f"Invalid header length: expected {HEADER_SIZE}, got {len(raw)}")
        magic, version, flags, msg_type_val, msg_id, transfer_id, length, digest = HEADER_STRUCT.unpack(raw)
        if magic != PROTOCOL_MAGIC:
            raise ProtocolFramingError(f"Invalid protocol magic: {magic!r}")
        if version != PROTOCOL_VERSION:
            raise ProtocolFramingError(f"Unsupported protocol version: {version}")
        try:
            msg_type = MessageType(msg_type_val)
        except ValueError as e:
            raise ProtocolFramingError(f"Unknown message type: 0x{msg_type_val:04x}") from e
        return cls(
            magic=magic,
            version=version,
            flags=flags,
            msg_type=msg_type,
            msg_id=msg_id,
            transfer_id=transfer_id,
            payload_length=length,
            sha256_digest=digest,
        )


@dataclass
class ProtocolFrame:
    header: FrameHeader
    payload: bytes

    def json_body(self) -> Dict[str, Any]:
        if self.header.flags & FrameFlags.IS_BINARY_CHUNK:
            raise ProtocolFramingError("Cannot parse binary file chunk as JSON control body")
        try:
            return json.loads(self.payload.decode("utf-8"))
        except Exception as e:
            raise ProtocolFramingError(f"Invalid JSON control payload: {e}") from e


def encode_frame(
    msg_type: MessageType,
    payload: bytes,
    msg_id: int,
    transfer_id: int = 0,
    flags: int = FrameFlags.NONE,
    aead_cipher: Optional[AeadChannelCipher] = None,
) -> bytes:
    """
    Encode a payload into a 64-byte header + payload bytes.
    Computes SHA-256 over the cleartext payload and optionally encrypts the payload with AES-256-GCM
    (binding the header metadata as Associated Data) when `aead_cipher` is provided.
    """
    digest = hashlib.sha256(payload).digest()
    if aead_cipher is not None:
        flags |= FrameFlags.ENCRYPTED_AEAD
        # Bind msg_type, msg_id, transfer_id, and digest in AEAD associated data
        aad = struct.pack("!BBHQQ32s", PROTOCOL_VERSION, flags, int(msg_type), msg_id, transfer_id, digest)
        wire_payload = aead_cipher.encrypt(payload, associated_data=aad)
    else:
        wire_payload = payload

    header = FrameHeader(
        magic=PROTOCOL_MAGIC,
        version=PROTOCOL_VERSION,
        flags=flags,
        msg_type=msg_type,
        msg_id=msg_id,
        transfer_id=transfer_id,
        payload_length=len(wire_payload),
        sha256_digest=digest,
    )
    return header.pack() + wire_payload


def _read_exact(stream: io.BufferedIOBase, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            if len(buf) == 0:
                raise EOFError("Stream closed cleanly")
            raise ProtocolFramingError(f"Unexpected EOF while reading frame: expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


def read_frame_from_stream(
    stream: io.BufferedIOBase,
    max_payload_bytes: int = MAX_CONTROL_FRAME_BYTES,
    aead_cipher: Optional[AeadChannelCipher] = None,
    require_aead: bool = False,
) -> ProtocolFrame:
    """
    Read and verify a complete ProtocolFrame from a byte stream.
    Enforces payload size limits, decrypts AEAD if active, and verifies SHA-256 content integrity.
    """
    raw_header = _read_exact(stream, HEADER_SIZE)
    header = FrameHeader.unpack(raw_header)

    if header.payload_length > max_payload_bytes:
        raise ProtocolFramingError(
            f"Frame payload length {header.payload_length} exceeds allowed maximum {max_payload_bytes}"
        )

    wire_payload = _read_exact(stream, header.payload_length) if header.payload_length > 0 else b""

    if require_aead and not (header.flags & FrameFlags.ENCRYPTED_AEAD):
        raise ProtocolFramingError("Unencrypted frame rejected on channel requiring AEAD encryption")

    if header.flags & FrameFlags.ENCRYPTED_AEAD:
        if aead_cipher is None:
            raise ProtocolFramingError("Received AEAD-encrypted frame but no cipher is configured")
        aad = struct.pack(
            "!BBHQQ32s",
            header.version,
            header.flags,
            int(header.msg_type),
            header.msg_id,
            header.transfer_id,
            header.sha256_digest,
        )
        try:
            cleartext = aead_cipher.decrypt(wire_payload, associated_data=aad)
        except Exception as e:
            raise ProtocolFramingError(f"AEAD decryption/authentication failed: {e}") from e
    else:
        cleartext = wire_payload

    actual_digest = hashlib.sha256(cleartext).digest()
    if actual_digest != header.sha256_digest:
        raise ProtocolFramingError("Frame SHA-256 integrity check failed")

    return ProtocolFrame(header=header, payload=cleartext)


def make_control_frame(
    msg_type: MessageType,
    body: Dict[str, Any],
    msg_id: int,
    transfer_id: int = 0,
    aead_cipher: Optional[AeadChannelCipher] = None,
) -> bytes:
    payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return encode_frame(
        msg_type=msg_type,
        payload=payload,
        msg_id=msg_id,
        transfer_id=transfer_id,
        flags=FrameFlags.NONE,
        aead_cipher=aead_cipher,
    )


def make_chunk_frame(
    chunk_bytes: bytes,
    msg_id: int,
    transfer_id: int,
    aead_cipher: Optional[AeadChannelCipher] = None,
) -> bytes:
    return encode_frame(
        msg_type=MessageType.FILE_CHUNK,
        payload=chunk_bytes,
        msg_id=msg_id,
        transfer_id=transfer_id,
        flags=FrameFlags.IS_BINARY_CHUNK,
        aead_cipher=aead_cipher,
    )
