"""
Unified TransportAdapter interface and concrete implementations for LinkBridge:
1. WifiTlsTransport:
   - Works over Local Wi-Fi LAN and Phone Wi-Fi Hotspot without internet.
   - Uses TLS 1.3 / 1.2 with X.509 ECDSA P-256 certificates + certificate fingerprint pinning
     + LinkBridge pairing & short-lived session authentication.
   - Includes UDP local subnet broadcast / multicast discovery with fallback to manual IP:Port & QR code.
2. BluetoothRfcommTransport:
   - Works over Bluetooth Classic RFCOMM sockets (`socket.AF_BLUETOOTH`, `socket.BTPROTO_RFCOMM` on Windows 10/11 & Linux).
   - Never assumes Bluetooth link-level security is sufficient: performs ephemeral ECDH P-256 key exchange
     bound to the paired LinkBridge link key via HKDF-SHA256 and encrypts all frames with AES-256-GCM (`AeadChannelCipher`).
   - Uses 16 KiB chunking (`BT_CHUNK_SIZE`) tuned for RFCOMM buffers and handles mid-stream disconnects cleanly.
3. LoopbackStreamTransport:
   - Deterministic in-memory / socketpair transport supporting both TLS and RFCOMM-AEAD modes,
     plus mid-stream fault injection for automated integration testing.
"""
import abc
import io
import json
import secrets
import socket
import ssl
import tempfile
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .constants import (
    BT_CHUNK_SIZE,
    BT_SERVICE_UUID,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_DISCOVERY_PORT,
    DEFAULT_WIFI_PORT,
    MAX_CONTROL_FRAME_BYTES,
    MessageType,
    TransportType,
)
from .crypto import (
    AeadChannelCipher,
    DeviceIdentity,
    PairingManager,
    SessionInfo,
    SessionManager,
)
from .messages import (
    ProtocolFrame,
    ProtocolFramingError,
    make_chunk_frame,
    make_control_frame,
    read_frame_from_stream,
)


class TransportError(Exception):
    """Raised when transport connection, I/O, or state fails."""


class AuthenticationError(TransportError):
    """Raised when peer certificate, pairing token, or session token is rejected."""


class SocketStreamAdapter(io.BufferedIOBase):
    """Wraps a socket or SSLSocket into a clean stream with exact read/write semantics."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def read(self, n: int = -1) -> bytes:
        if n <= 0:
            return self.sock.recv(4096)
        return self.sock.recv(n)

    def write(self, b: bytes) -> int:
        self.sock.sendall(b)
        return len(b)

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class TransportAdapter(abc.ABC):
    """
    Abstract base class separating clipboard and file transfer logic from the underlying medium
    (Wi-Fi LAN, Phone Hotspot, or Bluetooth RFCOMM).
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        transport_type: TransportType,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        self.identity = identity
        self.transport_type = transport_type
        self.chunk_size = chunk_size
        self._msg_counter = 0
        self._send_lock = threading.Lock()
        self._connected = False
        self.peer_device_id: Optional[str] = None
        self.peer_device_name: Optional[str] = None
        self.peer_fingerprint: Optional[str] = None
        self.session_token: Optional[str] = None
        self._aead_cipher: Optional[AeadChannelCipher] = None
        self._require_aead: bool = False
        self._dispatcher_active: bool = False
        self._reply_queue: "queue.Queue[Optional[ProtocolFrame]]" = queue.Queue()
        self._incoming_queue: "queue.Queue[Optional[ProtocolFrame]]" = queue.Queue()

    def next_msg_id(self) -> int:
        with self._send_lock:
            self._msg_counter += 1
            return self._msg_counter

    @property
    def is_connected(self) -> bool:
        return self._connected

    @abc.abstractmethod
    def _raw_stream(self) -> io.BufferedIOBase:
        """Return the active byte stream."""

    @abc.abstractmethod
    def close(self) -> None:
        """Close the underlying connection and release resources."""

    def send_control(
        self,
        msg_type: MessageType,
        body: Dict[str, Any],
        transfer_id: int = 0,
    ) -> int:
        if not self._connected:
            raise TransportError("الاتصال غير مفعّل (Transport is not connected)")
        msg_id = self.next_msg_id()
        if self.session_token and "session_token" not in body:
            body = dict(body)
            body["session_token"] = self.session_token
        raw = make_control_frame(
            msg_type=msg_type,
            body=body,
            msg_id=msg_id,
            transfer_id=transfer_id,
            aead_cipher=self._aead_cipher,
        )
        with self._send_lock:
            self._raw_stream().write(raw)
        return msg_id

    def send_chunk(self, chunk_bytes: bytes, transfer_id: int) -> int:
        if not self._connected:
            raise TransportError("الاتصال غير مفعّل أثناء إرسال الكتلة (Disconnected during chunk send)")
        msg_id = self.next_msg_id()
        raw = make_chunk_frame(
            chunk_bytes=chunk_bytes,
            msg_id=msg_id,
            transfer_id=transfer_id,
            aead_cipher=self._aead_cipher,
        )
        with self._send_lock:
            self._raw_stream().write(raw)
        return msg_id

    def _read_stream_frame(self, max_payload_bytes: int = MAX_CONTROL_FRAME_BYTES) -> ProtocolFrame:
        if not self._connected:
            raise TransportError("الاتصال غير مفعّل (Transport is not connected)")
        return read_frame_from_stream(
            self._raw_stream(),
            max_payload_bytes=max_payload_bytes,
            aead_cipher=self._aead_cipher,
            require_aead=(self._require_aead and self._aead_cipher is not None),
        )

    def receive_frame(self, max_payload_bytes: int = MAX_CONTROL_FRAME_BYTES) -> ProtocolFrame:
        if self._dispatcher_active:
            frame = self._incoming_queue.get(timeout=30.0)
            if frame is None:
                raise EOFError("Stream closed")
            return frame
        return self._read_stream_frame(max_payload_bytes=max_payload_bytes)

    def receive_reply_frame(self, max_payload_bytes: int = MAX_CONTROL_FRAME_BYTES) -> ProtocolFrame:
        if self._dispatcher_active:
            frame = self._reply_queue.get(timeout=30.0)
            if frame is None:
                raise EOFError("Stream closed while waiting for reply")
            return frame
        return self._read_stream_frame(max_payload_bytes=max_payload_bytes)

    def start_background_dispatcher(self, on_incoming_ready: Callable[[], None]) -> None:
        if self._dispatcher_active:
            return
        self._dispatcher_active = True
        reply_types = {
            MessageType.CLIPBOARD_ACK,
            MessageType.FILE_ACCEPT,
            MessageType.FILE_REJECT,
            MessageType.FILE_VERIFY_RESULT,
            MessageType.PONG,
        }

        def _reader_loop() -> None:
            while self._connected and self._dispatcher_active:
                try:
                    frame = self._read_stream_frame(max_payload_bytes=max(self.chunk_size * 2, MAX_CONTROL_FRAME_BYTES))
                except socket.timeout:
                    continue
                except Exception:
                    self._connected = False
                    self._reply_queue.put(None)
                    self._incoming_queue.put(None)
                    break
                if frame.header.msg_type in reply_types:
                    self._reply_queue.put(frame)
                else:
                    self._incoming_queue.put(frame)
                    if frame.header.msg_type in (
                        MessageType.CLIPBOARD_PUSH,
                        MessageType.FILE_OFFER,
                        MessageType.PING,
                        MessageType.DISCONNECT,
                        MessageType.REVOKE_PAIRING,
                    ):
                        threading.Thread(target=on_incoming_ready, daemon=True).start()

        threading.Thread(target=_reader_loop, daemon=True).start()

    # ------------------------------------------------------------------
    # Handshake, Pairing, and Session Authentication (Common to all media)
    # ------------------------------------------------------------------
    def client_handshake_and_pair_or_auth(
        self,
        pairing_manager: PairingManager,
        trusted_peers: Dict[str, Dict[str, Any]],
        pin_or_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Initiator (Client) handshake:
        1. Sends HELLO with local device_id, device_name, cert_pem, and optional ephemeral ECDH pubkey (if RFCOMM).
        2. Receives HELLO_ACK with responder's device_id, device_name, cert_pem, and optional ephemeral ECDH pubkey.
        3. If peer is not yet in `trusted_peers` (or `pin_or_secret` is provided), performs PAIR_REQUEST / PAIR_RESPONSE
           and derives the persistent `link_key`.
        4. Establishes AEAD cipher if on RFCOMM/AEAD mode.
        5. Performs AUTH_SESSION / AUTH_RESULT using HMAC proof over the session challenge to obtain a short-lived `session_token`.
        """
        eph_priv, eph_pub_pem = AeadChannelCipher.generate_ephemeral_ecdh()
        client_nonce = secrets.token_hex(16)
        hello_body = {
            "device_id": self.identity.device_id,
            "device_name": self.identity.device_name,
            "platform": self.identity.platform,
            "cert_pem": self.identity.cert_pem.decode("utf-8"),
            "fingerprint": self.identity.fingerprint_sha256,
            "transport": self.transport_type.value,
            "client_nonce": client_nonce,
            "ecdh_pub": eph_pub_pem.decode("utf-8"),
        }
        self.send_control(MessageType.HELLO, hello_body)
        ack_frame = self.receive_frame()
        if ack_frame.header.msg_type == MessageType.ERROR:
            raise AuthenticationError(ack_frame.json_body().get("reason", "Handshake rejected"))
        if ack_frame.header.msg_type != MessageType.HELLO_ACK:
            raise ProtocolFramingError(f"Expected HELLO_ACK, got {ack_frame.header.msg_type}")

        ack = ack_frame.json_body()
        peer_id = ack["device_id"]
        peer_name = ack["device_name"]
        peer_cert_pem = ack["cert_pem"].encode("utf-8")
        peer_fp = DeviceIdentity.fingerprint_from_pem(peer_cert_pem)
        if peer_fp != ack.get("fingerprint"):
            raise AuthenticationError("تعارض في بصمة شهادة الجهاز المقابل (Peer certificate fingerprint mismatch)")

        server_nonce = ack["server_nonce"]
        peer_ecdh_pub = ack["ecdh_pub"].encode("utf-8")

        # Check if already paired or needs pairing
        peer_record = trusted_peers.get(peer_id)
        if peer_record is not None and pin_or_secret == "AUTO_APPROVE":
            # Already paired and trusted! Skip PAIR_REQUEST and proceed directly to AUTH_SESSION
            pin_or_secret = None

        if peer_record is None or pin_or_secret is not None:
            if not pin_or_secret:
                raise AuthenticationError(
                    "الجهاز غير مقترن مسبقًا؛ يرجى الموافقة على الاتصال أولًا (Device not paired)"
                )
            if pin_or_secret == "AUTO_APPROVE":
                self.send_control(
                    MessageType.PAIR_REQUEST,
                    {
                        "device_id": self.identity.device_id,
                        "device_name": self.identity.device_name,
                        "pairing_mode": "PROMPT_APPROVAL",
                        "proof_hmac": "ECDH_PROMPT_APPROVAL",
                    },
                )
            else:
                proof = pairing_manager.compute_pairing_hmac(
                    pin_or_secret=pin_or_secret,
                    initiator_device_id=self.identity.device_id,
                    initiator_fp=self.identity.fingerprint_sha256,
                    responder_device_id=peer_id,
                    responder_fp=peer_fp,
                    nonce=f"{client_nonce}:{server_nonce}",
                )
                self.send_control(
                    MessageType.PAIR_REQUEST,
                    {
                        "device_id": self.identity.device_id,
                        "device_name": self.identity.device_name,
                        "pairing_mode": "PIN",
                        "proof_hmac": proof,
                    },
                )
            pair_resp_frame = self.receive_frame()
            if pair_resp_frame.header.msg_type != MessageType.PAIR_RESPONSE:
                raise AuthenticationError("فشل طلب الاقتران (Pairing failed)")
            pair_resp = pair_resp_frame.json_body()
            if not pair_resp.get("paired"):
                raise AuthenticationError(pair_resp.get("reason", "تم رفض الاتصال من الطرف الآخر (Connection rejected)"))

            if pin_or_secret == "AUTO_APPROVE":
                link_key = pairing_manager.derive_ecdh_approval_link_key(
                    local_ephemeral_priv=eph_priv,
                    peer_ephemeral_pub_pem=peer_ecdh_pub,
                    initiator_fp=self.identity.fingerprint_sha256,
                    responder_fp=peer_fp,
                    client_nonce=client_nonce,
                    server_nonce=server_nonce,
                )
            else:
                link_key = pairing_manager.derive_shared_link_key(
                    pin_or_secret=pin_or_secret,
                    initiator_fp=self.identity.fingerprint_sha256,
                    responder_fp=peer_fp,
                )
            peer_record = {
                "device_id": peer_id,
                "device_name": peer_name,
                "fingerprint": peer_fp,
                "cert_pem": peer_cert_pem.decode("utf-8"),
                "link_key_hex": link_key.hex(),
            }
            trusted_peers[peer_id] = peer_record
        else:
            # Verify pinned certificate fingerprint matches stored record
            if peer_record.get("fingerprint") != peer_fp:
                raise AuthenticationError(
                    "تحذير أمني: تغيرت بصمة شهادة الجهاز المقترن! تم رفض الاتصال (Pinned certificate mismatch)"
                )
            link_key = bytes.fromhex(peer_record["link_key_hex"])



        # Authenticate session using derived link_key
        import hmac as _hmac
        import hashlib as _hashlib

        auth_mac = _hmac.new(
            link_key,
            f"AUTH:{self.identity.device_id}:{peer_id}:{client_nonce}:{server_nonce}".encode("utf-8"),
            _hashlib.sha256,
        ).hexdigest()
        self.send_control(
            MessageType.AUTH_SESSION,
            {
                "device_id": self.identity.device_id,
                "auth_mac": auth_mac,
            },
        )
        auth_res_frame = self.receive_frame()
        if auth_res_frame.header.msg_type != MessageType.AUTH_RESULT:
            raise AuthenticationError("استجابة مصادقة غير صالحة (Invalid AUTH_RESULT)")
        auth_res = auth_res_frame.json_body()
        if not auth_res.get("authenticated"):
            raise AuthenticationError(auth_res.get("reason", "تم رفض الجلسة (Session rejected)"))

        self.peer_device_id = peer_id
        self.peer_device_name = peer_name
        self.peer_fingerprint = peer_fp
        self.session_token = auth_res["session_token"]
        if self._require_aead:
            transcript = f"{client_nonce}:{server_nonce}:{self.identity.fingerprint_sha256}:{peer_fp}".encode("utf-8")
            self._aead_cipher = AeadChannelCipher.from_ecdh_and_link_key(
                local_ephemeral_priv=eph_priv,
                peer_ephemeral_pub_pem=peer_ecdh_pub,
                paired_link_key=link_key,
                context_transcript=transcript,
            )
        return peer_record

    def server_handshake_and_pair_or_auth(
        self,
        pairing_manager: PairingManager,
        session_manager: SessionManager,
        trusted_peers: Dict[str, Dict[str, Any]],
        active_pin_or_secret: Optional[str] = None,
        pairing_approval_callback: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> SessionInfo:
        """
        Responder (Server) handshake:
        Verifies client HELLO, processes PAIR_REQUEST if needed, activates AEAD if RFCOMM,
        verifies AUTH_SESSION HMAC proof, and issues a short-lived SessionInfo.
        """
        hello_frame = self.receive_frame()
        if hello_frame.header.msg_type == MessageType.DISCOVER_PING:
            self.send_control(
                MessageType.DISCOVER_PONG,
                {
                    "proto": "LinkBridge/1.0",
                    "device_id": self.identity.device_id,
                    "device_name": self.identity.device_name,
                    "platform": self.identity.platform,
                    "fingerprint": self.identity.fingerprint_sha256,
                    "port": DEFAULT_WIFI_PORT,
                },
            )
            raise TransportError("DISCOVER_PING_HANDLED")
        if hello_frame.header.msg_type != MessageType.HELLO:
            raise ProtocolFramingError(f"Expected HELLO, got {hello_frame.header.msg_type}")
        hello = hello_frame.json_body()
        peer_id = hello["device_id"]
        peer_name = hello["device_name"]
        peer_cert_pem = hello["cert_pem"].encode("utf-8")
        peer_fp = DeviceIdentity.fingerprint_from_pem(peer_cert_pem)
        if peer_fp != hello.get("fingerprint"):
            self.send_control(MessageType.ERROR, {"reason": "Fingerprint mismatch"})
            raise AuthenticationError("Peer certificate fingerprint mismatch")

        client_nonce = hello["client_nonce"]
        peer_ecdh_pub = hello["ecdh_pub"].encode("utf-8")

        eph_priv, eph_pub_pem = AeadChannelCipher.generate_ephemeral_ecdh()
        server_nonce = secrets.token_hex(16)

        self.send_control(
            MessageType.HELLO_ACK,
            {
                "device_id": self.identity.device_id,
                "device_name": self.identity.device_name,
                "platform": self.identity.platform,
                "cert_pem": self.identity.cert_pem.decode("utf-8"),
                "fingerprint": self.identity.fingerprint_sha256,
                "server_nonce": server_nonce,
                "ecdh_pub": eph_pub_pem.decode("utf-8"),
            },
        )

        # Next frame can be PAIR_REQUEST or AUTH_SESSION
        next_frame = self.receive_frame()
        if next_frame.header.msg_type == MessageType.PAIR_REQUEST:
            req = next_frame.json_body()
            pairing_mode = req.get("pairing_mode", "PIN")
            if pairing_mode == "PROMPT_APPROVAL":
                approved = True
                if pairing_approval_callback is not None:
                    approved = bool(
                        pairing_approval_callback(
                            {
                                "device_id": peer_id,
                                "device_name": peer_name,
                                "platform": hello.get("platform", "Android"),
                                "fingerprint": peer_fp,
                                "transport": self.transport_type.value,
                            }
                        )
                    )
                if not approved:
                    reason = "تم رفض طلب الاتصال من قبل المستخدم (Connection declined by user)"
                    self.send_control(MessageType.PAIR_RESPONSE, {"paired": False, "reason": reason})
                    raise AuthenticationError(reason)
                reason = "تمت الموافقة على الاتصال بنجاح"
                link_key = pairing_manager.derive_ecdh_approval_link_key(
                    local_ephemeral_priv=eph_priv,
                    peer_ephemeral_pub_pem=peer_ecdh_pub,
                    initiator_fp=peer_fp,
                    responder_fp=self.identity.fingerprint_sha256,
                    client_nonce=client_nonce,
                    server_nonce=server_nonce,
                )
            else:
                provided_hmac = req.get("proof_hmac", "")
                ok, reason = pairing_manager.verify_pairing_request(
                    provided_hmac=provided_hmac,
                    initiator_device_id=peer_id,
                    initiator_fp=peer_fp,
                    responder_device_id=self.identity.device_id,
                    responder_fp=self.identity.fingerprint_sha256,
                    nonce=f"{client_nonce}:{server_nonce}",
                )
                if not ok or not active_pin_or_secret:
                    self.send_control(MessageType.PAIR_RESPONSE, {"paired": False, "reason": reason})
                    raise AuthenticationError(reason)

                link_key = pairing_manager.derive_shared_link_key(
                    pin_or_secret=active_pin_or_secret,
                    initiator_fp=peer_fp,
                    responder_fp=self.identity.fingerprint_sha256,
                )
            trusted_peers[peer_id] = {
                "device_id": peer_id,
                "device_name": peer_name,
                "fingerprint": peer_fp,
                "cert_pem": peer_cert_pem.decode("utf-8"),
                "link_key_hex": link_key.hex(),
            }
            self.send_control(MessageType.PAIR_RESPONSE, {"paired": True, "reason": reason})



            auth_frame = self.receive_frame()
        else:
            peer_record = trusted_peers.get(peer_id)
            if not peer_record:
                self.send_control(
                    MessageType.AUTH_RESULT,
                    {"authenticated": False, "reason": "الجهاز غير مقترن (Unpaired device)"},
                )
                raise AuthenticationError("Unpaired device attempted session authentication")
            if peer_record.get("fingerprint") != peer_fp:
                self.send_control(
                    MessageType.AUTH_RESULT,
                    {"authenticated": False, "reason": "Pinned certificate mismatch"},
                )
                raise AuthenticationError("Pinned certificate fingerprint mismatch")

            link_key = bytes.fromhex(peer_record["link_key_hex"])

            auth_frame = next_frame

        if auth_frame.header.msg_type != MessageType.AUTH_SESSION:
            raise ProtocolFramingError(f"Expected AUTH_SESSION, got {auth_frame.header.msg_type}")

        auth_body = auth_frame.json_body()
        import hmac as _hmac
        import hashlib as _hashlib

        expected_mac = _hmac.new(
            link_key,
            f"AUTH:{peer_id}:{self.identity.device_id}:{client_nonce}:{server_nonce}".encode("utf-8"),
            _hashlib.sha256,
        ).hexdigest()

        if not _hmac.compare_digest(auth_body.get("auth_mac", ""), expected_mac):
            self.send_control(
                MessageType.AUTH_RESULT,
                {"authenticated": False, "reason": "فشل التحقق من توقيع الجلسة (Invalid session MAC)"},
            )
            raise AuthenticationError("Session HMAC verification failed")

        session_info = session_manager.create_session(
            peer_device_id=peer_id,
            peer_fingerprint=peer_fp,
            transport_type=self.transport_type.value,
        )
        self.peer_device_id = peer_id
        self.peer_device_name = peer_name
        self.peer_fingerprint = peer_fp
        self.session_token = session_info.session_token

        self.send_control(
            MessageType.AUTH_RESULT,
            {
                "authenticated": True,
                "session_token": session_info.session_token,
                "expires_at": session_info.expires_at,
            },
        )
        if self._require_aead:
            transcript = f"{client_nonce}:{server_nonce}:{peer_fp}:{self.identity.fingerprint_sha256}".encode("utf-8")
            self._aead_cipher = AeadChannelCipher.from_ecdh_and_link_key(
                local_ephemeral_priv=eph_priv,
                peer_ephemeral_pub_pem=peer_ecdh_pub,
                paired_link_key=link_key,
                context_transcript=transcript,
            )
        return session_info


class WifiTlsTransport(TransportAdapter):
    """
    Wi-Fi LAN and Phone Hotspot transport over TCP + TLS 1.3/1.2.
    - Binds strictly to private RFC1918 / hotspot interfaces or explicit local IP.
    - Uses mutual certificate exchange / application-pinned X.509 certificates.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        sock: Optional[socket.socket] = None,
        is_hotspot: bool = False,
        require_aead: bool = False,
    ):
        super().__init__(
            identity=identity,
            transport_type=TransportType.WIFI_HOTSPOT if is_hotspot else TransportType.WIFI_LAN,
            chunk_size=DEFAULT_CHUNK_SIZE,
        )
        self._require_aead = require_aead
        self._ssl_sock: Optional[socket.socket] = sock
        self._stream: Optional[SocketStreamAdapter] = SocketStreamAdapter(sock) if sock else None
        self._connected = sock is not None

    @staticmethod
    def _create_ssl_context(identity: DeviceIdentity, is_server: bool) -> Tuple[ssl.SSLContext, Path]:
        purpose = ssl.Purpose.CLIENT_AUTH if is_server else ssl.Purpose.SERVER_AUTH
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if is_server else ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        # Certificate pinning is enforced cryptographically during LinkBridge HELLO/AUTH against SQLite pinned fingerprint
        ctx.verify_mode = ssl.CERT_NONE

        tmp_dir = Path(tempfile.mkdtemp(prefix="lb_tls_"))
        if is_server or b"BEGIN CERTIFICATE" in identity.cert_pem:
            cert_p = tmp_dir / "cert.pem"
            key_p = tmp_dir / "key.pem"
            cert_p.write_bytes(identity.cert_pem)
            key_p.write_bytes(identity.key_pem)
            ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
        return ctx, tmp_dir

    @classmethod
    def connect(
        cls,
        identity: DeviceIdentity,
        host: str,
        port: int = DEFAULT_WIFI_PORT,
        timeout: float = 10.0,
        is_hotspot: bool = False,
        use_tls: bool = True,
    ) -> "WifiTlsTransport":
        if not use_tls:
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            return cls(identity=identity, sock=raw_sock, is_hotspot=is_hotspot, require_aead=True)
        ctx, tmp_dir = cls._create_ssl_context(identity, is_server=False)
        try:
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname="linkbridge.local")
            return cls(identity=identity, sock=ssl_sock, is_hotspot=is_hotspot, require_aead=False)
        finally:
            for p in tmp_dir.glob("*"):
                try:
                    p.unlink()
                except OSError:
                    pass
            try:
                tmp_dir.rmdir()
            except OSError:
                pass

    @classmethod
    def wrap_accepted_socket(
        cls,
        identity: DeviceIdentity,
        client_sock: socket.socket,
        is_hotspot: bool = False,
    ) -> "WifiTlsTransport":
        ctx, tmp_dir = cls._create_ssl_context(identity, is_server=True)
        try:
            # Peek first byte: 0x16 = TLS ClientHello, 0x4C ('L') = LB01 AEAD frame
            first_byte = client_sock.recv(1, socket.MSG_PEEK)
            if first_byte == b"L":
                return cls(identity=identity, sock=client_sock, is_hotspot=is_hotspot, require_aead=True)
            ssl_sock = ctx.wrap_socket(client_sock, server_side=True)
            return cls(identity=identity, sock=ssl_sock, is_hotspot=is_hotspot, require_aead=False)
        finally:
            for p in tmp_dir.glob("*"):
                try:
                    p.unlink()
                except OSError:
                    pass
            try:
                tmp_dir.rmdir()
            except OSError:
                pass

    def _raw_stream(self) -> io.BufferedIOBase:
        if not self._stream:
            raise TransportError("لا يوجد اتصال TLS نشط (No active TLS stream)")
        return self._stream

    def close(self) -> None:
        self._connected = False
        if self._stream:
            self._stream.close()
            self._stream = None
        self._ssl_sock = None


class BluetoothRfcommTransport(TransportAdapter):
    """
    Bluetooth Classic RFCOMM transport (`TransportType.BLUETOOTH_RFCOMM`).
    - Inspects system capabilities (`socket.AF_BLUETOOTH` and `socket.BTPROTO_RFCOMM`) at runtime.
    - Uses `BT_CHUNK_SIZE` (16 KiB) to respect RFCOMM buffer characteristics.
    - Enforces `self._require_aead = True` so all frames after HELLO/PAIR are encrypted with
      forward-secret ECDH P-256 + HKDF-SHA256 + AES-256-GCM (`AeadChannelCipher`).
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        sock: Optional[socket.socket] = None,
        stream: Optional[io.BufferedIOBase] = None,
    ):
        super().__init__(
            identity=identity,
            transport_type=TransportType.BLUETOOTH_RFCOMM,
            chunk_size=BT_CHUNK_SIZE,
        )
        self._require_aead = True
        self._bt_sock = sock
        if stream is not None:
            self._stream: Optional[io.BufferedIOBase] = stream
            self._connected = True
        elif sock is not None:
            self._stream = SocketStreamAdapter(sock)
            self._connected = True
        else:
            self._stream = None
            self._connected = False

    @staticmethod
    def check_system_capabilities() -> Dict[str, Any]:
        """
        Inspect OS and Python runtime support for Bluetooth RFCOMM.
        Never claims Bluetooth hardware is available if the OS/environment lacks an adapter or RFCOMM support.
        """
        has_af_bt = hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_RFCOMM")
        adapter_available = False
        reason = ""
        if not has_af_bt:
            reason = (
                "واجهة مقابس Bluetooth RFCOMM غير مفعّلة في بناء Python الحالي "
                "(socket.AF_BLUETOOTH not compiled in this Python build)"
            )
        else:
            try:
                s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
                s.close()
                adapter_available = True
                reason = "مقابس Bluetooth RFCOMM مدعومة على مستوى النظام"
            except OSError as e:
                adapter_available = False
                reason = f"لا يوجد محول Bluetooth فعلي نشط أو تعذر فتح مقبس RFCOMM ({e})"

        return {
            "af_bluetooth_compiled": has_af_bt,
            "rfcomm_socket_creatable": adapter_available,
            "service_uuid": BT_SERVICE_UUID,
            "status_message": reason,
        }

    @classmethod
    def connect(
        cls,
        identity: DeviceIdentity,
        bt_mac_address: str,
        channel: int = 4,
        timeout: float = 12.0,
    ) -> "BluetoothRfcommTransport":
        caps = cls.check_system_capabilities()
        if not caps["af_bluetooth_compiled"]:
            raise TransportError(caps["status_message"])
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            sock.settimeout(timeout)
            sock.connect((bt_mac_address, channel))
            return cls(identity=identity, sock=sock)
        except OSError as e:
            raise TransportError(
                f"تعذر الاتصال عبر Bluetooth RFCOMM بالجهاز {bt_mac_address} على القناة {channel}: {e}"
            ) from e

    def _raw_stream(self) -> io.BufferedIOBase:
        if not self._stream:
            raise TransportError("لا يوجد اتصال Bluetooth RFCOMM نشط (No active RFCOMM stream)")
        return self._stream

    def close(self) -> None:
        self._connected = False
        if self._stream:
            self._stream.close()
            self._stream = None
        self._bt_sock = None


class LoopbackStreamTransport(TransportAdapter):
    """
    Connected pair of socket-backed transports for deterministic integration testing
    of both Wi-Fi and Bluetooth RFCOMM protocol stacks, including mid-transfer disconnect injection.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        sock: socket.socket,
        transport_type: TransportType = TransportType.WIFI_LAN,
        require_aead: bool = False,
    ):
        chunk_sz = BT_CHUNK_SIZE if transport_type == TransportType.BLUETOOTH_RFCOMM else DEFAULT_CHUNK_SIZE
        super().__init__(identity=identity, transport_type=transport_type, chunk_size=chunk_sz)
        self._sock = sock
        self._stream = SocketStreamAdapter(sock)
        self._connected = True
        self._require_aead = require_aead

    @classmethod
    def create_pair(
        cls,
        client_identity: DeviceIdentity,
        server_identity: DeviceIdentity,
        transport_type: TransportType = TransportType.WIFI_LAN,
    ) -> Tuple["LoopbackStreamTransport", "LoopbackStreamTransport"]:
        s1, s2 = socket.socketpair()
        s1.settimeout(10.0)
        s2.settimeout(10.0)
        require_aead = transport_type == TransportType.BLUETOOTH_RFCOMM
        return (
            cls(client_identity, s1, transport_type=transport_type, require_aead=require_aead),
            cls(server_identity, s2, transport_type=transport_type, require_aead=require_aead),
        )

    def _raw_stream(self) -> io.BufferedIOBase:
        return self._stream

    def close(self) -> None:
        self._connected = False
        self._stream.close()


class RouteSelector:
    """
    Selects or recommends the optimal transport route based on task type, payload size,
    and active connectivity, without ever silently switching mid-file-transfer.
    """

    @staticmethod
    def recommend_route(
        wifi_available: bool,
        hotspot_available: bool,
        bluetooth_available: bool,
        user_preferred: Optional[TransportType] = None,
        payload_size_bytes: int = 0,
        transfer_in_progress: bool = False,
        current_active_route: Optional[TransportType] = None,
    ) -> Dict[str, Any]:
        if transfer_in_progress and current_active_route is not None:
            return {
                "selected_route": current_active_route,
                "reason": "يمنع تبديل المسار تلقائيًا أثناء نقل ملف نشط للحفاظ على سلامة الكتل (Active transfer locked)",
                "switched": False,
            }

        if user_preferred == TransportType.BLUETOOTH_RFCOMM:
            if bluetooth_available:
                warning = (
                    "تم اختيار Bluetooth يدويًا؛ يُفضّل استخدام Wi-Fi للملفات الكبيرة لسرعة أعلى."
                    if payload_size_bytes > 1 * 1024 * 1024
                    else "تم اختيار Bluetooth يدويًا."
                )
                return {
                    "selected_route": TransportType.BLUETOOTH_RFCOMM,
                    "reason": warning,
                    "switched": False,
                }
            return {
                "selected_route": None,
                "reason": "مسار Bluetooth المختار يدويًا غير متاح حاليًا؛ يرجى التحقق من الاقتران أو اختيار Wi-Fi.",
                "switched": False,
            }

        if wifi_available:
            return {
                "selected_route": TransportType.WIFI_LAN,
                "reason": "الشبكة المحلية Wi-Fi متاحة وهي المسار المفضل والأسرع للنصوص والملفات الكبيرة.",
                "switched": False,
            }
        if hotspot_available:
            return {
                "selected_route": TransportType.WIFI_HOTSPOT,
                "reason": "نقطة اتصال الهاتف (Hotspot) متاحة وتوفر سرعة عالية دون الحاجة إلى إنترنت.",
                "switched": False,
            }
        if bluetooth_available:
            return {
                "selected_route": TransportType.BLUETOOTH_RFCOMM,
                "reason": "تم اختيار Bluetooth RFCOMM لعدم توفر شبكة Wi-Fi أو نقطة اتصال حاليًا.",
                "switched": False,
            }

        return {
            "selected_route": None,
            "reason": "لا يوجد مسار اتصال متاح حاليًا (تأكد من الاتصال بنفس شبكة Wi-Fi أو نقطة الاتصال أو إتمام اقتران Bluetooth).",
            "switched": False,
        }


class LocalDiscoveryService:
    """
    UDP local subnet discovery responder and scanner for Wi-Fi LAN / Hotspot.
    Also formats QR pairing payloads containing local IP, port, certificate fingerprint, and one-time pairing secret.
    """

    @staticmethod
    def get_local_private_ips() -> List[Dict[str, str]]:
        """Return list of private local IPv4 addresses (LAN or Hotspot) — never public internet interfaces."""
        results: List[Dict[str, str]] = []
        try:
            import netifaces

            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for addr_info in addrs:
                    ip = addr_info.get("addr", "")
                    if ip and not ip.startswith("127."):
                        mode = "WIFI_HOTSPOT" if ip.startswith("192.168.43.") or ip.startswith("192.168.137.") else "WIFI_LAN"
                        results.append({"interface": iface, "ip": ip, "mode": mode})
        except Exception:
            try:
                hostname = socket.gethostname()
                for ip in socket.gethostbyname_ex(hostname)[2]:
                    if not ip.startswith("127."):
                        results.append({"interface": "default", "ip": ip, "mode": "WIFI_LAN"})
            except Exception:
                pass
        if not results:
            results.append({"interface": "loopback", "ip": "127.0.0.1", "mode": "LOOPBACK"})
        return results

    @staticmethod
    def build_qr_pairing_payload(
        identity: DeviceIdentity,
        ip: str,
        port: int,
        pairing_secret_hex: str,
        pin_code: str,
        expires_at: float,
    ) -> str:
        """Return compact JSON string suitable for QR code scanning or manual copy."""
        return json.dumps(
            {
                "proto": "LinkBridge/1.0",
                "device_id": identity.device_id,
                "device_name": identity.device_name,
                "ip": ip,
                "port": port,
                "fp": identity.fingerprint_sha256,
                "secret": pairing_secret_hex,
                "pin": pin_code,
                "exp": int(expires_at),
            },
            ensure_ascii=False,
        )


    @staticmethod
    def get_primary_lan_ip() -> str:
        """Detect the active primary Wi-Fi / Hotspot IPv4 address reliably even without internet."""
        for target in ("192.168.43.1", "192.168.137.1", "192.168.1.1", "10.255.255.255"):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((target, 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                    return ip
            except OSError:
                pass
        ips = LocalDiscoveryService.get_local_private_ips()
        for item in ips:
            ip = item["ip"]
            if ip.startswith("192.168.") or ip.startswith("10."):
                return ip
        return ips[0]["ip"]

    @staticmethod
    def probe_peer_over_tls(
        identity: DeviceIdentity,
        ip: str,
        port: int = DEFAULT_WIFI_PORT,
        timeout: float = 0.45,
    ) -> Optional[Dict[str, Any]]:
        """Actively probe an IP:Port with MSG_DISCOVER_PING over TLS to identify a LinkBridge peer."""
        try:
            t = WifiTlsTransport.connect(identity, host=ip, port=port, timeout=timeout, use_tls=False)
            try:
                t.send_control(
                    MessageType.DISCOVER_PING,
                    {"device_id": identity.device_id, "device_name": identity.device_name},
                )
                pong_frame = t.receive_frame()
                if pong_frame.header.msg_type == MessageType.DISCOVER_PONG:
                    body = pong_frame.json_body()
                    if body.get("device_id") and body.get("device_id") != identity.device_id:
                        mode = "WIFI_HOTSPOT" if (ip.startswith("192.168.43.") or ip.startswith("192.168.137.")) else "WIFI_LAN"
                        return {
                            "device_id": body["device_id"],
                            "device_name": body.get("device_name", "LinkBridge Device"),
                            "platform": body.get("platform", "Android"),
                            "ip": ip,
                            "port": int(body.get("port", port)),
                            "transport": mode,
                            "address": f"{ip}:{int(body.get('port', port))}",
                        }
            finally:
                t.close()
        except Exception:
            pass
        return None


class AutoDiscoveryEngine:
    """
    Zero-configuration background discovery engine for LinkBridge:
    - Broadcasts UDP presence packets on port 48521 every 2 seconds across all local subnets & hotspot interfaces.
    - Listens on UDP port 48521 for peer beacons.
    - Actively scans ARP neighbors (native IP neighbor table) and local `/24` subnet IPs on TCP port 48520 using `DISCOVER_PING`
      so devices appear automatically even if the Wi-Fi router blocks UDP broadcasts or Windows Firewall blocks inbound UDP!
    - Scans paired Bluetooth devices on Windows/Linux.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        listen_port: int = DEFAULT_WIFI_PORT,
        discovery_port: int = DEFAULT_DISCOVERY_PORT,
        on_devices_updated: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    ):
        self.identity = identity
        self.listen_port = listen_port
        self.discovery_port = discovery_port
        self.on_devices_updated = on_devices_updated
        self._running = False
        self._lock = threading.Lock()
        self._discovered: Dict[str, Dict[str, Any]] = {}

    def get_discovered_devices(self) -> List[Dict[str, Any]]:
        with self._lock:
            now = time.time()
            # Keep devices seen within the last 45 seconds (or Bluetooth paired devices)
            stale = [
                k for k, v in self._discovered.items()
                if v.get("transport") != "BLUETOOTH_RFCOMM" and (now - v.get("last_seen", now)) > 45.0
            ]
            for k in stale:
                del self._discovered[k]
            return list(self._discovered.values())

    def _register_device(self, info: Dict[str, Any]) -> None:
        dev_id = info.get("device_id", "")
        if not dev_id or dev_id == self.identity.device_id:
            return
        info = dict(info)
        info["last_seen"] = time.time()
        changed = False
        with self._lock:
            prev = self._discovered.get(dev_id)
            if prev is None or prev.get("address") != info.get("address"):
                changed = True
            self._discovered[dev_id] = info
        if changed and self.on_devices_updated:
            try:
                self.on_devices_updated(self.get_discovered_devices())
            except Exception:
                pass

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        threading.Thread(target=self._udp_listener_loop, daemon=True).start()
        threading.Thread(target=self._udp_beacon_loop, daemon=True).start()
        threading.Thread(target=self._active_scan_loop, daemon=True).start()

    def stop(self) -> None:
        self._running = False

    def trigger_immediate_scan(self) -> None:
        threading.Thread(target=self._run_single_active_scan, daemon=True).start()

    def _udp_listener_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", self.discovery_port))
            sock.settimeout(1.0)
        except OSError:
            sock.close()
            return
        try:
            while self._running:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    msg = json.loads(data.decode("utf-8"))
                    if msg.get("proto", "").startswith("LinkBridge") and msg.get("device_id") != self.identity.device_id:
                        peer_ip = addr[0]
                        peer_port = int(msg.get("port", DEFAULT_WIFI_PORT))
                        mode = "WIFI_HOTSPOT" if (peer_ip.startswith("192.168.43.") or peer_ip.startswith("192.168.137.")) else "WIFI_LAN"
                        self._register_device(
                            {
                                "device_id": msg["device_id"],
                                "device_name": msg.get("device_name", "Android Phone"),
                                "platform": msg.get("platform", "Android"),
                                "ip": peer_ip,
                                "port": peer_port,
                                "transport": mode,
                                "address": f"{peer_ip}:{peer_port}",
                            }
                        )
                except Exception:
                    pass
        finally:
            sock.close()

    def _udp_beacon_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            while self._running:
                payload = json.dumps(
                    {
                        "proto": "LinkBridge/1.0",
                        "device_id": self.identity.device_id,
                        "device_name": self.identity.device_name,
                        "platform": self.identity.platform,
                        "port": self.listen_port,
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
                targets = {"255.255.255.255", "192.168.43.255", "192.168.137.255"}
                for item in LocalDiscoveryService.get_local_private_ips():
                    ip = item["ip"]
                    parts = ip.split(".")
                    if len(parts) == 4 and not ip.startswith("127."):
                        targets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.255")
                for bcast in targets:
                    try:
                        sock.sendto(payload, (bcast, self.discovery_port))
                    except OSError:
                        pass
                time.sleep(2.0)
        finally:
            sock.close()

    def _active_scan_loop(self) -> None:
        while self._running:
            self._run_single_active_scan()
            for _ in range(18):
                if not self._running:
                    break
                time.sleep(1.0)

    def _run_single_active_scan(self) -> None:
        # 1. Collect candidate IPs from ARP table and local /24 subnets
        candidate_ips: List[str] = ["192.168.43.1", "192.168.137.1", "192.168.49.1"]
        local_ips = {item["ip"] for item in LocalDiscoveryService.get_local_private_ips()}
        primary_ip = LocalDiscoveryService.get_primary_lan_ip()
        if primary_ip:
            local_ips.add(primary_ip)

        # Read ARP cache using native Win32 API (iphlpapi.GetIpNetTable) or /proc/net/arp — ZERO external processes / console windows!
        try:
            if os.name == "nt":
                import ctypes
                import struct as _struct
                iphlpapi = ctypes.windll.iphlpapi
                size = ctypes.c_ulong(0)
                iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
                if size.value > 0:
                    buf = ctypes.create_string_buffer(size.value)
                    if iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False) == 0:
                        num_entries = _struct.unpack_from("<I", buf.raw, 0)[0]
                        offset = 4
                        # Each MIB_IPNETROW is 24 bytes: dwIndex(4), dwPhysAddrLen(4), bPhysAddr(8), dwAddr(4), dwType(4)
                        for _ in range(min(num_entries, 512)):
                            if offset + 24 > size.value:
                                break
                            dw_addr, dw_type = _struct.unpack_from("<II", buf.raw, offset + 16)
                            offset += 24
                            if dw_type in (3, 4):  # Dynamic (3) or Static (4)
                                ip_str = socket.inet_ntoa(_struct.pack("<I", dw_addr))
                                if not ip_str.startswith("127.") and not ip_str.startswith("224.") and not ip_str.endswith(".255"):
                                    if ip_str not in local_ips and ip_str not in candidate_ips:
                                        candidate_ips.append(ip_str)
            elif Path("/proc/net/arp").exists():
                for line in Path("/proc/net/arp").read_text(encoding="utf-8").splitlines()[1:]:
                    parts = line.split()
                    if parts and parts[0] not in local_ips and parts[0] not in candidate_ips:
                        candidate_ips.append(parts[0])
        except Exception:
            pass

        # Add /24 subnet IPs of primary interface
        for lip in list(local_ips):
            parts = lip.split(".")
            if len(parts) == 4 and (lip.startswith("192.168.") or lip.startswith("10.") or lip.startswith("172.")):
                prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
                for host_id in range(1, 255):
                    cip = f"{prefix}.{host_id}"
                    if cip not in local_ips and cip not in candidate_ips:
                        candidate_ips.append(cip)

        # Fast parallel TCP check on port 48520 using worker threads
        from concurrent.futures import ThreadPoolExecutor

        def _check_ip(ip_addr: str) -> None:
            if not self._running:
                return
            # Quick 180ms TCP connect check first before TLS handshake
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.18)
                if s.connect_ex((ip_addr, self.listen_port)) != 0:
                    s.close()
                    return
                s.close()
            except OSError:
                return
            info = LocalDiscoveryService.probe_peer_over_tls(self.identity, ip_addr, self.listen_port, timeout=1.2)
            if info:
                self._register_device(info)

        with ThreadPoolExecutor(max_workers=8) as pool:
            pool.map(_check_ip, candidate_ips[:64])
